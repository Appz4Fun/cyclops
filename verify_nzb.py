from __future__ import annotations

import argparse
import asyncio
import binascii
import configparser
import math
import random
import ssl as ssl_module
import sys
import time
import xml.etree.ElementTree as ET
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator


@dataclass(frozen=True)
class ServerConfig:
    name: str
    host: str
    port: int
    ssl: bool
    username: str | None
    password: str | None
    max_connections: int
    timeout: float


@dataclass
class DeepCheckSummary:
    sampled: int
    ok: int
    corrupt: int
    error: int
    body_requests: int
    elapsed_seconds: float


@dataclass
class VerificationSummary:
    total_checked: int
    present: int
    missing: int
    error: int
    stat_requests: int
    elapsed_seconds: float
    deep: DeepCheckSummary | None = None


@dataclass(frozen=True)
class YencValidationResult:
    ok: bool
    decoded_size: int
    error: str | None = None


@dataclass(frozen=True)
class DeepCheckResult:
    message_id: str
    status: str
    detail: str
    server: str | None = None


class NntpError(Exception):
    """Base class for NNTP failures."""


class TransientNntpError(NntpError):
    """A network or timeout problem that can be retried."""


class ProtocolNntpError(NntpError):
    """An unexpected NNTP response."""


class MissingArticleError(NntpError):
    """The NNTP server does not have the requested article."""


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def parse_nzb_message_ids(path: str | Path) -> Iterator[str]:
    """Yield message IDs from <segment> elements in an NZB file."""
    with open(path, "rb") as handle:
        context = ET.iterparse(handle, events=("start", "end"))
        context = iter(context)
        try:
            event, root = next(context)
        except StopIteration:
            return

        for event, elem in context:
            if event == "end":
                if _local_name(elem.tag) == "segment":
                    text = (elem.text or "").strip()
                    if text:
                        yield text
                elem.clear()
                root.clear()


def normalize_message_id(message_id: str) -> str:
    text = message_id.strip()
    if text.startswith("<") and text.endswith(">"):
        return text
    return f"<{text.strip('<>')}>"


def _parse_yenc_attrs(line: bytes) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for token in line.decode("latin-1", errors="replace").split()[1:]:
        if "=" in token:
            key, value = token.split("=", 1)
            attrs[key.lower()] = value
    return attrs


def _decode_yenc_lines(lines: Iterable[bytes]) -> bytes:
    decoded = bytearray()
    for line in lines:
        index = 0
        while index < len(line):
            byte = line[index]
            if byte == 61:
                index += 1
                if index >= len(line):
                    raise ValueError("dangling yEnc escape")
                byte = (line[index] - 64) % 256
            decoded.append((byte - 42) % 256)
            index += 1
    return bytes(decoded)


def validate_yenc_body(lines: Iterable[bytes | str]) -> YencValidationResult:
    ybegin_attrs: dict[str, str] | None = None
    ypart_attrs: dict[str, str] | None = None
    yend_attrs: dict[str, str] | None = None
    data_lines: list[bytes] = []

    for raw_line in lines:
        line = raw_line.encode("latin-1") if isinstance(raw_line, str) else bytes(raw_line)
        line = line.rstrip(b"\r\n")
        if line.startswith(b"=ybegin"):
            ybegin_attrs = _parse_yenc_attrs(line)
            continue
        if line.startswith(b"=ypart"):
            ypart_attrs = _parse_yenc_attrs(line)
            continue
        if line.startswith(b"=yend"):
            yend_attrs = _parse_yenc_attrs(line)
            break
        if ybegin_attrs is not None:
            data_lines.append(line)

    if ybegin_attrs is None:
        return YencValidationResult(ok=False, decoded_size=0, error="missing ybegin")
    if yend_attrs is None:
        return YencValidationResult(ok=False, decoded_size=0, error="missing yend")

    try:
        decoded = _decode_yenc_lines(data_lines)
    except ValueError as exc:
        return YencValidationResult(ok=False, decoded_size=0, error=str(exc))

    expected_size = yend_attrs.get("size") or ybegin_attrs.get("size")
    if expected_size is not None:
        try:
            size_value = int(expected_size)
        except ValueError:
            return YencValidationResult(
                ok=False,
                decoded_size=len(decoded),
                error=f"invalid yEnc size: {expected_size}",
            )
        if len(decoded) != size_value:
            return YencValidationResult(
                ok=False,
                decoded_size=len(decoded),
                error=f"size mismatch: expected {size_value}, got {len(decoded)}",
            )

    if ypart_attrs is not None:
        begin_text = ypart_attrs.get("begin")
        end_text = ypart_attrs.get("end")
        if begin_text is None or end_text is None:
            return YencValidationResult(
                ok=False,
                decoded_size=len(decoded),
                error="invalid ypart: missing begin/end",
            )
        try:
            begin_value = int(begin_text)
            end_value = int(end_text)
        except ValueError:
            return YencValidationResult(
                ok=False,
                decoded_size=len(decoded),
                error=f"invalid ypart range: begin={begin_text} end={end_text}",
            )
        if begin_value < 1 or end_value < begin_value:
            return YencValidationResult(
                ok=False,
                decoded_size=len(decoded),
                error=f"invalid ypart range: begin={begin_value} end={end_value}",
            )
        expected_part_size = end_value - begin_value + 1
        if expected_part_size != len(decoded):
            return YencValidationResult(
                ok=False,
                decoded_size=len(decoded),
                error=f"ypart range mismatch: expected {expected_part_size}, got {len(decoded)}",
            )

    expected_crc = yend_attrs.get("pcrc32") or yend_attrs.get("crc32")
    if expected_crc is not None:
        actual_crc = f"{binascii.crc32(decoded) & 0xFFFFFFFF:08x}"
        if actual_crc.lower() != expected_crc.lower():
            return YencValidationResult(
                ok=False,
                decoded_size=len(decoded),
                error=f"crc32 mismatch: expected {expected_crc.lower()}, got {actual_crc}",
            )

    return YencValidationResult(ok=True, decoded_size=len(decoded), error=None)


def select_deep_sample(
    message_ids: Iterable[str],
    *,
    sample_percent: float,
    sample_seed: int | None,
) -> list[str]:
    if not 0 < sample_percent <= 100:
        raise ValueError("sample_percent must be greater than 0 and at most 100")
    unique_ids = list(dict.fromkeys(message_ids))
    if not unique_ids:
        return []
    sample_size = min(len(unique_ids), max(1, math.ceil(len(unique_ids) * sample_percent / 100)))
    if sample_size == len(unique_ids):
        return unique_ids
    return random.Random(sample_seed).sample(unique_ids, sample_size)


def load_config(path: str | Path) -> list[ServerConfig]:
    parser = configparser.ConfigParser()
    with open(path, "r", encoding="utf-8") as handle:
        parser.read_file(handle)

    servers: list[ServerConfig] = []
    for section in parser.sections():
        if not section.startswith("server."):
            continue
        name = section.split(".", 1)[1]
        host = parser.get(section, "host", fallback=None)
        port = parser.getint(section, "port", fallback=None)
        use_ssl = parser.getboolean(section, "ssl", fallback=None)
        max_connections = parser.getint(section, "max_connections", fallback=None)
        timeout = parser.getfloat(section, "timeout", fallback=None)
        username = parser.get(section, "username", fallback=None)
        password = parser.get(section, "password", fallback=None)

        missing = [
            field_name
            for field_name, value in (
                ("host", host),
                ("port", port),
                ("ssl", use_ssl),
                ("max_connections", max_connections),
                ("timeout", timeout),
            )
            if value is None
        ]
        if missing:
            raise ValueError(f"missing required options in [{section}]: {', '.join(missing)}")
        if (username is None) ^ (password is None):
            raise ValueError(f"[{section}] must set both username and password or neither")
        if max_connections < 1:
            raise ValueError(f"[{section}] max_connections must be at least 1")
        if port < 1:
            raise ValueError(f"[{section}] port must be at least 1")
        if timeout <= 0:
            raise ValueError(f"[{section}] timeout must be greater than 0")

        servers.append(
            ServerConfig(
                name=name,
                host=host,
                port=port,
                ssl=use_ssl,
                username=username,
                password=password,
                max_connections=max_connections,
                timeout=timeout,
            )
        )

    if not servers:
        raise ValueError("configuration must contain at least one [server.<name>] section")
    return servers


class AsyncNntpConnection:
    def __init__(self, config: ServerConfig):
        self.config = config
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self.request_count = 0
        self.body_request_count = 0

    async def connect(self, retries: int = 0) -> None:
        await self._retry(self._connect_once, retries)

    async def stat(self, message_id: str, retries: int = 0) -> int:
        return await self._retry(self._stat_once, retries, message_id)

    async def body(self, message_id: str, retries: int = 0) -> list[bytes]:
        return await self._retry(self._body_once, retries, message_id)

    async def close(self) -> None:
        writer = self._writer
        self._reader = None
        self._writer = None
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _retry(self, func, retries: int, *args):
        attempts = retries + 1
        last_error: Exception | None = None
        for attempt in range(attempts):
            try:
                return await func(*args)
            except TransientNntpError as exc:
                last_error = exc
                await self.close()
                if attempt + 1 >= attempts:
                    raise
            except ProtocolNntpError:
                await self.close()
                raise
        if last_error is not None:
            raise last_error
        raise TransientNntpError("unreachable")

    async def _connect_once(self) -> None:
        if self._writer is not None:
            return
        ssl_context = ssl_module.create_default_context() if self.config.ssl else None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.config.host,
                    self.config.port,
                    ssl=ssl_context,
                ),
                timeout=self.config.timeout,
            )
            self._reader = reader
            self._writer = writer
            code, _ = await self._read_response()
            if code not in (200, 201):
                raise ProtocolNntpError(f"unexpected greeting {code}")
            if self.config.username is not None:
                await self._authenticate()
        except asyncio.TimeoutError as exc:
            raise TransientNntpError("connection timeout") from exc
        except OSError as exc:
            raise TransientNntpError("connection failed") from exc

    async def _authenticate(self) -> None:
        assert self._writer is not None
        assert self._reader is not None
        username = self.config.username or ""
        password = self.config.password or ""
        code, _ = await self._send_command(f"AUTHINFO USER {username}")
        if code == 281:
            return
        if code != 381:
            raise ProtocolNntpError(f"unexpected AUTHINFO USER response {code}")
        code, _ = await self._send_command(f"AUTHINFO PASS {password}")
        if code != 281:
            raise ProtocolNntpError(f"unexpected AUTHINFO PASS response {code}")

    async def _stat_once(self, message_id: str) -> int:
        await self._connect_once()
        self.request_count += 1
        code, _ = await self._send_command(f"STAT {normalize_message_id(message_id)}")
        if code in (223, 430):
            return code
        raise ProtocolNntpError(f"unexpected STAT response {code}")

    async def _body_once(self, message_id: str) -> list[bytes]:
        await self._connect_once()
        self.body_request_count += 1
        code, _ = await self._send_command(f"BODY {normalize_message_id(message_id)}")
        if code == 222:
            return await self._read_multiline()
        if code == 430:
            raise MissingArticleError(f"missing article: {message_id}")
        raise ProtocolNntpError(f"unexpected BODY response {code}")

    async def _send_command(self, command: str) -> tuple[int, str]:
        assert self._writer is not None
        assert self._reader is not None
        try:
            self._writer.write((command + "\r\n").encode("ascii"))
            await asyncio.wait_for(self._writer.drain(), timeout=self.config.timeout)
            return await self._read_response()
        except UnicodeEncodeError as exc:
            raise ProtocolNntpError("NNTP command is not ASCII encodable") from exc
        except asyncio.TimeoutError as exc:
            raise TransientNntpError("command timeout") from exc
        except (ConnectionResetError, BrokenPipeError, OSError, asyncio.IncompleteReadError) as exc:
            raise TransientNntpError("connection lost") from exc

    async def _read_response(self) -> tuple[int, str]:
        assert self._reader is not None
        try:
            line = await asyncio.wait_for(self._reader.readline(), timeout=self.config.timeout)
        except asyncio.TimeoutError as exc:
            raise TransientNntpError("read timeout") from exc
        if not line:
            raise TransientNntpError("connection closed")
        text = line.decode("utf-8", errors="replace").rstrip("\r\n")
        if len(text) < 3 or not text[:3].isdigit():
            raise ProtocolNntpError(f"malformed response: {text!r}")
        return int(text[:3]), text[4:] if len(text) > 4 else ""

    async def _read_multiline(self) -> list[bytes]:
        assert self._reader is not None
        lines: list[bytes] = []
        while True:
            try:
                line = await asyncio.wait_for(self._reader.readline(), timeout=self.config.timeout)
            except asyncio.TimeoutError as exc:
                raise TransientNntpError("read timeout") from exc
            if not line:
                raise TransientNntpError("connection closed")
            line = line.rstrip(b"\r\n")
            if line == b".":
                return lines
            if line.startswith(b".."):
                line = line[1:]
            lines.append(line)


@dataclass
class _Job:
    message_id: str
    target_server_index: int | None = None


@dataclass
class _MessageState:
    tried_servers: set[int] = field(default_factory=set)
    final_status: str | None = None
    had_error: bool = False
    queued: bool = False
    in_flight: bool = False


class _Verifier:
    def __init__(
        self,
        servers: list[ServerConfig],
        *,
        retries: int,
        progress_stream,
    ):
        self.servers = servers
        self.retries = retries
        self.progress_stream = progress_stream
        self.jobs: deque[_Job] = deque()
        self.job_condition = asyncio.Condition()
        self.connections: list[list[AsyncNntpConnection]] = [
            [AsyncNntpConnection(server) for _ in range(server.max_connections)]
            for server in servers
        ]
        self.workers: list[asyncio.Task[None]] = []
        self.states: dict[str, _MessageState] = {}
        self.issues: list[tuple[str, str]] = []
        self.total_checked = 0
        self.present = 0
        self.missing = 0
        self.error = 0
        self.present_message_ids: list[str] = []
        self._input_complete = False
        self._pending_messages = 0
        self._finished = asyncio.Event()
        self._shutdown = False
        self._progress_was_written = False
        self._progress_failed = False

    async def run(self, message_ids: Iterable[str], missing_output: str | Path | None = None) -> VerificationSummary:
        start = time.monotonic()
        try:
            await self._start_workers()
            for message_id in message_ids:
                self.total_checked += 1
                self.states.setdefault(message_id, _MessageState())
                await self._enqueue_message(message_id)
            async with self.job_condition:
                self._input_complete = True
                self._maybe_finish_locked()
            await self._finished.wait()
        finally:
            await self._stop_workers()
        self._finish_progress()

        if missing_output is not None:
            path = Path(missing_output)
            with path.open("w", encoding="utf-8") as handle:
                for message_id, status in self.issues:
                    handle.write(f"{message_id}\t{status}\n")

        elapsed = time.monotonic() - start
        return VerificationSummary(
            total_checked=self.total_checked,
            present=self.present,
            missing=self.missing,
            error=self.error,
            stat_requests=sum(conn.request_count for server in self.connections for conn in server),
            elapsed_seconds=elapsed,
        )

    async def _start_workers(self) -> None:
        for server_index, server in enumerate(self.servers):
            for worker_index in range(server.max_connections):
                connection = self.connections[server_index][worker_index]
                task = asyncio.create_task(self._worker_loop(server_index, connection))
                self.workers.append(task)

        await asyncio.gather(
            *(connection.connect(self.retries) for server_connections in self.connections for connection in server_connections),
            return_exceptions=True,
        )

    async def _stop_workers(self) -> None:
        async with self.job_condition:
            self._shutdown = True
            self.job_condition.notify_all()
        if self.workers:
            await asyncio.gather(*self.workers, return_exceptions=True)
        for server_connections in self.connections:
            for connection in server_connections:
                await connection.close()

    async def _worker_loop(self, server_index: int, connection: AsyncNntpConnection) -> None:
        try:
            while True:
                job = await self._take_job(server_index)
                if job is None:
                    return
                try:
                    await self._handle_job(server_index, connection, job.message_id, job.target_server_index)
                except Exception:
                    async with self.job_condition:
                        state = self.states.get(job.message_id)
                        if state is not None:
                            state.had_error = True
                            await self._finalize_locked(job.message_id, "error")
        except asyncio.CancelledError:
            raise

    async def _take_job(self, server_index: int) -> _Job | None:
        async with self.job_condition:
            while True:
                job = self._find_job_for_server(server_index)
                if job is not None:
                    self.jobs.remove(job)
                    state = self.states[job.message_id]
                    state.queued = False
                    state.in_flight = True
                    return job
                if self._shutdown:
                    return None
                await self.job_condition.wait()

    def _find_job_for_server(self, server_index: int) -> _Job | None:
        for job in self.jobs:
            if job.target_server_index is None or job.target_server_index == server_index:
                return job
        return None

    async def _handle_job(
        self,
        server_index: int,
        connection: AsyncNntpConnection,
        message_id: str,
        target_server_index: int | None,
    ) -> None:
        state = self.states[message_id]
        async with self.job_condition:
            if state.final_status is not None:
                state.in_flight = False
                return
            if target_server_index is not None and target_server_index != server_index:
                self._defer_message_locked(message_id, target_server_index)
                return
            state.tried_servers.add(server_index)

        try:
            code = await connection.stat(message_id, self.retries)
        except TransientNntpError:
            async with self.job_condition:
                state.had_error = True
                next_index = self._next_server_index_locked(state, server_index)
                if next_index is not None:
                    self._defer_message_locked(message_id, next_index)
                    return
                await self._finalize_locked(message_id, "error")
                return
        except ProtocolNntpError:
            async with self.job_condition:
                state.had_error = True
                next_index = self._next_server_index_locked(state, server_index)
                if next_index is not None:
                    self._defer_message_locked(message_id, next_index)
                    return
                await self._finalize_locked(message_id, "error")
                return

        async with self.job_condition:
            if code == 223:
                await self._finalize_locked(message_id, "present")
                return
            next_index = self._next_server_index_locked(state, server_index)
            if code == 430:
                if next_index is not None:
                    self._defer_message_locked(message_id, next_index)
                    return
                await self._finalize_locked(message_id, "error" if state.had_error else "missing")
                return
            state.had_error = True
            if next_index is not None:
                self._defer_message_locked(message_id, next_index)
                return
            await self._finalize_locked(message_id, "error")

    async def _enqueue_message(self, message_id: str) -> bool:
        async with self.job_condition:
            state = self.states[message_id]
            if state.final_status is not None or state.queued or state.in_flight:
                return False
            state.queued = True
            self._pending_messages += 1
            self.jobs.append(_Job(message_id=message_id))
            self.job_condition.notify_all()
            return True

    def _defer_message_locked(self, message_id: str, server_index: int) -> None:
        state = self.states[message_id]
        if state.final_status is not None or state.queued:
            return
        state.in_flight = False
        state.queued = True
        self.jobs.append(_Job(message_id=message_id, target_server_index=server_index))
        self.job_condition.notify_all()

    def _next_server_index_locked(self, state: _MessageState, current_server_index: int) -> int | None:
        total = len(self.servers)
        for offset in range(1, total + 1):
            candidate = (current_server_index + offset) % total
            if candidate not in state.tried_servers:
                return candidate
        return None

    async def _finalize_locked(self, message_id: str, final_status: str) -> None:
        state = self.states[message_id]
        if state.final_status is not None:
            return
        state.final_status = final_status
        state.in_flight = False
        if final_status == "present":
            self.present += 1
            self.present_message_ids.append(message_id)
        elif final_status == "missing":
            self.missing += 1
            self.issues.append((message_id, "missing"))
        else:
            self.error += 1
            self.issues.append((message_id, "error"))
        self._pending_messages -= 1
        self._maybe_finish_locked()
        self._write_progress(message_id, final_status)

    def _write_progress(self, message_id: str, final_status: str) -> None:
        if self._progress_failed:
            return
        stream = self.progress_stream
        try:
            stream.write(
                "\r"
                f"checked {self.total_checked} total, present={self.present}, missing={self.missing}, "
                f"error={self.error}, last={message_id} => {final_status}"
            )
            flush = getattr(stream, "flush", None)
            if callable(flush):
                flush()
            self._progress_was_written = True
        except OSError:
            self._progress_failed = True

    def _maybe_finish_locked(self) -> None:
        if self._input_complete and self._pending_messages == 0:
            self._finished.set()

    def _finish_progress(self) -> None:
        if not self._progress_was_written or self._progress_failed:
            return
        try:
            self.progress_stream.write("\n")
            flush = getattr(self.progress_stream, "flush", None)
            if callable(flush):
                flush()
        except OSError:
            self._progress_failed = True


class _DeepVerifier:
    def __init__(self, servers: list[ServerConfig], *, retries: int):
        self.servers = servers
        self.retries = retries
        self.connection_queues: list[asyncio.Queue[AsyncNntpConnection]] = [
            asyncio.Queue() for _ in servers
        ]
        self.connections: list[list[AsyncNntpConnection]] = [
            [AsyncNntpConnection(server) for _ in range(server.max_connections)]
            for server in servers
        ]

    async def run(
        self,
        message_ids: list[str],
        *,
        deep_output: str | Path | None = None,
    ) -> DeepCheckSummary:
        start = time.monotonic()
        try:
            await self._start()
            results = await asyncio.gather(
                *(self._check_one(index, message_id) for index, message_id in enumerate(message_ids))
            )
        finally:
            await self._stop()

        if deep_output is not None:
            with Path(deep_output).open("w", encoding="utf-8") as handle:
                for result in results:
                    server = result.server or "-"
                    handle.write(f"{result.message_id}\t{result.status}\t{result.detail}\t{server}\n")

        elapsed = time.monotonic() - start
        return DeepCheckSummary(
            sampled=len(message_ids),
            ok=sum(1 for result in results if result.status == "ok"),
            corrupt=sum(1 for result in results if result.status == "corrupt"),
            error=sum(1 for result in results if result.status == "error"),
            body_requests=sum(
                connection.body_request_count
                for server_connections in self.connections
                for connection in server_connections
            ),
            elapsed_seconds=elapsed,
        )

    async def _start(self) -> None:
        await asyncio.gather(
            *(connection.connect(self.retries) for server_connections in self.connections for connection in server_connections),
            return_exceptions=True,
        )
        for server_index, server_connections in enumerate(self.connections):
            for connection in server_connections:
                self.connection_queues[server_index].put_nowait(connection)

    async def _stop(self) -> None:
        for server_connections in self.connections:
            for connection in server_connections:
                await connection.close()

    async def _check_one(self, sample_index: int, message_id: str) -> DeepCheckResult:
        last_error = "article body unavailable"
        server_count = len(self.servers)
        for offset in range(server_count):
            server_index = (sample_index + offset) % server_count
            connection = await self.connection_queues[server_index].get()
            try:
                try:
                    body_lines = await connection.body(message_id, self.retries)
                except MissingArticleError:
                    last_error = f"missing on {self.servers[server_index].name}"
                    continue
                except NntpError as exc:
                    last_error = f"{self.servers[server_index].name}: {exc}"
                    continue

                validation = validate_yenc_body(body_lines)
                if validation.ok:
                    return DeepCheckResult(
                        message_id=message_id,
                        status="ok",
                        detail=f"decoded_size={validation.decoded_size}",
                        server=self.servers[server_index].name,
                    )
                return DeepCheckResult(
                    message_id=message_id,
                    status="corrupt",
                    detail=validation.error or "yEnc validation failed",
                    server=self.servers[server_index].name,
                )
            finally:
                self.connection_queues[server_index].put_nowait(connection)

        return DeepCheckResult(message_id=message_id, status="error", detail=last_error, server=None)


async def verify_nzb(
    nzb_path: str | Path,
    config_path: str | Path,
    *,
    retries: int = 1,
    missing_output: str | Path | None = None,
    deep_check: bool = False,
    sample_percent: float = 1.0,
    sample_seed: int | None = None,
    deep_output: str | Path | None = None,
    progress_stream = sys.stdout,
) -> VerificationSummary:
    servers = load_config(config_path)
    verifier = _Verifier(servers, retries=retries, progress_stream=progress_stream)
    summary = await verifier.run(parse_nzb_message_ids(nzb_path), missing_output=missing_output)
    if deep_check:
        sampled_ids = select_deep_sample(
            verifier.present_message_ids,
            sample_percent=sample_percent,
            sample_seed=sample_seed,
        )
        deep_verifier = _DeepVerifier(servers, retries=retries)
        summary.deep = await deep_verifier.run(sampled_ids, deep_output=deep_output)
    return summary


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify NZB message IDs against NNTP servers.")
    parser.add_argument("nzb_path", type=Path, help="path to the NZB file")
    parser.add_argument("--config", required=True, type=Path, help="path to the NNTP INI file")
    parser.add_argument("--retries", type=int, default=1, help="retry count for transient network errors")
    parser.add_argument(
        "--missing-output",
        type=Path,
        default=None,
        help="write missing/error message IDs to this file",
    )
    parser.add_argument(
        "--deep-check",
        action="store_true",
        help="download a sampled set of present article bodies and validate yEnc CRC/size",
    )
    parser.add_argument(
        "--sample-percent",
        type=float,
        default=1.0,
        help="percentage of present articles to deep-check when --deep-check is set",
    )
    parser.add_argument(
        "--sample-seed",
        type=int,
        default=None,
        help="random seed for deterministic deep-check sampling",
    )
    parser.add_argument(
        "--deep-output",
        type=Path,
        default=None,
        help="write sampled deep-check results to this file",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    summary = asyncio.run(
        verify_nzb(
            args.nzb_path,
            args.config,
            retries=args.retries,
            missing_output=args.missing_output,
            deep_check=args.deep_check,
            sample_percent=args.sample_percent,
            sample_seed=args.sample_seed,
            deep_output=args.deep_output,
        )
    )
    print(
        "summary: "
        f"checked={summary.total_checked} present={summary.present} missing={summary.missing} "
        f"error/indeterminate={summary.error} stat_requests={summary.stat_requests} "
        f"elapsed={summary.elapsed_seconds:.3f}s",
        flush=True,
    )
    if summary.deep is not None:
        print(
            "deep: "
            f"sampled={summary.deep.sampled} ok={summary.deep.ok} corrupt={summary.deep.corrupt} "
            f"error={summary.deep.error} body_requests={summary.deep.body_requests} "
            f"elapsed={summary.deep.elapsed_seconds:.3f}s",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
