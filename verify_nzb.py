from __future__ import annotations

import argparse
import asyncio
import configparser
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
class VerificationSummary:
    total_checked: int
    present: int
    missing: int
    error: int
    stat_requests: int
    elapsed_seconds: float


class NntpError(Exception):
    """Base class for NNTP failures."""


class TransientNntpError(NntpError):
    """A network or timeout problem that can be retried."""


class ProtocolNntpError(NntpError):
    """An unexpected NNTP response."""


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def parse_nzb_message_ids(path: str | Path) -> Iterator[str]:
    """Yield message IDs from <segment> elements in an NZB file."""

    with open(path, "rb") as handle:
        for event, elem in ET.iterparse(handle, events=("end",)):
            if _local_name(elem.tag) != "segment":
                continue
            text = (elem.text or "").strip()
            if text:
                yield text
            elem.clear()


def normalize_message_id(message_id: str) -> str:
    text = message_id.strip()
    if text.startswith("<") and text.endswith(">"):
        return text
    return f"<{text.strip('<>')}>"


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

    async def connect(self, retries: int = 0) -> None:
        await self._retry(self._connect_once, retries)

    async def stat(self, message_id: str, retries: int = 0) -> int:
        return await self._retry(self._stat_once, retries, message_id)

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

    async def _send_command(self, command: str) -> tuple[int, str]:
        assert self._writer is not None
        assert self._reader is not None
        try:
            self._writer.write((command + "\r\n").encode("ascii"))
            await asyncio.wait_for(self._writer.drain(), timeout=self.config.timeout)
            return await self._read_response()
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
        self._input_complete = False
        self._pending_messages = 0
        self._finished = asyncio.Event()
        self._shutdown = False
        self._progress_was_written = False

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
                await self._handle_job(server_index, connection, job.message_id, job.target_server_index)
        except asyncio.CancelledError:
            raise

    async def _take_job(self, server_index: int) -> _Job | None:
        async with self.job_condition:
            while True:
                job = self._find_job_for_server(server_index)
                if job is not None:
                    self.jobs.remove(job)
                    self.states[job.message_id].queued = False
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
                return
            if target_server_index is None:
                state.next_server_index = server_index
            elif target_server_index != server_index:
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
            if state.final_status is not None or state.queued:
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
        state.queued = True
        state.next_server_index = server_index
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
        if final_status == "present":
            self.present += 1
        elif final_status == "missing":
            self.missing += 1
            self.issues.append((message_id, "missing"))
        else:
            self.error += 1
            self.issues.append((message_id, "error"))
        self._write_progress(message_id, final_status)
        self._pending_messages -= 1
        self._maybe_finish_locked()

    def _write_progress(self, message_id: str, final_status: str) -> None:
        stream = self.progress_stream
        stream.write(
            "\r"
            f"checked {self.total_checked} total, present={self.present}, missing={self.missing}, "
            f"error={self.error}, last={message_id} => {final_status}"
        )
        flush = getattr(stream, "flush", None)
        if callable(flush):
            flush()
        self._progress_was_written = True

    def _maybe_finish_locked(self) -> None:
        if self._input_complete and self._pending_messages == 0:
            self._finished.set()

    def _finish_progress(self) -> None:
        if not self._progress_was_written:
            return
        self.progress_stream.write("\n")
        flush = getattr(self.progress_stream, "flush", None)
        if callable(flush):
            flush()

async def verify_nzb(
    nzb_path: str | Path,
    config_path: str | Path,
    *,
    retries: int = 1,
    missing_output: str | Path | None = None,
    progress_stream = sys.stdout,
) -> VerificationSummary:
    servers = load_config(config_path)
    verifier = _Verifier(servers, retries=retries, progress_stream=progress_stream)
    return await verifier.run(parse_nzb_message_ids(nzb_path), missing_output=missing_output)


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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    summary = asyncio.run(
        verify_nzb(
            args.nzb_path,
            args.config,
            retries=args.retries,
            missing_output=args.missing_output,
        )
    )
    print(
        "summary: "
        f"checked={summary.total_checked} present={summary.present} missing={summary.missing} "
        f"error/indeterminate={summary.error} stat_requests={summary.stat_requests} "
        f"elapsed={summary.elapsed_seconds:.3f}s",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
