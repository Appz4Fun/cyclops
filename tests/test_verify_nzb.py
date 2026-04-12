import asyncio
import io
import tempfile
import textwrap
from pathlib import Path
import unittest


class FakeNntpServer:
    def __init__(
        self,
        *,
        stat_responses,
        username=None,
        password=None,
        initial_code="200 fake ready",
        stat_delay=None,
    ):
        self.stat_responses = stat_responses
        self.username = username
        self.password = password
        self.initial_code = initial_code
        self.stat_delay = stat_delay or {}
        self.server = None
        self.host = "127.0.0.1"
        self.port = None
        self.connection_count = 0
        self.commands = []
        self.stat_commands = []

    async def __aenter__(self):
        self.server = await asyncio.start_server(self._handle_client, self.host, 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, exc_type, exc, tb):
        self.server.close()
        await self.server.wait_closed()

    async def _handle_client(self, reader, writer):
        self.connection_count += 1
        writer.write((self.initial_code + "\r\n").encode("ascii"))
        await writer.drain()
        authed = self.username is None

        try:
            while True:
                line = await reader.readline()
                if not line:
                    return
                command = line.decode("utf-8").rstrip("\r\n")
                self.commands.append(command)

                if command.startswith("AUTHINFO USER "):
                    if self.username is None:
                        writer.write(b"502 auth not required\r\n")
                        await writer.drain()
                        continue
                    if command[len("AUTHINFO USER ") :] != self.username:
                        writer.write(b"481 invalid username\r\n")
                        await writer.drain()
                        continue
                    writer.write(b"381 PASS required\r\n")
                    await writer.drain()
                    continue

                if command.startswith("AUTHINFO PASS "):
                    if self.password is None:
                        writer.write(b"502 auth not required\r\n")
                        await writer.drain()
                        continue
                    if command[len("AUTHINFO PASS ") :] != self.password:
                        writer.write(b"481 invalid password\r\n")
                        await writer.drain()
                        continue
                    authed = True
                    writer.write(b"281 authentication accepted\r\n")
                    await writer.drain()
                    continue

                if command.startswith("STAT "):
                    self.stat_commands.append(command[len("STAT ") :])
                    if self.username is not None and not authed:
                        writer.write(b"480 authentication required\r\n")
                        await writer.drain()
                        continue
                    message_id = command[len("STAT ") :]
                    delay = self.stat_delay.get(message_id, 0)
                    if delay:
                        await asyncio.sleep(delay)
                    code = self.stat_responses.get(message_id, 430)
                    writer.write(f"{code} {message_id}\r\n".encode("ascii"))
                    await writer.drain()
                    continue

                writer.write(b"500 command unsupported\r\n")
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()


def make_nzb(contents):
    return textwrap.dedent(contents).lstrip()


class TestVerifyNzbParsingAndConfig(unittest.TestCase):
    def test_parse_nzb_message_ids_streams_segment_text(self):
        import verify_nzb

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "sample.nzb"
            path.write_text(
                make_nzb(
                    """
                    <?xml version="1.0" encoding="utf-8"?>
                    <nzb>
                      <file>
                        <segments>
                          <segment>first@example.invalid</segment>
                          <segment>second@example.invalid</segment>
                        </segments>
                      </file>
                    </nzb>
                    """
                ),
                encoding="utf-8",
            )

            assert list(verify_nzb.parse_nzb_message_ids(path)) == [
                "first@example.invalid",
                "second@example.invalid",
            ]

    def test_load_config_multiple_server_sections(self):
        import verify_nzb

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "nntp.ini"
            path.write_text(
                textwrap.dedent(
                    """
                    [server.primary]
                    host = news1.example.com
                    port = 563
                    ssl = true
                    username = alice
                    password = secret
                    max_connections = 2
                    timeout = 3.5

                    [server.secondary]
                    host = news2.example.com
                    port = 119
                    ssl = false
                    max_connections = 1
                    timeout = 8
                    """
                ).lstrip(),
                encoding="utf-8",
            )

            servers = verify_nzb.load_config(path)

            assert [server.name for server in servers] == ["primary", "secondary"]
            assert servers[0].host == "news1.example.com"
            assert servers[0].port == 563
            assert servers[0].ssl is True
            assert servers[0].username == "alice"
            assert servers[0].password == "secret"
            assert servers[0].max_connections == 2
            assert servers[0].timeout == 3.5
            assert servers[1].host == "news2.example.com"
            assert servers[1].ssl is False


class TestVerifyNzbAsync(unittest.IsolatedAsyncioTestCase):
    async def test_authentication_and_persistent_connection_reuse_stat_only(self):
        import verify_nzb

        async with FakeNntpServer(
            stat_responses={
                "<one@example.invalid>": 223,
                "<two@example.invalid>": 223,
            },
            username="alice",
            password="secret",
        ) as server:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp = Path(tmpdir)
                nzb_path = tmp / "input.nzb"
                config_path = tmp / "nntp.ini"
                nzb_path.write_text(
                    make_nzb(
                        f"""
                        <nzb>
                          <file><segments><segment>&lt;one@example.invalid&gt;</segment></segments></file>
                          <file><segments><segment>&lt;two@example.invalid&gt;</segment></segments></file>
                        </nzb>
                        """
                    ),
                    encoding="utf-8",
                )
                config_path.write_text(
                    textwrap.dedent(
                        f"""
                        [server.primary]
                        host = {server.host}
                        port = {server.port}
                        ssl = false
                        username = alice
                        password = secret
                        max_connections = 1
                        timeout = 1
                        """
                    ).lstrip(),
                    encoding="utf-8",
                )

                summary = await verify_nzb.verify_nzb(
                    nzb_path,
                    config_path,
                    retries=0,
                    progress_stream=io.StringIO(),
                )

        assert summary.total_checked == 2
        assert summary.present == 2
        assert summary.missing == 0
        assert summary.error == 0
        assert server.connection_count == 1
        assert server.stat_commands == ["<one@example.invalid>", "<two@example.invalid>"]
        assert all(
            command.startswith("AUTHINFO ") or command.startswith("STAT ")
            for command in server.commands
        )

    async def test_active_active_multi_server_behavior_and_cross_server_verification(self):
        import verify_nzb

        async with FakeNntpServer(
            stat_responses={
                "<one@example.invalid>": 430,
                "<two@example.invalid>": 223,
            }
        ) as server_a, FakeNntpServer(
            stat_responses={
                "<one@example.invalid>": 223,
                "<two@example.invalid>": 430,
            }
        ) as server_b:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp = Path(tmpdir)
                nzb_path = tmp / "input.nzb"
                config_path = tmp / "nntp.ini"
                nzb_path.write_text(
                    make_nzb(
                        """
                        <nzb>
                          <file><segments><segment>&lt;one@example.invalid&gt;</segment></segments></file>
                          <file><segments><segment>&lt;two@example.invalid&gt;</segment></segments></file>
                        </nzb>
                        """
                    ),
                    encoding="utf-8",
                )
                config_path.write_text(
                    textwrap.dedent(
                        f"""
                        [server.primary]
                        host = {server_a.host}
                        port = {server_a.port}
                        ssl = false
                        max_connections = 1
                        timeout = 1

                        [server.secondary]
                        host = {server_b.host}
                        port = {server_b.port}
                        ssl = false
                        max_connections = 1
                        timeout = 1
                        """
                    ).lstrip(),
                    encoding="utf-8",
                )

                summary = await verify_nzb.verify_nzb(
                    nzb_path,
                    config_path,
                    retries=0,
                    progress_stream=io.StringIO(),
                )

        assert summary.total_checked == 2
        assert summary.present == 2
        assert summary.missing == 0
        assert summary.error == 0
        assert server_a.connection_count == 1
        assert server_b.connection_count == 1
        assert "<one@example.invalid>" in server_a.stat_commands
        assert "<one@example.invalid>" in server_b.stat_commands
        assert "<two@example.invalid>" in server_a.stat_commands
        assert "<two@example.invalid>" in server_b.stat_commands

    async def test_timeout_and_transient_error_yields_error_and_missing_output(self):
        import verify_nzb

        async with FakeNntpServer(
            stat_responses={"<missing@example.invalid>": 430}
        ) as server_a, FakeNntpServer(
            stat_responses={"<missing@example.invalid>": 430},
            stat_delay={"<missing@example.invalid>": 0.25},
        ) as server_b:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp = Path(tmpdir)
                nzb_path = tmp / "input.nzb"
                config_path = tmp / "nntp.ini"
                missing_output = tmp / "missing.txt"
                nzb_path.write_text(
                    make_nzb(
                        """
                        <nzb>
                          <file><segments><segment>&lt;missing@example.invalid&gt;</segment></segments></file>
                        </nzb>
                        """
                    ),
                    encoding="utf-8",
                )
                config_path.write_text(
                    textwrap.dedent(
                        f"""
                        [server.primary]
                        host = {server_a.host}
                        port = {server_a.port}
                        ssl = false
                        max_connections = 1
                        timeout = 0.05

                        [server.secondary]
                        host = {server_b.host}
                        port = {server_b.port}
                        ssl = false
                        max_connections = 1
                        timeout = 0.05
                        """
                    ).lstrip(),
                    encoding="utf-8",
                )

                summary = await verify_nzb.verify_nzb(
                    nzb_path,
                    config_path,
                    retries=0,
                    missing_output=missing_output,
                    progress_stream=io.StringIO(),
                )

                output = missing_output.read_text(encoding="utf-8").splitlines()

        assert summary.total_checked == 1
        assert summary.present == 0
        assert summary.missing == 0
        assert summary.error == 1
        assert output == ["<missing@example.invalid>\terror"]


if __name__ == "__main__":
    unittest.main()
