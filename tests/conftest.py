"""Shared test plumbing for popup.

Design note: nearly everything here drives popup.py *as a subprocess through its CLI*
(`main()` is the only entry point the README pins) instead of poking at internal
server objects.  That keeps the suite honest about the documented interface contract
and stops it from rotting every time an internal helper is renamed.

No test touches the network: every server involved (popup, the proxy upstream, the
FTP snapshot source, moto's S3) binds 127.0.0.1 on an ephemeral port.
"""

from __future__ import annotations

import http.client
import importlib.util
import json
import os
import pathlib
import re
import socket
import socketserver
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
POPUP_PY = ROOT / "popup.py"
READY_TIMEOUT = 45.0   # CI contention: 20s produced flaky 'did not bind' with empty child output
EXIT_TIMEOUT = 15.0


# --------------------------------------------------------------------------- module

def load_popup() -> Any:
    """Import popup.py as a module (it must be import-safe: no side effects at import)."""
    if not POPUP_PY.exists():
        pytest.fail(f"popup.py not found at {POPUP_PY}")
    spec = importlib.util.spec_from_file_location("popup_under_test", POPUP_PY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["popup_under_test"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="session")
def popup() -> Any:
    return load_popup()


# --------------------------------------------------------------------------- net utils

def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def port_open(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def raw_get(
    port: int,
    path: str,
    headers: dict[str, str] | None = None,
    method: str = "GET",
    timeout: float = 15.0,
) -> tuple[int, dict[str, str], bytes]:
    """Send `path` verbatim (no normalisation) so traversal probes reach the server intact."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.putrequest(method, path, skip_host=False, skip_accept_encoding=True)
        for k, v in (headers or {}).items():
            conn.putheader(k, v)
        conn.endheaders()
        resp = conn.getresponse()
        body = resp.read()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, body
    finally:
        conn.close()


# --------------------------------------------------------------------------- popup process

KILL_RE = re.compile(r"/kill/([A-Za-z0-9_\-]{16,})")
URL_RE = re.compile(r"https://[A-Za-z0-9._-]+\.[A-Za-z]{2,}")


class PopupProc:
    """A running `popup.py` child, bound to 127.0.0.1 with tunnelling disabled."""

    def __init__(self, args: list[str], env: dict[str, str] | None = None, cwd: str | None = None):
        self.port = free_port()
        self.cmd = [
            sys.executable, str(POPUP_PY), *args,
            "--tunnel", "none", "--port", str(self.port), "--no-qr", "--no-password",
        ]
        full_env = dict(os.environ)
        full_env.update(env or {})
        full_env.setdefault("PYTHONUNBUFFERED", "1")
        self.proc = subprocess.Popen(
            self.cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, env=full_env, cwd=cwd,
        )
        self._out: list[str] = []
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()

    def _pump(self) -> None:
        assert self.proc.stdout
        for line in self.proc.stdout:
            self._out.append(line)

    # -- observation ------------------------------------------------------
    @property
    def output(self) -> str:
        return "".join(self._out)

    @property
    def kill_secret(self) -> str:
        m = KILL_RE.search(self.output)
        assert m, f"no /kill/<secret> in launch banner:\n{self.output}"
        return m.group(1)

    def wait_ready(self, timeout: float = READY_TIMEOUT) -> PopupProc:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise AssertionError(
                    f"popup exited early (rc={self.proc.returncode})\n"
                    f"cmd: {' '.join(self.cmd)}\noutput:\n{self.output}"
                )
            if port_open(self.port):
                return self
            time.sleep(0.05)
        raise AssertionError(
            f"popup did not bind 127.0.0.1:{self.port} in {timeout}s\n"
            f"cmd: {' '.join(self.cmd)}\noutput:\n{self.output}"
        )

    def wait_output(self, pattern: str, timeout: float = READY_TIMEOUT) -> str:
        rx = re.compile(pattern)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            m = rx.search(self.output)
            if m:
                return m.group(0)
            time.sleep(0.05)
        raise AssertionError(f"pattern {pattern!r} never appeared. output:\n{self.output}")

    def wait_exit(self, timeout: float = EXIT_TIMEOUT) -> int:
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            raise AssertionError(f"popup still running after {timeout}s\noutput:\n{self.output}")

    # -- requests ---------------------------------------------------------
    def get(self, path: str, headers: dict[str, str] | None = None, method: str = "GET"):
        return raw_get(self.port, path, headers, method)

    def config(self) -> dict[str, Any]:
        """Pull the JSON the server injected in place of the __POPUP_CONFIG__ token."""
        status, _, body = self.get("/")
        assert status == 200, f"GET / -> {status}"
        text = body.decode("utf-8", "replace")
        assert "__POPUP_CONFIG__" not in text, "server did not replace the __POPUP_CONFIG__ token"
        m = re.search(r"(?:window\.POPUP|const CONFIG)\s*=\s*", text)
        assert m, f"no injected config assignment in the shell:\n{text[:800]}"
        start = text.index("{", m.end())
        cfg, _ = json.JSONDecoder().raw_decode(text, start)
        return cfg

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)


@pytest.fixture
def spawn() -> Iterator[Any]:
    procs: list[PopupProc] = []

    def _spawn(*args: str, env: dict[str, str] | None = None, cwd: str | None = None,
               ready: bool = True) -> PopupProc:
        p = PopupProc(list(args), env=env, cwd=cwd)
        procs.append(p)
        return p.wait_ready() if ready else p

    yield _spawn
    for p in procs:
        p.close()


# --------------------------------------------------------------------------- upstream HTTP/WS

class _Upstream(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _UpstreamHandler(socketserver.BaseRequestHandler):
    """Minimal raw-socket HTTP server used as a proxy target.

    GET /host  -> the Host header exactly as received (proves popup rewrote it)
    GET /ws with Upgrade: websocket -> 101 then a raw byte echo (proves the splice)
    anything else -> 200 "upstream ok"
    """

    def handle(self) -> None:
        sock = self.request
        sock.settimeout(15)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                return
            buf += chunk
        head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        lines = head.split("\r\n")
        target = lines[0].split(" ")[1] if len(lines[0].split(" ")) > 1 else "/"
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        if headers.get("upgrade", "").lower() == "websocket":
            sock.sendall(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
            )
            while True:  # raw echo: anything popup splices through comes straight back
                try:
                    data = sock.recv(4096)
                except OSError:
                    return
                if not data:
                    return
                sock.sendall(data)

        body = headers.get("host", "").encode() if target.startswith("/host") else b"upstream ok"
        sock.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body
        )


@pytest.fixture
def upstream() -> Iterator[int]:
    port = free_port()
    srv = _Upstream(("127.0.0.1", port), _UpstreamHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield port
    srv.shutdown()
    srv.server_close()


# --------------------------------------------------------------------------- mini FTP

class MiniFTP(threading.Thread):
    """Read-only loopback FTP server: USER/PASS/TYPE/CWD/PWD/SIZE/PASV/RETR/QUIT.

    This *is* the "ftp mocked" requirement -- a real protocol speaker is both smaller
    and less brittle than monkeypatching whichever ftplib/urllib entry point popup picks.
    """

    def __init__(self, root: pathlib.Path):
        super().__init__(daemon=True)
        self.root = root
        self.port = free_port()
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", self.port))
        self.sock.listen(5)
        self._stop = False

    def run(self) -> None:
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(conn,), daemon=True).start()

    def stop(self) -> None:
        self._stop = True
        self.sock.close()

    def _session(self, conn: socket.socket) -> None:
        conn.settimeout(20)
        cwd = pathlib.PurePosixPath("/")
        pasv: socket.socket | None = None
        f = conn.makefile("rwb")
        try:
            f.write(b"220 popup-test-ftp\r\n")
            f.flush()
            for raw in f:
                line = raw.decode("latin-1").strip()
                cmd, _, arg = line.partition(" ")
                cmd = cmd.upper()
                if cmd in ("USER", "PASS", "TYPE", "NOOP", "MODE", "STRU"):
                    f.write(b"230 ok\r\n" if cmd == "PASS" else b"200 ok\r\n")
                elif cmd == "SYST":
                    f.write(b"215 UNIX Type: L8\r\n")
                elif cmd == "PWD":
                    f.write(f'257 "{cwd}"\r\n'.encode())
                elif cmd == "CWD":
                    cwd = cwd / arg if not arg.startswith("/") else pathlib.PurePosixPath(arg)
                    f.write(b"250 ok\r\n")
                elif cmd == "SIZE":
                    p = self._path(cwd, arg)
                    f.write(f"213 {p.stat().st_size}\r\n".encode() if p.is_file() else b"550 no\r\n")
                elif cmd == "PASV":
                    pasv = socket.socket()
                    pasv.bind(("127.0.0.1", 0))
                    pasv.listen(1)
                    p = pasv.getsockname()[1]
                    f.write(f"227 Entering Passive Mode (127,0,0,1,{p >> 8},{p & 0xFF})\r\n".encode())
                elif cmd in ("RETR", "LIST", "NLST"):
                    p = self._path(cwd, arg)
                    if cmd == "RETR" and not p.is_file():
                        f.write(b"550 not found\r\n")
                    elif pasv is None:
                        f.write(b"425 use PASV\r\n")
                    else:
                        f.write(b"150 opening data connection\r\n")
                        f.flush()
                        data, _ = pasv.accept()
                        payload = p.read_bytes() if cmd == "RETR" else b"".join(
                            f"-rw-r--r-- 1 u u {c.stat().st_size} Jan  1 00:00 {c.name}\r\n".encode()
                            for c in sorted(p.iterdir())
                        ) if p.is_dir() else b""
                        data.sendall(payload)
                        data.close()
                        pasv.close()
                        pasv = None
                        f.write(b"226 transfer complete\r\n")
                elif cmd == "QUIT":
                    f.write(b"221 bye\r\n")
                    f.flush()
                    return
                else:
                    f.write(b"502 not implemented\r\n")
                f.flush()
        except (OSError, ValueError):
            return
        finally:
            try:
                f.close()
                conn.close()
            except OSError:
                pass

    def _path(self, cwd: pathlib.PurePosixPath, arg: str) -> pathlib.Path:
        rel = (cwd / arg).as_posix().lstrip("/")
        return self.root / rel


@pytest.fixture
def ftp_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[MiniFTP]:
    root = tmp_path_factory.mktemp("ftproot")
    (root / "doc.txt").write_text("ftp snapshot payload\n")
    srv = MiniFTP(root)
    srv.start()
    yield srv
    srv.stop()
