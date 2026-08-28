"""Phase-4 gate: Host rewrite, WebSocket upgrade splice, run-mode env scrub."""

from __future__ import annotations

import json
import os
import pathlib
import signal
import socket
import subprocess
import sys
import time

import pytest
from conftest import POPUP_PY, free_port, port_open, raw_get

# Secrets planted in popup's own environment; the run-mode child must not see them.
DIRTY_ENV = {
    "AWS_ACCESS_KEY_ID": "AKIAPOPUPTESTKEY0000",
    "AWS_SECRET_ACCESS_KEY": "s3cr3t-aws-value",
    "AWS_SESSION_TOKEN": "session-token-value",
    "GITHUB_TOKEN": "ghp_popuptesttoken",
    "MY_APP_SECRET": "app-secret-value",
    "DEPLOY_KEY": "deploy-key-value",
    "SLACK_TOKEN": "slack-token-value",
    "POPUP_HARMLESS": "keep-me",
}


# --------------------------------------------------------------------------- proxy mode

def test_host_header_is_rewritten(spawn, upstream):
    p = spawn(f":{upstream}")
    status, _, body = p.get("/host", {"Host": "calm-frog-3121.trycloudflare.com"})
    assert status == 200
    assert body.decode() == f"localhost:{upstream}", (
        "upstream must see Host: localhost:PORT, not the tunnel hostname "
        "(that is what trips Vite/Django host checks)"
    )


def test_proxy_passes_through_other_paths(spawn, upstream):
    p = spawn(f":{upstream}")
    assert p.get("/anything/else")[2] == b"upstream ok"


def test_websocket_upgrade_is_spliced(spawn, upstream):
    p = spawn(f":{upstream}")
    s = socket.create_connection(("127.0.0.1", p.port), timeout=15)
    try:
        s.sendall(
            b"GET /ws HTTP/1.1\r\n"
            b"Host: calm-frog-3121.trycloudflare.com\r\n"
            b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            b"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = s.recv(4096)
            assert chunk, "connection closed before the 101 handshake"
            head += chunk
        assert head.startswith(b"HTTP/1.1 101"), head[:200]
        assert b"upgrade: websocket" in head.lower()

        s.sendall(b"\x81\x04ping")          # raw frame bytes; the upstream echoes verbatim
        s.settimeout(10)
        echoed = s.recv(64)
        assert echoed == b"\x81\x04ping", f"splice did not echo raw bytes: {echoed!r}"
    finally:
        s.close()


def test_upstream_down_is_502(spawn):
    dead = free_port()                      # nothing listening
    p = spawn(f":{dead}")
    status, _, body = p.get("/")
    assert status == 502
    assert b"retry" in body.lower() or b"502" in body


# --------------------------------------------------------------------------- run mode env scrub

# The child follows popup's documented convention: bind $PORT.  It records its env and
# pid on disk first, so the assertions do not depend on the proxy hop working.
CHILD = """\
import json, os, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

open(sys.argv[1], "w").write(json.dumps(dict(os.environ)))
open(sys.argv[2], "w").write(str(os.getpid()))


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(dict(os.environ)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


ThreadingHTTPServer(("127.0.0.1", int(os.environ["PORT"])), H).serve_forever()
"""


def _start_run_mode(tmp_path: pathlib.Path, extra_args: list[str]):
    script = tmp_path / "child.py"
    script.write_text(CHILD)
    env_file = tmp_path / "env.json"
    pid_file = tmp_path / "child.pid"
    env = {**os.environ, **DIRTY_ENV, "PYTHONUNBUFFERED": "1"}
    proc = subprocess.Popen(
        [sys.executable, str(POPUP_PY), "run",
         f"{sys.executable} {script} {env_file} {pid_file}",
         *extra_args, "--tunnel", "none", "--port", str(free_port()),
         "--no-qr", "--no-password"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env,
    )
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if env_file.exists() and pid_file.exists() and pid_file.stat().st_size:
            time.sleep(0.2)
            return proc, json.loads(env_file.read_text()), int(pid_file.read_text())
        if proc.poll() is not None:
            pytest.fail("popup run exited before the child started:\n"
                        + (proc.stdout.read() if proc.stdout else ""))
        time.sleep(0.1)
    proc.terminate()
    pytest.fail("run-mode child never started")


def _run_child_env(tmp_path: pathlib.Path, extra_args: list[str]) -> dict[str, str]:
    proc, child_env, _ = _start_run_mode(tmp_path, extra_args)
    try:
        return child_env
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_run_child_env_is_scrubbed(tmp_path):
    child_env = _run_child_env(tmp_path, [])
    leaked = [k for k in child_env if k.startswith("AWS_")]
    assert not leaked, f"child must not inherit AWS_* ({leaked})"
    for name in ("GITHUB_TOKEN", "MY_APP_SECRET", "DEPLOY_KEY", "SLACK_TOKEN"):
        assert name not in child_env, f"{name} must be scrubbed from the child env"
    for value in DIRTY_ENV.values():
        if value == "keep-me":
            continue
        assert value not in child_env.values(), "a scrubbed secret leaked under another name"
    assert child_env.get("PATH"), "scrubbing must not strip PATH"
    assert child_env.get("PORT"), "popup must tell the child which port to bind"


def test_pass_env_allow_list(tmp_path):
    child_env = _run_child_env(tmp_path, ["--pass-env", "AWS_ACCESS_KEY_ID"])
    assert child_env.get("AWS_ACCESS_KEY_ID") == DIRTY_ENV["AWS_ACCESS_KEY_ID"]
    assert "AWS_SECRET_ACCESS_KEY" not in child_env, "--pass-env must be an allow-list, not a switch"


def test_run_mode_proxies_to_child(tmp_path):
    proc, _, _ = _start_run_mode(tmp_path, [])
    try:
        port = int(proc.args[proc.args.index("--port") + 1])
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and not port_open(port):
            time.sleep(0.1)
        status, _, body = raw_get(port, "/")
        assert status == 200
        assert b"AWS_SECRET_ACCESS_KEY" not in body
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_run_mode_kills_child_on_exit(tmp_path):
    """Acceptance criterion: Ctrl-C leaves no orphan processes."""
    proc, _, child_pid = _start_run_mode(tmp_path, [])
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=20)
    except subprocess.TimeoutExpired:
        proc.terminate()
        proc.wait(timeout=10)

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            os.kill(child_pid, 0)
        except OSError:
            return
        time.sleep(0.2)
    os.kill(child_pid, 9)
    pytest.fail(f"child pid {child_pid} survived popup shutdown (orphan)")
