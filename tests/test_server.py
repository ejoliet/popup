"""Phase-1 gate: path jail, Range, MIME, SSE reload, TTL, view cap, kill secret."""

from __future__ import annotations

import http.client
import json
import os
import pathlib
import re
import socket
import threading
import time

import pytest
from conftest import port_open

HELLO = "# hello\n\nsome markdown body\n" + ("x" * 512)


@pytest.fixture
def sample(tmp_path: pathlib.Path) -> pathlib.Path:
    root = tmp_path / "share"
    root.mkdir()
    (root / "hello.md").write_text(HELLO)
    (root / "data.bin").write_bytes(bytes(range(256)) * 8)
    (root / "mod.mjs").write_text("export const a = 1;\n")
    (root / "app.wasm").write_bytes(b"\0asm\x01\0\0\0")
    (root / "sub").mkdir()
    (root / "sub" / "nested.txt").write_text("nested\n")
    secret = tmp_path / "outside.txt"
    secret.write_text("SHOULD NEVER BE SERVED\n")
    os.symlink(secret, root / "escape.txt")
    return root


# --------------------------------------------------------------------------- shell + config

def test_shell_replaces_config_token(spawn, sample):
    p = spawn(str(sample / "hello.md"))
    cfg = p.config()
    assert cfg["mode"] == "file"
    assert cfg["name"] == "hello.md"
    assert cfg["ext"] == ".md"
    assert cfg["size"] == len(HELLO.encode())


def test_dir_mode_lists_entries(spawn, sample):
    p = spawn(str(sample))
    cfg = p.config()
    assert cfg["mode"] == "dir"
    names = {e["name"] for e in cfg["entries"]}
    assert {"hello.md", "data.bin", "sub"} <= names


def test_dir_entry_opens_its_own_renderer(spawn, sample):
    """README: "directory -> generated index page | each entry gets its renderer".

    The shell links each entry to `GET /<relative-path>`, so the server has to answer
    that with a shell page configured for *that* file (not just /raw/ bytes).
    """
    p = spawn(str(sample))
    status, _, body = p.get("/hello.md")
    assert status == 200, f"GET /hello.md -> {status}; dir entries have no renderer page"
    text = body.decode("utf-8", "replace")
    assert "__POPUP_CONFIG__" not in text
    m = re.search(r"(?:window\.POPUP|const CONFIG)\s*=\s*", text)
    assert m
    cfg = json.JSONDecoder().raw_decode(text, text.index("{", m.end()))[0]
    assert cfg["name"] == "hello.md" and cfg["ext"] == ".md"

    assert p.get("/sub/nested.txt")[0] == 200, "nested dir entries must render too"


# --------------------------------------------------------------------------- raw bytes + Range

def test_raw_serves_exact_bytes(spawn, sample):
    p = spawn(str(sample / "hello.md"))
    status, headers, body = p.get("/raw/hello.md")
    assert status == 200
    assert body == HELLO.encode()
    assert headers.get("accept-ranges") == "bytes"


def test_range_partial_content(spawn, sample):
    p = spawn(str(sample))
    status, headers, body = p.get("/raw/data.bin", {"Range": "bytes=10-19"})
    assert status == 206
    assert body == (bytes(range(256)) * 8)[10:20]
    assert headers["content-range"] == f"bytes 10-19/{256 * 8}"
    assert headers["content-length"] == "10"


def test_range_open_ended_and_suffix(spawn, sample):
    p = spawn(str(sample))
    full = bytes(range(256)) * 8
    status, _, body = p.get("/raw/data.bin", {"Range": "bytes=2040-"})
    assert status == 206 and body == full[2040:]
    status, _, body = p.get("/raw/data.bin", {"Range": "bytes=-8"})
    assert status == 206 and body == full[-8:]


def test_range_unsatisfiable_416(spawn, sample):
    p = spawn(str(sample))
    status, headers, _ = p.get("/raw/data.bin", {"Range": "bytes=99999-100000"})
    assert status == 416
    assert headers.get("content-range") == f"bytes */{256 * 8}"


PINNED = [
    "main", "Source", "LocalSource", "S3Source", "SnapshotSource", "ProxySource", "RunSource",
    "PopupHandler", "range_response", "jail", "MIME_OVERRIDES", "SHELL_HTML", "pick_renderer",
    "TunnelAdapter", "Cloudflared", "LocalhostRun", "Pinggy", "detect", "build_container_cmd",
    "PopupError", "TunnelUnavailableError", "PathTraversalError", "S3AccessError", "UpstreamDownError",
]


def test_pinned_symbols_exist(popup):
    """README "File map" + the team interface contract pin these names."""
    missing = [n for n in PINNED if not hasattr(popup, n)]
    assert not missing, f"popup.py is missing pinned symbols: {missing}"


# --------------------------------------------------------------------------- MIME

def test_mime_override_map(popup):
    assert popup.MIME_OVERRIDES[".wasm"] == "application/wasm"
    assert popup.MIME_OVERRIDES[".mjs"] == "text/javascript"


def test_mime_overrides_on_the_wire(spawn, sample):
    p = spawn(str(sample))
    assert "application/wasm" in p.get("/raw/app.wasm")[1]["content-type"]
    assert "text/javascript" in p.get("/raw/mod.mjs")[1]["content-type"]
    assert "text/markdown" in p.get("/raw/hello.md")[1]["content-type"] or \
           "text/" in p.get("/raw/hello.md")[1]["content-type"]


# --------------------------------------------------------------------------- path jail

@pytest.mark.parametrize(
    "path",
    [
        "/raw/../outside.txt",
        "/raw/../../etc/passwd",
        "/raw/sub/../../outside.txt",
        "/raw/%2e%2e/outside.txt",
        "/raw/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/raw/..%2foutside.txt",
        "/raw/escape.txt",          # symlink pointing outside the jail
    ],
)
def test_path_traversal_is_403(spawn, sample, path):
    p = spawn(str(sample))
    status, _, body = p.get(path)
    assert status == 403, f"{path} -> {status} {body[:200]!r}"
    assert b"SHOULD NEVER BE SERVED" not in body


@pytest.mark.parametrize("path", ["/raw/%252e%252e%252foutside.txt", "/raw//etc/passwd"])
def test_ambiguous_paths_are_never_served(spawn, sample, path):
    """Double-encoded and empty-segment paths must decode exactly once: a second
    decode would itself be the vulnerability, so 404 is as correct as 403 here --
    what matters is that nothing outside the jail comes back."""
    p = spawn(str(sample))
    status, _, body = p.get(path)
    assert status in (403, 404), f"{path} -> {status}"
    assert b"SHOULD NEVER BE SERVED" not in body
    assert b"root:" not in body


def test_jail_unit(popup, sample):
    """jail(root, relpath) -> resolved path inside root, else PathTraversalError."""
    root = pathlib.Path(sample)
    assert popup.jail(root, "hello.md").name == "hello.md"
    for bad in ("../outside.txt", "sub/../../outside.txt", "/etc/passwd", "escape.txt"):
        with pytest.raises(popup.PathTraversalError):
            popup.jail(root, bad)


def test_pick_renderer(popup):
    assert popup.pick_renderer(".md") == "markdown"
    assert popup.pick_renderer(".parquet") == "parquet"
    assert popup.pick_renderer(".xyzzy") == "download"   # never guess


# --------------------------------------------------------------------------- SSE reload

def test_sse_emits_reload_on_mtime_change(spawn, sample):
    target = sample / "hello.md"
    p = spawn(str(target))
    conn = http.client.HTTPConnection("127.0.0.1", p.port, timeout=20)
    conn.request("GET", "/events", headers={"Accept": "text/event-stream"})
    resp = conn.getresponse()
    assert resp.status == 200
    assert "text/event-stream" in resp.getheader("Content-Type", "")

    seen: list[bytes] = []

    def pump() -> None:
        while True:
            line = resp.fp.readline()
            if not line:
                return
            seen.append(line)

    t = threading.Thread(target=pump, daemon=True)
    t.start()
    time.sleep(0.6)
    target.write_text(HELLO + "\nedited\n")
    os.utime(target, None)

    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if any(b"event: reload" in line or b"event:reload" in line for line in seen):
            conn.close()
            return
        time.sleep(0.1)
    conn.close()
    pytest.fail(f"no `event: reload` on /events within 15s; got {seen!r}")


# --------------------------------------------------------------------------- lifecycle

def test_ttl_expiry_shuts_down(spawn, sample):
    p = spawn(str(sample / "hello.md"), "--ttl", "3s")
    assert p.get("/")[0] == 200
    p.wait_exit(timeout=25)
    assert not port_open(p.port)


def test_max_views_burns_after_n(spawn, sample):
    p = spawn(str(sample / "hello.md"), "--max-views", "1")
    assert p.get("/")[0] == 200
    p.wait_exit(timeout=25)
    assert not port_open(p.port)


def test_once_is_max_views_one(spawn, sample):
    p = spawn(str(sample / "hello.md"), "--once")
    assert p.get("/")[0] == 200
    p.wait_exit(timeout=25)


def test_kill_secret(spawn, sample):
    p = spawn(str(sample / "hello.md"))
    secret = p.kill_secret
    assert len(secret) >= 22, "kill secret must carry >= 128 bits of entropy"

    status, _, _ = p.get("/kill/definitely-not-the-secret", method="POST")
    assert status in (403, 404)
    time.sleep(0.4)
    assert p.proc.poll() is None, "wrong kill secret must not shut the server down"

    p.get(f"/kill/{secret}", method="POST")
    p.wait_exit(timeout=15)


def test_banner_states_url_auth_and_ttl(spawn, sample):
    """README: the launch banner always states the URL, the password status and the TTL."""
    p = spawn(str(sample / "hello.md"), "--ttl", "45m")
    p.wait_output(r"https?://\S+")
    p.wait_output(r"(?i)(auth|password|no password|the URL is the only secret)")
    p.wait_output(r"(?i)45m|45 min")


def _lan_ip() -> str | None:
    """Local non-loopback address, without touching DNS or the network."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("192.0.2.1", 9))     # TEST-NET-1: no packet is actually sent
            ip = s.getsockname()[0]
        except OSError:
            return None
    return None if ip.startswith("127.") else ip


def test_binds_loopback_only(spawn, sample):
    p = spawn(str(sample / "hello.md"))
    ip = _lan_ip()
    if ip is None:
        pytest.skip("no non-loopback address on this host")
    with socket.socket() as s:
        s.settimeout(1.5)
        assert s.connect_ex((ip, p.port)) != 0, (
            f"server is reachable on {ip}:{p.port}; it must bind 127.0.0.1 only"
        )
