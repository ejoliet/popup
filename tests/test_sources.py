"""Phase-3 gate: S3 range proxy (moto), HTTP/FTP snapshot.

moto runs in *server* mode on loopback and popup talks to it through
AWS_ENDPOINT_URL, so nothing is stubbed inside popup.py and no packet leaves
the machine.
"""

from __future__ import annotations

import functools
import http.client
import http.server
import pathlib
import subprocess
import sys
import threading
import time
from collections.abc import Iterator

import pytest
from conftest import free_port, port_open

boto3 = pytest.importorskip("boto3", reason="pip install boto3 (PEP 723 extra) to run S3 tests")
pytest.importorskip("moto", reason="pip install 'moto[server]' to run S3 tests")

BUCKET = "popup-test"
BLOB = bytes(range(256)) * 4096          # 1 MiB, byte i == i % 256
AWS_ENV = {
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",
    "AWS_SESSION_TOKEN": "testing",
    "AWS_DEFAULT_REGION": "us-east-1",
    "AWS_REGION": "us-east-1",
}


@pytest.fixture(scope="module")
def moto_s3() -> Iterator[str]:
    port = free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "moto.server", "-p", str(port), "-H", "127.0.0.1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    endpoint = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and not port_open(port):
        if proc.poll() is not None:
            pytest.fail("moto server failed to start (install with: moto[server])")
        time.sleep(0.1)
    try:
        s3 = boto3.client("s3", endpoint_url=endpoint, region_name="us-east-1",
                          aws_access_key_id="testing", aws_secret_access_key="testing")
        s3.create_bucket(Bucket=BUCKET)
        s3.put_object(Bucket=BUCKET, Key="cat.parquet", Body=BLOB)
        s3.put_object(Bucket=BUCKET, Key="notes/a.md", Body=b"# a\n")
        s3.put_object(Bucket=BUCKET, Key="notes/b.csv", Body=b"x,y\n1,2\n")
        yield endpoint
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def s3_env(endpoint: str) -> dict[str, str]:
    return {**AWS_ENV, "AWS_ENDPOINT_URL": endpoint, "AWS_ENDPOINT_URL_S3": endpoint}


# --------------------------------------------------------------------------- S3 object

def test_s3_object_serves_shell_config(spawn, moto_s3):
    p = spawn(f"s3://{BUCKET}/cat.parquet", env=s3_env(moto_s3))
    cfg = p.config()
    assert cfg["mode"] == "file"
    assert cfg["name"] == "cat.parquet"
    assert cfg["ext"] == ".parquet"
    assert cfg["size"] == len(BLOB)


def test_s3_range_is_proxied_not_downloaded(spawn, moto_s3):
    p = spawn(f"s3://{BUCKET}/cat.parquet", env=s3_env(moto_s3))
    raw = "/raw/" + p.config()["path"]
    status, headers, body = p.get(raw, {"Range": "bytes=1000-1063"})
    assert status == 206
    assert body == BLOB[1000:1064]
    assert headers["content-range"] == f"bytes 1000-1063/{len(BLOB)}"
    # a range read must not have pulled the whole object down
    assert int(headers["content-length"]) == 64


def test_s3_tail_range(spawn, moto_s3):
    """Parquet footers are read from the tail: suffix ranges must work end-to-end."""
    p = spawn(f"s3://{BUCKET}/cat.parquet", env=s3_env(moto_s3))
    raw = "/raw/" + p.config()["path"]
    status, _, body = p.get(raw, {"Range": "bytes=-16"})
    assert status == 206
    assert body == BLOB[-16:]


def test_s3_prefix_gives_index(spawn, moto_s3):
    p = spawn(f"s3://{BUCKET}/notes/", env=s3_env(moto_s3))
    cfg = p.config()
    assert cfg["mode"] == "dir"
    names = {e["name"] for e in cfg["entries"]}
    assert {"a.md", "b.csv"} <= names


def test_s3_missing_key_is_404_and_leaks_nothing(spawn, moto_s3):
    # Prefix mode is where /raw/<key> actually resolves a key, so that is where the
    # S3AccessError -> 404/403 mapping is observable.
    p = spawn(f"s3://{BUCKET}/notes/", env=s3_env(moto_s3))
    status, _, body = p.get("/raw/does-not-exist.md")
    assert status in (403, 404)
    text = body.decode("utf-8", "replace")
    assert "arn:aws" not in text
    assert AWS_ENV["AWS_SECRET_ACCESS_KEY"] not in text


def test_s3_credentials_never_reach_the_browser(spawn, moto_s3):
    p = spawn(f"s3://{BUCKET}/cat.parquet", env=s3_env(moto_s3))
    body = p.get("/")[2].decode("utf-8", "replace")
    assert "AWS_SECRET_ACCESS_KEY" not in body
    assert AWS_ENV["AWS_SECRET_ACCESS_KEY"] not in body


# --------------------------------------------------------------------------- HTTP snapshot

@pytest.fixture
def http_origin(tmp_path_factory) -> Iterator[tuple[int, pathlib.Path]]:
    root = tmp_path_factory.mktemp("origin")
    (root / "doc.md").write_text("# snapshot\n")
    port = free_port()
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(root))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield port, root
    srv.shutdown()
    srv.server_close()


def test_http_snapshot_fetches_once(spawn, http_origin):
    port, root = http_origin
    p = spawn(f"http://127.0.0.1:{port}/doc.md")
    cfg = p.config()
    assert cfg["mode"] == "file"
    assert cfg["name"] == "doc.md"
    assert p.get("/raw/" + cfg["path"])[2] == b"# snapshot\n"

    # snapshot == a frozen copy: mutating the origin must not change what popup serves
    (root / "doc.md").write_text("# changed\n")
    time.sleep(0.5)
    assert p.get("/raw/" + cfg["path"])[2] == b"# snapshot\n"


def test_http_snapshot_writes_only_into_tempdir(spawn, http_origin):
    port, _ = http_origin
    before = set(pathlib.Path.cwd().iterdir())
    p = spawn(f"http://127.0.0.1:{port}/doc.md")
    p.config()
    assert set(pathlib.Path.cwd().iterdir()) == before, "snapshot must land in a tempfile dir"


# --------------------------------------------------------------------------- FTP snapshot

def test_ftp_snapshot(spawn, ftp_server):
    p = spawn(f"ftp://127.0.0.1:{ftp_server.port}/doc.txt")
    cfg = p.config()
    assert cfg["name"] == "doc.txt"
    assert p.get("/raw/" + cfg["path"])[2] == b"ftp snapshot payload\n"


def test_ftp_defaults_to_password_protected(ftp_server):
    """README: password is forced ON by default for ftp:// (opt out with --no-password)."""
    port = free_port()
    child = subprocess.Popen(
        [sys.executable, str(pathlib.Path(__file__).resolve().parents[1] / "popup.py"),
         f"ftp://127.0.0.1:{ftp_server.port}/doc.txt",
         "--tunnel", "none", "--port", str(port), "--no-qr"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and not port_open(port):
            if child.poll() is not None:
                pytest.fail("popup exited: " + (child.stdout.read() if child.stdout else ""))
            time.sleep(0.05)
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("GET", "/")
        assert conn.getresponse().status == 401
        conn.close()
    finally:
        child.terminate()
        child.wait(timeout=10)
