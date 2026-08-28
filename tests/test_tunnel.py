"""Phase-5 gate: adapter detection order, URL parsing, fallback chain.

Adapter contract exercised here (README "tunnel" file map row):
    class TunnelAdapter:
        name: str
        @staticmethod def available() -> bool          # binary/ssh present on PATH
        def start(port: int) -> str                    # returns the public https URL
        def stop() -> None
    detect() -> ordered adapters, cloudflared first, then the ssh providers
No process is ever really spawned: subprocess.Popen is replaced with a fake.
"""

from __future__ import annotations

import io
import shutil
import subprocess
import sys
import time

import pytest
from conftest import POPUP_PY, free_port, port_open

CLOUDFLARED_BANNER = """\
2026-08-27T10:00:00Z INF Thank you for trying Cloudflare Tunnel.
2026-08-27T10:00:00Z INF +--------------------------------------------------------+
2026-08-27T10:00:00Z INF |  https://calm-frog-3121.trycloudflare.com               |
2026-08-27T10:00:00Z INF +--------------------------------------------------------+
2026-08-27T10:00:01Z INF Registered tunnel connection
"""

# Real captured MOTD: localhost.run advertises its admin console *before* the tunnel
# line, so a naive "first https:// wins" scrape hands the viewer admin.localhost.run.
LOCALHOSTRUN_BANNER = """\
Welcome to localhost.run!

Follow your favourite reverse tunnel at [https://twitter.com/localhost_run].

**You need a SSH key to access this service.**
To set up and manage custom domains go to https://admin.localhost.run/

** your connection id is 2f0a4c11-9d3e-4b77-8e21-0a5f6c3d9b12, please mention it if you send me a message **

2ab87e43f3949b.lhr.life tunneled with tls termination, https://2ab87e43f3949b.lhr.life
"""

# Same trap on pinggy: the dashboard link is printed above the real tunnel URLs.
PINGGY_BANNER = """\
You are using Pinggy Free tier. Tunnel will expire in 60 minutes.
Upgrade to Pinggy Pro to get unlimited tunnel time: https://dashboard.pinggy.io

http://rnabc-1-2-3-4.a.free.pinggy.link
https://rnabc-1-2-3-4.a.free.pinggy.link
"""


class FakeProc:
    """Stand-in for subprocess.Popen: replays a banner, then stays 'alive'."""

    def __init__(self, banner: str) -> None:
        self.stdout = io.StringIO(banner)
        self.stderr = io.StringIO(banner)
        self.returncode = None
        self.args: list[str] = []
        self.killed = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = 0
        return 0

    def terminate(self) -> None:
        self.killed = True
        self.returncode = 0

    kill = terminate

    def communicate(self, timeout=None):
        return self.stdout.read(), self.stderr.read()


def adapter_names(result) -> list[str]:
    """detect() may hand back a class, an instance, or an ordered sequence."""
    items = result if isinstance(result, (list, tuple)) else [result]
    out = []
    for a in items:
        if a is None:
            continue
        out.append(a.__name__ if isinstance(a, type) else type(a).__name__)
    return out


# --------------------------------------------------------------------------- detection order

def test_detect_prefers_cloudflared(popup, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda n: "/usr/local/bin/" + n if n in ("cloudflared", "ssh") else None)
    assert adapter_names(popup.detect())[0] == "Cloudflared"


def test_detect_falls_back_to_ssh_when_cloudflared_absent(popup, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda n: "/usr/bin/ssh" if n == "ssh" else None)
    names = adapter_names(popup.detect())
    assert names, "detect() returned nothing while ssh is available"
    assert "Cloudflared" not in names
    assert names[0] == "LocalhostRun", f"ssh fallback order must be localhost.run then pinggy, got {names}"


def test_detect_returns_nothing_without_cloudflared_or_ssh(popup, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda n: None)
    assert adapter_names(popup.detect()) == []


def test_documented_fallback_order(popup, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda n: "/bin/" + n)
    assert adapter_names(popup.detect()) == ["Cloudflared", "LocalhostRun", "Pinggy"]


# --------------------------------------------------------------------------- URL parsing

@pytest.mark.parametrize(
    "cls_name, banner, expected",
    [
        ("Cloudflared", CLOUDFLARED_BANNER, "https://calm-frog-3121.trycloudflare.com"),
        ("LocalhostRun", LOCALHOSTRUN_BANNER, "https://2ab87e43f3949b.lhr.life"),
        ("Pinggy", PINGGY_BANNER, "https://rnabc-1-2-3-4.a.free.pinggy.link"),
    ],
)
def test_adapter_parses_public_url(popup, monkeypatch, cls_name, banner, expected):
    fake = FakeProc(banner)
    monkeypatch.setattr(popup.subprocess, "Popen", lambda *a, **kw: fake)
    adapter = getattr(popup, cls_name)()
    url = adapter.start(free_port())
    assert url == expected


@pytest.mark.parametrize(
    "cls_name, banner, decoy",
    [
        ("LocalhostRun", LOCALHOSTRUN_BANNER, "https://admin.localhost.run/"),
        ("Pinggy", PINGGY_BANNER, "https://dashboard.pinggy.io"),
    ],
)
def test_adapter_ignores_provider_console_links(popup, monkeypatch, cls_name, banner, decoy):
    """The MOTD advertises the provider's own console before the tunnel line.

    Handing that URL to the viewer would silently share nothing at all, so scraping
    must skip it -- whether the fix lives in the regex or in accept().
    """
    assert decoy in banner, "fixture must actually contain the decoy"
    monkeypatch.setattr(popup.subprocess, "Popen", lambda *a, **kw: FakeProc(banner))
    url = getattr(popup, cls_name)().start(free_port())
    assert url.rstrip("/") != decoy.rstrip("/")
    assert "admin." not in url and "dashboard." not in url


def test_adapter_raises_when_no_url_appears(popup, monkeypatch):
    monkeypatch.setattr(popup.subprocess, "Popen", lambda *a, **kw: FakeProc("nothing useful here\n"))
    with pytest.raises(popup.TunnelUnavailableError):
        popup.Cloudflared().start(free_port())


def test_adapter_stop_kills_the_process(popup, monkeypatch):
    fake = FakeProc(CLOUDFLARED_BANNER)
    monkeypatch.setattr(popup.subprocess, "Popen", lambda *a, **kw: fake)
    a = popup.Cloudflared()
    a.start(free_port())
    a.stop()
    assert fake.killed


# --------------------------------------------------------------------------- fallback chain

def test_fallback_chain_skips_a_dead_adapter(popup, monkeypatch):
    """First adapter fails -> the next one is tried; the working URL wins."""
    monkeypatch.setattr(shutil, "which", lambda n: "/bin/" + n)

    def boom(self, port):
        raise popup.TunnelUnavailableError("cloudflared exploded")

    monkeypatch.setattr(popup.Cloudflared, "start", boom)
    monkeypatch.setattr(popup.LocalhostRun, "start", lambda self, port: "https://ok.lhr.life")

    url = None
    for adapter in popup.detect():
        inst = adapter() if isinstance(adapter, type) else adapter
        try:
            url = inst.start(1234)
            break
        except popup.TunnelUnavailableError:
            continue
    assert url == "https://ok.lhr.life"


def test_ttl_over_provider_cap_demotes_pinggy(popup, monkeypatch):
    """Open Question resolved: a --ttl beyond pinggy's 60-minute free cap must not
    land on pinggy while an uncapped adapter is available."""
    monkeypatch.setattr(shutil, "which", lambda n: "/bin/" + n)
    assert adapter_names(popup.detect(ttl=90 * 60))[-1] == "Pinggy"
    assert adapter_names(popup.detect(ttl=90 * 60))[0] == "Cloudflared"
    # inside the cap, the documented order is untouched
    assert adapter_names(popup.detect(ttl=30 * 60)) == ["Cloudflared", "LocalhostRun", "Pinggy"]


def test_only_pinggy_available_still_returned(popup, monkeypatch):
    """Demotion is a preference, not a ban: pinggy alone is better than no tunnel."""
    monkeypatch.setattr(shutil, "which", lambda n: "/bin/ssh" if n == "ssh" else None)
    monkeypatch.setattr(popup.Cloudflared, "available", staticmethod(lambda: False))
    monkeypatch.setattr(popup.LocalhostRun, "available", staticmethod(lambda: False))
    assert adapter_names(popup.detect(ttl=90 * 60)) == ["Pinggy"]


# --------------------------------------------------------------------------- end-to-end

def test_no_tunnel_binary_still_serves_locally(tmp_path):
    """"if all fail, print LAN URL + hint" -- popup must never die because a tunnel is missing."""
    target = tmp_path / "hello.md"
    target.write_text("# hi\n")
    port = free_port()
    empty_bin = tmp_path / "emptybin"
    empty_bin.mkdir()
    env = {"PATH": str(empty_bin), "HOME": str(tmp_path), "PYTHONUNBUFFERED": "1"}
    proc = subprocess.Popen(
        [sys.executable, str(POPUP_PY), str(target), "--tunnel", "cloudflared",
         "--port", str(port), "--no-qr", "--no-password"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env,
    )
    try:
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline and not port_open(port):
            if proc.poll() is not None:
                pytest.fail("popup exited instead of falling back to the LAN URL:\n"
                            + (proc.stdout.read() if proc.stdout else ""))
            time.sleep(0.1)
        assert port_open(port), "popup never bound its local port"
    finally:
        proc.terminate()
        proc.wait(timeout=15)
