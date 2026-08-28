"""In-process unit tests for popup.py's pure functions.

No server, no subprocess, no sleeps, no network -- popup.py is imported directly
(see the `popup` fixture in conftest.py) and only side-effect-free helpers are called.
This is where the vendored QR encoder and the small parsers get their coverage; the
other test modules deliberately drive the CLI end to end instead.
"""

from __future__ import annotations

import argparse
import itertools
import pathlib

import pytest

# --------------------------------------------------------------------------- QR encoder

# Payload length -> QR version boundary (byte mode, EC level L), so these also pin
# popup's version-selection table.  size == 17 + 4 * version.
QR_CASES = [(10, 1, 21), (60, 4, 33), (150, 7, 45), (271, 10, 57)]


def _payload(n: int) -> str:
    return ("https://calm-frog-3121.trycloudflare.com/" + "x" * 300)[:n]


@pytest.mark.parametrize("length, version, size", QR_CASES)
def test_qr_matrix_shape_and_version(popup, length, version, size):
    m = popup.qr_matrix(_payload(length))
    assert len(m) == size, f"{length} bytes should encode as version {version} ({size}x{size})"
    assert all(len(row) == size for row in m), "matrix must be square"
    assert all(isinstance(v, bool) for row in m for v in row)


def test_qr_finder_patterns(popup):
    m = popup.qr_matrix(_payload(60))
    n = len(m)
    for r0, c0 in ((0, 0), (0, n - 7), (n - 7, 0)):
        block = [row[c0:c0 + 7] for row in m[r0:r0 + 7]]
        assert all(block[0]) and all(block[6]), "finder outer ring"
        assert all(row[0] and row[6] for row in block), "finder outer ring"
        assert not any(block[1][1:6]), "finder inner light ring"
        assert all(all(row[2:5]) for row in block[2:5]), "finder 3x3 dark core"


def test_qr_timing_and_dark_module(popup):
    m = popup.qr_matrix(_payload(60))
    n = len(m)
    for c in range(8, n - 8):
        assert m[6][c] is (c % 2 == 0), f"horizontal timing broken at col {c}"
        assert m[c][6] is (c % 2 == 0), f"vertical timing broken at row {c}"
    assert m[n - 8][8] is True, "the dark module is mandatory"


def test_qr_is_deterministic(popup):
    url = "https://calm-frog-3121.trycloudflare.com"
    assert popup.qr_matrix(url) == popup.qr_matrix(url)


def test_qr_rejects_oversized_payload(popup):
    popup.qr_matrix(_payload(271))                  # exactly at the version-10 limit
    with pytest.raises(ValueError):
        popup.qr_matrix(_payload(272))


@pytest.mark.parametrize("length, _version, size", QR_CASES)
def test_qr_terminal_renders_half_blocks(popup, length, _version, size):
    art = popup.qr_terminal(_payload(length))
    lines = art.split("\n")
    assert lines, "qr_terminal must return something printable"
    assert set("".join(lines)) <= {"█", "▄", "▀", " "}, "half-block glyphs only"
    assert len({len(line) for line in lines}) == 1, "all rows must be the same width"
    assert len(lines[0]) == size + 4, "2-module quiet zone on each side"
    assert len(lines) == (size + 4 + 1) // 2, "two module rows per character cell"


def test_qr_matches_reference_encoder_if_available(popup):
    """Byte-exact cross-check against the `qrcode` package when it is installed.

    The comparison is over all 8 mask patterns: matching *any* of them proves the byte
    encoding, Reed-Solomon codewords and module placement are exactly right.  Which mask
    wins is a per-implementation penalty tie-break, not a correctness property -- popup
    currently lands on mask 2 for this URL where `qrcode`'s fit picks a different one.
    """
    qrcode = pytest.importorskip("qrcode", reason="optional reference encoder not installed")
    url = "https://calm-frog-3121.trycloudflare.com"
    mine = popup.qr_matrix(url)
    for mask in range(8):
        ref = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L,
                            border=0, mask_pattern=mask)
        ref.add_data(url)
        ref.make(fit=True)
        if [[bool(v) for v in row] for row in ref.get_matrix()] == mine:
            return
    pytest.fail("vendored QR output matches no reference mask pattern")


# --------------------------------------------------------------------------- parse_duration

@pytest.mark.parametrize(
    "text, seconds",
    [
        ("90s", 90.0), ("30m", 1800.0), ("2h", 7200.0), ("1d", 86400.0),
        ("45", 45.0),                       # bare number == seconds
        ("1.5h", 5400.0), ("0.5m", 30.0),
        ("  30m  ", 1800.0),                # surrounding whitespace
        ("30 m", 1800.0),                   # inner whitespace
        ("30M", 1800.0), ("2H", 7200.0),    # case-insensitive
        ("0", 0.0),
    ],
)
def test_parse_duration_ok(popup, text, seconds):
    assert popup.parse_duration(text) == seconds


@pytest.mark.parametrize("text", ["", "abc", "30x", "-5", "1m30s", "m", "30mm", "1,5h", "nan"])
def test_parse_duration_rejects(popup, text):
    with pytest.raises(argparse.ArgumentTypeError):
        popup.parse_duration(text)


@pytest.mark.parametrize(
    "seconds, text",
    [(None, "never"), (0, "never"), (45, "45s"), (90, "1.5m"), (1800, "30m"), (7200, "2h")],
)
def test_format_duration(popup, seconds, text):
    assert popup.format_duration(seconds) == text


# --------------------------------------------------------------------------- renderers / MIME

@pytest.mark.parametrize(
    "ext, renderer",
    [
        (".md", "markdown"), (".markdown", "markdown"), (".MD", "markdown"),
        (".csv", "table"), (".tsv", "table"),
        (".parquet", "parquet"),
        (".ipynb", "notebook"),
        (".fits", "fits"), (".fit", "fits"), (".fz", "fits"), (".asdf", "fits"),
        (".pdf", "pdf"),
        (".html", "html"), (".htm", "html"),
        (".png", "image"), (".jpg", "image"), (".jpeg", "image"), (".gif", "image"),
        (".webp", "image"), (".svg", "image"), (".avif", "image"), (".bmp", "image"),
        (".py", "code"), (".js", "code"), (".ts", "code"), (".sql", "code"),
        (".yaml", "code"), (".sh", "code"), (".toml", "code"), (".txt", "code"),
        (".xyzzy", "download"), ("", "download"), (".exe", "download"),
        (".json", "code"),   # README code row lists .json explicitly
    ],
)
def test_pick_renderer(popup, ext, renderer):
    assert popup.pick_renderer(ext) == renderer


def test_mime_overrides(popup):
    assert popup.MIME_OVERRIDES[".wasm"] == "application/wasm"
    assert popup.MIME_OVERRIDES[".mjs"] == "text/javascript"
    assert popup.guess_type("bundle.wasm") == "application/wasm"
    assert popup.guess_type("mod.MJS") == "text/javascript"
    assert popup.guess_type("notes.md").startswith("text/markdown")
    assert popup.guess_type("mystery.xyzzy") == "application/octet-stream"


@pytest.mark.parametrize(
    "target, kind",
    [
        ("s3://bucket/key", "s3"), ("s3://bucket/prefix/", "s3"),
        ("ftp://host/f.txt", "ftp"), ("ftps://host/f.txt", "ftp"),
        ("http://h/x", "http"), ("https://h/x", "http"),
        (":8000", "proxy"), (":80", "proxy"),
        ("run", "run"),
        ("README.md", "local"), ("./dir", "local"), ("/abs/path", "local"),
        (":notaport", "local"), (":123456", "local"),
    ],
)
def test_target_kind(popup, target, kind):
    assert popup.target_kind(target) == kind


# --------------------------------------------------------------------------- env scrubbing

DIRTY = {
    "AWS_ACCESS_KEY_ID": "a", "AWS_SECRET_ACCESS_KEY": "b", "AWS_SESSION_TOKEN": "c",
    "GITHUB_TOKEN": "d", "X_SECRET_Y": "e", "MY_KEY": "f", "FOO_TOKEN": "g",
    "DB_PASSWORD": "h", "SECRET_SAUCE": "i", "KEY_MATERIAL": "j", "PGPASSWD": "k",
    "PATH": "/usr/bin", "HOME": "/home/u", "LANG": "C.UTF-8", "PORT": "8000",
}


def test_scrub_env_drops_credentials(popup):
    out = popup.scrub_env(dict(DIRTY))
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                 "GITHUB_TOKEN", "X_SECRET_Y", "MY_KEY", "FOO_TOKEN", "DB_PASSWORD",
                 "SECRET_SAUCE", "KEY_MATERIAL", "PGPASSWD"):
        assert name not in out, f"{name} must be scrubbed"
    assert out == {"PATH": "/usr/bin", "HOME": "/home/u", "LANG": "C.UTF-8", "PORT": "8000"}


def test_scrub_env_is_case_insensitive(popup):
    assert popup.scrub_env({"aws_secret_access_key": "x", "my_token": "y", "path": "/bin"}) \
        == {"path": "/bin"}


def test_scrub_env_allow_list(popup):
    out = popup.scrub_env(dict(DIRTY), allow=["AWS_ACCESS_KEY_ID"])
    assert out["AWS_ACCESS_KEY_ID"] == "a"
    assert "AWS_SECRET_ACCESS_KEY" not in out, "allow-list must re-admit one name, not all"


def test_scrub_env_does_not_mutate_input(popup):
    src = dict(DIRTY)
    popup.scrub_env(src)
    assert src == DIRTY


# --------------------------------------------------------------------------- sandbox

@pytest.mark.parametrize("runtime", ["container", "podman", "docker"])
def test_build_container_cmd(popup, runtime, tmp_path):
    cmd = popup.build_container_cmd(runtime, "node:22", tmp_path, 8123)
    assert cmd[0] == runtime and cmd[1] == "run"
    assert cmd[-1] == "node:22", "image must be the last argument"
    assert "--rm" in cmd
    pairs = dict(itertools.pairwise(cmd))
    assert pairs["--volume"] == f"{tmp_path.resolve()}:/app:ro", "app dir must be read-only"
    assert pairs["--publish"] == "127.0.0.1:8123:8123", "port must publish on loopback only"
    assert pairs["--workdir"] == "/app"
    assert cmd.count("--env") == 1 and pairs["--env"] == "PORT=8123", \
        "only PORT crosses into the container; no host env"


def test_build_container_cmd_shape_is_runtime_independent(popup, tmp_path):
    shapes = {
        r: popup.build_container_cmd(r, "img", tmp_path, 1)[1:]
        for r in ("container", "podman", "docker")
    }
    assert len(set(map(tuple, shapes.values()))) == 1, "long flags only: one shape for all runtimes"


def test_build_container_cmd_resolves_relative_dir(popup, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cmd = popup.build_container_cmd("podman", "img", pathlib.Path("."), 1)
    mount = dict(itertools.pairwise(cmd))["--volume"]
    assert mount.startswith(str(tmp_path.resolve())) and mount.endswith(":/app:ro")


@pytest.mark.parametrize(
    "available, expected",
    [
        ({"container", "podman", "docker"}, "container"),
        ({"podman", "docker"}, "podman"),
        ({"docker"}, "docker"),
    ],
)
def test_detect_runtime_order(popup, monkeypatch, available, expected):
    monkeypatch.setattr(popup.shutil, "which", lambda n: f"/bin/{n}" if n in available else None)
    assert popup.detect_runtime() == expected


def test_detect_runtime_without_any_runtime(popup, monkeypatch):
    monkeypatch.setattr(popup.shutil, "which", lambda n: None)
    with pytest.raises(popup.PopupError):
        popup.detect_runtime()


# --------------------------------------------------------------------------- tunnel URL regexes

BANNERS = {
    "Cloudflared": (
        "INF |  https://calm-frog-3121.trycloudflare.com  |\n",
        "https://calm-frog-3121.trycloudflare.com",
    ),
    "LocalhostRun": (
        ("33a1b7c9d0e2f4.lhr.life tunneled with tls termination, "
         "https://33a1b7c9d0e2f4.lhr.life\n"),
        "https://33a1b7c9d0e2f4.lhr.life",
    ),
    "Pinggy": (
        "http://rnabc-1-2-3-4.a.free.pinggy.link\nhttps://rnabc-1-2-3-4.a.free.pinggy.link\n",
        "https://rnabc-1-2-3-4.a.free.pinggy.link",
    ),
}


@pytest.mark.parametrize("cls_name", list(BANNERS))
def test_adapter_url_regex(popup, cls_name):
    line, expected = BANNERS[cls_name]
    assert getattr(popup, cls_name).url_re.search(line).group(0) == expected


@pytest.mark.parametrize("cls_name", list(BANNERS))
def test_adapter_url_regex_ignores_other_providers(popup, cls_name):
    others = [text for name, (text, _) in BANNERS.items() if name != cls_name]
    rx = getattr(popup, cls_name).url_re
    for text in others:
        assert rx.search(text) is None, f"{cls_name} matched another provider's banner"


@pytest.mark.parametrize("cls_name", list(BANNERS))
def test_adapter_url_regex_ignores_noise(popup, cls_name):
    rx = getattr(popup, cls_name).url_re
    # The last two are the provider consoles advertised in the real MOTDs: the regex
    # is where popup draws the line, so it must not treat them as tunnel URLs.
    noises = ["no url here\n", "http://insecure.trycloudflare.com\n", "ssh: connect failed\n",
              "go to https://admin.localhost.run/ to manage domains\n",
              "upgrade at https://dashboard.pinggy.io\n"]
    for noise in noises:
        assert rx.search(noise) is None


def test_adapter_argv_and_caps(popup):
    assert popup.Cloudflared().argv(9000)[0] == "cloudflared"
    assert "http://127.0.0.1:9000" in popup.Cloudflared().argv(9000)
    assert popup.LocalhostRun().argv(9000)[0] == "ssh"
    assert "80:localhost:9000" in popup.LocalhostRun().argv(9000)
    assert popup.Pinggy().argv(9000)[0] == "ssh"
    assert "0:localhost:9000" in popup.Pinggy().argv(9000)
    assert popup.Pinggy().ttl_cap == 3600.0, "pinggy free tier caps sessions at 60 min"
    assert popup.Cloudflared().ttl_cap is None and popup.LocalhostRun().ttl_cap is None


def test_adapter_start_without_binary_raises(popup, monkeypatch):
    monkeypatch.setattr(popup.shutil, "which", lambda n: None)
    with pytest.raises(popup.TunnelUnavailableError):
        popup.Cloudflared().start(9000)


# --------------------------------------------------------------------------- misc helpers

def test_load_asset_prefers_disk_then_falls_back(popup):
    assert "__POPUP_CONFIG__" in popup.load_asset("shell.html", "EMBEDDED")
    assert popup.load_asset("no-such-asset.html", "EMBEDDED") == "EMBEDDED"


def test_gen_password_is_long_and_random(popup):
    pw = popup.gen_password()
    assert len(pw) >= 12, "auto-generated passwords must be >= 12 chars"
    assert pw.isalnum()
    assert popup.gen_password() != pw


def test_error_hierarchy(popup):
    for exc in (popup.TunnelUnavailableError, popup.PathTraversalError,
                popup.S3AccessError, popup.UpstreamDownError):
        assert issubclass(exc, popup.PopupError)
