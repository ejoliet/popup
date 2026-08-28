#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# AIDEV: happy path (local file/dir + cloudflared) is stdlib-only, so `dependencies`
# is empty on purpose. s3:// mode lazily imports boto3 and tells the user to re-run
# with `uv run --with boto3 popup.py s3://...`. PEP 723 has no optional-extras syntax,
# so an explicit lazy import + actionable error beats faking one.
"""popup - ephemeral URL for any file, folder, S3 object, or local web app.

Single-file tool. Server stays dumb: it serves bytes (with Range) plus one
renderer shell page; all rendering happens client-side from CDN libs.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import email.utils
import hmac
import http.client
import json
import mimetypes
import os
import queue
import re
import secrets
import selectors
import shutil
import signal
import socket
import string
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, BinaryIO, ClassVar, Protocol, runtime_checkable
from urllib.parse import parse_qs, quote, unquote, urlsplit

__version__ = "0.1.0"

# --------------------------------------------------------------------------- #
# errors
# --------------------------------------------------------------------------- #


class PopupError(Exception):
    """Base error; message is safe to show the operator (never the browser)."""


class TunnelUnavailableError(PopupError):
    """Adapter cannot start (binary missing, handshake failed, no URL parsed)."""


class PathTraversalError(PopupError):
    """Requested path escaped the jail."""


class S3AccessError(PopupError):
    """boto3/S3 failure, already stripped of ARNs and credentials."""


class UpstreamDownError(PopupError):
    """Proxy target refused the connection."""


# --------------------------------------------------------------------------- #
# mime / renderers
# --------------------------------------------------------------------------- #

# AIDEV: mimetypes' system table is unreliable across distros for these; pin the
# ones that break browsers (wasm needs the exact type for streaming compile,
# .mjs must be a JS type or module imports are blocked by nosniff).
MIME_OVERRIDES: dict[str, str] = {
    ".wasm": "application/wasm",
    ".mjs": "text/javascript",
    ".js": "text/javascript",
    ".md": "text/markdown; charset=utf-8",
    ".markdown": "text/markdown; charset=utf-8",
    ".csv": "text/csv; charset=utf-8",
    ".tsv": "text/tab-separated-values; charset=utf-8",
    ".parquet": "application/vnd.apache.parquet",
    ".ipynb": "application/json; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".yaml": "text/plain; charset=utf-8",
    ".yml": "text/plain; charset=utf-8",
    ".toml": "text/plain; charset=utf-8",
    ".fits": "application/octet-stream",
    ".fit": "application/octet-stream",
    ".fz": "application/octet-stream",
    ".asdf": "application/octet-stream",
    ".py": "text/plain; charset=utf-8",
    ".sh": "text/plain; charset=utf-8",
    ".sql": "text/plain; charset=utf-8",
    ".ts": "text/plain; charset=utf-8",
}

CODE_EXTS = frozenset(
    [".py", ".js", ".json", ".mjs", ".ts", ".tsx", ".jsx", ".sql", ".yaml", ".yml", ".toml", ".sh", ".bash", ".zsh", ".c", ".h", ".cpp", ".hpp", ".rs", ".go", ".java", ".rb", ".php", ".pl", ".r", ".jl", ".lua", ".ini", ".cfg", ".conf", ".dockerfile", ".make", ".txt", ".log", ".diff", ".patch", ".xml", ".tex"]
)


def guess_type(name: str) -> str:
    ext = Path(name).suffix.lower()
    if ext in MIME_OVERRIDES:
        return MIME_OVERRIDES[ext]
    ctype, _ = mimetypes.guess_type(name)
    return ctype or "application/octet-stream"


def pick_renderer(ext: str) -> str:
    """Map a file extension to a client-side renderer name (shell dispatches on it)."""
    ext = ext.lower()
    if ext in (".md", ".markdown"):
        return "markdown"
    if ext == ".csv" or ext == ".tsv":
        return "table"
    if ext == ".parquet":
        return "parquet"
    if ext == ".ipynb":
        return "notebook"
    if ext in (".fits", ".fit", ".fz", ".asdf"):
        return "fits"
    if ext == ".pdf":
        return "pdf"
    if ext in (".html", ".htm"):
        return "html"
    if ext in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".avif", ".bmp"):
        return "image"
    if ext in CODE_EXTS:
        return "code"
    return "download"


# --------------------------------------------------------------------------- #
# terminal QR (vendored, zero-dep)
# --------------------------------------------------------------------------- #

# AIDEV: byte mode, EC level L, versions 1-10 (271 bytes max) - tunnel URLs are
# ~60 chars, so higher versions would be dead code. Vendored to keep the tool
# dependency-free; a real library would be 100x the surface for one glyph grid.
_QR_TOTAL_CW = [26, 44, 70, 100, 134, 172, 196, 242, 292, 346]
_QR_EC_PER_BLOCK = [7, 10, 15, 20, 26, 18, 20, 24, 30, 18]
_QR_BLOCKS = [1, 1, 1, 1, 1, 2, 2, 2, 2, 4]
_QR_ALIGN = [
    [], [6, 18], [6, 22], [6, 26], [6, 30],
    [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50],
]
_GF_EXP = [0] * 512
_GF_LOG = [0] * 256


def _gf_init() -> None:
    x = 1
    for i in range(255):
        _GF_EXP[i] = x
        _GF_LOG[x] = i
        x = (x << 1) ^ 0x11D if x & 0x80 else x << 1
    for i in range(255, 512):
        _GF_EXP[i] = _GF_EXP[i - 255]


_gf_init()


def _gf_mul(a: int, b: int) -> int:
    return 0 if a == 0 or b == 0 else _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _rs_ec(data: list[int], nec: int) -> list[int]:
    gen = [1]
    for i in range(nec):
        nxt = [0] * (len(gen) + 1)
        for j, g in enumerate(gen):
            nxt[j] ^= _gf_mul(g, 1)
            nxt[j + 1] ^= _gf_mul(g, _GF_EXP[i])
        gen = nxt
    rem = list(data) + [0] * nec
    for i in range(len(data)):
        coef = rem[i]
        if coef:
            for j, g in enumerate(gen):
                rem[i + j] ^= _gf_mul(g, coef)
    return rem[len(data):]


def _qr_bch(value: int, poly: int, bits: int) -> int:
    v = value << bits
    plen = poly.bit_length() - 1
    while v.bit_length() - 1 >= plen:
        v ^= poly << (v.bit_length() - 1 - plen)
    return v


def qr_matrix(text: str) -> list[list[bool]]:
    """Encode `text` as a QR matrix (True = dark). Raises ValueError if too long."""
    data = text.encode("utf-8")
    for vi in range(10):
        cap = _QR_TOTAL_CW[vi] - _QR_EC_PER_BLOCK[vi] * _QR_BLOCKS[vi]
        cci = 8 if vi < 9 else 16
        if 4 + cci + 8 * len(data) <= cap * 8:  # mode + count + payload bits
            break
    else:
        raise ValueError("payload too long for QR versions 1-10")
    version, ncw = vi + 1, cap
    bits: list[int] = [0, 1, 0, 0]
    for i in range(cci - 1, -1, -1):
        bits.append((len(data) >> i) & 1)
    for byte in data:
        bits.extend((byte >> i) & 1 for i in range(7, -1, -1))
    bits.extend([0] * min(4, ncw * 8 - len(bits)))
    bits.extend([0] * (-len(bits) % 8))
    cws = [int("".join(str(b) for b in bits[i:i + 8]), 2) for i in range(0, len(bits), 8)]
    for pad in (0xEC, 0x11):
        while len(cws) < ncw:
            cws.append(pad)
            pad = 0x11 if pad == 0xEC else 0xEC
    cws = cws[:ncw]

    nblocks = _QR_BLOCKS[vi]
    short = ncw // nblocks
    nlong = ncw % nblocks
    blocks: list[list[int]] = []
    pos = 0
    for b in range(nblocks):
        size = short + (1 if b >= nblocks - nlong else 0)
        blocks.append(cws[pos:pos + size])
        pos += size
    ecs = [_rs_ec(b, _QR_EC_PER_BLOCK[vi]) for b in blocks]
    stream: list[int] = []
    for i in range(max(len(b) for b in blocks)):
        stream.extend(b[i] for b in blocks if i < len(b))
    for i in range(_QR_EC_PER_BLOCK[vi]):
        stream.extend(e[i] for e in ecs)

    size = version * 4 + 17
    mat: list[list[int]] = [[-1] * size for _ in range(size)]

    def put_finder(r0: int, c0: int) -> None:
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                r, c = r0 + dr, c0 + dc
                if 0 <= r < size and 0 <= c < size:
                    inner = 2 <= dr <= 4 and 2 <= dc <= 4
                    ring = dr in (0, 6) or dc in (0, 6)
                    mat[r][c] = 1 if (inner or ring) and 0 <= dr <= 6 and 0 <= dc <= 6 else 0

    put_finder(0, 0)
    put_finder(0, size - 7)
    put_finder(size - 7, 0)
    for i in range(size):
        if mat[6][i] == -1:
            mat[6][i] = 1 - i % 2
        if mat[i][6] == -1:
            mat[i][6] = 1 - i % 2
    for r in _QR_ALIGN[vi]:
        for c in _QR_ALIGN[vi]:
            # AIDEV: only the three centres colliding with finder patterns are
            # dropped; the ones sitting on the timing lines ARE drawn (v7+).
            if (r < 8 and c < 8) or (r < 8 and c > size - 9) or (r > size - 9 and c < 8):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    mat[r + dr][c + dc] = 1 if max(abs(dr), abs(dc)) != 1 else 0
    for i in range(9):  # reserve both format-info copies (spec 7.9)
        for r, c in ((8, i), (i, 8)):
            if mat[r][c] == -1:
                mat[r][c] = 0
    for i in range(8):
        for r, c in ((8, size - 1 - i), (size - 1 - i, 8)):
            if mat[r][c] == -1:
                mat[r][c] = 0
    mat[size - 8][8] = 1  # permanently dark module
    if version >= 7:
        vbits = (version << 12) | _qr_bch(version, 0x1F25, 12)
        for i in range(18):
            bit = (vbits >> i) & 1
            mat[i // 3][size - 11 + i % 3] = bit
            mat[size - 11 + i % 3][i // 3] = bit

    reserved = [[mat[r][c] != -1 for c in range(size)] for r in range(size)]
    idx = 0
    col = size - 1
    upward = True
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for row in rows:
            for c in (col, col - 1):
                if reserved[row][c]:
                    continue
                bit = (stream[idx >> 3] >> (7 - (idx & 7))) & 1 if idx >> 3 < len(stream) else 0
                mat[row][c] = bit
                idx += 1
        col -= 2
        upward = not upward

    def masked(m: int, r: int, c: int) -> int:
        return (
            (r + c) % 2, (r) % 2, c % 3, (r + c) % 3,
            (r // 2 + c // 3) % 2, (r * c) % 2 + (r * c) % 3,
            ((r * c) % 2 + (r * c) % 3) % 2, ((r + c) % 2 + (r * c) % 3) % 2,
        )[m] == 0

    best: tuple[int, list[list[int]]] | None = None
    for m in range(8):
        grid = [row[:] for row in mat]
        for r in range(size):
            for c in range(size):
                if not reserved[r][c] and masked(m, r, c):
                    grid[r][c] ^= 1
        data5 = 0b01000 | m  # EC level L = 01, then 3 mask bits
        fbits = ((data5 << 10) | _qr_bch(data5, 0x537, 10)) ^ 0x5412
        _place_format(grid, size, fbits)
        pen = _qr_penalty(grid, size)
        if best is None or pen < best[0]:
            best = (pen, grid)
    assert best is not None
    return [[bool(v) for v in row] for row in best[1]]


def _place_format(grid: list[list[int]], size: int, fbits: int) -> None:
    for i in range(15):
        bit = (fbits >> i) & 1
        if i < 6:
            grid[i][8] = bit
        elif i == 6:
            grid[7][8] = bit
        elif i == 7:
            grid[8][8] = bit
        elif i == 8:
            grid[8][7] = bit
        else:
            grid[8][14 - i] = bit
        if i < 8:
            grid[8][size - 1 - i] = bit
        else:
            grid[size - 15 + i][8] = bit
    grid[size - 8][8] = 1


def _qr_penalty(g: list[list[int]], n: int) -> int:
    score = 0
    for line in [[g[r][c] for c in range(n)] for r in range(n)] + [
        [g[r][c] for r in range(n)] for c in range(n)
    ]:
        run, prev = 1, line[0]
        for v in line[1:]:
            if v == prev:
                run += 1
            else:
                if run >= 5:
                    score += 3 + run - 5
                run, prev = 1, v
        if run >= 5:
            score += 3 + run - 5
        txt = "".join(str(v) for v in line)
        score += 40 * (txt.count("10111010000") + txt.count("00001011101"))
    for r in range(n - 1):
        for c in range(n - 1):
            if g[r][c] == g[r][c + 1] == g[r + 1][c] == g[r + 1][c + 1]:
                score += 3
    dark = sum(sum(row) for row in g)
    score += 10 * (abs(dark * 100 // (n * n) - 50) // 5)
    return score


def qr_terminal(text: str) -> str:
    """Render a QR code with half-block glyphs (2 modules per character cell)."""
    m = qr_matrix(text)
    n = len(m)
    q = 2
    rows = [[False] * (n + 2 * q) for _ in range(q)]
    rows += [[False] * q + row + [False] * q for row in m]
    rows += [[False] * (n + 2 * q) for _ in range(q)]
    if len(rows) % 2:
        rows.append([False] * len(rows[0]))
    out = []
    for i in range(0, len(rows), 2):
        top, bot = rows[i], rows[i + 1]
        # inverted: dark module -> light glyph, so it scans on dark terminals too
        line = "".join(
            {(0, 0): "█", (1, 0): "▄", (0, 1): "▀", (1, 1): " "}[
                (int(t), int(b))
            ]
            for t, b in zip(top, bot)
        )
        out.append(line)
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# embedded assets
# --------------------------------------------------------------------------- #

# --- EMBED:SHELL ---
SHELL_HTML = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>popup</title>
<link rel="stylesheet"
  href="https://cdn.jsdelivr.net/npm/github-markdown-css@5.5.1/github-markdown-light.min.css">
<style>body{margin:0}main{box-sizing:border-box;max-width:900px;margin:0 auto;padding:2rem}
pre{overflow:auto}</style>
</head><body><main id="app" class="markdown-body">loading&hellip;</main>
<script src="https://cdn.jsdelivr.net/npm/marked@12.0.2/marked.min.js"></script>
<script>
const CONFIG = __POPUP_CONFIG__;
const app = document.getElementById('app');
const raw = p => '/raw/' + p.split('/').map(encodeURIComponent).join('/');
async function render() {
  document.title = CONFIG.name || 'popup';
  if (CONFIG.mode === 'dir') {
    app.innerHTML = '<h1>' + CONFIG.name + '</h1><ul>' + CONFIG.entries.map(e =>
      '<li><a href="' + (e.dir ? '/?p=' + encodeURIComponent(e.path) : raw(e.path)) +
      '">' + e.name + (e.dir ? '/' : '') + '</a></li>').join('') + '</ul>';
    return;
  }
  const r = await fetch(raw(CONFIG.path));
  if (CONFIG.renderer === 'markdown') app.innerHTML = marked.parse(await r.text());
  else if (CONFIG.renderer === 'image') app.innerHTML = '<img src="' + raw(CONFIG.path) + '">';
  else if (CONFIG.renderer === 'download')
    app.innerHTML = '<a href="' + raw(CONFIG.path) + '" download>' + CONFIG.name + '</a>';
  else { const pre = document.createElement('pre'); pre.textContent = await r.text();
         app.replaceChildren(pre); }
}
render();
new EventSource('/events').addEventListener('reload', () => location.reload());
</script></body></html>
"""
# --- /EMBED:SHELL ---

# --- EMBED:FITS ---
FITS_JS = """// popup FITS/ASDF header viewer (placeholder; real one lives in renderers/fits.js)
export async function readHeader(url) {
  const r = await fetch(url, { headers: { Range: 'bytes=0-28799' } });
  const buf = new Uint8Array(await r.arrayBuffer());
  const cards = [];
  for (let i = 0; i + 80 <= buf.length; i += 80) {
    const card = new TextDecoder('ascii').decode(buf.subarray(i, i + 80));
    cards.push(card);
    if (card.startsWith('END ')) break;
  }
  return cards;
}
"""
# --- /EMBED:FITS ---

_HERE = Path(__file__).resolve().parent


def load_asset(filename: str, embedded: str) -> str:
    """Dev mode: prefer the on-disk asset next to popup.py, else the embedded copy."""
    candidate = _HERE / filename
    try:
        return candidate.read_text(encoding="utf-8")
    except OSError:
        return embedded


# --------------------------------------------------------------------------- #
# sources
# --------------------------------------------------------------------------- #


@dataclass
class Blob:
    """One raw-bytes response. `ranged` means the upstream already applied Range."""

    ctype: str
    size: int | None = None
    fileobj: BinaryIO | None = None
    stream: Iterator[bytes] | None = None
    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    ranged: bool = False
    mtime: float | None = None


@runtime_checkable
class Source(Protocol):
    """Backend behind the URL. `mode` drives which routes the handler exposes."""

    mode: str
    name: str

    def config(self, rel: str) -> dict[str, Any]:
        """Shell config for `GET /` (injected as __POPUP_CONFIG__)."""

    def blob(self, rel: str, rng: str | None) -> Blob:
        """Bytes for `GET /raw/<rel>`."""

    def close(self) -> None:
        """Release temp dirs / child processes."""


_ENCODED_SEP_RE = re.compile(r"%(?:2e|2f|5c|00)", re.IGNORECASE)


def jail(root: str | Path, rel: str) -> Path:
    """Resolve a (still URL-encoded) relative path inside `root` or raise.

    AIDEV: the single unquote lives here so encoded traversal (`%2e%2e%2f`) is
    decoded exactly once and then caught by the resolved is_relative_to check.
    Decoding twice would itself be the vulnerability, so anything that still
    looks encoded after one pass (`%252e...`) is treated as an attack, as is an
    absolute path. Symlinks are followed by resolve(), so a symlink out of the
    tree also 403s.
    """
    decoded = unquote(rel)
    if "\x00" in decoded or decoded.startswith("/") or _ENCODED_SEP_RE.search(decoded):
        raise PathTraversalError(rel)
    root = Path(root).resolve()
    target = (root / decoded).resolve()
    if target != root and not target.is_relative_to(root):
        raise PathTraversalError(rel)
    return target


def _entries(root: Path, directory: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for child in sorted(directory.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
        if child.name.startswith("."):
            continue
        try:
            is_dir = child.is_dir()
            size = 0 if is_dir else child.stat().st_size
        except OSError:
            continue
        out.append(
            {
                "name": child.name,
                "path": child.relative_to(root).as_posix(),
                "dir": is_dir,
                "ext": "" if is_dir else child.suffix.lower(),
                "size": size,
                "renderer": "dir" if is_dir else pick_renderer(child.suffix),
            }
        )
    return out


class LocalSource:
    """Jailed static serve of a file or directory on the host filesystem."""

    def __init__(self, target: Path, watch: bool = True) -> None:
        target = target.expanduser().resolve()
        if not target.exists():
            raise PopupError(f"no such file or directory: {target}")
        if target.is_dir():
            self.root, self.default_rel, self.mode = target, "", "dir"
        else:
            self.root, self.default_rel, self.mode = target.parent, target.name, "file"
        self.name = target.name
        self.watch_root: Path | None = self.root if watch else None

    def _resolve(self, rel: str) -> tuple[Path, str]:
        rel = rel or quote(self.default_rel)
        path = jail(self.root, rel)
        return path, path.relative_to(self.root).as_posix() if path != self.root else ""

    def config(self, rel: str) -> dict[str, Any]:
        path, relpath = self._resolve(rel)
        if path.is_dir():
            return {
                "mode": "dir",
                "name": path.name or self.name,
                "path": relpath,
                "ext": "",
                "size": 0,
                "renderer": "dir",
                "entries": _entries(self.root, path),
            }
        stat = path.stat()
        return {
            "mode": "file",
            "name": path.name,
            "path": relpath,
            "ext": path.suffix.lower(),
            "size": stat.st_size,
            "renderer": pick_renderer(path.suffix),
            "entries": [],
        }

    def blob(self, rel: str, rng: str | None) -> Blob:
        path, _ = self._resolve(rel)
        if path.is_dir():
            raise IsADirectoryError(rel)
        stat = path.stat()
        return Blob(
            ctype=guess_type(path.name),
            size=stat.st_size,
            fileobj=path.open("rb"),
            mtime=stat.st_mtime,
        )

    def close(self) -> None:
        return None


class SnapshotSource(LocalSource):
    """Fetch-once http(s)/ftp target into a temp dir, then serve it locally."""

    def __init__(self, url: str) -> None:
        self._tmp = tempfile.mkdtemp(prefix="popup-snap-")
        name = Path(unquote(urlsplit(url).path)).name or "download"
        dest = Path(self._tmp) / name
        # AIDEV: urllib handles http/https/ftp with one call; a streamed copy keeps
        # multi-GB snapshots off the heap. Nothing is written outside this temp dir.
        try:
            with urllib.request.urlopen(url, timeout=60) as resp, dest.open("wb") as fh:
                shutil.copyfileobj(resp, fh, 1 << 20)
        except Exception as exc:
            shutil.rmtree(self._tmp, ignore_errors=True)
            raise PopupError(f"could not fetch {url}: {type(exc).__name__}") from exc
        super().__init__(dest, watch=False)

    def close(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)


class S3Source:
    """Range proxy over a private S3 object, or a paginated index over a prefix."""

    MAX_KEYS = 1000

    def __init__(self, uri: str) -> None:
        rest = uri[5:]
        self.bucket, _, self.key = rest.partition("/")
        if not self.bucket:
            raise PopupError("s3:// target needs a bucket")
        self.mode = "dir" if (self.key == "" or self.key.endswith("/")) else "file"
        self.name = self.key.rstrip("/").rsplit("/", 1)[-1] or self.bucket
        self.watch_root: Path | None = None
        try:
            import boto3  # type: ignore[import-not-found]
        except ImportError as exc:
            raise PopupError(
                "s3:// needs boto3 - rerun as: uv run --with boto3 popup.py " + uri
            ) from exc
        self._client = boto3.client("s3")

    def _safe(self, exc: Exception) -> S3AccessError:
        # AIDEV: boto error strings embed bucket ARNs and sometimes the access key
        # id; only the error code crosses back so nothing leaks to the browser.
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if code in ("NoSuchKey", "NoSuchBucket", "404"):
            return S3AccessError("404")
        return S3AccessError("403")

    def _key_for(self, rel: str) -> str:
        decoded = unquote(rel).lstrip("/")
        if self.mode == "file":
            # AIDEV: single-object mode exposes exactly one key; anything else is a
            # 404, otherwise /raw/<anything> would hand out the object.
            if decoded and decoded not in (self.name, self.key):
                raise S3AccessError("404")
            return self.key
        if ".." in decoded.split("/"):
            raise PathTraversalError(rel)
        return f"{self.key}{decoded}" if decoded else self.key

    def config(self, rel: str) -> dict[str, Any]:
        if self.mode == "file":
            try:
                head = self._client.head_object(Bucket=self.bucket, Key=self.key)
            except Exception as exc:
                raise self._safe(exc) from exc
            ext = Path(self.key).suffix.lower()
            return {
                "mode": "file",
                "name": self.name,
                "path": quote(self.name),
                "ext": ext,
                "size": int(head["ContentLength"]),
                "renderer": pick_renderer(ext),
                "entries": [],
            }
        entries: list[dict[str, Any]] = []
        try:
            pages = self._client.get_paginator("list_objects_v2").paginate(
                Bucket=self.bucket,
                Prefix=self.key,
                PaginationConfig={"MaxItems": self.MAX_KEYS},
            )
            for page in pages:
                for obj in page.get("Contents", []):
                    sub = obj["Key"][len(self.key):]
                    if not sub:
                        continue
                    ext = Path(sub).suffix.lower()
                    entries.append(
                        {
                            "name": sub,
                            "path": quote(sub),
                            "dir": False,
                            "ext": ext,
                            "size": int(obj["Size"]),
                            "renderer": pick_renderer(ext),
                        }
                    )
        except Exception as exc:
            raise self._safe(exc) from exc
        return {
            "mode": "dir",
            "name": f"s3://{self.bucket}/{self.key}",
            "path": "",
            "ext": "",
            "size": 0,
            "renderer": "dir",
            "truncated": len(entries) >= self.MAX_KEYS,
            "entries": entries,
        }

    def blob(self, rel: str, rng: str | None) -> Blob:
        kwargs: dict[str, Any] = {"Bucket": self.bucket, "Key": self._key_for(rel)}
        if rng:
            kwargs["Range"] = rng
        try:
            obj = self._client.get_object(**kwargs)
        except Exception as exc:
            raise self._safe(exc) from exc
        headers = {"Accept-Ranges": "bytes"}
        if "ContentRange" in obj:
            headers["Content-Range"] = obj["ContentRange"]
        body = obj["Body"]
        return Blob(
            ctype=guess_type(kwargs["Key"]),
            size=int(obj["ContentLength"]),
            stream=iter(lambda: body.read(1 << 16), b""),
            status=206 if rng and "ContentRange" in obj else 200,
            headers=headers,
            ranged=True,
        )

    def close(self) -> None:
        return None


class ProxySource:
    """Reverse proxy to an app already listening on 127.0.0.1:<port>."""

    mode = "proxy"

    def __init__(self, port: int) -> None:
        self.port = port
        self.name = f":{port}"
        self.watch_root: Path | None = None

    def config(self, rel: str) -> dict[str, Any]:
        return {"mode": "proxy", "name": self.name, "ext": "", "size": 0, "entries": []}

    def blob(self, rel: str, rng: str | None) -> Blob:
        raise FileNotFoundError(rel)

    def close(self) -> None:
        return None


SCRUB_PREFIXES = ("AWS_",)
SCRUB_SUBSTRINGS = ("_SECRET", "SECRET_", "_KEY", "KEY_", "TOKEN", "PASSWORD", "PASSWD")
SCRUB_EXACT = ("GITHUB_TOKEN",)


def scrub_env(env: dict[str, str], allow: list[str] | None = None) -> dict[str, str]:
    """Drop credential-shaped variables; `allow` re-admits explicit names."""
    keep = set(allow or ())
    out = {}
    for name, value in env.items():
        upper = name.upper()
        if name in keep:
            out[name] = value
            continue
        if upper in SCRUB_EXACT or upper.startswith(SCRUB_PREFIXES):
            continue
        if any(token in upper for token in SCRUB_SUBSTRINGS):
            continue
        out[name] = value
    return out


def build_container_cmd(runtime: str, image: str, directory: Path, port: int) -> list[str]:
    """Container invocation prefix: app dir read-only, no host env, one port.

    AIDEV: long flags only - `apple/container`, podman and docker all accept
    --rm/--volume/--workdir/--publish, while short flags diverge.
    """
    return [
        runtime,
        "run",
        "--rm",
        "--interactive",
        "--workdir",
        "/app",
        "--volume",
        f"{directory.resolve()}:/app:ro",
        "--publish",
        f"127.0.0.1:{port}:{port}",
        "--env",
        f"PORT={port}",
        image,
    ]


def detect_runtime() -> str:
    for candidate in ("container", "podman", "docker"):
        if shutil.which(candidate):
            return candidate
    raise PopupError("--sandbox needs one of: container, podman, docker")


class RunSource(ProxySource):
    """popup owns the child process (optionally containerised) and proxies to it."""

    def __init__(
        self,
        command: str,
        pass_env: list[str] | None = None,
        sandbox: bool = False,
        image: str = "python:3.12-slim",
        cwd: Path | None = None,
        stop: threading.Event | None = None,
    ) -> None:
        port = free_port()
        super().__init__(port)
        self.name = f"run {command}"
        directory = (cwd or Path.cwd()).resolve()
        # AIDEV: the child is told its port via $PORT (the 12-factor convention);
        # popup cannot guess an arbitrary framework's default, so a command that
        # ignores $PORT fails fast below with an actionable message.
        env = scrub_env(dict(os.environ), pass_env)
        env["PORT"] = str(port)
        env["POPUP_PORT"] = str(port)
        self._sandbox = sandbox
        if sandbox:
            argv: list[str] = [
                *build_container_cmd(detect_runtime(), image, directory, port),
                "sh",
                "-c",
                command,
            ]
            self.proc = subprocess.Popen(
                argv,
                env=scrub_env({"PATH": os.environ.get("PATH", "")}),
                start_new_session=True,
            )
        else:
            # AIDEV: own session => one killpg reaps the shell AND its grandchildren,
            # which is what "Ctrl-C leaves no orphans" actually requires.
            self.proc = subprocess.Popen(
                command, shell=True, cwd=directory, env=env, start_new_session=True
            )
        if not wait_for_port(port, timeout=20.0, proc=self.proc, stop=stop):
            if stop is not None and stop.is_set():
                return
            # Not fatal: popup answers 502 with a hint until the child comes up.
            print(
                f"popup: nothing listening on 127.0.0.1:{port} yet - if the command "
                f'does not bind $PORT, restart it as: run "… --port $PORT"',
                file=sys.stderr,
            )

    def close(self) -> None:
        proc = getattr(self, "proc", None)
        if proc is None or proc.poll() is not None:
            return
        for sig in (signal.SIGTERM, signal.SIGKILL):
            with contextlib.suppress(OSError, ProcessLookupError):
                os.killpg(os.getpgid(proc.pid), sig)
            try:
                proc.wait(timeout=5)
                return
            except subprocess.TimeoutExpired:
                continue


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_port(
    port: int,
    timeout: float,
    proc: subprocess.Popen[bytes] | None = None,
    stop: threading.Event | None = None,
) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if stop is not None and stop.is_set():
            return False
        if proc is not None and proc.poll() is not None:
            return False
        with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), 0.5):
            return True
        time.sleep(0.15)
    return False


def resolve_source(
    target: str, args: argparse.Namespace, stop: threading.Event | None = None
) -> Source:
    """Map the CLI target to a backend by URI scheme."""
    if target.startswith("s3://"):
        return S3Source(target)
    if target.startswith(("http://", "https://", "ftp://", "ftps://")):
        return SnapshotSource(target)
    if re.fullmatch(r":\d{1,5}", target):
        return ProxySource(int(target[1:]))
    if target == "run":
        if not args.command:
            raise PopupError('run mode needs a command: popup run "uvicorn app:app"')
        return RunSource(
            args.command,
            pass_env=args.pass_env,
            sandbox=args.sandbox,
            image=args.image,
            stop=stop,
        )
    return LocalSource(Path(target))


# --------------------------------------------------------------------------- #
# server
# --------------------------------------------------------------------------- #

HOP_BY_HOP = frozenset(
    ["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade"]
)
_RANGE_RE = re.compile(r"^bytes=(\d*)-(\d*)$")


def range_response(rng: str | None, total: int) -> tuple[int, int] | None:
    """Parse a single-range `Range` header into inclusive (start, end).

    Returns None when the full entity should be sent. Raises ValueError when the
    range is unsatisfiable (caller answers 416). Multi-range is deliberately
    ignored (returns None): the spec only promises single-range support.
    """
    if not rng:
        return None
    match = _RANGE_RE.match(rng.strip())
    if not match:
        return None
    first, last = match.group(1), match.group(2)
    if not first and not last:
        return None
    if not first:  # suffix range: last N bytes
        length = int(last)
        if length == 0:
            raise ValueError(rng)
        return max(0, total - length), total - 1
    start = int(first)
    end = int(last) if last else total - 1
    if start >= total or start > end:
        raise ValueError(rng)
    return start, min(end, total - 1)


@dataclass
class App:
    """Everything the handler threads share."""

    source: Source
    port: int
    kill_secret: str
    password: str | None = None
    coi: bool = False
    spa: bool = False
    max_views: int | None = None
    views: int = 0
    bytes_out: int = 0
    stop: threading.Event = field(default_factory=threading.Event)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _subs: list[queue.Queue[str]] = field(default_factory=list)
    _hinted: bool = False

    def count_view(self) -> bool:
        """Register a shell view; returns False once the cap is exhausted."""
        with self._lock:
            self.views += 1
            return self.max_views is None or self.views < self.max_views

    def account(self, nbytes: int) -> None:
        with self._lock:
            self.bytes_out += nbytes

    def subscribe(self) -> queue.Queue[str]:
        q: queue.Queue[str] = queue.Queue(maxsize=8)
        with self._lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q: queue.Queue[str]) -> None:
        with self._lock:
            if q in self._subs:
                self._subs.remove(q)

    def publish(self, path: str) -> None:
        with self._lock:
            subs = list(self._subs)
        for q in subs:
            with contextlib.suppress(queue.Full):
                q.put_nowait(path)

    def hint_once(self, message: str) -> None:
        with self._lock:
            if self._hinted:
                return
            self._hinted = True
        print(message, file=sys.stderr)


class PopupHandler(BaseHTTPRequestHandler):
    """Routes: `/`, `/raw/<path>`, `/events`, `/kill/<secret>`, else proxy or 404."""

    server_version = f"popup/{__version__}"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    app: ClassVar[App]

    # ---- plumbing -------------------------------------------------------- #

    def log_message(self, fmt: str, *args: Any) -> None:
        return None  # AIDEV: silent by default; the banner is the only UI

    def _security_headers(self) -> None:
        if self.app.coi:
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
            self.send_header("Cross-Origin-Resource-Policy", "cross-origin")

    def _send(self, status: int, body: bytes, ctype: str, extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.app.account(len(body))

    def _error(self, status: int, message: str) -> None:
        self._send(status, f"{status} {message}\n".encode(), "text/plain; charset=utf-8")

    def _auth_ok(self) -> bool:
        if not self.app.password:
            return True
        header = self.headers.get("Authorization", "")
        if header.startswith("Basic "):
            with contextlib.suppress(Exception):
                raw = base64.b64decode(header[6:]).decode("utf-8")
                _, _, given = raw.partition(":")
                if hmac.compare_digest(given, self.app.password):
                    return True
        return False

    # ---- dispatch -------------------------------------------------------- #

    def _dispatch(self) -> None:
        try:
            split = urlsplit(self.path)
            path = split.path
            if not self._auth_ok():
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="popup"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if path.startswith("/kill/"):
                self._kill(path[len("/kill/"):])
                return
            if self.app.source.mode == "proxy":
                self._proxy()
                return
            if path in ("/", ""):
                self._shell(parse_qs(split.query).get("p", [""])[0])
                return
            if path == "/events":
                self._events()
                return
            if path.startswith("/raw/"):
                self._raw(path[len("/raw/"):])
                return
            if path in ("/renderers/fits.js", "/__popup__/fits.js"):
                self._send(
                    200,
                    load_asset("renderers/fits.js", FITS_JS).encode(),
                    "text/javascript",
                )
                return
            if isinstance(self.app.source, LocalSource) and self.app.source.mode == "dir":
                # README: "directory -> generated index page | each entry gets its
                # renderer". The index links entries to /<relpath>, so that path has
                # to answer with a shell configured for THAT entry. A miss falls
                # through to --spa / 404; config() raises before anything is sent.
                try:
                    self._shell(path.lstrip("/"))
                    return
                except (FileNotFoundError, NotADirectoryError):
                    pass
            if self.app.spa:
                self._shell("")
                return
            self._error(404, "Not Found")
        except PathTraversalError:
            self._error(403, "Forbidden")
        except S3AccessError as exc:
            self._error(404 if str(exc) == "404" else 403, "Not Found")
        except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
            self._error(404, "Not Found")
        except PermissionError:
            self._error(403, "Forbidden")
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception as exc:  # noqa: BLE001 - never leak internals to viewers
            print(f"popup: {type(exc).__name__}: {exc}", file=sys.stderr)
            with contextlib.suppress(Exception):
                self._error(500, "Internal Error")

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _dispatch

    # ---- routes ---------------------------------------------------------- #

    def _kill(self, secret: str) -> None:
        if self.command != "POST" or not hmac.compare_digest(secret, self.app.kill_secret):
            self._error(404, "Not Found")
            return
        self._send(200, b"bye\n", "text/plain; charset=utf-8")
        self.app.stop.set()

    def _shell(self, rel: str) -> None:
        alive = self.app.count_view()
        config = self.app.source.config(rel)
        config["coi"] = self.app.coi
        config["spa"] = self.app.spa
        html = load_asset("shell.html", SHELL_HTML).replace(
            "__POPUP_CONFIG__", json.dumps(config, separators=(",", ":"))
        )
        self._send(
            200,
            html.encode("utf-8"),
            "text/html; charset=utf-8",
            {"Cache-Control": "no-store"},
        )
        if not alive:
            self.app.stop.set()

    def _raw(self, rel: str) -> None:
        blob = self.app.source.blob(rel, self.headers.get("Range"))
        try:
            if blob.ranged or blob.fileobj is None:
                self._stream_blob(blob)
                return
            total = blob.size or 0
            try:
                window = range_response(self.headers.get("Range"), total)
            except ValueError:
                self.send_response(416)
                self.send_header("Content-Range", f"bytes */{total}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            start, end = window if window else (0, total - 1)
            length = max(0, end - start + 1)
            self.send_response(206 if window else 200)
            self.send_header("Content-Type", blob.ctype)
            self.send_header("Content-Length", str(length))
            self.send_header("Accept-Ranges", "bytes")
            if blob.mtime:
                self.send_header("Last-Modified", email.utils.formatdate(blob.mtime, usegmt=True))
            if window:
                self.send_header("Content-Range", f"bytes {start}-{end}/{total}")
            self._security_headers()
            self.end_headers()
            if self.command == "HEAD":
                return
            blob.fileobj.seek(start)
            remaining = length
            while remaining > 0:
                chunk = blob.fileobj.read(min(1 << 16, remaining))
                if not chunk:
                    break
                self.wfile.write(chunk)
                remaining -= len(chunk)
            self.app.account(length - remaining)
        finally:
            if blob.fileobj is not None:
                blob.fileobj.close()

    def _stream_blob(self, blob: Blob) -> None:
        self.send_response(blob.status)
        self.send_header("Content-Type", blob.ctype)
        if blob.size is not None:
            self.send_header("Content-Length", str(blob.size))
        else:
            self.close_connection = True
        for key, value in blob.headers.items():
            self.send_header(key, value)
        self._security_headers()
        self.end_headers()
        if self.command == "HEAD" or blob.stream is None:
            return
        for chunk in blob.stream:
            self.wfile.write(chunk)
            self.app.account(len(chunk))

    def _events(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self._security_headers()
        self.end_headers()
        self.close_connection = True
        sub = self.app.subscribe()
        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            while not self.app.stop.is_set():
                try:
                    changed = sub.get(timeout=10.0)
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                else:
                    payload = changed.replace("\n", " ")
                    self.wfile.write(f"event: reload\ndata: {payload}\n\n".encode())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.app.unsubscribe(sub)

    # ---- proxy ----------------------------------------------------------- #

    def _proxy(self) -> None:
        port = getattr(self.app.source, "port", 0)
        if "websocket" in self.headers.get("Upgrade", "").lower():
            self._splice(port)
            return
        headers = {
            k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP and k.lower() != "host"
        }
        headers["Host"] = f"localhost:{port}"
        headers["X-Forwarded-Proto"] = "https"
        headers["X-Forwarded-Host"] = self.headers.get("Host", f"localhost:{port}")
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
        try:
            conn.request(self.command, self.path, body=body, headers=headers)
            upstream = conn.getresponse()
        except OSError:
            conn.close()
            self._error(502, "Bad Gateway - upstream not answering, is it still running?")
            return
        try:
            out = [(k, v) for k, v in upstream.getheaders() if k.lower() not in HOP_BY_HOP]
            if 400 <= upstream.status < 500:
                # AIDEV: Vite/Django reject unknown Host headers with a 4xx; buffer
                # the small body so we can tell the operator exactly what to add.
                payload = upstream.read(65536)
                self._host_check_hint(upstream.status, payload)
                self.send_response(upstream.status)
                for key, value in out:
                    if key.lower() != "content-length":
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)
                return
            self.send_response(upstream.status)
            has_length = any(k.lower() == "content-length" for k, _ in out)
            for key, value in out:
                self.send_header(key, value)
            if not has_length:
                self.close_connection = True
            self.end_headers()
            if self.command == "HEAD":
                return
            while True:  # unbuffered pass-through keeps SSE/streaming alive
                chunk = upstream.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
                self.app.account(len(chunk))
        finally:
            conn.close()

    def _host_check_hint(self, status: int, payload: bytes) -> None:
        text = payload[:4096].decode("utf-8", "replace")
        if "Blocked request" in text or "allowedHosts" in text:
            self.app.hint_once(
                "popup: upstream blocked the tunnel hostname. Add to vite.config:\n"
                "       server: { allowedHosts: true }"
            )
        elif "DisallowedHost" in text or "ALLOWED_HOSTS" in text:
            self.app.hint_once(
                "popup: upstream blocked the tunnel hostname. In Django settings:\n"
                '       ALLOWED_HOSTS = ["*"]  # or the exact tunnel host'
            )

    def _splice(self, port: int) -> None:
        """Raw bidirectional socket splice for `Upgrade: websocket`."""
        try:
            upstream = socket.create_connection(("127.0.0.1", port), timeout=10)
        except OSError:
            self._error(502, "Bad Gateway")
            return
        lines = [f"{self.command} {self.path} HTTP/1.1"]
        for key, value in self.headers.items():
            lines.append(f"{key}: {f'localhost:{port}' if key.lower() == 'host' else value}")
        upstream.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
        client = self.connection
        client.setblocking(False)
        upstream.setblocking(False)
        self.close_connection = True
        sel = selectors.DefaultSelector()
        sel.register(client, selectors.EVENT_READ, upstream)
        sel.register(upstream, selectors.EVENT_READ, client)
        try:
            while not self.app.stop.is_set():
                for event, _ in sel.select(timeout=1.0):
                    sock: socket.socket = event.fileobj  # type: ignore[assignment]
                    data = sock.recv(65536)
                    if not data:
                        return
                    event.data.sendall(data)
                    self.app.account(len(data))
        except OSError:
            return
        finally:
            sel.close()
            with contextlib.suppress(OSError):
                upstream.close()


def watch_tree(root: Path, app: App, interval: float = 0.7) -> None:
    """Poll mtimes and publish changed paths to SSE subscribers."""

    def snapshot() -> dict[str, float]:
        out: dict[str, float] = {}
        for count, path in enumerate(root.rglob("*")):
            if count > 5000:  # ponytail: linear rescan, swap for watchdog if it hurts
                break
            with contextlib.suppress(OSError):
                if path.is_file():
                    out[str(path)] = path.stat().st_mtime
        return out

    previous = snapshot()
    while not app.stop.wait(interval):
        current = snapshot()
        for name, mtime in current.items():
            if previous.get(name) != mtime:
                with contextlib.suppress(ValueError):
                    app.publish(Path(name).relative_to(root).as_posix())
                break
        else:
            if set(previous) != set(current):
                app.publish("")
        previous = current


# --------------------------------------------------------------------------- #
# tunnel adapters
# --------------------------------------------------------------------------- #


@runtime_checkable
class TunnelAdapter(Protocol):
    name: str
    ttl_cap: float | None

    def available(self) -> bool: ...

    def start(self, port: int) -> str: ...

    def stop(self) -> None: ...

    def alive(self) -> bool: ...


class _ProcAdapter:
    """Shared plumbing: spawn a process, scrape its output for the public URL."""

    name = "proc"
    ttl_cap: float | None = None
    url_re: re.Pattern[str]  # every adapter must pin its own tunnel-domain shape
    boot_timeout = 40.0

    def __init__(self) -> None:
        self.proc: subprocess.Popen[str] | None = None
        self._port = 0

    def argv(self, port: int) -> list[str]:
        raise NotImplementedError

    def available(self) -> bool:
        return shutil.which(self.argv(0)[0]) is not None

    def start(self, port: int) -> str:
        self._port = port
        if not self.available():
            raise TunnelUnavailableError(f"{self.name}: binary not on PATH")
        try:
            self.proc = subprocess.Popen(
                self.argv(port),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except OSError as exc:
            raise TunnelUnavailableError(f"{self.name}: {exc}") from exc
        found: list[str] = []

        def reader() -> None:
            assert self.proc is not None and self.proc.stdout is not None
            for line in self.proc.stdout:
                if not found:
                    match = self.url_re.search(line)
                    if match:
                        found.append(match.group(0).rstrip("/"))

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        deadline = time.monotonic() + self.boot_timeout
        while time.monotonic() < deadline:
            if found:
                return found[0]
            if self.proc.poll() is not None:
                raise TunnelUnavailableError(f"{self.name}: exited rc={self.proc.returncode}")
            time.sleep(0.1)
        self.stop()
        raise TunnelUnavailableError(f"{self.name}: no URL after {self.boot_timeout:.0f}s")

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


class Cloudflared(_ProcAdapter):
    """trycloudflare quick tunnel: one binary, no account, HTTPS by default."""

    name = "cloudflared"
    url_re = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")

    def argv(self, port: int) -> list[str]:
        return [
            "cloudflared",
            "tunnel",
            "--no-autoupdate",
            "--url",
            f"http://127.0.0.1:{port}",
        ]


_SSH_OPTS = [
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "ServerAliveInterval=30",
    "-o", "ExitOnForwardFailure=yes",
]


# AIDEV: provider MOTDs advertise their own admin/dashboard site BEFORE the tunnel
# line, and those hostnames are shaped exactly like a tunnel host
# (`https://admin.localhost.run/`). First-matching one publishes a third-party URL in
# the banner and QR *and* prints a kill command that POSTs popup's kill secret to
# somebody else's server. So every adapter regex pins the tunnel domain shape and
# excludes the known non-tunnel labels.
_NOT_TUNNEL_HOST = r"(?!admin\.|dashboard\.|www\.|docs\.|status\.|support\.|blog\.|api\.)"


class LocalhostRun(_ProcAdapter):
    """localhost.run over plain ssh: zero install, rotating hostname."""

    name = "localhost.run"
    url_re = re.compile(
        rf"https://{_NOT_TUNNEL_HOST}[A-Za-z0-9-]+\.(?:lhr\.life|localhost\.run)"
    )

    def argv(self, port: int) -> list[str]:
        return ["ssh", *_SSH_OPTS, "-R", f"80:localhost:{port}", "nokey@localhost.run"]


class Pinggy(_ProcAdapter):
    """pinggy over ssh/443: firewall friendly, 60-minute free-tier session cap."""

    name = "pinggy"
    ttl_cap = 60 * 60.0
    # Tunnels are `<random>[.a][.free].pinggy.link` or `<random>.a.pinggy.io`; the
    # marketing site is a bare `*.pinggy.io`, so requiring `.a.pinggy.io` excludes it.
    url_re = re.compile(
        rf"https://{_NOT_TUNNEL_HOST}[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.pinggy\.link"
        rf"|https://{_NOT_TUNNEL_HOST}[A-Za-z0-9-]+\.a\.pinggy\.io"
    )

    def argv(self, port: int) -> list[str]:
        # AIDEV: pinggy can do basic auth via the `u:user:pass@` ssh username trick,
        # but popup enforces its own auth in-process so it works on every adapter.
        return ["ssh", *_SSH_OPTS, "-p", "443", "-R", f"0:localhost:{port}", "a.pinggy.io"]


ADAPTERS: dict[str, type[_ProcAdapter]] = {
    "cloudflared": Cloudflared,
    "localhostrun": LocalhostRun,
    "pinggy": Pinggy,
}


def detect(ttl: float | None = None) -> list[_ProcAdapter]:
    """Adapters to try, best first. Providers whose cap is below `ttl` go last."""
    ordered = [Cloudflared(), LocalhostRun(), Pinggy()]
    usable = [a for a in ordered if a.available()]
    if ttl is not None:
        # Open question resolved: auto-prefer an uncapped adapter over pinggy's 60m.
        usable.sort(key=lambda a: 1 if (a.ttl_cap is not None and ttl > a.ttl_cap) else 0)
    return usable


def open_tunnel(choice: str, port: int, ttl: float | None) -> tuple[_ProcAdapter | None, str]:
    """Try adapters until one yields a URL; falls back to the LAN URL."""
    if choice == "none":
        return None, local_url(port)
    candidates = detect(ttl) if choice == "auto" else [ADAPTERS[choice]()]
    for adapter in candidates:
        try:
            url = adapter.start(port)
        except TunnelUnavailableError as exc:
            print(f"popup: {exc}; trying next adapter", file=sys.stderr)
            continue
        if adapter.ttl_cap is not None and ttl is not None and ttl > adapter.ttl_cap:
            print(
                f"popup: {adapter.name} caps sessions at {adapter.ttl_cap / 60:.0f}m,"
                " the tunnel will drop before --ttl expires",
                file=sys.stderr,
            )
        return adapter, url
    print(
        "popup: no tunnel available (install cloudflared, or check ssh egress);"
        " serving on 127.0.0.1 only",
        file=sys.stderr,
    )
    return None, local_url(port)


def local_url(port: int) -> str:
    # AIDEV: popup binds 127.0.0.1 only (non-negotiable), so the fallback URL has to
    # be the loopback one. Printing the LAN IP would advertise an address nothing is
    # listening on; reaching popup from elsewhere is the tunnel's job.
    return f"http://127.0.0.1:{port}"


def guard_tunnel(adapter: _ProcAdapter, port: int, app: App, url_box: list[str]) -> None:
    """One restart attempt if the tunnel process dies, else a clean shutdown."""
    restarted = False
    while not app.stop.wait(2.0):
        if adapter.alive():
            continue
        if restarted:
            print("popup: tunnel died twice; shutting down", file=sys.stderr)
            app.stop.set()
            return
        restarted = True
        print("popup: tunnel died, restarting once...", file=sys.stderr)
        try:
            url_box[0] = adapter.start(port)
        except TunnelUnavailableError as exc:
            print(f"popup: restart failed ({exc}); shutting down", file=sys.stderr)
            app.stop.set()
            return
        print(f"popup: new URL (the old one is dead): {url_box[0]}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# cli / lifecycle
# --------------------------------------------------------------------------- #

_DURATION_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*([smhd]?)$", re.IGNORECASE)
_UNITS = {"": 1.0, "s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}


def parse_duration(text: str) -> float:
    """`90s` / `30m` / `2h` / `1d` / bare seconds -> seconds."""
    match = _DURATION_RE.match(text.strip())
    if not match:
        raise argparse.ArgumentTypeError(f"bad duration: {text!r} (try 30m, 2h, 90s)")
    return float(match.group(1)) * _UNITS[match.group(2).lower()]


def gen_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


FORCED_PASSWORD_MODES = ("s3", "ftp", "proxy", "run")


def target_kind(target: str) -> str:
    if target.startswith("s3://"):
        return "s3"
    if target.startswith(("ftp://", "ftps://")):
        return "ftp"
    if target.startswith(("http://", "https://")):
        return "http"
    if re.fullmatch(r":\d{1,5}", target):
        return "proxy"
    if target == "run":
        return "run"
    return "local"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="popup",
        description="Ephemeral URL for any file, folder, S3 object, or local web app.",
    )
    parser.add_argument("target", help="path | s3://… | http(s)://… | ftp://… | :PORT | run")
    parser.add_argument("command", nargs="?", help='command for run mode, e.g. "uvicorn app:app"')
    parser.add_argument("--ttl", metavar="30m", default=os.environ.get("POPUP_TTL"),
                        help="hard kill timer (30m, 2h, 90s)")
    parser.add_argument("--max-views", type=int, metavar="N", help="burn after N views")
    parser.add_argument("--once", action="store_true", help="same as --max-views 1")
    parser.add_argument("--password", nargs="?", const="", default=None, metavar="PW",
                        help="HTTP basic auth (auto-generated when the value is omitted)")
    parser.add_argument("--no-password", action="store_true",
                        help="opt out of the password forced on s3/ftp/proxy/run modes")
    parser.add_argument("--tunnel", choices=["auto", *ADAPTERS, "none"],
                        default=os.environ.get("POPUP_TUNNEL", "auto"))
    parser.add_argument("--port", type=int, default=0, help="local bind port (always 127.0.0.1)")
    parser.add_argument("--coi", action="store_true", help="send COOP/COEP (threaded WASM)")
    parser.add_argument("--spa", action="store_true", help="serve the shell on unknown paths")
    parser.add_argument("--sandbox", action="store_true", help="run mode: isolate in a container")
    parser.add_argument("--image", default="python:3.12-slim", help="--sandbox image")
    parser.add_argument("--pass-env", action="append", metavar="NAME", default=[],
                        help="run mode: allow-list an env var through the scrubber")
    parser.add_argument("--qr", action=argparse.BooleanOptionalAction, default=True,
                        help="terminal QR code")
    parser.add_argument("--version", action="version", version=f"popup {__version__}")
    return parser


def banner(url: str, app: App, ttl: float | None, show_qr: bool, tunnel: str) -> None:
    public = tunnel != "none"
    life = f"dies in {format_duration(ttl)} or Ctrl-C" if ttl else "dies on Ctrl-C"
    print(f"\n▲ popup  {url}   ({life})")
    if show_qr:
        with contextlib.suppress(ValueError):
            print(qr_terminal(url))
    if public:
        print("  !  this URL is public - anyone who has it can read what you are serving")
    else:
        print("  !  no tunnel - this URL is NOT public; only this machine"
              " can reach it")
    if app.password:
        print(f"  auth   user: (any)   password: {app.password}")
    else:
        print("  auth   none - the URL is the only secret")
    print(f"  tunnel {tunnel}   views: {app.views}"
          + (f"/{app.max_views}" if app.max_views else ""))
    print(f"  kill   curl -X POST {url}/kill/{app.kill_secret}\n", flush=True)


def format_duration(seconds: float | None) -> str:
    if not seconds:
        return "never"
    if seconds >= 3600:
        return f"{seconds / 3600:g}h"
    if seconds >= 60:
        return f"{seconds / 60:g}m"
    return f"{seconds:g}s"


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    ttl = parse_duration(args.ttl) if args.ttl else None
    kind = target_kind(args.target)

    password: str | None = args.password
    if password == "":
        password = gen_password()
    if password is None and kind in FORCED_PASSWORD_MODES and not args.no_password:
        password = gen_password()  # security is free: never paywalled, never opt-in
    if args.no_password:
        password = None

    cleanup: list[Any] = []
    stop = threading.Event()

    def shutdown(*_: Any) -> None:
        stop.set()

    # AIDEV: installed before resolve_source because run/snapshot startup can take
    # seconds; a default SIGTERM there would kill popup and orphan the child.
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, shutdown)

    try:
        source = resolve_source(args.target, args, stop)
    except PopupError as exc:
        print(f"popup: {exc}", file=sys.stderr)
        return 2
    cleanup.append(source)
    if stop.is_set():  # interrupted mid-startup
        source.close()
        return 130

    app = App(
        source=source,
        port=args.port or free_port(),
        kill_secret=secrets.token_urlsafe(24),  # 192 bits
        password=password,
        coi=args.coi,
        spa=args.spa,
        max_views=1 if args.once else args.max_views,
        stop=stop,
    )
    PopupHandler.app = app
    server = ThreadingHTTPServer(("127.0.0.1", app.port), PopupHandler)
    server.daemon_threads = True
    app.port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    watch_root = getattr(source, "watch_root", None)
    if watch_root is not None:
        threading.Thread(target=watch_tree, args=(watch_root, app), daemon=True).start()

    adapter, url = open_tunnel(args.tunnel, app.port, ttl)
    url_box = [url]
    if adapter is not None:
        cleanup.append(adapter)
        threading.Thread(
            target=guard_tunnel, args=(adapter, app.port, app, url_box), daemon=True
        ).start()

    if ttl:
        threading.Timer(ttl, shutdown).start()

    banner(url_box[0], app, ttl, args.qr, adapter.name if adapter else "none")
    try:
        app.stop.wait()
    finally:
        print(f"popup: shutting down ({app.views} views, {app.bytes_out} bytes served)")
        server.shutdown()
        for item in reversed(cleanup):
            with contextlib.suppress(Exception):
                item.stop() if hasattr(item, "stop") else item.close()
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
