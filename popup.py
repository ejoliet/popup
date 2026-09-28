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
    ".sqlite": "application/vnd.sqlite3",
    ".sqlite3": "application/vnd.sqlite3",
    ".db": "application/vnd.sqlite3",
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
    if ext in (".sqlite", ".sqlite3", ".db"):
        return "sqlite"
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
SHELL_HTML = '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width,initial-scale=1">\n<title>popup</title>\n\n<!-- Server replaces the literal token below with a JSON object before serving GET /.\n     Shape: {"mode":"file|dir|proxy","name":"x.md","path":"rel/x.md","ext":".md","size":123,\n             "entries":[{"name":"a.md","path":"a.md","ext":".md","size":1,"dir":false}]} -->\n<script>window.POPUP = __POPUP_CONFIG__;</script>\n\n<!-- AIDEV: every CDN asset is pinned to an exact version with a real SRI hash\n     (sha384, computed from the served bytes 2026-08-27). Floating versions would\n     silently invalidate the hashes; bump version + hash together. -->\n<link rel="stylesheet"\n      href="https://cdn.jsdelivr.net/npm/github-markdown-css@5.5.1/github-markdown.min.css"\n      integrity="sha384-e9Z5Y4NP8q09WWmORPPBa0O1ZwQbbp3DDIFLatAwPCB7uxLR46YRAGw/QI/mxsBj"\n      crossorigin="anonymous" referrerpolicy="no-referrer">\n<link rel="stylesheet"\n      href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css"\n      integrity="sha384-wH75j6z1lH97ZOpMOInqhgKzFkAInZPPSPlZpYKYTOqsaizPvhQZmAtLcPKXpLyH"\n      crossorigin="anonymous" referrerpolicy="no-referrer">\n<style>\n  :root { color-scheme: light dark; --fg:#c9d1d9; --bg:#0d1117; --dim:#8b949e; --line:#30363d; }\n  * { box-sizing: border-box; }\n  body { margin:0; background:var(--bg); color:var(--fg);\n         font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif; }\n  #bar { display:flex; gap:12px; align-items:center; padding:8px 16px;\n         border-bottom:1px solid var(--line); position:sticky; top:0; background:var(--bg); z-index:5; }\n  #bar b { font-weight:600; }\n  #bar .dim { color:var(--dim); font-size:12px; }\n  #bar a { color:#58a6ff; text-decoration:none; margin-left:auto; }\n  #app { padding:24px; max-width:1100px; margin:0 auto; }\n  #app.wide { max-width:none; }\n  .markdown-body { background:transparent; color:var(--fg); }\n  pre.plain { background:#161b22; padding:12px; border-radius:6px; overflow:auto; }\n  table.grid { border-collapse:collapse; font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace; width:100%; }\n  table.grid th, table.grid td { border:1px solid var(--line); padding:3px 8px; text-align:left;\n                                 white-space:nowrap; max-width:340px; overflow:hidden; text-overflow:ellipsis; }\n  table.grid th { background:#161b22; position:sticky; top:0; }\n  .scroll { overflow:auto; max-height:72vh; border:1px solid var(--line); border-radius:6px; }\n  .msg { color:var(--dim); padding:8px 0; }\n  .err { color:#f85149; white-space:pre-wrap; }\n  #sql { display:flex; gap:8px; margin:12px 0; }\n  #sql input { flex:1; font:12px ui-monospace,Menlo,monospace; padding:6px 8px;\n               background:#0d1117; color:var(--fg); border:1px solid var(--line); border-radius:6px; }\n  #sql button, .btn { padding:6px 12px; border:1px solid var(--line); border-radius:6px;\n                      background:#21262d; color:var(--fg); cursor:pointer; }\n  ul.entries { list-style:none; padding:0; }\n  ul.entries li { padding:4px 0; border-bottom:1px solid var(--line); display:flex; gap:12px; }\n  ul.entries a { color:#58a6ff; text-decoration:none; flex:1; }\n  ul.entries span { color:var(--dim); font-size:12px; }\n  iframe.native { width:100%; height:82vh; border:1px solid var(--line); border-radius:6px; background:#fff; }\n  img.native { max-width:100%; }\n  .mermaid { background:#fff; border-radius:6px; padding:8px; }\n  .fits-hdu { margin-bottom:24px; }\n  .fits-hdu h3 { font:600 13px ui-monospace,Menlo,monospace; color:var(--dim); margin:0 0 6px; }\n  /* sqlite console (harlequin-ish: schema tree left, editor + results right) */\n  .db { display:grid; grid-template-columns:280px minmax(0,1fr); gap:16px; align-items:start; }\n  .db-side { border:1px solid var(--line); border-radius:6px; max-height:82vh; overflow:auto; }\n  .db-side h3 { margin:0; padding:8px 10px; font:600 11px/1.4 ui-monospace,Menlo,monospace;\n                color:var(--dim); text-transform:uppercase; letter-spacing:.06em;\n                border-bottom:1px solid var(--line); position:sticky; top:0; background:var(--bg); }\n  .db-obj { border-bottom:1px solid var(--line); }\n  .db-obj > summary { cursor:pointer; padding:5px 10px; font:12px ui-monospace,Menlo,monospace;\n                      color:#79c0ff; list-style:none; display:flex; gap:6px; align-items:baseline; }\n  .db-obj > summary::-webkit-details-marker { display:none; }\n  .db-obj > summary:hover { background:#161b22; }\n  .db-obj > summary .n { color:var(--dim); font-size:11px; margin-left:auto; }\n  .db-cols { list-style:none; margin:0; padding:0 0 6px; }\n  .db-cols li { padding:2px 10px 2px 24px; font:11px ui-monospace,Menlo,monospace; display:flex; gap:8px; }\n  .db-cols .ty { color:var(--dim); margin-left:auto; }\n  .db-cols .pk { color:#d29922; }\n  .db-main { min-width:0; }\n  .db-ex { display:flex; flex-wrap:wrap; gap:6px; margin:0 0 10px; }\n  .db-ex button { font:11px ui-monospace,Menlo,monospace; padding:4px 8px; border:1px solid var(--line);\n                  border-radius:6px; background:#161b22; color:var(--fg); cursor:pointer; }\n  .db-ex button:hover { border-color:#58a6ff; }\n  textarea.sqlbox { width:100%; min-height:88px; resize:vertical; padding:8px 10px; border-radius:6px;\n                    border:1px solid var(--line); background:#0d1117; color:var(--fg);\n                    font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace; }\n  .db-run { display:flex; gap:10px; align-items:center; margin:8px 0; }\n  .db-ddl { margin:0; padding:8px 10px; background:#161b22; border-radius:6px;\n            font:11px/1.4 ui-monospace,Menlo,monospace; overflow:auto; }\n</style>\n</head>\n<body>\n<header id="bar">\n  <b id="bar-name">—</b>\n  <span class="dim" id="bar-meta"></span>\n  <a id="bar-raw" href="#" download>download raw</a>\n</header>\n<main id="app" class="markdown-body"></main>\n\n<script src="https://cdn.jsdelivr.net/npm/marked@12.0.2/marked.min.js"\n        integrity="sha384-/TQbtLCAerC3jgaim+N78RZSDYV7ryeoBCVqTuzRrFec2akfBkHS7ACQ3PQhvMVi"\n        crossorigin="anonymous" referrerpolicy="no-referrer"></script>\n<script src="https://cdn.jsdelivr.net/npm/dompurify@3.1.6/dist/purify.min.js"\n        integrity="sha384-+VfUPEb0PdtChMwmBcBmykRMDd+v6D/oFmB3rZM/puCMDYcIvF968OimRh4KQY9a"\n        crossorigin="anonymous" referrerpolicy="no-referrer"></script>\n<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"\n        integrity="sha384-F/bZzf7p3Joyp5psL90p/p89AZJsndkSoGwRpXcZhleCWhd8SnRuoYo4d0yirjJp"\n        crossorigin="anonymous" referrerpolicy="no-referrer"></script>\n<script>\n"use strict";\n(function () {\n  const CFG = window.POPUP || {};\n  let version = 0;\n\n  // ---------- CDN registry (lazy-loaded libs; static <script> tags above carry their own SRI) ----------\n  const LAZY = {\n    mermaid: {\n      url: "https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js",\n      sri: "sha384-WmdflGW9aGfoBdHc4rRyWzYuAjEmDwMdGdiPNacbwfGKxBW/SO6guzuQ76qjnSlr",\n    },\n    notebook: {\n      // AIDEV: cdnjs has no notebookjs mirror; jsdelivr npm origin, pinned + SRI.\n      url: "https://cdn.jsdelivr.net/npm/notebookjs@0.8.3/notebook.min.js",\n      sri: "sha384-mn4lLiKITElZwtBaUw17mY+tFOqTJ9/oSm2AwhOidI2IL7b5/AecG2KIjmSg+c+X",\n    },\n    ansiup: {\n      url: "https://cdn.jsdelivr.net/npm/ansi_up@6.0.2/ansi_up.js",\n      sri: "sha384-eP6G0IklLAGlS7n6+Qa6ebBn4cnmmv6X9qsnhY8toWJc6y7C4uFWOb13Dk2xa/iq",\n    },\n  };\n  // AIDEV: sql.js is the SQLite engine (~50 KB js + 660 KB wasm). The .js gets SRI; the\n  // .wasm is fetched by emscripten\'s own loader via locateFile, which has no SRI hook —\n  // same limitation as duckdb below. Both URLs are pinned to an exact version.\n  const SQLJS = {\n    url: "https://cdnjs.cloudflare.com/ajax/libs/sql.js/1.13.0/sql-wasm.js",\n    sri: "sha384-DJiKBv+LC78e5InEB+MvFIAH079ynMK/ERTtFUCpDzXhH1Bht7aVfpg3yOVsuYl9",\n    base: "https://cdnjs.cloudflare.com/ajax/libs/sql.js/1.13.0/",\n  };\n  // AIDEV: duckdb-wasm is a dynamic ESM import; the `integrity` attribute only exists on\n  // <script>/<link> elements, so SRI cannot be applied to import(). Version is pinned exactly\n  // and the worker/wasm bundles are resolved from that same pinned tree by getJsDelivrBundles().\n  const DUCKDB_ESM = "https://cdn.jsdelivr.net/npm/@duckdb/duckdb-wasm@1.29.0/+esm";\n\n  function loadScript(url, sri) {\n    return new Promise((res, rej) => {\n      const existing = document.querySelector(\'script[src="\' + url + \'"]\');\n      if (existing) { existing.dataset.ok ? res() : existing.addEventListener("load", () => res()); return; }\n      const s = document.createElement("script");\n      s.src = url;\n      s.crossOrigin = "anonymous";\n      s.referrerPolicy = "no-referrer";\n      if (sri) s.integrity = sri;\n      s.onload = () => { s.dataset.ok = "1"; res(); };\n      s.onerror = () => rej(new Error("failed to load " + url));\n      document.head.appendChild(s);\n    });\n  }\n\n  // ---------- helpers ----------\n  const CODE_EXTS = new Set([".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sql", ".yaml", ".yml",\n    ".json", ".sh", ".bash", ".zsh", ".c", ".h", ".cc", ".cpp", ".hpp", ".rs", ".go", ".java", ".kt",\n    ".rb", ".php", ".pl", ".lua", ".r", ".jl", ".swift", ".scala", ".toml", ".ini", ".cfg", ".conf",\n    ".xml", ".css", ".scss", ".dockerfile", ".make", ".mk", ".tf", ".proto", ".graphql", ".vim", ".el"]);\n  const IMG_EXTS = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".bmp", ".ico", ".svg"]);\n  const TEXT_EXTS = new Set([".txt", ".log", ".text", ".rst", ".env", ".gitignore", ".license", ""]);\n\n  function pickRenderer(ext) {\n    ext = (ext || "").toLowerCase();\n    if (ext === ".md" || ext === ".markdown") return "markdown";\n    if (ext === ".csv" || ext === ".tsv") return "csv";\n    if (ext === ".parquet" || ext === ".pq") return "parquet";\n    if (ext === ".sqlite" || ext === ".sqlite3" || ext === ".db") return "sqlite";\n    if (ext === ".ipynb") return "notebook";\n    if (ext === ".fits" || ext === ".fit" || ext === ".fts" || ext === ".fz" || ext === ".asdf") return "fits";\n    if (ext === ".pdf") return "pdf";\n    if (ext === ".html" || ext === ".htm") return "html";\n    if (IMG_EXTS.has(ext)) return "image";\n    if (CODE_EXTS.has(ext)) return "code";\n    if (TEXT_EXTS.has(ext)) return "text";\n    return "download";  // never guess\n  }\n  window.popupPickRenderer = pickRenderer;  // exposed for the smoke test\n\n  function rawUrl(path, bust) {\n    const p = String(path || "").split("/").map(encodeURIComponent).join("/");\n    return "/raw/" + p + (bust ? "?v=" + version : "");\n  }\n  function absUrl(u) { return new URL(u, location.href).href; }\n  function human(n) {\n    if (n == null) return "";\n    const u = ["B", "KB", "MB", "GB", "TB"];\n    let i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }\n    return (i ? n.toFixed(1) : n) + " " + u[i];\n  }\n  function el(tag, attrs, text) {\n    const e = document.createElement(tag);\n    if (attrs) for (const k in attrs) e.setAttribute(k, attrs[k]);\n    if (text != null) e.textContent = text;\n    return e;\n  }\n  function fail(root, e) {\n    root.appendChild(el("div", { class: "err" }, String((e && e.stack) || e)));\n  }\n  async function fetchText(url) {\n    const r = await fetch(url, { cache: "no-store" });\n    if (!r.ok) throw new Error("HTTP " + r.status + " for " + url);\n    return r.text();\n  }\n\n  // ---------- renderers ----------\n  async function renderMarkdown(root, url) {\n    const src = await fetchText(url);\n    const html = DOMPurify.sanitize(marked.parse(src));\n    root.innerHTML = html;\n    // Mermaid is 3.3 MB: only fetch it when the document actually contains a mermaid fence.\n    const blocks = root.querySelectorAll("code.language-mermaid");\n    if (blocks.length) {\n      await loadScript(LAZY.mermaid.url, LAZY.mermaid.sri);\n      blocks.forEach((c) => {\n        const d = el("div", { class: "mermaid" }, c.textContent);\n        c.closest("pre").replaceWith(d);\n      });\n      mermaid.initialize({ startOnLoad: false, securityLevel: "strict" });\n      await mermaid.run({ nodes: root.querySelectorAll("div.mermaid") });\n    }\n    root.querySelectorAll("pre code").forEach((c) => hljs.highlightElement(c));\n  }\n\n  async function renderCode(root, url, ext) {\n    const src = await fetchText(url);\n    const lang = (ext || "").replace(/^\\./, "");\n    const code = el("code", null, src);\n    if (lang && hljs.getLanguage(lang)) code.className = "language-" + lang;\n    const pre = el("pre", { class: "plain" });\n    pre.appendChild(code);\n    root.appendChild(pre);\n    hljs.highlightElement(code);   // falls back to auto-detect when the class is absent\n  }\n\n  function renderText(root, url) {\n    return fetchText(url).then((t) => root.appendChild(el("pre", { class: "plain" }, t)));\n  }\n\n  function renderNative(root, url, kind) {\n    if (kind === "image") { root.appendChild(el("img", { class: "native", src: url, alt: CFG.name || "" })); return; }\n    // README: "browser native passthrough" / "HTML served as-is" — no sandbox attr,\n    // a sandboxed iframe breaks the exact apps (and PDF viewers) this is meant to show.\n    root.appendChild(el("iframe", { class: "native", src: url }));\n    const p = el("p");\n    p.appendChild(el("a", { href: url, target: "_blank", rel: "noopener" }, "open in new tab"));\n    root.appendChild(p);\n  }\n\n  function renderDownload(root, url, name) {\n    root.appendChild(el("p", { class: "msg" }, "No renderer for this file type."));\n    root.appendChild(el("a", { class: "btn", href: url, download: name || "" }, "Download " + (name || "file")));\n  }\n\n  function renderDir(root, entries) {\n    const ul = el("ul", { class: "entries" });\n    (entries || []).forEach((e) => {\n      const path = e.path || e.name;\n      const li = el("li");\n      // Directory entries route back through the shell (server serves GET /<path>);\n      // that keeps "each entry gets its renderer" without duplicating dispatch here.\n      li.appendChild(el("a", { href: "/" + String(path).split("/").map(encodeURIComponent).join("/") },\n        (e.dir ? "📁 " : "📄 ") + (e.name || path)));\n      li.appendChild(el("span", null, e.dir ? "" : human(e.size)));\n      ul.appendChild(li);\n    });\n    if (!ul.children.length) ul.appendChild(el("li", { class: "msg" }, "(empty)"));\n    root.appendChild(ul);\n  }\n\n  async function renderNotebook(root, url) {\n    await loadScript(LAZY.ansiup.url, LAZY.ansiup.sri).catch(() => {});\n    await loadScript(LAZY.notebook.url, LAZY.notebook.sri);\n    nb.markdown = (t) => DOMPurify.sanitize(marked.parse(t));\n    nb.highlighter = (text, pre, code, lang) => {\n      if (code) { code.textContent = text; if (lang && hljs.getLanguage(lang)) code.className = "language-" + lang; hljs.highlightElement(code); return code.innerHTML; }\n      return text;\n    };\n    const ipynb = JSON.parse(await fetchText(url));\n    root.appendChild(nb.parse(ipynb).render());\n  }\n\n  async function renderFits(root, url) {\n    // /renderers/fits.js is served by popup.py (from disk in dev, from the embedded\n    // FITS_JS constant otherwise). Same-origin, so no SRI needed.\n    await loadScript("/renderers/fits.js");\n    await window.popupFits.render(root, url);\n  }\n\n  // ---------- DuckDB-WASM (csv >= 50 KB, parquet at any size) ----------\n  let dbPromise = null;\n  async function duckdb() {\n    if (!dbPromise) {\n      dbPromise = (async () => {\n        const duck = await import(DUCKDB_ESM);\n        const bundle = await duck.selectBundle(duck.getJsDelivrBundles());\n        const workerUrl = URL.createObjectURL(\n          new Blob([\'importScripts("\' + bundle.mainWorker + \'");\'], { type: "text/javascript" }));\n        const db = new duck.AsyncDuckDB(new duck.ConsoleLogger(duck.LogLevel.WARNING), new Worker(workerUrl));\n        await db.instantiate(bundle.mainModule, bundle.pthreadWorker);\n        URL.revokeObjectURL(workerUrl);\n        return { duck, db };\n      })();\n    }\n    return dbPromise;\n  }\n\n  function cell(v) {\n    if (v == null) return "";\n    if (typeof v === "bigint") return v.toString();\n    if (v instanceof Uint8Array) return "<blob " + human(v.length) + ">";\n    return String(v);\n  }\n\n  function drawRows(host, cols, rows) {\n    host.innerHTML = "";\n    const t = el("table", { class: "grid" });\n    const thead = el("thead"), hr = el("tr");\n    cols.forEach((c) => hr.appendChild(el("th", null, c)));\n    thead.appendChild(hr); t.appendChild(thead);\n    const tb = el("tbody");\n    for (const row of rows) {\n      const tr = el("tr");\n      row.forEach((v) => tr.appendChild(el("td", null, cell(v))));\n      tb.appendChild(tr);\n    }\n    t.appendChild(tb);\n    const wrap = el("div", { class: "scroll" }); wrap.appendChild(t); host.appendChild(wrap);\n  }\n\n  function drawTable(host, table) {\n    const cols = table.schema.fields.map((f) => f.name);\n    const rows = table.toArray().map((row) => {\n      const o = row.toJSON ? row.toJSON() : row;\n      return cols.map((c) => o[c]);\n    });\n    drawRows(host, cols, rows);\n  }\n\n  async function renderTabular(root, url, kind) {\n    const status = el("div", { class: "msg" }, "loading DuckDB-WASM…");\n    root.appendChild(status);\n    const { duck, db } = await duckdb();\n    const alias = "popup_" + version + "_" + (CFG.name || "data").replace(/[^\\w.]/g, "_");\n    // HTTP protocol => duckdb issues HEAD + ranged GETs against /raw/, so a multi-GB\n    // parquet only transfers the footer + the column chunks a query touches.\n    await db.registerFileURL(alias, absUrl(url), duck.DuckDBDataProtocol.HTTP, false);\n    const conn = await db.connect();\n    const from = kind === "parquet"\n      ? "read_parquet(\'" + alias + "\')"\n      : "read_csv_auto(\'" + alias + "\')";\n\n    const host = el("div");\n    const bar = el("div", { id: "sql" });\n    const input = el("input", { value: "SELECT * FROM " + from + " LIMIT 200", spellcheck: "false" });\n    const go = el("button", null, "Run");\n    bar.appendChild(input); bar.appendChild(go);\n    root.appendChild(bar); root.appendChild(host);\n\n    async function run(sql) {\n      status.textContent = "querying…";\n      try {\n        drawTable(host, await conn.query(sql));\n        status.textContent = "";\n      } catch (e) { host.innerHTML = ""; fail(host, e); status.textContent = ""; }\n    }\n    go.onclick = () => run(input.value);\n    input.onkeydown = (ev) => { if (ev.key === "Enter") run(input.value); };\n\n    try {\n      const c = await conn.query("SELECT count(*) AS n FROM " + from);\n      status.textContent = c.toArray()[0].n + " rows";\n    } catch (e) { status.textContent = ""; }\n    await run(input.value);\n  }\n\n  // ---------- SQLite (sql.js) ----------\n  const MAX_DRAW = 2000;          // rows painted per result; the DOM, not SQLite, is the limit\n  const MAX_DB = 256 * 1024 * 1024;\n\n  function qid(name) { return \'"\' + String(name).replace(/"/g, \'""\') + \'"\'; }\n\n  function sqlPre(text) {\n    const code = el("code", { class: "language-sql" }, text);\n    const pre = el("pre", { class: "db-ddl" });\n    pre.appendChild(code);\n    hljs.highlightElement(code);\n    return pre;\n  }\n\n  async function renderSqlite(root, url) {\n    const status = el("div", { class: "msg" }, "loading SQLite (sql.js)…");\n    root.appendChild(status);\n    // AIDEV: sql.js has no ranged/lazy mode — the whole database is copied into wasm\n    // memory, so a huge file would just wedge the tab. Offer the bytes instead.\n    if ((CFG.size || 0) > MAX_DB) {\n      status.textContent = "";\n      root.appendChild(el("p", { class: "msg" }, "Database is " + human(CFG.size) +\n        "; the in-browser engine loads it fully into memory. Download it instead:"));\n      root.appendChild(el("a", { class: "btn", href: url, download: CFG.name || "" },\n        "Download " + (CFG.name || "database")));\n      return;\n    }\n\n    await loadScript(SQLJS.url, SQLJS.sri);\n    const SQL = await initSqlJs({ locateFile: (f) => SQLJS.base + f });\n    const r = await fetch(url, { cache: "no-store" });\n    if (!r.ok) throw new Error("HTTP " + r.status + " for " + url);\n    const db = new SQL.Database(new Uint8Array(await r.arrayBuffer()));\n    const q = (sql) => { const res = db.exec(sql); return res.length ? res[res.length - 1] : { columns: [], values: [] }; };\n\n    const layout = el("div", { class: "db" });\n    const side = el("aside", { class: "db-side" });\n    const main = el("div", { class: "db-main" });\n    layout.appendChild(side); layout.appendChild(main); root.appendChild(layout);\n\n    const editor = el("textarea", { class: "sqlbox", spellcheck: "false" });\n    const runBtn = el("button", { class: "btn" }, "Run  ⌘/Ctrl+↵");\n    const note = el("span", { class: "msg" });\n    const runbar = el("div", { class: "db-run" });\n    const examples = el("div", { class: "db-ex" });\n    const host = el("div");\n    runbar.appendChild(runBtn); runbar.appendChild(note);\n    main.appendChild(examples); main.appendChild(editor); main.appendChild(runbar); main.appendChild(host);\n\n    function run(sql) {\n      editor.value = sql;\n      note.textContent = "querying…";\n      host.innerHTML = "";\n      try {\n        const res = db.exec(sql);\n        const last = res.length ? res[res.length - 1] : null;\n        if (!last) { note.textContent = "OK — " + db.getRowsModified() + " rows modified (in memory only)"; return; }\n        const rows = last.values.slice(0, MAX_DRAW);\n        drawRows(host, last.columns, rows);\n        note.textContent = last.values.length + " rows" +\n          (rows.length < last.values.length ? " (showing first " + MAX_DRAW + ")" : "");\n      } catch (e) { note.textContent = ""; fail(host, e); }\n    }\n    runBtn.onclick = () => run(editor.value);\n    editor.addEventListener("keydown", (ev) => {\n      if (ev.key === "Enter" && (ev.metaKey || ev.ctrlKey)) { ev.preventDefault(); run(editor.value); }\n    });\n\n    // ----- schema sidebar -----\n    const objs = q("SELECT type, name, sql FROM sqlite_master " +\n                   "WHERE type IN (\'table\',\'view\') AND name NOT LIKE \'sqlite_%\' ORDER BY type DESC, name").values;\n    side.appendChild(el("h3", null, objs.length + " tables / views"));\n    objs.forEach(([type, name, ddl], i) => {\n      const d = el("details", { class: "db-obj" });\n      const sum = el("summary");\n      sum.appendChild(el("span", null, (type === "view" ? "◇ " : "▤ ") + name));\n      let n = "";\n      try { n = String(q("SELECT count(*) FROM " + qid(name)).values[0][0]) + " rows"; } catch (e) { /* view may be broken */ }\n      sum.appendChild(el("span", { class: "n" }, n));\n      // Clicking the object both expands it and previews it — harlequin muscle memory.\n      sum.addEventListener("click", () => run("SELECT * FROM " + qid(name) + " LIMIT 100"));\n      d.appendChild(sum);\n      const ul = el("ul", { class: "db-cols" });\n      q("PRAGMA table_info(" + qid(name) + ")").values.forEach(([, cname, ctype, notnull, , pk]) => {\n        const li = el("li");\n        li.appendChild(el("span", { class: pk ? "pk" : "" }, (pk ? "🔑 " : "") + cname));\n        li.appendChild(el("span", { class: "ty" }, (ctype || "?") + (notnull ? " NOT NULL" : "")));\n        ul.appendChild(li);\n      });\n      d.appendChild(ul);\n      if (ddl) d.appendChild(sqlPre(ddl));\n      if (i === 0) d.open = true;\n      side.appendChild(d);\n    });\n\n    // ----- example queries (clickable; they run, so the URL is useful with zero SQL typed) -----\n    const first = objs.length ? objs[0][1] : null;\n    const SCHEMA_SQL = "SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE \'sqlite_%\' ORDER BY type, name";\n    const ex = [["schema", SCHEMA_SQL]];\n    if (first) {\n      ex.unshift(["preview " + first, "SELECT * FROM " + qid(first) + " LIMIT 100"]);\n      ex.push(["columns of " + first, "SELECT name, type, \\"notnull\\", pk FROM pragma_table_info(\'" + String(first).replace(/\'/g, "\'\'") + "\')"]);\n    }\n    if (objs.length > 1) {\n      ex.push(["row counts", objs.map(([, n]) => "SELECT \'" + String(n).replace(/\'/g, "\'\'") +\n        "\' AS \\"table\\", count(*) AS rows FROM " + qid(n)).join("\\nUNION ALL ")]);\n    }\n    ex.forEach(([label, sql]) => {\n      const b = el("button", null, label);\n      b.onclick = () => run(sql);\n      examples.appendChild(b);\n    });\n\n    status.textContent = "";\n    run(first ? "SELECT * FROM " + qid(first) + " LIMIT 100" : SCHEMA_SQL);\n  }\n\n  // ---------- dispatch ----------\n  async function render() {\n    version++;\n    const root = document.getElementById("app");\n    root.innerHTML = "";\n    root.className = "markdown-body";\n\n    const name = CFG.name || "";\n    const path = CFG.path || name;\n    document.title = name ? "popup · " + name : "popup";\n    document.getElementById("bar-name").textContent = name || (CFG.mode === "dir" ? "/" : "popup");\n    document.getElementById("bar-meta").textContent =\n      CFG.mode === "dir" ? ((CFG.entries || []).length + " entries") : human(CFG.size);\n\n    if (CFG.mode === "dir") {\n      document.getElementById("bar-raw").style.display = "none";\n      renderDir(root, CFG.entries);\n      return;\n    }\n\n    const url = rawUrl(path, true);\n    const link = document.getElementById("bar-raw");\n    link.href = url; link.setAttribute("download", name);\n\n    const kind = pickRenderer(CFG.ext || ("." + name.split(".").pop()));\n    try {\n      switch (kind) {\n        case "markdown": return await renderMarkdown(root, url);\n        case "code":     return await renderCode(root, url, CFG.ext);\n        case "text":     return await renderText(root, url);\n        case "notebook": return await renderNotebook(root, url);\n        case "fits":     root.className = ""; return await renderFits(root, url);\n        case "image":\n        case "pdf":\n        case "html":     root.className = "wide"; return renderNative(root, url, kind);\n        case "csv":\n          // README: plain <pre> under 50 KB — no reason to boot a 30 MB WASM engine for a small file.\n          if ((CFG.size || 0) < 50 * 1024) return await renderText(root, url);\n          root.className = "wide"; return await renderTabular(root, url, "csv");\n        case "parquet":  root.className = "wide"; return await renderTabular(root, url, "parquet");\n        case "sqlite":   root.className = "wide"; return await renderSqlite(root, url);\n        default:         return renderDownload(root, url, name);\n      }\n    } catch (e) { fail(root, e); }\n  }\n\n  // ---------- live reload ----------\n  function connectSSE() {\n    if (!window.EventSource || CFG.mode === "proxy") return;\n    const es = new EventSource("/events");\n    es.addEventListener("reload", () => render());\n    es.onerror = () => { /* browser auto-reconnects; server may simply be gone */ };\n  }\n\n  render().then(connectSSE);\n})();\n</script>\n</body>\n</html>\n'  # generated by `make embed` — edit shell.html, not this line
# --- /EMBED:SHELL ---

# --- EMBED:FITS ---
FITS_JS = '/* popup — FITS / ASDF header + HDU viewer.\n *\n * Header display only: no image rendering (explicit non-goal in the README).\n * Everything is read with HTTP Range requests against /raw/<file>, so opening a\n * 40 GB cube costs a few tens of KB.\n *\n * Public API (used by shell.html):\n *   window.popupFits.render(rootElement, rawUrl) -> Promise<void>\n */\n"use strict";\n(function () {\n  const BLOCK = 2880;          // FITS logical record\n  const CARD = 80;             // characters per card\n  const CHUNK = BLOCK * 8;     // bytes fetched per range request while scanning a header\n  const MAX_HDUS = 128;\n  const MAX_HEADER_BLOCKS = 256;\n  const dec = new TextDecoder("latin1");\n\n  async function getRange(url, start, len) {\n    const r = await fetch(url, {\n      headers: { Range: "bytes=" + start + "-" + (start + len - 1) },\n      cache: "no-store",\n    });\n    if (r.status === 416) return { text: "", total: null };\n    if (!r.ok) throw new Error("HTTP " + r.status + " reading " + url);\n    const cr = r.headers.get("Content-Range");\n    let total = null;\n    if (cr && cr.indexOf("/") >= 0) {\n      const n = parseInt(cr.split("/")[1], 10);\n      if (!isNaN(n)) total = n;\n    }\n    let bytes = new Uint8Array(await r.arrayBuffer());\n    if (r.status !== 206) {\n      // Server ignored Range and sent the whole entity: slice locally so the\n      // caller\'s offset arithmetic still holds.\n      if (total == null) total = bytes.length;\n      bytes = bytes.subarray(Math.min(start, bytes.length), Math.min(start + len, bytes.length));\n    }\n    return { text: dec.decode(bytes), total: total };\n  }\n\n  // ---- card parsing -------------------------------------------------------\n  // "KEY     = value / comment", strings single-quoted with \'\' as an escaped quote.\n  function parseCard(card) {\n    const key = card.slice(0, 8).trim();\n    if (!key) return null;\n    if (key === "END") return { key: "END", value: "", comment: "" };\n    if (key === "COMMENT" || key === "HISTORY" || key === "CONTINUE" || card.slice(8, 10) !== "= ") {\n      return { key: key, value: "", comment: card.slice(8).trim() };\n    }\n    const s = card.slice(10);\n    const q = s.indexOf("\'");\n    let value, rest;\n    if (q >= 0 && s.slice(0, q).trim() === "") {\n      let i = q + 1, out = "";\n      while (i < s.length) {\n        if (s[i] === "\'") {\n          if (s[i + 1] === "\'") { out += "\'"; i += 2; continue; }\n          i++; break;\n        }\n        out += s[i++];\n      }\n      value = out.replace(/\\s+$/, "");   // FITS pads strings with blanks\n      rest = s.slice(i);\n    } else {\n      const slash = s.indexOf("/");\n      value = (slash < 0 ? s : s.slice(0, slash)).trim();\n      rest = slash < 0 ? "" : s.slice(slash);\n    }\n    const slash = rest.indexOf("/");\n    return { key: key, value: value, comment: slash < 0 ? "" : rest.slice(slash + 1).trim() };\n  }\n\n  function typed(v) {\n    if (v === "T") return true;\n    if (v === "F") return false;\n    if (v === "") return null;\n    const n = Number(String(v).replace(/[DdEe]([+-]?\\d+)$/, "e$1"));\n    return isNaN(n) ? v : n;\n  }\n\n  function toMap(cards) {\n    const m = Object.create(null);\n    for (const c of cards) if (!(c.key in m) && c.key !== "COMMENT" && c.key !== "HISTORY") m[c.key] = typed(c.value);\n    return m;\n  }\n\n  // Data unit size per the FITS standard, rounded up to whole 2880-byte blocks.\n  function dataBytes(h) {\n    const naxis = Number(h.NAXIS) || 0;\n    if (!naxis) return 0;\n    let n = 1;\n    for (let i = 1; i <= naxis; i++) n *= Number(h["NAXIS" + i]) || 0;\n    const width = Math.abs(Number(h.BITPIX) || 0) / 8;\n    const gcount = h.GCOUNT == null ? 1 : Number(h.GCOUNT);\n    const pcount = h.PCOUNT == null ? 0 : Number(h.PCOUNT);\n    const size = width * gcount * (pcount + n);\n    return Math.ceil(size / BLOCK) * BLOCK;\n  }\n\n  // ---- HDU walking --------------------------------------------------------\n  async function readHeader(url, offset) {\n    let buf = "", total = null, cards = [], endAt = -1;\n    while (endAt < 0) {\n      if (buf.length / BLOCK > MAX_HEADER_BLOCKS) throw new Error("no END card within " + MAX_HEADER_BLOCKS + " blocks");\n      const got = await getRange(url, offset + buf.length, CHUNK);\n      if (got.total != null) total = got.total;\n      if (!got.text.length) return null;\n      const from = buf.length;\n      buf += got.text;\n      for (let i = from - (from % CARD); i + CARD <= buf.length; i += CARD) {\n        const c = parseCard(buf.slice(i, i + CARD));\n        if (!c) continue;\n        if (c.key === "END") { endAt = i + CARD; break; }\n        cards.push(c);\n      }\n      if (got.text.length < CHUNK) break;   // hit EOF\n    }\n    if (endAt < 0) return null;\n    return { cards: cards, headerBytes: Math.ceil(endAt / BLOCK) * BLOCK, total: total };\n  }\n\n  async function readHDUs(url) {\n    const hdus = [];\n    let offset = 0, total = null;\n    while (hdus.length < MAX_HDUS) {\n      const h = await readHeader(url, offset);\n      if (!h) break;\n      if (h.total != null) total = h.total;\n      const map = toMap(h.cards);\n      if (!hdus.length && !("SIMPLE" in map)) throw new Error("not a FITS file (no SIMPLE card)");\n      const data = dataBytes(map);\n      hdus.push({ index: hdus.length, offset: offset, cards: h.cards, map: map, dataBytes: data });\n      offset += h.headerBytes + data;\n      if (total != null && offset >= total) break;\n    }\n    return { hdus: hdus, total: total };\n  }\n\n  // ---- ASDF ---------------------------------------------------------------\n  // ASDF files start with "#ASDF <version>" and a YAML document terminated by "..." on its own line.\n  async function readAsdf(url) {\n    let buf = "";\n    for (let i = 0; i < 8; i++) {\n      const got = await getRange(url, buf.length, CHUNK * 4);\n      if (!got.text.length) break;\n      buf += got.text;\n      const end = buf.search(/^\\.\\.\\.\\s*$/m);\n      if (end >= 0) return buf.slice(0, end).replace(/\\s+$/, "");\n      if (got.text.length < CHUNK * 4) break;\n    }\n    return buf;\n  }\n\n  // ---- rendering ----------------------------------------------------------\n  function el(tag, attrs, text) {\n    const e = document.createElement(tag);\n    if (attrs) for (const k in attrs) e.setAttribute(k, attrs[k]);\n    if (text != null) e.textContent = text;\n    return e;\n  }\n\n  function hduTitle(hdu) {\n    const m = hdu.map;\n    const parts = ["HDU " + hdu.index];\n    parts.push(hdu.index === 0 ? String(m.XTENSION || "PRIMARY") : String(m.XTENSION || "IMAGE"));\n    if (m.EXTNAME) parts.push(String(m.EXTNAME));\n    const naxis = Number(m.NAXIS) || 0;\n    if (naxis) {\n      const dims = [];\n      for (let i = 1; i <= naxis; i++) dims.push(m["NAXIS" + i]);\n      parts.push("[" + dims.join(" x ") + "]");\n    } else parts.push("no data");\n    if (m.BITPIX != null) parts.push("BITPIX " + m.BITPIX);\n    parts.push("data " + hdu.dataBytes + " B @ " + hdu.offset);\n    return parts.join(" · ");\n  }\n\n  function renderHDU(hdu) {\n    const box = el("section", { class: "fits-hdu" });\n    box.appendChild(el("h3", null, hduTitle(hdu)));\n    const t = el("table", { class: "grid" });\n    const head = el("tr");\n    ["keyword", "value", "comment"].forEach((h) => head.appendChild(el("th", null, h)));\n    t.appendChild(el("thead")).appendChild(head);\n    const body = el("tbody");\n    hdu.cards.forEach((c) => {\n      const tr = el("tr");\n      tr.appendChild(el("td", null, c.key));\n      tr.appendChild(el("td", null, c.value));\n      tr.appendChild(el("td", null, c.comment));\n      body.appendChild(tr);\n    });\n    t.appendChild(body);\n    const wrap = el("div", { class: "scroll" });\n    wrap.appendChild(t);\n    box.appendChild(wrap);\n    return box;\n  }\n\n  async function render(root, url) {\n    root.appendChild(el("div", { class: "msg" }, "reading header…"));\n    try {\n      const head = await getRange(url, 0, BLOCK);\n      root.innerHTML = "";\n      if (head.text.slice(0, 5) === "#ASDF") {\n        root.appendChild(el("h3", null, "ASDF header"));\n        root.appendChild(el("pre", { class: "plain" }, await readAsdf(url)));\n        return;\n      }\n      const out = await readHDUs(url);\n      root.appendChild(el("div", { class: "msg" },\n        out.hdus.length + " HDU" + (out.hdus.length === 1 ? "" : "s") +\n        (out.total != null ? " · " + out.total + " bytes total" : "")));\n      out.hdus.forEach((h) => root.appendChild(renderHDU(h)));\n    } catch (e) {\n      root.innerHTML = "";\n      root.appendChild(el("div", { class: "err" }, String((e && e.message) || e)));\n    }\n  }\n\n  window.popupFits = { render: render, parseCard: parseCard, dataBytes: dataBytes, readHDUs: readHDUs };\n})();\n'  # generated by `make embed` — edit renderers/fits.js, not this line
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
