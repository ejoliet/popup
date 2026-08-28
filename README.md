# popup

> Ephemeral URL for any file, folder, S3 object, or local web app — one command, smart rendering, dies on Ctrl-C.

**Type**: RDD spec (Type A — agent implements from this README)
**Author**: Emmanuel Joliet (`ejoliet`) · **Status**: Draft · **Date**: 2026-08-14
**Brand**: Popworks (`pop*` family — siblings: poptail, popvote, poptable)

---

## Purpose

**Problem**: Sharing a rendered view of a file today means git push + GH Pages + CI wait, or uploading to a third-party service, or screenshots. Sharing a private S3 object means presigned-URL sprawl or bucket policy changes. Sharing a running dev app means installing and configuring a tunnel by hand.

**Solution**: `popup <target>` starts a local smart-render server, opens an ephemeral tunnel, prints an HTTPS URL + terminal QR. Nothing is uploaded; bytes flow only through the live tunnel. Ctrl-C (or TTL, or view cap) kills everything.

**Who benefits**: developers/scientists sharing reports, notebooks, catalogs, demos with zero hosting; Emmanuel's concrete case: markdown notes, Parquet/FITS on Roman S3 buckets, FastAPI spikes.

```bash
$ popup roman-ingest-notes.md --ttl 30m
▲ popup  https://calm-frog-3121.trycloudflare.com   (dies in 30m or Ctrl-C)
  [QR]   views: 0
```

## Architecture

Single-file Python script (`popup.py`, PEP 723 inline metadata, run via `uv run`). Four components in one process:

- **Source resolver** — maps the CLI target to a source backend by URI scheme: local path, `s3://`, `http(s)://`, `ftp://`, `:port` (proxy), `run "cmd"` (managed child).
- **HTTP server** — stdlib `http.server` + `ThreadingHTTPServer`. Serves a renderer shell page, raw bytes with **Range support**, `/events` SSE endpoint (live reload), `/kill` secret endpoint, view counter, TTL timer.
- **Renderer shell** — a single embedded HTML template. All rendering is **client-side** from CDN libs; the server never transforms content. Renderer chosen by extension (table below).
- **Tunnel adapter** — pluggable; auto-detects `cloudflared`, falls back to ssh-based providers.

```
viewer browser ──HTTPS──> tunnel provider ──> popup.py (localhost)
                                                ├─ local file/dir (jailed)
                                                ├─ S3 range proxy (host creds)
                                                ├─ HTTP/FTP snapshot (temp dir)
                                                └─ reverse proxy -> :PORT / child proc
```

> 💡 Server stays dumb (~600 lines target). The "smart" lives in the browser: keeps popup single-file, no build step, no server-side render deps.

### Renderers (client-side)

| Extension | Renderer | Notes |
|---|---|---|
| `.md` | marked.js + github-markdown-css + Mermaid | Mermaid lazy-loaded only if fenced block present |
| code (`.py .js .ts .sql .yaml .json .sh …`) | highlight.js | auto-detect language from extension |
| `.csv` | DuckDB-WASM table view | falls back to plain `<pre>` under 50 KB |
| `.parquet` | DuckDB-WASM (Range-request reads) | works on multi-GB files via range proxy |
| `.ipynb` | notebookjs | static render, no kernel |
| `.fits` / `.asdf` | custom header/HDU viewer (JS) | reads first blocks via Range; reuse astrohead parsing logic ported to JS |
| images / `.pdf` / `.html` | browser native passthrough | HTML served as-is (see `--coi`, `--spa`) |
| directory | generated index page | each entry gets its renderer |
| unknown | download link | never guess |

### Modes

| Mode | Invocation | Behavior |
|---|---|---|
| File/dir | `popup path` | jailed static serve + rendering + SSE reload on file change |
| Remote snapshot | `popup https://… | ftp://…` | fetch once to temp dir, serve locally; no reload |
| S3 range proxy | `popup s3://bucket/key[/prefix/]` | no download; incoming Range → S3 `GetObject` Range via host boto3 creds. Prefix → paginated index (cap 1 000 keys + client-side filter box) |
| Proxy | `popup :8000` | reverse proxy to running app; Host header rewritten; WebSocket + SSE pass-through |
| Run | `popup run "uvicorn app:app"` | popup owns child process (env-scrubbed), proxies to it, kills on exit |
| Sandbox | `popup run --sandbox [--image node:22] "cmd"` | child runs in container: `apple/container` (macOS) → podman → docker. App dir mounted RO, no host env, only published port |

## Recommended Stack

Tunnel and sandbox layers researched 2026-08-14 (links in References); JS renderer picks are stable, mainstream choices.

| Layer | Chosen | Why | Rejected |
|---|---|---|---|
| Language/server | Python 3.11+ stdlib (`http.server`, `asyncio` for proxy splice) | zero deps for happy path; PEP 723 allows `boto3` extra only when `s3://` used | FastAPI/uvicorn (dep weight, overkill); Node (breaks "python+ssh anywhere" pitch) |
| Tunnel default | cloudflared quick tunnel | one binary, **no account**, HTTPS/DDoS by default; random URL per run; ~200 in-flight request cap; no uptime guarantee | ngrok (account+token required) |
| Tunnel fallback 1 | localhost.run (`ssh -R 80:localhost:PORT localhost.run`) | **zero install**, no account; rotating hostnames, speed-limited | serveo (reliability history) |
| Tunnel fallback 2 | pinggy (`ssh -p443 -R0:localhost:PORT a.pinggy.io`) | zero install via port 443 (firewall-friendly); basic-auth via SSH username trick; **60-min free cap** | — |
| Sandbox (macOS) | `apple/container` v1.0 | VM-per-container isolation, sub-second start, Apple silicon + macOS 26, Apache-2.0 | Docker Desktop (license friction), OrbStack (fine as fallback) |
| Sandbox (Linux) | podman → docker | ubiquitous; rootless | Quark/gVisor/Firecracker (niche/KVM-only, wrong friction) |
| Markdown | marked.js | largest adoption, single CDN file, fast enough for ≤10 MB docs | markdown-it (plugin system unneeded), remark (build step) |
| Code highlight | highlight.js | CDN single-file, auto-detect | shiki (WASM weight), Prism (manual language loading) |
| Tables/Parquet | DuckDB-WASM | proven in joinmap/QueryDeck; range reads over HTTP | perspective (heavier), papaparse (CSV only) |
| QR in terminal | vendored pure-python QR (~120 lines) or `qrcode` via PEP 723 | keep zero-dep goal | — |

> 💡 One override round expected — flag any layer to swap before implementation.

## Repository Layout

```
popup/
├── popup.py            # the tool (single file, PEP 723 header)
├── shell.html          # renderer shell — embedded into popup.py at release by make embed
├── renderers/fits.js   # custom FITS/ASDF header viewer (embedded likewise)
├── tests/
│   ├── test_server.py  # jail, range, mime, SSE, TTL, views
│   ├── test_sources.py # s3 proxy (moto), snapshot, ftp (mock)
│   ├── test_proxy.py   # host rewrite, WS upgrade splice, env scrub
│   └── test_tunnel.py  # adapter detection + URL parsing (mocked processes)
├── Makefile            # embed, lint, test, smoke
├── README.md           # this file → later Type C for OSS
└── LICENSE             # MIT
```

## Prerequisites

- Python ≥ 3.11; `uv` recommended (`uv run popup.py …`), plain `python` works for file mode.
- One of: `cloudflared` on PATH, or an `ssh` client (always present on macOS/Linux).
- `s3://` mode: AWS credentials in the usual chain; `boto3` (declared in PEP 723 extras, uv fetches on demand).
- `--sandbox`: `container` (macOS 26 / Apple silicon) or `podman`/`docker`.

## Quick Start

```bash
git clone https://github.com/ejoliet/popup && cd popup
uv run popup.py README.md                      # 1. share this file
uv run popup.py s3://mybucket/cat.parquet      # 2. private S3 → queryable URL
uv run popup.py :8000 --password               # 3. expose running FastAPI /docs
```

## Configuration Reference

CLI flags are the interface; env vars only for defaults.

| Flag | Type / default | Purpose |
|---|---|---|
| `--ttl 30m` | duration / none | hard kill timer |
| `--max-views N` | int / none | burn after N views (`--once` = 1) |
| `--password [pw]` | str / auto-gen | HTTP basic auth. **Forced ON default** for `s3://`, `ftp://`, proxy, run modes (opt out: `--no-password`) |
| `--tunnel X` | `auto|cloudflared|localhostrun|pinggy|none` / auto | `none` = LAN only |
| `--port N` | int / random free | local bind (always 127.0.0.1) |
| `--coi` | bool / false | send COOP/COEP headers (SharedArrayBuffer / threaded WASM) |
| `--spa` | bool / false | serve index.html on unknown paths (client routers) |
| `--sandbox`, `--image` | bool / false; str / `python:3.12-slim` | run-mode container isolation |
| `--qr / --no-qr` | bool / true | terminal QR |
| `POPUP_TUNNEL`, `POPUP_TTL` | env | default overrides |

## Interface Contract (server routes)

| Route | Behavior |
|---|---|
| `GET /` | renderer shell for target (or dir index / proxy pass) |
| `GET /raw/<path>` | bytes; honors `Range`; correct MIME (override map: `application/wasm`, `text/javascript` for `.mjs`) |
| `GET /events` | SSE: `reload` on file mtime change |
| `POST /kill/<secret>` | immediate shutdown; secret printed at launch |
| any (proxy mode) | pass-through incl. `Upgrade: websocket` via raw socket splice; Host rewritten to `localhost:PORT`; streaming unbuffered |

## Error Handling

| Error | Behavior |
|---|---|
| `TunnelUnavailableError` | try next adapter; if all fail, print LAN URL + hint |
| `PathTraversalError` | 403; jail = `resolved.is_relative_to(root)`, symlinks resolved, `..` rejected |
| `S3AccessError` | map boto3 errors to 404/403; never leak ARNs/creds in response |
| `UpstreamDownError` (proxy) | 502 page with retry hint; detect Vite/Django host-check 4xx and print `allowedHosts`/`ALLOWED_HOSTS` hint to terminal |
| Tunnel process dies | detect, attempt one restart, else shut down cleanly (URL changes → warn) |

## Security Requirements (non-negotiable)

- Bind 127.0.0.1 only; public exposure exclusively via tunnel.
- Path jail on every file read (test-covered).
- Run mode: child env **scrubbed by default** — drop `AWS_*`, `GITHUB_TOKEN`, `*_SECRET*`, `*_KEY*`, `*TOKEN*`; `--pass-env NAME` to allow-list.
- S3 creds live only in host process; never forwarded to child/sandbox/browser.
- `/kill` secret ≥ 128-bit random; password auto-gen ≥ 12 chars, printed once.
- Launch banner always states: URL is public to anyone who has it; password status; TTL.
- Run `ship-check` skill before publishing repo (no keys, no account IDs).

## Testing

`make test` → pytest; S3 via `moto`, tunnels/child procs mocked; no network in tests. `make smoke` → real end-to-end: serve README.md via cloudflared, curl the public URL, assert 200 + rendered title (manual/CI-optional).

## Non-Goals (v1)

- Multi-file "rooms" with nav sidebar (Pro, v1.1)
- Serve+proxy hybrid `--api :8000` (v1.1)
- FITS image display (JS9) — header/HDU only
- Persistent/custom URLs, accounts, analytics dashboards
- Windows support (macOS/Linux only)
- Compose/multi-container sandboxing

## Open Questions

- [ ] Name collision: `popup` is generic (npm/pypi). Ship as `popup-cli` on PyPI, keep `popup` binary name? Alternates: `popurl`, `popserve`.
- [ ] Embed strategy: `make embed` inlines shell.html + fits.js into popup.py — acceptable, or ship 3 files?
- [ ] CDN pinning: pin exact lib versions + SRI hashes, or float minor versions?
- [ ] Pinggy 60-min cap vs `--ttl` > 60m: warn, or auto-prefer cloudflared when TTL exceeds provider cap?
- [ ] Pro tier gate (Ed25519 offline license, Lemon Squeezy): which features — password-on-any-adapter is free (security must not be paywalled); rooms + theming + view log = Pro?

## Agent Build Instructions

> Implement end-to-end from this README only. Resolve Open Questions first (defaults: `popup-cli`/`popup`; embed; pin+SRI; auto-prefer cloudflared; security features free).

### Build order

| Phase | Deliverable | Gate ("done when") |
|---|---|---|
| **0 — SPIKE (hard gate)** | stdlib server + cloudflared adapter + marked.js render + SSE reload, one local .md file | public trycloudflare URL renders the file; edit → browser auto-reloads. **No further work until this passes.** |
| 1 | Range support, MIME map, path jail, dir index, TTL/max-views/kill, QR, password | `test_server.py` green |
| 2 | Renderer shell complete (all table rows), `--coi`, `--spa` | manual render check per type; parquet range reads verified |
| 3 | Sources: snapshot (http/ftp), S3 range proxy + prefix index | `test_sources.py` green (moto) |
| 4 | Proxy + run modes: splice, Host rewrite, WS, env scrub | FastAPI `/docs` + Vite HMR work through tunnel |
| 5 | ssh tunnel adapters + auto-detect; `--sandbox` | adapter matrix manually verified on macOS + Linux |

### File map (sections within popup.py)

| Section | Key symbols |
|---|---|
| cli | `main()`, argparse, banner |
| sources | `Source` protocol; `LocalSource`, `S3Source`, `SnapshotSource`, `ProxySource`, `RunSource` |
| server | `PopupHandler`, `range_response()`, `jail()`, `sse_events()`, `MIME_OVERRIDES` |
| shell | `SHELL_HTML` (embedded), `pick_renderer(ext)` |
| tunnel | `TunnelAdapter` protocol; `Cloudflared`, `LocalhostRun`, `Pinggy`; `detect()` |
| sandbox | `build_container_cmd(runtime, image, dir, port)` |
| lifecycle | TTL timer, view counter, signal handlers, kill secret |

### Constraints

- Python 3.11+, typed signatures, `ruff` + `mypy` clean; `AIDEV-` comments for non-obvious decisions.
- Happy path (local file + cloudflared) must run with **zero pip installs**.
- Never write outside a `tempfile` dir; never log credentials or the kill secret after launch.

### Acceptance criteria

- [ ] Phase 0 spike gate passed and demoed
- [ ] `make test` green, coverage ≥ 80%; `make lint` clean
- [ ] `time` from command to printed URL < 5 s (cloudflared warm)
- [ ] 5 GB Parquet on S3 queryable in browser with < 20 MB transferred (verify via server byte counter)
- [ ] Path-traversal attempts (symlink, `..`, encoded) all 403 in tests
- [ ] Run mode child sees no `AWS_*` env (test asserts)
- [ ] Ctrl-C leaves no orphan processes (tunnel, child, container)

## References

- trycloudflare — no-account quick tunnels: https://trycloudflare.com/
- Quick tunnel limits/behavior: https://www.dotruby.com/articles/how-to-expose-your-rails-localhost-securely-using-cloudflare-tunnel
- Zero-install SSH tunnels (localhost.run, pinggy incl. basic-auth trick): https://dev.to/instatunnel/zero-install-tunneling-in-2026-the-developers-complete-guide-to-agentless-localhost-proxies-321o
- pinggy free-tier 60-min cap: https://pinggy.io/
- apple/container (VM-per-container, macOS 26): https://github.com/apple/container

## Next Steps

1. Answer the 5 Open Questions (one pass).
2. Run Phase 0 spike (~1 afternoon).
3. If gate passes → Phases 1–5; if cloudflared friction bites, re-evaluate default adapter before Phase 5.
