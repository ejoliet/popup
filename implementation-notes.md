# implementation-notes

One line per entry, grep-friendly. DEVIATION: = conservative departure from spec.

## 2026-08-27 worker-1 (popup.py, LICENSE)
- 2026-08-27 decision: vendored QR (byte mode, EC-L, v1-10, 271B cap); byte-exact vs `qrcode` lib for all lens 1..271; rejected qrcode dep (breaks zero-install) and fixed mask 0 (full penalty scoring so it scans)
- 2026-08-27 decision: boto3 NOT in PEP 723 dependencies (no extras syntax); lazy import, error says `uv run --with boto3 popup.py s3://...`; rejected unconditional dep
- 2026-08-27 decision: sources return Blob (ctype/size/stream/ranged flag); handler does range math for file sources, S3 sets ranged=True so upstream Range wins; rejected handler-into-source coupling
- 2026-08-27 decision: single URL-decode inside jail(); still-encoded after one pass (%252e, %2f) or leading `/` -> 403 (double-decode IS the vuln); jail() accepts str|Path root
- 2026-08-27 decision: run mode passes child port via $PORT; nothing listening in 20s is non-fatal (502 + hint per UpstreamDownError); rejected hard-fail and guessing 8000
- 2026-08-27 decision: child start_new_session=True + os.killpg SIGTERM->SIGKILL; plain terminate() on shell=True orphaned grandchildren (real test failure)
- 2026-08-27 decision: signal handlers installed BEFORE resolve_source(); run-mode port wait polls stop event; Ctrl-C during startup used to orphan child (real test failure)
- 2026-08-27 bugfix: single-object s3:// served its object for /raw/<anything>; now 404 for any other key (test_s3_missing_key_is_404)
- 2026-08-27 decision: password enforced in-process on every adapter (security free per resolved Open Question); rejected pinggy ssh-username basic-auth trick (one provider only)
- 2026-08-27 decision: kill secret 192-bit token_urlsafe(24) printed once; auto password 16 chars; banner always states public reach + loopback bind
- 2026-08-27 decision: fits.js served at BOTH /renderers/fits.js and /__popup__/fits.js (contract did not pin URL)
- 2026-08-27 decision: container flags long-form only (--rm --volume --workdir --publish --env); apple/container/podman/docker diverge on short flags; apple/container networking untested on real macOS 26 hw
- 2026-08-27 decision: multi-range Range headers ignored (200 full body); spec promises single-range only
- 2026-08-27 DEVIATION: run-mode $PORT convention instead of guessing child port — conservative, non-fatal, hinted
- 2026-08-27 DEVIATION: popup.py 1754 lines vs ~600-900 target; overage = vendored QR (258) + embedded SHELL/FITS fallbacks + docstrings/AIDEV; working code not compressed to hit line count
- 2026-08-27 note: moto tests need moto[server] + flask; plain --with moto fails ("moto server failed to start")

## 2026-08-27 worker-2 (shell.html, renderers/fits.js, tests/, Makefile)
- 2026-08-27 decision: tests drive CLI as subprocess, not internals; main() only pinned entry point; rejected in-process fixtures (guessed constructor signatures)
- 2026-08-27 decision: moto SERVER mode via AWS_ENDPOINT_URL (nothing in popup.py stubbed, real S3 range path); rejected mock_aws decorators/monkeypatching boto3; needs moto[server]+flask
- 2026-08-27 decision: 100-line loopback FTP server as "ftp mock"; rejected patching ftplib/urllib internals
- 2026-08-27 decision: env-scrub test asserts file written by child + proxy round-trip; child binds $PORT per popup convention
- 2026-08-27 decision: DOMPurify 3.1.6 added (unrequested) — markdown/notebook HTML attacker-controlled for s3/http sources; one call at trust boundary
- 2026-08-27 decision: CSV <50KB -> <pre> per README (no 30MB WASM boot); SQL box for csv+parquet (5GB-parquet criterion implies one)
- 2026-08-27 decision: no sandbox attr on html/pdf iframe — "served as-is" spec; sandboxing breaks the apps being shown
- 2026-08-27 decision: make embed builds `#` via chr(35) (make eats # in assignments); missing-marker path exits 1
- 2026-08-27 DEVIATION: make smoke asserts 200 + window.POPUP + __POPUP_CONFIG__ replaced + config names README.md — title renders client-side, curl cannot see it
- 2026-08-27 note: SRI sha384 pinned on all CDN libs except @duckdb/duckdb-wasm 1.29.0 (+esm import() has no integrity attr; version-pinned tree, AIDEV note)
- 2026-08-27 note: fits.js parser verified out-of-band (node, synthetic FITS: 2 HDUs, offsets 0/23040, unquoted OBJECT); no permanent JS harness (no JS toolchain in repo)
- 2026-08-27 note: fits.js ceiling — CONTINUE/HIERARCH cards render as own rows; upgrade when a real file needs it
- 2026-08-27 note: config JSON `path` key is load-bearing (shell builds /raw/<path> from it) — treat as contract

## 2026-08-27 verify round 1 (opus verifier, REJECT -> fix loop 2)
- 2026-08-27 blocker B1: LocalhostRun url_re first-matched https://admin.localhost.run from real MOTD (admin link precedes tunnel line) — wrong URL in banner/QR + kill secret POSTed to third-party host; Pinggy url_re same class (matches dashboard.pinggy.io); test fixtures were synthetic, missed it
- 2026-08-27 fix (lead): ".json" added to CODE_EXTS — README code row lists .json; shell.html already treated it as code; test_units expectation updated
- 2026-08-27 finding F3: suite flaky under CPU contention — READY_TIMEOUT 20s too tight (8 identical bind-timeout flakes, none reached assertions); raise to 45s
- 2026-08-27 finding F4: SSE does NOT stream through trycloudflare quick tunnels (proven with non-popup origin: 0 ticks vs 10 via localhost.run; not a popup framing issue) — live reload works locally + via ssh adapters; document limitation, consider preferring ssh adapter when reload matters
- 2026-08-27 finding F5: time-to-URL 5.11s warm vs <5s criterion — dominated by cloudflared registration, popup startup negligible
- 2026-08-27 finding F6: embedded SHELL_HTML/FITS_JS in popup.py are reduced fallbacks; run `make embed` at release or standalone single-file popup.py renders degraded (release checklist item)
- 2026-08-27 coverage: subprocess-hooked measure 68% before unit-test round; worker-2 added tests/test_units.py (116 tests, QR block + pure helpers, 43% standalone) — re-measure pending
- 2026-08-27 verified security list: loopback-only bind, jail, env scrub allowlist, S3 cred isolation, 192-bit kill secret + no-op log_message, forced password modes, banner wording, no ARN/cred leakage — all confirmed by verifier with line refs

## 2026-08-27 fix round 2 (B1 + hardening)
- 2026-08-27 fix B1: shared _NOT_TUNNEL_HOST negative lookahead (admin/dashboard/www/docs/status/support/blog/api) baked into LocalhostRun + Pinggy url_re; pinggy also pinned to *.pinggy.link | *.a.pinggy.io shape so stale denylist still cannot match dashboard.pinggy.io; live-verified on real localhost.run tunnel (correct URL in banner/QR/kill cmd)
- 2026-08-27 decision: deleted permissive _ProcAdapter.url_re catch-all default (annotation only now — future adapter that forgets to pin fails loudly instead of matching any URL) and deleted never-overridden accept() hook; net -5 lines
- 2026-08-27 tests: test_tunnel.py fixtures replaced with real captured MOTDs incl. decoy lines; test proven to trap by replaying old regexes (picked admin/dashboard URLs); READY_TIMEOUT 20s->45s; .gitignore added; make clean removes coverage/caches
- 2026-08-27 status: 176 passed 1 skipped (optional qrcode cross-check), ruff+mypy clean
- 2026-08-27 coverage final: popup.py 86% (1099 stmts, 152 miss) via COVERAGE_PROCESS_START subprocess hook; 176 passed 1 skipped — >=80% acceptance criterion met
