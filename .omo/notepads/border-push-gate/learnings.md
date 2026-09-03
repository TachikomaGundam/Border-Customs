# Learnings — border-push-gate

Conventions, patterns, and successful approaches discovered during work on this plan.

_Auto-scaffolded by /start-work. Append new entries below - never overwrite._

---

## todo 1 (scaffold + engine provisioning) — 2026-09-04
- EXACT pins installed: zod 4.5.4 (runtime, only dep), devDeps typescript 5.9.3 / esbuild 0.25.12 / @types/node 22.19.0 / publint 0.3.24 / verdaccio 6.10.2 (latest at install via `npm view verdaccio version`). npm install: 330 packages, 28s.
- gitleaks v8.30.1: `github.com` itself is effectively unreachable from this box (TLS EOF / connect timeouts, even with retries). WORKING ROUTE: api.github.com release asset endpoint `curl -H "Accept: application/octet-stream" https://api.github.com/repos/gitleaks/gitleaks/releases/assets/<id>` (resume with `-C -` for slow links). Tarball sha256 551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb == API digest field. Installed ~/.local/bin/gitleaks -> `gitleaks version 8.30.1`.
- PATH: ~/.local/bin IS already on PATH in this session (which gitleaks resolves), but require-engines.ts still probes PATH then ~/.local/bin fallback per plan (runner environments may differ). Do NOT edit shell rc files.
- VENDORED CONFIG INTEGRITY: python urllib fetches of api.github.com returned ALTERED BYTES (same size 97731, sha1 mismatch) vs curl for identical URLs — likely proxy tampering keyed on client. ALWAYS verify vendored assets with `git hash-object` against the tree-declared blob sha (v8.30.1 -> commit 83d9cd684c87d95d656c1458ef04895a7f1cbd8e, config/gitleaks.toml blob 256f64790ea6d954f0041024be2938089ae1e7a7, sha256 e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf). curl + raw.githubusercontent.com agreed; urllib did not.
- register-ts.mjs copied from ../magi/tools/ — it registers sibling ts-hooks.mjs (esbuild transformSync loader); Node v22.22.1 here lacks native type-stripping (ERR_NO_TYPESCRIPT / ERR_UNKNOWN_FILE_EXTENSION). Any `node --import ./tools/register-ts.mjs` runner must use it for direct .ts imports; relative .ts imports need explicit .ts extension.
- npm 11.19.1 prints `install-scripts` warning for esbuild postinstall (allowScripts coverage) — harmless: esbuild binary works via @esbuild/linux-x64 optional dep (`npx esbuild --version` = 0.25.12).
- python engines: `pip install --user --break-system-packages build twine` (PEP 668) -> build 1.6.0, twine 7.0.0 on python3.14 (~/.local/lib/python3.14/site-packages).
- git identity resolves globally (Wiki.js / wiki@sumteclab.com) — no repo-local config needed. border repo `git init -b main`; outer /home/lab/workspace baseline untouched (its porcelain head-5 listing unchanged pre/post).
