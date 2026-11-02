# Engines and consumer installs

Extracted from README (2026-11 page-governance split): engine-by-engine posture,
vendoring decisions, version matrices.

## Engines in consumer installs

`dist/index.js` is one self-contained esbuild bundle and every runtime asset (vendored
gitleaks rules, prompt template, the secretlint fingerprint snapshot) ships inside `dist/`,
so after `npm i -D border-customs` (or `-g`) the engine surface is:

- **publint** — installed automatically: it is an exact-pinned runtime dependency of the
  package, invoked via bin resolution (package-local `node_modules/.bin`, the hoisted
  project-level `node_modules/.bin`, then `PATH`, then `~/.local/bin`). The
  `publint-fail` leg of the npm artifact stage works out of the box in a consumer install.
- **secretlint** — no consumer action, ever: the default lint runs **in-process** with the
  `@secretlint/*` rule modules already declared as border's own runtime dependencies
  (`src/engines/secretlint.ts` header). The `mode: "cli"` fallback that spawns a
  `secretlint` binary is border-internal (test transport); it is not reachable from
  `border.yaml` or any flag, so installing `secretlint` into your project changes nothing
  for border. If the engine probe cannot read the bundled lock snapshot
  (`dist/assets/package-lock.json`), the run fails closed as `DEGRADED-ENGINE` exit 2 —
  never a silent pass.
- **gitleaks** — stays external, same posture as `git`: border vendors the 8.30.1 rule
  config but the binary is yours (on `PATH` or `~/.local/bin/gitleaks`; see the
  requirements paragraph at the top and `src/engines/ADAPTER-CONTRACT.md`). Missing
  gitleaks means `border check` records a CRITICAL `DEGRADED-ENGINE` finding and exits 2,
  and `border scan` exits 2 with `engine binary 'gitleaks' not found; border fails
  closed`. Neither command degrades to a skip.
- **trufflehog** — optional third engine, external binary, same posture as gitleaks once
  enabled: `engines.trufflehog: true` puts it in the required set, and an absent binary
  degrades the run to exit 2 exactly like a missing gitleaks.

There is no "engine absent ⇒ leg silently skipped" state anywhere: missing required
engines are exit 2 (`2` = the gate could not answer, see
[Exit codes](#exit-codes-the-contract)), and the ledger refuses to write a PASS for a
degraded run.

