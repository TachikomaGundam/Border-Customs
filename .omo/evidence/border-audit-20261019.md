# border audit remediation — 2026-10-19

Base: `72bd98a` (main = origin/main), version 0.8.1. No commit, tag, or push.
Scope: third-party audit (2026-10-17) + handoff B0. Machine-facing receipt.

## Full suite (final)

```
$ BORDER_PACK_TEST=1 npm test
# tests 877
# pass 864
# fail 0
# skipped 13
# duration_ms 170464.042332
RC=0
```

## Static gates

```
$ npm run typecheck      # RC 0 (tsc --noEmit)
$ npm run version:check  # version-sync: clean at 0.8.1
$ npm run build          # RC 0 (esbuild 1.7mb + copy-assets)
$ node dist/index.js --help  # RC 0
$ node -e "yaml.parse(...)"  # ci.yml, publish.yml, dependabot.yml all parse
$ git diff --check       # clean
```

## B0 reproduction (npm 10 executes target code)

Fixture: package.json with `scripts.prepare` touching `PREPARE-RAN`.

```
npm 10.9.7:  prepare EXECUTED; PREPARE-RAN created; file packed into tarball.
             preparse? no: prepack/postpack/prepublish/prepublishOnly/install/
             postinstall stayed silent under --ignore-scripts.
npm 11.19.1: no hook executed.
```

Fix: `src/artifacts/npmPackSafety.ts` probes `npm --version` before pack.
npm < 11 + non-empty `prepack`/`prepare`/`postpack` => named `EngineRunError`
(exit 2). Packages without pack-phase hooks remain scannable. The same probe
runs in `src/ledger/freshness.ts`; unsafe => `null` (cannot justify a skip).

Proof:
- `test/artifacts.npmSafety.test.ts` — 5 cases (npm10+prepare refused, marker
  absent; npm10 no hooks ok; npm11+prepare ok; unparseable version refused;
  hook reader).
- Real npm 10.9.7 `packOnce` refused the prepare fixture; marker false.
- Real npm 11.19.1 packed the same fixture; marker false.
- `test/artifacts.npm.test.ts` lifecycle fixture moved to `install` so both
  npm lines keep the 2 CRITICAL findings deterministic.

## Other fixes

- B3/B4 path patterns: drive-letter negative lookbehind + UNC no newline.
  `test/engines.secretlint.test.ts` 4 new cases (prose escape no-fire, real
  `D:\data\x.txt` fires, cross-line stub no-fire, real `\\server\share` fires).
- B1: JSON already used `path`; no `file` alias. `test/report.test.ts` pins
  `path` and the absence of `file`; README states the schema.
- Version single source: `tools/version-sync.mjs` + `npm run version:check`;
  UA URL fixed to `https://github.com/TachikomaGundam/Border-Customs`.
  `test/releaseCoherence.test.ts` checks lock roots, plugin line, README pin,
  UA URL, engines floor.
- Engines floor `>=22.22.2` (transitive `ini@7`).
- gitleaks vendored config: MIT notice restored.
- CI: `.github/workflows/ci.yml` (main + PR; Node 22/24; version, typecheck,
  build, critical-only audit, full suite; logs archived).
- Release gate: 308 -> 247 lines; empty allowlist machinery removed; TAP
  count balance + exit-code agreement retained (all real reds fail closed).
- Community files: SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, issue
  templates, PR template, Dependabot.
- README: npm 11 safety probe, JSON schema, Development section, three
  relative links made absolute for npmjs.

## Dependency facts

```
$ npm audit --omit=dev --json
production: 4 (1 moderate fast-uri; 3 high via
  @secretlint/secretlint-rule-pattern@13.0.5 -> braces/micromatch)
critical production: 0
```

No patched `braces` release; secretlint 13.0.7 still uses the same range.
CI blocks critical production advisories and archives the full report.

## Named gaps (not changed)

- `.omo/` committed workspace files (392 files, 4.6 MB); explicit
  self-exemption in `border.yaml`. Removal needs a human decision (evidence
  retention).
- No ESLint/Prettier config; typecheck is the static gate.
- GitHub Releases, repo description/topics/homepage, Discussions: external
  settings, not repo files.
- B2 waiver-pin formatter resilience and B5 reveal mode: design items.
- `@types/node@22` matches the runtime floor, not CI Node 24 (intentional).
- Actions still referenced by tag, not SHA.
