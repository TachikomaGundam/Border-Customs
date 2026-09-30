# F-INSPECT-0.8.0 — dogfood receipts for `border opencode inspect` + R1 allowlist (plan v2 T6)

date 2026-09-30 (host clock: `date +%FT%T%:z` captured 19:33:22+08:00 this wave) · node v22.22.1 · repo head at evidence time: e64b24c+db5220c (main, ahead of origin) · branch main

## Acceptance #1 — machine's real state, all PASS exit 0

$ node dist/index.js opencode inspect --json
{"schemaVersion":1,"scope":"v1","verdict":"PASS","aspects":[
 {"id":"cache-version","verdict":"PASS","detail":"cache self-consistent: latest->0.7.1"},
 {"id":"spec-freshness","verdict":"PASS","detail":"cache matches spec: 0.7.1"},
 {"id":"identity-handshake","verdict":"PASS","detail":"packaged dist/index.js (shebang exec) passed the identity handshake"},
 {"id":"route-a-parity","verdict":"PASS","detail":"/home/lab/.config/opencode/plugins/border.ts: absent — Route A not installed, nothing to be stale"},
 {"id":"dual-route","verdict":"PASS","detail":"Route B only: 'border-customs@latest', no file drop …"},
 {"id":"scope","verdict":"PASS","detail":"verdict scope = v1-load-surface; NOT covered (declared blind, separate ledger item): V2 project-local .opencode/plugins/, V2 npm-prefix/node_modules installs, V2 lazy activation state"}]}
rc=0
(The cache line reads latest->0.7.1: registry @latest == 0.7.1 == cache == what this repo will SUPERSEDE at publish; dist-tag leg live against the real registry.)

## Acceptance #2 — sabotage shots (fail-loud proven)

- S1 identity: `env BORDER_BIN=/bin/echo node dist/index.js opencode inspect` → verdict FAIL,
  identity-handshake=FAIL, **direct rc=1** (first read piped through python and displayed the
  pipe's rc — I4-lesson recount: re-ran with exit code captured before any pipe).
- S2 stale exact-pin (fake HOME world, cache pkg.json 0.8.0 under dir @0.9.9, pin @0.9.9):
  verdict FAIL — cache-version FAIL + spec-freshness FAIL "cache holds 0.9.9->0.8.0, spec expects 0.9.9".
- S3 dual-route (fake world + Route A file drop while config declares Route B):
  verdict FAIL — dual-route FAIL "both routes registered: Route A drop at …" (+ S2's stale legs still red).
- Lying-registry variant (spec-freshness FAIL via dist-tag registry value ahead of cache) is covered
  by the injected ScanFetcher seam in test/opencode.inspect.test.ts (no live-registry lie was
  possible without env seam; honest live/unit split — no env seam added mid-wave, BORDER_BIN was
  the only env-verified sabotage channel on purpose).
- NOT-CACHED path: declared pin, empty cache dir → aggregate rc=2 with aspect detail anchored
  "NOT-CACHED:" (top-level CANNOT while spec-freshness PASSes — the B2 precedence lives in the shell).

## Acceptance #3 — drift-watch thin shell, cron tri-state live

$ node tools/plugin-drift-watch.mjs border-customs            → verdict: FRESH — … rc=0
$ BORDER_BIN=<fake FAIL json:cache-version>                    → verdict: DRIFT — cache-version: stale, rc=1
$ BORDER_BIN=<fake CANNOT detail:"NOT-CACHED: declared…">      → verdict: NOT-CACHED — …, rc=0
crontab line untouched (contract byte-stable). `--purge` remains shell-local rmSync (unit case).

## Suite + gates (final tree state, includes R1 + bump)

- `npm run typecheck` rc=0 · `npm run build` rc=0
- `npm test`: # tests 856 | # pass 840 | # fail 2 (EXACTLY sanctioned C5-1 + C5-4) | # skipped 14
  (13 baseline + 1 new env-gated live-registry E2E skip; fail-set unchanged = M3 rule holds)
- R1 mid-wave catch recorded honestly: the closed-list sentence lives in THREE renderings
  (ALLOWED_COMMANDS array, COMMAND_TEMPLATE, refusal message + border-command.md mirror);
  the hygiene byte-mirror test went red on the first full suite and forced the enumeration
  completion — pin worked as designed. Note for the ledger: this is a latent L-SINGLE-SOURCE
  violation (four renderings of one fact) — candidate cleanup item for a later wave.

## Version rotation (bump 0.7.1→0.8.0, four-way + pins)

package.json:3 · package-lock.json:3,9 (deps untouched) · plugin/border.ts marker (rode commit db5220c)
· src/scan/fetch.ts UA · README example pin L720 · test/residue.config.test.ts:361 R4-DOC pin+rationale
· README changelog en ### 0.8.0 + zh **0.8.0（…）** paragraph.
