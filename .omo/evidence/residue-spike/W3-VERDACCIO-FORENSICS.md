# W3.1 — verdaccio loopback publish legs: runner-vs-devbox root-cause + fix

Scope: **W3.1** (verdaccio PUT root-cause on runners) and the **AC-trio HALF of W3.3**
(prune I1/AC1/AC3 from the sanctioned allowlist). Repo `/home/lab/workspace/harness/border`.
Branch `forensics/w3-verdaccio` (fix+allowlist commits) — NOT merged (human gate).
Author: autonomous W3.1 worker, 2026-09-11.

## Verdict (one line)

The three legs are **NOT a publish/network/auth regression**. The `npm publish` PUT
*lands on verdaccio on the runners* (server answers `201 Created`, `runNpmPublish` returns
exit 0). The failure is purely in the **test harness**: it counts requests by grepping the
verdaccio **stdout log file** for the literal substrings `http <--` and `requested 'PUT'`,
and on GitHub-hosted runners those substrings are **split by ANSI color escape codes**, so the
counters return `0` and the "PUT landed" assertions time out. On the dev box the same log is
plain ASCII, so the substrings match and the legs are green.

## The three affected tests (exact TAP titles retired from the ALLOWLIST)

| Entry | File | Line |
| --- | --- | --- |
| `AC1 npm E2E: dry-run prints exact command with ZERO verdaccio hits; --yes publishes with warning-before-spawn, visible version, push-record` | test/push.registries.test.ts | 350 |
| `AC3 npm double-publish: second --yes attempt re-probes, hard-FAILs with bump message, issues no PUT` | test/push.registries.test.ts | 415 |
| `I1 git+npm PENDING: push --yes lands the bare, publishes to verdaccio, and writes BOTH push-records under the PASS key` | test/push.integration.test.ts | 305 |

Runner symptom (dev-era evidence `.omo/evidence/residue-spike/CI-RUNNER-REDSET-2026-09-09.txt`):
AC1 `error: '--yes path did contact the registry (probe + PUT)'` (expected true, actual false);
AC3 `error: 'first attempt performs exactly one publish PUT'`; I1 `error: 'verdaccio saw the
publish PUT'`. All three fail on a **log-line-count** assertion, at the 5s `waitUntil` timeout,
while the earlier `pubExit == 0` / `EXIT_PASS` assertions already passed — i.e. the publish
succeeded and the counter stayed zero.

## Root cause (proven, not guessed)

Harness counting contract (test/push.registries.test.ts:281-283, mirrored at
test/push.integration.test.ts:174-176):
```
requestCount: () => logLines().filter(l => l.includes("http <--")).length
putCount:     () => logLines().filter(l => l.includes("requested 'PUT'")).length
```
`logLines()` = `readFileSync(logPath, "utf8").split("\n")` where `logPath` is the file that
verdaccio's **stdout** is redirected to (`stdio: ["ignore", fd, fd]`, `fd = openSync(logPath,"a")`).

verdaccio 6.10.2 logs through `@verdaccio/logger-prettify`, whose color layer is **colorette
2.0.20** (`node_modules/@verdaccio/logger-prettify/package.json`). Colorette's gate
(`node_modules/colorette/index.js:9-25`):
```
isDisabled = "NO_COLOR" in env || argv.includes("--no-color")
isForced   = "FORCE_COLOR" in env || argv.includes("--color")
isCompatibleTerminal = tty.isatty(1) && env.TERM && env.TERM !== "dumb"
isCI       = "CI" in env && ("GITHUB_ACTIONS" in env || "GITLAB_CI" in env || "CIRCLECI" in env)
isColorSupported = !isDisabled && (isForced || (win32 && !dumb) || isCompatibleTerminal || isCI)
```
Key term: **`isCI`**. GitHub-hosted runners always export `CI=true` **and**
`GITHUB_ACTIONS=true`. So `isColorSupported` is **true even though verdaccio's stdout is a
redirected file (`isatty(1)` is false → `isCompatibleTerminal` false)**. The runner therefore
writes colorized lines; the dev box (no `CI`/`GITHUB_ACTIONS`) writes plain lines. Raw bytes
captured from the runner (final-green run, log line 421, ANSI shown literally):
```
[35mhttp [39m[37m[32m<--[37m [33m200[37m, user: [1mnull[22m([32m127.0.0.1[37m), req: '[32mPUT[37m [32m/w3f-widget[37m', bytes: [33m1263[37m/[33m0[39m
```
After stripping escapes it is the exact expected text `http <-- 200, …, req: 'PUT /w3f-widget', …`.
The escape sequences sit **between `http ` and `<--`** (breaking `includes("http <--")`) and
**between `requested '` and `PUT'`** (breaking `includes("requested 'PUT'")`). Both counters
return 0 on the runner. This is a pure test-observability bug; border's product publish path is
correct (it never parses verdaccio logs — only the test does).

## Hypothesis table (all four planned hypotheses, falsified/confirmed by forensics)

| # | Hypothesis (W3.1 brief order) | Prediction if true | Observed on runner | Verdict |
| --- | --- | --- | --- | --- |
| 1 | npm 11 vs 12 argv / provenance negotiation breaks the PUT | runner npm≠dev; `--provenance`-oidc interferes with loopback PUT | runner = node v24.20.0 / **npm 11.19.0**; dev box npm 11.19.1 (same major, same minor 11.19). Test `npm publish` argv is `publish <tgz> --registry <url>` — **no `--provenance`** (that flag is only on the real `Publish` step, gated to tag pushes, never the gate tests). PUT lands (verdaccio 201) in the forensics probe. | **FALSIFIED** |
| 2 | loopback bind vs `localhost` IPv6 (`::1` vs `127.0.0.1`); runner `/etc/hosts` differs | verdaccio binds `::1` or client resolves `localhost`→`::1` | harness binds/queries **explicit `127.0.0.1`** everywhere (`listen: 127.0.0.1:<port>`, `url=http://127.0.0.1:<port>`, `_authToken` key `//127.0.0.1:<port>/`). In-process `fetch(127.0.0.1:<port>)` in the probe returned HTTP responses; `/proc/net/tcp` showed the LISTEN on `0100007F:<hexport>`. No `localhost`/`::1` in the data path. | **FALSIFIED** (dead-on-inspection + probe) |
| 3 | runner npm globalconfig / proxy / `NPM_CONFIG_USERCONFIG` leaks and rewrites the PUT target | PUT goes to a proxy/real registry, verdaccio never sees it; ENEEDAUTH | probe dumped `/proc/<verdaccio-pid>/environ` (real child env, case-visible) + `npm config get userconfig/globalconfig/registry/proxy/https-proxy/dry-run/offline`; direct seam publish + stripped-CI-env publish **both exited 0 and both landed a PUT** (log shows the `201`). No proxy var set; `registry=https://registry.npmjs.org/` is irrelevant (overridden by `--registry`). setup-node v6 exports no `NPM_CONFIG_USERCONFIG` unless `registry-url` is set (it is not — comment at publish.yml:47-50). | **FALSIFIED** |
| 4 | verdaccio sqlite/log under `/tmp` cleanup race | log/`.verdaccio-db.json` unlinked before read | probe walked the storage tree (under the repo `test/tmp/` mkdtemp root, NOT `/tmp`) and re-read the log after a 2s grace — content present & correct, just colorized. No race. | **FALSIFIED** |
| **+** | **(found) verdaccio log ANSI-colorized under CI, harness substring counters miss** | counters 0 while PUT succeeds + exit 0 | MATRIX `{"B1":"hits 0→0 (puts 0), exit=0","B2":…exit=0,"B3":…exit=0}` on the runner while the same log tail shows `req: 'PUT /w3f-widget'` 200/201. Locally reproduced: `CI=1 GITHUB_ACTIONS=1` flips AC1+AC3+I1 **red on the dev box**; removing those two vars → green. | **CONFIRMED** |

## Fix (at source: test harness — product code untouched, and correct)

Both harness files, two independent layers so the counters are environment-agnostic:

1. **Spawn verdaccio with `NO_COLOR=1`** → colorette `isDisabled` (presence of `NO_COLOR`)
   forces `isColorSupported=false` regardless of CI — the log is plain text at the source.
   (`NO_COLOR_ENV = { ...process.env, NO_COLOR: "1" }`; passed as `env:` on the verdaccio
   `spawn`. Deliberately did **not** set `FORCE_COLOR` — its mere *presence* would force color
   on via `isForced`; `NO_COLOR` wins but we avoid the trap entirely.)
2. **`stripAnsi()` on the log read** (`logLines = () => stripAnsi(readFileSync(logPath,"utf8")).split("\n")`,
   regex `/\x1b\[[0-9;]*m/g`) → defense in depth: even if a future verdaccio/colorette ignores
   `NO_COLOR`, or injects escapes another way, the substring predicates still match.

Files changed (identical fix in both):
- `test/push.registries.test.ts` — `startVerdaccio` spawn `env`, + `stripAnsi` in `logLines`.
- `test/push.integration.test.ts` — same two edits (helpers are replicated, export nothing).

ALLOWLIST (`.github/workflows/publish.yml`): retired I1/AC1/AC3 + their comment lines
(v2 → v3), with the root cause recorded in the header comment. Remaining sanctioned set (kept
verbatim per the W3.3 AC-trio-mandate):
`channels golden`, `C5-1`, `C5-4`, `stage: real gem build`, `freshness: rubygems repacks` (5).

AC2 (also verdaccio-based) only asserts **zero** hits; colorization was making it *falsely* pass
(counter always 0). The fix keeps it green for the right reason (dry-run/tamper make no request).

## Dispatch log (runner forensics, branch-limited, ≤4 cycles)

| Run id | Purpose | Result |
| --- | --- | --- |
| `34614069251` | forensics probe `test/w3.forensics.test.ts` (never-fail; env/argv/child-env/listener/log-dump matrix; NO allowlist change) | gate red as expected (only diff was stale `-stage` entry, trio still red) — **delivered the smoking gun**: MATRIX all `exit=0, puts=0` while the runner log tail held colorized `req: 'PUT /w3f-widget'` 200/201. Raw log: `w3-verdaccio-runlogs/forensics-34614069251.log`. |
| `34616009447` | final proof: fix + allowlist prune, probe removed | **GREEN through the gate.** `release gate green: 705 tests / 690 pass / exactly 5 sanctioned failure(s) matching the allowlist`. Pack+verify success. `Publish (npm Trusted Publishing / OIDC)` step **skipped** (gated on `github.event_name == 'push'`; `workflow_dispatch` can never publish — see publish.yml:228,231). Overall job conclusion: success. Raw log: `w3-verdaccio-runlogs/final-green-34616009447.log`. |

Gating verified before first dispatch: `Publish` runs `if: github.event_name == 'push'`; the
dispatch path prints `dry-run: publish only on v* tag push`. So `workflow_dispatch` is a DRY RUN
by design — no dispatch could publish for real.

## Runner-vs-devbox environment diff (the asymmetry)

| Factor | dev box (v22.22.1) | GitHub-hosted runner (v24.20.0) | Effect |
| --- | --- | --- | --- |
| `CI` env var | unset | `true` | colorette `isCI` → color on (with `GITHUB_ACTIONS`) |
| `GITHUB_ACTIONS` env var | unset | `true` | second conjunct of colorette `isCI` |
| verdaccio stdout target | file fd (`isatty=false`) | file fd (`isatty=false`) | identical, so `isCompatibleTerminal` is false on **both** — color on the runner comes ONLY from `isCI` |
| colorette colorization of log | **OFF** (plain `http <--`) | **ON** (`http <esc><--`) | substring counters break on runner, work on dev box |
| npm | 11.19.1 | 11.19.0 | same major/minor — irrelevant to the bug (H1) |
| verdaccio | 6.10.2 (pinned devDep) | 6.10.2 (npm ci, same lock) | identical version |
| registry bind | `127.0.0.1:<eph>` | `127.0.0.1:<eph>` | identical, explicit IPv4 (H2) |

## Local reproduction (dispatch-free validation)

`CI=1 GITHUB_ACTIONS=1 node --import ./tools/register-ts.mjs --test test/push.registries.test.ts test/push.integration.test.ts`
- **before fix:** AC1, AC3, I1 fail (the exact runner signature) — this is a faithful local
  reproduction of the runner asymmetry.
- **after fix:** `# tests 13 / # pass 13 / # fail 0` — all three green with the CI vars set.
This is why the fix is trustworthy independent of the runner: the bug and the fix both
reproduce deterministically on the dev box by toggling `CI`/`GITHUB_ACTIONS`.

## Residual / notes (NOT touched — out of scope)

- **`stage: real gem build` nondeterminism:** in forensics run `34614069251` it was ABSENT from
  actual failures (single-hunk diff `-stage`) i.e. gem build was byte-deterministic *that* run;
  in proof run `34616009447` it was present again. The test (test/channels.rubygems.test.ts:408)
  asserts `first.sha256 === second.sha256` (in-run determinism, no stored golden). It is
  flaky-green on the runner image. Left in the allowlist per the task mandate ("keep the gem
  duo"); it matched in the proof run so the gate was green. **W3.2 (golden normalization) owns
  making this deterministic/normalized** — flagged here, not fixed (different plan wave, and the
  exact-set gate is fail-closed so a green-in-one-run entry must stay listed until W3.2).
- The other four env reds (`channels golden`, `gem freshness`, `C5-1`, `C5-4`) are untouched;
  W3.2 (goldens) and border-push-channels (C5) own them. W3.3's *remaining* half (revert gate to
  sanctioned-pair / plain `npm test`) is explicitly deferred to those.

## Handoff

- Branch `forensics/w3-verdaccio`: `cc7bf25` (probe, later reverted) → `35ed244` (fix + allowlist
  prune + probe removal). NOT merged (human gate). Fix diff on the 3 real files also applied
  **uncommitted** to the main working tree for root verify+commit.
- Product code (`src/push/*`, `src/channels/npm.ts`) intentionally unchanged — the bug was
  never in border; `spawnInherit` stdio:inherit + G28 tokenless design are correct.
