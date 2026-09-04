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

## todo 3 (findings model + secret redactor) — 2026-09-04
- EXPORT CONTRACT — later todos must import these exact signatures:
  - `src/findings.ts`: `SEVERITIES` (readonly tuple INFO|LOW|MEDIUM|HIGH|CRITICAL), `type Severity`, `SEVERITY_ORDER: Readonly<Record<Severity, number>>`, `isBlocking(severity: Severity): boolean` (THE gate rule; CRITICAL/HIGH block, rest warn — import it, never re-code), `type Finding` (fields rule/severity/target/path?/line?/commit?/engine/message/valueDigest/snippet), `type Verdict = "PASS"|"FAIL"|"NO-OP"`, `type ReportCounts` (per-severity + total/blocking/warnings), `type Report = {schemaVersion: 1, key, head, dirty, exposureSet, refSet, rulesHash, verdict, counts, findings, ts}`, `computeVerdict(findings): "PASS"|"FAIL"`, `countFindings(findings): ReportCounts`, `validateFinding(unknown): Finding` (throws InvalidFindingError), `InvalidFindingError`.
  - `src/redact.ts`: `redact(value: string): {valueDigest, snippet}` (ALL adapters MUST route every matched value through redact() at ingest — G23 invariant, raw bytes never persist/print), `class TextSanitizer` with `register(valueDigest: string, rawValue: string): void` + `sanitize(text: string): string` (registry lives in memory only, never persisted), `sanitizeUrl(urlText: string): string` (strip userinfo + query params whose name matches /token|auth|key|secret|password|passwd/i; unparseable input -> '[invalid-url-redacted]' fail-closed), `computeRulesHash({bundledRulePaths, configDigest, engineVersions, promptTemplatePaths}): Promise<string>` (throws `MissingRulesInputError` on missing file) + `type RulesHashInput`.
- '[REDACTED:<sha8>]' token format (todo 18 bundle-masking contract): exactly `[REDACTED:` + first 8 hex chars of the value's sha256 + `]`. TextSanitizer sanitize() is idempotent to a fixpoint (bounded passes) so a registered value that itself looks like a token is scrubbed exactly once.
- LENGTH METRIC DECISION: redact() measures string length in CODE POINTS (`[...value].length`), not UTF-16 units or bytes. Rationale: the ≤12 rule is about what a human can read/retype from the snippet; a 7-code-point CJK secret (21 UTF-8 bytes) must still be fully masked. first4/last4 are code-point based too (never splits a surrogate pair). Documented in redact() docstring + tests.
- TRAP: `err instanceof NodeJS.ErrnoException` is a TYPE-ONLY global (from @types/node) — at runtime under esbuild transpile it evaluates `NodeJS` as a value and throws ReferenceError. Check ENOENT structurally: `typeof err === "object" && err !== null && (err as {code?: unknown}).code === "ENOENT"`.
- erasableSyntaxOnly: no TS enums — Severity is a string-literal union + SEVERITY_ORDER record for ordinals.
- URL normalization note: sanitizeUrl returns WHATWG-serialized output (host-only URL gains trailing '/'); query params keep original order minus stripped ones.

## todo 2 (border.yaml schema + loader + target inference) — 2026-09-04
- `yaml@2.9.0` exact pin (npm view latest at task time); only runtime dep added. `yaml` 2.9 does NOT resolve `<<` merge keys by default (merge:false family) — border treats `<<` as an ordinary unknown key => strict-schema rejects it BY NAME, so merge keys are not a schema escape hatch. Deliberate: do not enable `merge:true`.
- zod 4.5.4 API notes: `.strict()` still chainable; unknown-key issues are `code:"unrecognized_keys"` with `issues[].keys: PropertyKey[]` and message `Unrecognized key: "x"` — issue ORDER is innermost-first, so a config with both a nested and a top-level unknown key reports the nested one first; error mapper takes issues[0] and names that key. Missing fields surface as `invalid_type` at full dotted path (`rules.authors.emails`) — path-joined message satisfies the "name the field" AC without custom wording.
- yaml 2.9 error line info lives on `YAMLParseError.linePos[0].{line,col}` — the round-2-plan assumption "ParseError has .line/.pos" is STALE: `.line`/`.column` are undefined at runtime, `pos` is [start,end] offsets. ConfigError.line/column sourced from linePos.
- overlay deep-merge approach: merge at RAW parsed-doc level (plain objects recurse; arrays & scalars REPLACE wholesale), validate merged doc once with the same strict schema. Partial overlays legal; unknown keys in either layer still named. Overlay search order: dirname(discovered base) > cwd > git toplevel, first `.border/config.local.yaml` found wins.
- loader decision: top-level `allow`/`engines` omitted-with-defaults (plan-specified defaults imply omission); `rules` required. NO-OP fires for both "no config + no remotes" AND "config declares zero targets" (todo 19 dogfood depends on remotes:[] legality). `${VAR}` expansion runs AFTER validation on url/registry/repository only; unset var = hard missing-env error (fail-closed, never silent-empty).
- concurrent todo-3 integration: `import { sanitizeUrl } from "./redact.ts"` resolved as soon as 73ae8e2 landed — exposureSet asserts 'https://user:tok@h/r.git' enters as 'https://h/r.git'. Reusable gates under concurrent tsc: scoped `node --import ./tools/register-ts.mjs --test test/config.test.ts` + full `tsc --noEmit` partitioned by file ownership (at task end the WHOLE repo typechecks: 0 errors).
- LOC honesty: src/config.ts measured 340 pure lines (>250 ceiling). Kept unsplit because the task hard-mandates EXACTLY src/config.ts + test/config.test.ts as product files; if a later todo grows it, split schema/ from load/ first.
consumers see scp-form output '<host>/<path>' (no scheme) — exposureSet entries differ per remote (fix: sanitizeUrl SCP_STYLE_RE branch before WHATWG fallback, src/redact.ts)
- 2026-09-04 todo4 gitleaks adapter: FIXTURE GIT LEAK INCIDENT — a fixture helper
  that ran `git add -A` before gitInit() committed planted secrets into border's
  OWN repo (commits on top of 32987c4). Recovery: reset --mixed + reflog expire
  --all + gc --prune=now, verified blob unreachable. Prevention shipped in
  test/helpers/fixtures.ts: git() throws unless <cwd>/.git exists (gitInit
  exempts only `init`) and sets GIT_CEILING_DIRECTORIES=dirname(cwd) so discovery
  can never walk up into the enclosing repo. ALWAYS gitInit before any git helper.
- todo4 spike lesson: gitleaks archive dispatch is EXTENSION-based, not
  magic-based — .tgz silently missed by `dir --max-archive-depth 2` while
  .tar.gz/.zip/.tar/.gz/.tar.bz2 are native (⇒ extract.ts shim exists solely for
  .tgz = npm pack). Byte-identical duplicate secrets across archives in ONE scan
  are DEDUPED to a single finding — fixtures must plant fresh random pairs
  (randAwsPair()), never reused literals.
- todo4 literal-shape lesson: not every "AKIA…" string is detected — the vendored
  aws regex is AKIA[A-Z2-7]{16} (I/T/0/1 excluded) and generic-api-key needs real
  entropy (a 40-char zero-padded "secret" scored 0). Fixed evidence literals must
  be tuned against the real binary before being baked into AC proofs.
- Node quirk: rmSync(dir,{recursive:false}) throws EISDIR on non-empty dirs —
  use rmdirSync for the "prune tmp root only if empty" pattern, swallow ENOTEMPTY.

## todo 5 (secretlint adapter) — 2026-09-04
- secretlint 13.0.5 EXACT pins (@secretlint/core + preset-recommend/no-homedir/
  pattern/no-dotenv deps, secretlint CLI devDep). @secretlint/preset is a 404 —
  the preset package is @secretlint/secretlint-rule-preset-recommend. In-process
  API HOLDS (spike tools/spike-secretlint.mjs kept as contract evidence):
  lintSource({source:{content,filePath,contentType},options:{config,locale}}),
  rule packages export NAMED `creator`.
- TRAP (fail-open class): preset-recommend gates AKIA… scanning behind
  options.enableIDScanRule which DEFAULTS FALSE — without the preset-entry
  override {id:"@secretlint/secretlint-rule-aws",options:{enableIDScanRule:true}}
  AWS keys silently pass. Same category as gitleaks rules=[] — pin an AC.
- TRAP: upstream 13.0.5 AWSSecretAccessKey range is [fullMatchStart,
  +groupLength] — range-slicing returns the label prefix, not the credential.
  Adapter trusts slice only if the en-message echoes it, else recovers the
  ": <cred>" tail gated on source-presence (recoverRawValue). valueDigest/sanitizer
  keys on the TRUE value (AC8/AC11).
- ruleId asymmetry: core reports the CONFIG id; CLI loader reports the rule's
  META/package id. Pattern rule must be matched under BOTH ("border-pattern"
  and "@secretlint/secretlint-rule-pattern") for transport-transparent mode
  switching (AC12).
- CLI fallback flags are load-bearing: --no-gitignore (v13 respects it by
  DEFAULT — spec forbids), --no-maskSecrets (masks by default → digests the
  mask), --secretlintrcJSON inline (never write .secretlintrc.json into the
  target), --no-glob + explicit abs paths, chunks of 200 for ARG_MAX.
- @textlint/regexp-string-matcher: slash-wrapped "/src/flags" strings compile as
  regex SOURCE (flags merged with "ug"), bare strings auto-escape. border
  slash-wraps everything: config literals escapeRegex'd first (a(b proven
  literal-safe AC5), built-in defaults carry raw regex sources. Empty pattern
  string => adapter fails closed with the rule name BEFORE engine throw (AC6).
- Pattern rule reports carry no structural name (message "found matching
  <name>: <cred>") — Finding.rule resolved by re-matching own compiled regexes
  against the range.
- LOC honesty: src/engines/secretlint.ts 347 pure lines > 250 ceiling — kept
  single-file per todo-2 precedent (task mandates the exact artifact; adapter +
  pattern-gen + fingerprint are one transport abstraction; split candidate =
  patterns/fingerprint if todo 6 grows it).

## todo 7 (CLI surface + exit-code contract) findings
- esbuild ESM bundle + CJS dep graph: the moment src/config.ts (yaml) entered the
  bundle graph, `node dist/index.js` died with `Dynamic require of "process" is not
  supported` (esbuild's __require shim). Fix lives in package.json build script:
  `--banner:js='import{createRequire as __borderRequire}from"node:module";const
  require=__borderRequire(import.meta.url);'`. If anything touches the build script,
  re-run `node dist/index.js --help` or the bin ships dead.
- border.yaml zod schema REQUIRES the full `rules` block (authors.emails/names,
  hosts, ips, pathPatterns); only allow/engines carry defaults. Minimal test
  fixtures must emit all four or loadConfig fails `invalid config at 'rules'`.
- YAML gotcha: a block sequence under `remotes:` must be indented deeper than the
  key, and an empty list belongs inline (`remotes: []`) — a dangling ` []` line
  after `remotes:` is a parse error.
- Registry seam supports cross-PROCESS test injection: a tiny .mjs wrapper run
  under `node --import ./tools/register-ts.mjs` imports src/cli.ts, calls
  setHandler("check", verdict-spy), then `run(["push"])` — full real parseArgs +
  dispatch + dry-run layer with only the gate faked. This is how todo 7 proves
  m-R5-a (dry-run exits with the gate's verdict) before todo 10's engines exist.
- sanitizeUrl() replaces UNPARSEABLE input with `[invalid-url-redacted]` wholesale —
  never run it on plain filesystem remote paths. push.ts exports displayRemote():
  scheme-URL / scp-form ⇒ sanitizeUrl, plain path ⇒ verbatim.
- translateError sanitization for free-form messages: collapse `\s+` to one space,
  cap 512, and regex-scrub only URL-shaped substrings
  `(?:\w+:\/\/\S+|user@host:\S+)` through sanitizeUrl — whole-message sanitizing
  would placeholder ordinary prose.
- node:test `before()` takes the fn (or options object), NOT (name, fn) — the
  string-first form is a typecheck failure.
- LOC honesty: test/cli.test.ts 357 pure lines stays above the 250 marker —
  consistent with repo test culture (config.test.ts 420); src files all ≤161.
  cli.test.ts = unit+seam, cli.dist.test.ts = child-process AC2.

## todo 10 (2026-09-04) — check orchestration
- refSet basis DEVIATION (documented in src/check/context.ts header): git's
  `rev-list --branches=<name>` is a PREFIX-GLOB (empirically can return EMPTY for an
  exact refname), so border enumerates FULL REFNAMES (current branch symbolic-ref +
  every refs/tags/*) and feeds them to gitleaks `--log-opts` as positive revs.
  Detached HEAD pushes tags only ⇒ branch entry drops; history falls back to headSha.
- gitleaks leg path shapes (probed live): history leg ⇒ REPO-RELATIVE, dir/tree leg ⇒
  ABSOLUTE, archive reattribution ⇒ `<abs>!<inner>`. Exclusions filter normalises via
  toRepoRelative + segment-wise `.border` match — never prefix-match one shape only.
- gitleaks v8.30.1 DOES have `gitleaks stdin` (reads text on stdin, exit 0/1, JSON on
  stdout with File:'' — attribution must come from the caller: we set path=<tag refname>,
  commit=<dereferenced sha>). support.ts spawnEngine CANNOT pipe stdin (no input option)
  ⇒ tagScan.ts spawns its own spawnSync loop mirroring the 0/1-only exit discipline.
- G23 fixture trap (bit once): border's own built-in secretlint path patterns
  (/home/[a-z]+/) fire on the fixture border.yaml itself if the remote URL is an
  absolute /home/... file:// path ⇒ committed config self-flags. Test remotes use
  scp-form `origin.example:widgets.git` (sanitizeUrl: user@ REQUIRED for scp branch —
  a bare `host:path` without user falls through WHATWG and passes through verbatim).
- .border/.gitignore `*` SELF-IGNORES the whole state dir ⇒ a planted .border secret
  does NOT make `git status --porcelain=v1` dirty; dirty-flag tests need non-.border dirt.
- PIPELINE DESIGN (all fail-closed): probe degraded skips ONLY the broken engine's legs
  but detectHostileConfig runs regardless (pure git plumbing, guards gitleaks
  self-silencing); native aiArtifacts/identity always run so a degraded run still
  reports what CAN be seen; guard fires BEFORE any engine leg (B-R5-1).
- Lock liveness: process.kill(pid,0) EPERM = ALIVE (other uid), ESRCH = dead. Recovery
  loop is 2-attempt: unlink stale ⇒ retry wx; second EEXIST ⇒ re-probe (the race winner
  is alive ⇒ refuse). releaseLock only unlinks while our pid is still the holder.
- configDigest policy: sha256 of raw border.yaml bytes when the source path exists;
  canonical stableStringify(effective config) for the git-remote inferred fallback
  (no file). Overlay-merged env expansion already baked into `config` — base-file bytes
  would under-fingerprint IF overlays exist (flagged risk; todo 14 can revisit).
- DIST BUNDLE GAP (surfaced, NOT todo-10's fix): esbuild bundle resolves
  GITLEAKS_VENDORED_CONFIG relative to dist/ ⇒ `<parent>/harness/assets/...` (outside
  the package; package.json files:["dist"] doesn't ship assets/ at all). The CLI fails
  CLOSED (exit 2, one clear line) — cli.dist.test.ts now pins the fail-closed path.
  Release packaging (todo 20/21) must ship assets/ + resolve paths from the package root.
- CLI test culture: todo 7's "check stub" expectations (loop entry + push-unwired 2)
  were the canary that the stub was replaced — reworked, cli.ts itself untouched.

## todo-12 (PyPI pipeline) — 2026-09-04
- twine check renders via rich: with narrow/no TTY it WRAPS long abs paths mid-token, so the
  `Checking <path>: FAILED` line can be split across lines. Pass env COLUMNS=100000 NO_COLOR=1
  when parsing twine output.
- cli.dist.test.ts rebuilds dist from the LIVE tree (test/cli.dist.test.ts:24 `npm run build`).
  With 3 concurrent workers, a sibling's uncommitted check.ts wiring flips the pinned fail-closed
  message => shared-tree `npm test` redness is NOT yours. Authoritative check: `git worktree add
  <tmp> <base>` + copy ONLY your files + node_modules symlink + run suite there (194/194 here).
- engines.gitleaks.test.ts AC2b (.tgz native-archive dir leg) flakes under 3x parallel suite
  load; green 11/11 standalone. Attribute before touching anything.
- gitleaks dir-mode does NOT honor a PARENT .gitignore: secrets inside <repo>/.border/tmp/ ARE
  found even when .border is ignored by the repo. The false-green trap is purely
  filterBorderStateFindings dropping findings whose path contains a `.border` segment — scope
  finding paths to the extraction root (strip wrapper, rewrite abs->rel).
- sdist is .gitignore-blind two ways (G17): setuptools package-walk ships untracked package-dir
  .py AND MANIFEST.in-declared untracked files. Wheel bytes are not bit-stable across runs
  (zip mtimes) — build-once idempotence must be asserted on per-run name-sets + sha-vs-file
  self-consistency, never byte-equality across runs.
- `python3 -m build --no-isolation` is mandatory for offline + no-venv (plan Must-NOT);
  binaryCandidates' ~/.local/bin fallback means PATH-stub tests must stub HOME too.

## task-11 npm artifact pipeline (2026-09-04) — gitleaks AWS fixture alphabet landmine
- VENDORED aws-access-token regex is `[A-Z2-7]{16}` (BASE32 window), NOT [A-Z0-9] — digits 0/1/8/9 make
  a planted key regex-immune (~83% of naive keys). randAwsPair() drew from A-Z0-9 => every aws-shaped
  fixture had ~5/6 chance of NOT firing the AWS rule; suites passed only because `aws_access_key_id = X`
  line-shape also matches broader rules. FIXED in test/helpers/fixtures.ts (AWS_KEY_ALPHABET=base32).
  Task-brief text repeating "[A-Z0-9]" is stale — trust assets/gitleaks-defaults-v8.30.1.toml:208.
- LESSON: assert `f.rule === "aws-access-token"`, never `f.engine === "gitleaks"` — engine-level
  assertions mask rule-level false greens (exactly the misleading-success class todo 11 demands e2e proof of).
- Throwaway probe that found this: nested secret (key inside secret.js inside dist/bundle.tgz inside the
  pack) — promoted to permanent suite test (package/dist/bundle.tgz!secret.js reattribution survives
  filterBorderStateFindings because stage re-scopes to artifact-root-relative). Probe bugs en route:
  `b % 36` against a 32-char alphabet => 'undefined' chars in key; tree-snapshot taken before
  ensureStateDir legitimately creates .border.
- npm pack facts: `npm pack <abs-repo> --ignore-scripts --json --pack-destination <dir>` works from any
  cwd (spawnEngine has no cwd opt); deterministic bytes across runs (todo 17 re-hash equality holds);
  report files[].path is tar-root-relative, shasum=sha1/size cross-checked against on-disk bytes;
  --ignore-scripts means target-repo prepack/prepare NEVER execute during border's pack (verified by
  absence of a PWNED marker file).
- Node>=22 spawnSync timeout quirk: killed child gets error=ETIMEDOUT with status=null — support.ts now
  maps that to EngineRunError instead of leaking an untyped Error (hung-npm QA).
- publint 0.3.24 invoked as devDependency binary node_modules/.bin/publint <tarball> --level error
  (NO npx --yes — no network, no prompt); exit 1 => HIGH publint-fail, missing binary => EngineMissingError
  (fails closed, never silent pass).

## todo 14 (ledger) learnings
- `run()` from src/cli.ts takes (argv, out, err, {cwd, env}) — integration tests can drive the whole
  CLI in-process from a fixture cwd, no child spawn needed; env overrides ({...process.env, PATH: shim})
  make engineVersion-stub ACs trivial (shim: intercept --version, exec the real binary for all legs —
  scan speed stays REAL, only the fingerprint moves).
- git SHA fields need their own width regex: parser demanded HEX64 for head and every fixture record
  died as "unreadable" — tests caught the production bug (40 vs 64 hex). Corrupt-tolerance tests must
  distinguish fixture mistakes from real corruption by asserting WARNING counts exactly.
- Order of operations at a new pre-pipeline seam matters: anything consulted BEFORE executeCheck
  inherits its failure modes out of context (see decisions.md best-effort rule). Run the FULL suite
  after wiring, not just your own tests — the dist test that caught it isn't even a ledger test.
- /usr/bin/time under the TS loader measures ~1.0s of pure bootstrap (--help baseline) — quote fast-path
  numbers in-process or subtract the baseline, never claim <1s against raw wall time of a loader run.
- Shared-worktree hazards: `test/tmp/` fixtures with planted literals MUST live under border's own
  gitignored tmp (grep /tmp for the literal returns a SIBLING's debug dirs — not your receipt, don't
  chase it); sibling workers commit concurrently — rebase expectations onto `git log` right before
  staging, and stage ONLY your files (git add <list>, never -A).
- retention pruning is dir-slice math when dir names embed a sanitized ISO ts (lexicographic ==
  chronological): pruneRunDirs = filter `${key8}-` prefix, sort, drop head. Ledger lines never pruned.

## todo 14 fix (G33 repack parity)
- Every pack of the target repo inside border must pass `--ignore-scripts` (packOnce in
  src/artifacts/npmPack.ts and packNpmArtifacts in src/ledger/freshness.ts — two pack call-sites,
  one invariant). Beyond the supply-chain angle, flag divergence is a CORRECTNESS bug: a
  script-bearing repo's certified pack (script-free) vs ledger repack (with scripts) would never
  digest-match ⇒ permanent false re-checks, SKIP silently dead for exactly those repos.
- Regression-fixture placement gotcha proven live: an absolute in-repo marker path written into
  package.json trips border's own /home/[a-z]+/ path-pattern rule (run1 FAILs the gate — wrong
  red); an in-repo marker file dirties porcelain and masks skip assertions. Marker belongs in
  /tmp with a pid+ts-unique name, rm'd in finally.

## todo 18 — llm bundle contract (worker log, 2026-09-04)
- Masking raw secrets in patch text cannot reuse ledger digests (the ledger is pre-redaction
  by design). Solution: llm-request feeds the patches themselves through the deterministic
  detector (scanTree over a throwaway .border/llm-mask-* sandbox; chunks ≤ 8MiB because
  gitleaks silently skips files > 10MiB) so TextSanitizer registers the SAME raws and
  sanitize() emits the contract token [REDACTED:<valueDigest[:8]>]. The token then provably
  matches the deterministic finding's valueDigest — masking and reporting agree by
  construction. If the detector cannot run: fail closed, never ship unmasked patches.
- fixture gotchas that cost 3 red rounds: absolute /home/... remote URLs trip secretlint
  HOMEDIR/path-pattern CRITICALs (use relative ../remote.git — sanitizes identically on both
  sides of exposureSet matching); non-allowlisted committer trips identity rule (fixtures need
  rules.authors); ANY file written inside the clone changes porcelainDigest ⇒ findings.json /
  bundle-adjacent scratch files belong OUTSIDE the worktree (now in SKILL.md).
- runGitChecked's 1MiB maxBuffer ENOBUFS-fails on big diffs; llm code owns its gitOut
  (64MiB). spawnSync default buffers are a trap for anything diff-shaped.
- {llm:true} ledger records already can't satisfy plain-check skips (lookupSkipRecord
  record.llm===q.llm); the two-directional no-riding test locks it. ingest writes through
  recordCheckRun so there is exactly one persistence seam.
- agent findings have no raw secret: valueDigest = sha256(stableStringify(finding core)) is
  the honest stand-in that satisfies C1's 64-hex schema without inventing a "secret".

## todo 13 (registry pre-flight) — 2026-09-04
- spawnSync + in-process node:http stub = guaranteed deadlock (event loop blocked, server
  never answers). Production probes AND debug one-offs must use async spawn. Symptom:
  silent 60-240s hangs, no error.
- Background stubs do NOT survive across bash tool calls (and add a self-exit timer);
  any live-CLI demo must start the stub inside the SAME call as the CLI run.
- npm view <name> <field1> <field2> --json on fields a packument lacks ⇒ exit 0 + EMPTY
  stdout. The plan's "empty stdout must never read as absent" trap is real (confirmed v11.19.1).
- Multi-signal OR matchers need a per-branch test: every self-owner unit test passed via
  the email branch, so the repo-URL branch shipped broken (scheme regex missing the colon
  before //: /^[a-z][a-z0-9+.-]*\/\// never strips 'git+https://'). The mandated LIVE CLI
  run caught it. Lesson: keep at least one live end-to-end phase per feature, not only units.
- Full-suite baseline drifted 222→258 mid-task (concurrent sibling workers landing llm
  commits); "green" must be asserted as fail-0 on the current tree, twice, not against a
  memorized count.

## [2026-09-04T13:35:00+08:00] Task: 15 — push state machine
- `git ls-remote` emits a legitimate `<sha>\tHEAD` line; a fail-closed parser must
  whitelist-and-skip it (never enter the ref map). Learned the hard way: the first
  bare-repo run red on exactly this line.
- runGitChecked's error text embeds the raw remote url (it joins argv). Wrapping
  ls-remote failures means DROPPING the cause string and re-emitting with
  sanitizeUrl only — otherwise a credential-bearing url leaks into the exit-2 line.
- configDigest gotcha for todo 17: derivePushState must receive the SAME
  computeConfigDigest(load) value the check run used, or fp.key differs and every
  gate reads UNCHECKED. Pass cfg+configDigest straight from the check-flow caller.
- Owner==self PUSHED clause = lost-ledger recovery; the squatter defense is the
  FOREIGN_OWNER_RULE finding (todo-13 emits it for both foreign AND ambiguous
  zero-signal owners, so "no foreign finding" is a real positive proof, not absence
  of evidence).
- Resume set = PENDING only, not "everything non-PUSHED": BLOCKED-unchecked and
  BLOCKED-squatter are non-PUSHED but pushing them is the exact failure the gate
  exists to stop. Documented in code + evidence matrix.

## [2026-09-04T14:33:49+08:00] Task: 19
>> allow post-filter (G14) at check.ts pipeline tail before verdict/counts; allowHits on Report (optional, schemaVersion 1); recordCheckRun persists md beside canonical json.
>> configDigest = sha256(stableStringify(full config)) already covers allow[] — key rotation e9f299a9->06eb5c54 proved it live; no digest hole.
>> blanket ban implemented as rejecting ONLY unscoped {rule:'*',match:'*'} pairs; wildcard pairs require a repo-relative file glob — otherwise the 3 sanctioned categories are inexpressible (DECISIONS #1 in evidence).
>> explicit-empty border.yaml no longer collapses to no-op: LoadResult carries explicit:{config,source} only when the file was discovered; runCheck narrows it to loaded. Undiscovered+no-remotes stays loud no-op exit 0.
>> dist asset resolution: src/assets.ts candidate walk (here/assets -> ../assets -> ../../assets, src path first => rulesHash stable) + tools/copy-assets.mjs in build; banner untouched.
>> gitleaks tree leg emits ABSOLUTE paths — allow file-scoping normalizes via toRepoRelative + strips '<archive>!' prefix; pin preserved.
>> cli/exit.ts EACCES label widened to 'permission denied' (fs writes now share the errno funnel).
>> dogfood: 497 suppressed across 7 entries (a .omo/** 228, b test/** 46 + self-corpus 158+27+25+12+1 incl c abs-path 27); exit 0; zero raw fixture literals in .border/.

## [2026-09-04T22:10:48+08:00] Task: F3-fix status
>> push records key git legs as `git:${name ?? sanitizeUrl(url)}` (pushstate.ts:226) — any consumer matching effectiveTargets kinds MUST re-derive ids (push.ts gitLegs + status gitRemoteIds) or stay on bare-fallback.

## [2026-09-04T23:05:00+08:00] Task: F2-polish push timeout + pretest
>> Node 22 spawnSync budget kill = {status:null, signal:"SIGTERM", error:ETIMEDOUT} — BOTH set; a genuine spawn failure keeps signal:null. Check `status===null && signal!==null` FIRST, else the timeout is mislabeled "git could not start (spawnSync git ETIMEDOUT)" (bit the first fix iteration; the /timed out/i assertion caught it).
>> GNU sleep rejects non-numeric argv (`sleep 10 marker` exits instantly) — for lingering-process proof use stub `echo $$ > pidfile; exec sleep 10`: exec keeps the PID, so the pidfile IS the sleeper and kill(pid,0) proves the kill. pgrep -f marker plans die on this.
>> executePush failure => caller (commands/push.ts) prints PARTIAL + EXIT_BLOCKED and cannot reach recordPushSuccess — fail-closed-on-timeout needs ZERO caller changes; put the ls-remote verify advice in the failure string.
>> NEVER `pkill -f register-ts` (or any broad -f pattern) to clean own orphans: it matched a sibling worker's in-flight llm.test.ts run and killed it. Record and kill own PIDs only; the lifecycle-proof `npm test | head` trick orphans the suite child — grab `pgrep -f` output, eyeball, kill listed PIDs.
>> npm runs "pretest" automatically before "test"; `node -e` is CJS even under "type":"module", so require('node:fs') works; rm+recreate test/tmp = contents swept, dir kept, missing/empty tolerated.

## [2026-09-04] Task: F3-followup unnamed-remote collision fix
>> RED reproduction of the double-push defect: two unnamed remotes w/ local-path urls (`/tmp/x/a.git` style) collapse through sanitizeUrl to ONE id `git:[invalid-url-redacted]` — pushstate.ts:227 built the id, push.ts gitLegs `.find(r => expr === t.target)` returned the FIRST match for both legs, so a.git got double-pushed, b.git never. Both ledger records carried identical target strings (record identity + resume broken). status.ts gitRemoteIds held a THIRD drift copy of the expression.
>> GOTCHA (exactOptionalPropertyTypes): zod's z.string().optional() infers `name?: string | undefined`; a helper param declared `{ readonly name?: string }` REJECTS that shape with TS2379 at every call site — the param type must be `{ readonly name?: string | undefined }`.
>> GOTCHA: `git:${` template-literal expressions cannot appear inside a compress-tool summary payload — the harness interpolates `${...}` and truncates the call. Paraphrase expressions as 'git:' + name-or-index instead.
>> GOTCHA (environment): the run-continuation daemon COMMITS concurrently (it landed d98087a fix(push): bounded timeout + 61cc84c test/tmp sweep mid-task). Re-check `git status` + `git log` before staging; stage explicit paths only. Full-suite flakes seen under parallel load (llm.test.ts 'prompt template edit' AssertionError, push.git.timeout tests ETIMEDOUT) were the daemon's in-flight uncommitted feature; once committed + test/tmp swept, full suite went 334/334.
>> Design that worked: per-remote push target id = `git:${remote.name ?? '#'+index}` in ONE shared helper (src/gitTargetId.ts). Safety: border.yaml feeds computeConfigDigest → fingerprint key, so any remote-set reorder/edit yields a new key; records are always consulted key-matched ⇒ index ids cannot be confused across configs. Named remotes keep `git:origin` — backward compatible with existing ledgers.
>> gitLegs must use a per-id Map (remotes.map((r,i)=>[id,i])) not `.find()` — Map.get is the only collision-free target→remote resolution.
