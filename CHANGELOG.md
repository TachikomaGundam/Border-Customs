# Changelog

Per-version history with the motivating incident for each release.
The README carries the current contract; this file carries the history.


### 0.8.6 (unreleased)

Push-path forensics from the Sibyl release wheel 2026-11-08. The owner's Sibyl `border.yaml`
carried the defect's own confession — an allowlist workaround annotated "Workaround for a
KNOWN border push-path defect (counts already-public objects as transmitted; ticket open)" —
while `.border/ledger.jsonl` held zero traces of the 08:48 refusal and the ~14:31 executor
death. Design: `docs/design/push-outcome-accounting-20261108.md`.

- FIX (wound 1, gate parity): the push identity gate now decides with the check face's
  single-source predicate `isBlocking` — INFO `identity-already-public` findings (offenders
  every configured remote already carries) no longer refuse a `push --yes` whose objects are
  all public, while first-time exposure keeps blocking exactly as before. The refusal reason
  names how many already-public findings were not counted. A PENDING leg whose scan is
  INFO-only is now pushable — closing the dry-run-PASS / --yes-REFUSE split on one key.
  `scanIdentity` on the push path also receives the run's env (seam parity with check).
- NEW (wound 2, outcome accounting): every `border push --yes` run that reaches push-state
  appends exactly one `t:"push-result"` verdict line — landed/blocked/partial/failed/noop —
  with target ids, branch, bounded url-scrubbed reason (url-shaped prose tokens sanitized at
  the mint; prose is never fed whole to `sanitizeUrl`, whose fail-closed placeholder is for
  unparseable URLs), and `gitExit` (null = killed/unconfirmed, INDETERMINATE). All exits mint:
  derivation failure (keyless), gate refusal, divergence, pre-flight refusal, mid-loop partial,
  unconfirmable success, landing-blocked-after-landing, registry-leg failure. DRY-RUN mints
  nothing; the pre-derivation no-targets NO-OP (no fingerprint key exists yet) keeps its
  documented silence. Older binaries read these lines with their existing loud per-line
  warning (roundtrip/landing precedent).
- NEW (wound 3, named pre-flight): `preflightPushRefs` checks `check-ref-format` shape, local
  resolve, and non-empty leg urls BEFORE any `git push` spawns; problems name the ref, the
  remote(s), and what is missing, and are ledged as blocked verdicts. DIVERGED lines now
  distinguish branch non-fast-forward from a moved tag and name the missing channel. A
  `--ref <refspec>` channel stays OUT of the frozen push surface pending an owner policy
  ruling (it would carry force-shaped operations through a gate whose doctrine is "border
  never force-pushes").
- FIX (wound 4, found during remediation): the no-targets NO-OP path certified "nothing to
  push" on a swallowed probe failure. `remoteTrackingDrift` now reports `probesOk`; a probe
  that cannot answer exits 2, named — only a working instrument certifies absence. The
  honest NO-OP (remote-less repo; not-a-repo, which cannot hold remote-tracking refs) keeps
  exit 0.
- FIX: `border push` dry-run now prints the detached-HEAD warning `--yes` already refused on,
  so the plan never shows a line `--yes` would refuse to run.
- TESTS: pushstate INFO-only repro (Sibyl shape: published offender + fresh tag, zero new
  objects) + mixed-rung counting; CLI repro lands the Sibyl wheel; dry-run ledger silence;
  blocked/noop/partial(+gitExit)/moved-tag rows; preflight naming; probesOk + named exit 2;
  push-result schema mint gates, roundtrip, prose-vs-url scrubbing, corrupt-line tolerance.


### 0.8.5 (2026-11-06)

Dual-face remediation wave, ruled by the sibyl chamber `sibyl-20261105T082510Z-5f96` after the
owner asked "why are two border versions installed and which one is actually live?" (two silent
faces found: a cron landing on the mutable worktree; the PATH fallback handing argv to an older
published CLI, because the identity handshake verifies identity but never version).

- NEW: `border opencode inspect` seventh aspect `global-resolution` — names every CLI face
  (BORDER_BIN / packaged dist / PATH) with its `--version` stamp and judges the ACTIVE face
  against the registry's latest on the informational WARN rung (lag under pinned consumption is
  a legitimate steady state; WARN never moves the aggregate exit or any purge trigger;
  registry-unreachable stays named UNREACHABLE; `BORDER_INSPECT_OFFLINE=1` reports "skipped",
  never fresh).
- NEW: the plugin tool result always carries `face: <resolved candidate> version=<stamp>`;
  `BORDER_REQUIRE_PKG_VERSION=1` gates the call to the package's own version (mismatch ⇒
  cannot-answer, zero argv delivered).
- NEW: drift-watch rc 3 (GLOBAL-WARN / GLOBAL-UNREACHABLE) — warn-only, structurally invisible
  to the cron purge guard — plus `--heartbeat <path>` appending one ISO/verdict/rc/bin line
  per run.
- FIX: `border status` prints its own `engine:` identity line (the usage table promised engine
  versions since 0.8.0 without printing them).
- FIX (owner escalation 2026-11-08, blocking-class factual misreport): identity exposure claims
  are now computed against LIVE `git ls-remote` endpoints, never the full local walk or stale
  remote-tracking refs. Offenders already public on a remote ride the new INFO
  `identity-already-public` rung (no remediation advice — rewriting published history is pure
  damage); only objects leaving the machine for the FIRST time keep the CRITICAL rung with its
  filter-repo advice. Offenders + unreachable remote THROWS (exit 2): the exposure class is
  never guessed. First-push and no-remote semantics unchanged.
- FIX (owner escalation 2026-11-08, scope): tree-facet findings on .gitignore'd AND untracked
  paths demote to INFO with a named note — `git add` honours .gitignore, so those bytes can
  never reach a push, and blocking on them trains users to mute the gate (Sibyl's own tool
  evidence tree produced 26 such CRITICALs). Committed blobs, tip-tree bytes and artifact
  targets are untouched; tracked-but-ignored stays fully blocking; the allow-list is unchanged.
- DOC: `docs/release/v0.8.4.md` named doc-only statement with a third-party byte-diff recipe;
  README contract sync + owner-approved pinned-consumption clarification (2026-11-06).


### 0.8.4 (2026-11-04)

Same code as 0.8.3; documentation and disclosure updates only (history scrub —
see SECURITY.md rows 1/1a/1b). 0.8.2/0.8.3 deprecated on the registry pointing
here. Version rotation via tools/version-sync (single-source).

### 0.8.3 (2026-11-02)
- Fix: `exfil-cred-location` is now syntax-aware in JS/TS sources (handoff b61b42a) —
  `.env` tokens count only inside string-literal spans (TypeScript compiler API, shipped
  as a runtime dependency, bundle stays external-pinned); member accesses (`opts.env`),
  short receivers and comment text are no longer reported. Markdown/text keep the
  bare-mention behavior; every other rule is untouched. All tree faces (check, history,
  tip lens) share the guard; parse failure ⇒ old behavior + one stderr note, exit codes
  unchanged. Rules fingerprint rotated (cached PASSes re-verify once).

### 0.8.2 (2026-11-01)
- Production dependency graph now measures ZERO advisories (`npm audit --omit=dev`): the
  pattern rule is vendored (`src/engines/borderPatternRule.ts`, MIT attribution; drops the
  unpatchable braces/micromatch + fast-uri chain) and `tool` — an identity function — is
  vendored in `plugin/border.ts`, moving `@opencode-ai/plugin` (and its effect-beta → toml
  chain) to devDependencies; live-host probe tests keep the activation proof. The CI audit
  gate tightens from critical to HIGH so this cannot rot.
- `border sandbox init|pin|status|unpin` — the opt-in pin helper from the Q1 ruling
  (machine store only, 0600 atomic writes, §3 self-verification with rollback of its own
  writes; deliberately absent from the plugin's agent-reachable command set).
- Security tier for execution-deciding keys (`src/tier.ts`, sibyl §3⁗/§3⁖/§3‡):
  `sandboxImage`/`allowBuilds` honor only from fd-chain-qualified machine-store or out-of-repo
  `--config` sources; repo declarations, lax-mode files, and hijacked `XDG_CONFIG_HOME` are
  named refusals (`sandbox-config-shadowed`/`sandbox-config-unqualified`); the
  `BORDER_ALLOW_BUILDS` environment channel is REMOVED (never released, so no migration);
  passwd-derived canonical store root — `$HOME` spoofing cannot move it.
- Sandboxed artifact builds: optional `targets.<ch>.sandboxImage` (digest-pinned, tags fail
  closed at load) runs consented npm/pypi/crates/rubygems builds — and freshness re-packs —
  inside `docker run` with `--network none` proved by an in-container DNS+TCP probe, a
  read-only repo mount, tmpfs build, `--cap-drop ALL`, scrubbed env, and the ledger record
  bound to the exact image digest (a rotated image invalidates cached PASS). Missing docker
  with an image configured is a named exit 2, never a host fallback. New `test/sandbox.test.ts`
  pins the docker argv contract token by token.
- Hardened the npm pack-phase guard (sibyl must_fix): ALL package.json manifests in the tree
  are scanned, not just the root (a workspaces child's `prepare` is now refused on npm < 11),
  and unreadable manifests or a walk-cap hit count as a hook — unknown is never assumed safe.
- Machine-side config (HR decoupling handoff 2026-10-23): resolution chain is now
  `--config > $BORDER_CONFIG (fail-closed) > machine store (XDG/border/machines, keyed by
  canonical remote URL) > ./border.yaml > git-remote inference`, so gate config and waiver
  lists live on the checking machine and never need to be committed into a product repo.
  Allow entries gained `values` (fixture-set waivers that never cover a new value), `until`
  (UTC sunset, expired entries echoed never silently honored), `\!` archive-member escaping,
  and `rules.aliases` (rule renames no longer strand waivers). Border state was already
  porcelain-invisible (`.border/.gitignore` self-ignore; verified 2026-10-23).
- Provenance: every check and push record carries `engineBuild`
  (`<version>+<commit>[.dirty]`, the string `border --version` prints), so a verdict names
  the exact border build that produced it. Motivated by a machine where every gate ran off
  an unpinned worktree bundle and no record said so; worktree use is now visible on the
  record face (see "Pinned consumption"). Bundles are stamped by `tools/build.mjs`.
- Security (breaking): artifact build stages now require operator consent. A hostile clone can
  ship its own border.yaml declaring pypi/rubygems targets, and `border check` built them —
  PEP 517 backends and gemspecs ARE code (`python3 -m build --no-isolation` and `gem build`
  markers reproduced 2026-10-23). Default runs are now scan-only (zero build spawns, pinned by
  `test/build.execMarkers.test.ts`); consent comes only from outside the audited tree:
  `--allow-builds` or `BORDER_ALLOW_BUILDS=1`. A scan-only PASS records no artifact digests and
  therefore can never back a registry publish; `border scan` of third-party artifacts requires
  the same consent (named exit 2 without it).
- Security: refuse npm < 11 packages that declare `prepack`/`prepare`/`postpack` before
  spawning `npm pack`. npm 10 executes `prepare` even with `--ignore-scripts` (reproduced on
  10.9.7; npm 11.19.1 is clean), so the old defense could execute code from the audited repo.
  The probe also runs before freshness re-packs. New regression tests pin the refusal and the
  never-fires hook marker.
- Fix: the Windows drive-letter path pattern no longer fires on JS escapes in prose
  (`raw-repoPath:\n`); the UNC pattern no longer spans newlines.
- Docs: the `--json` findings schema is stated explicitly (`path`, no `file` alias);
  npm-target prerequisites now name the npm 11 boundary.

### 0.8.1 (2026-10-06)
- Maintenance release: certificate-chain rebuild off the scrubbed lineage (INCIDENT-20261006
  identity-exposure cleanup). No functional change vs 0.8.0; 0.8.0's tarball is byte-intact but
  its OIDC provenance pin moved with the history rewrite, so a fresh tag + publish restores a
  verifiable chain. Rotation: package.json + lock roots + plugin marker + scan UA + README pins +
  this entry.

### 0.8.0 (2026-09-30)
- Add: **`border opencode inspect [--json]`** — the load-surface self-audit becomes a gate-owned
  surface: six read-only aspects (cache self-consistency, spec freshness vs pin/registry, identity
  handshake replay, Route A byte parity, Route A∧B dual-route collision, scope declaration),
  fail-closed aggregation FAIL 1 > CANNOT 2 > PASS 0. `--json` pins `scope:"v1"` — V2 load surfaces
  are a declared blind spot, not silently covered. Zero writes; `--purge` stays in the cron shell.
- Change: **`exfil` joins the plugin's closed command list** (owner ruling R1 under the four-question
  eligibility gate — no mutation, no credentials, no foreign-byte execution, no local egress;
  packet: `.omo/evidence/F-EXFIL-ALLOWLIST-RULING-2026-09-30.md`). `border opencode …` verbs stay
  terminal-only: they mutate `$XDG_CONFIG_HOME` and fail the gate's first question.
- Change: `tools/plugin-drift-watch.mjs` retires to a thin shell over `border opencode inspect --json`
  (single source of verdicts); the cron rc contract is byte-stable — FRESH 0, DRIFT 1, NOT-CACHED 0
  (special-cased per ruling B2), CANNOT 2 — and the crontab line is unchanged.

### 0.7.1 (2026-09-30)
- Fix: **release-gate test ruler race** (`test/push.integration.test.ts` I4) — the
  "dry-run made ZERO verdaccio requests" invariant counted lines in verdaccio's stdout
  log, an eventually-consistent view: on a saturated CI runner the gate-leg probe lines
  of an earlier phase land after the snapshot, inflating the dry-run delta (v0.7.0 CI
  run 36671401844 failed `6 !== 2` while the identical bytes pass locally). The suite
  now takes every snapshot through a FIFO drain barrier (sentinel request whose log line
  must be visible before counting; sentinel traffic is excluded from the count). The
  zero-network dry-run contract itself is unchanged — verified request-free on both sides
  of the barrier; only the measuring instrument was repaired.

### 0.7.0 (2026-09-28)
- Add: **OpenCode 2 (beta) plugin compatibility** — the plugin module is dual-shaped
  (`{id, setup}` for V2 hosts, frozen V1 `server()`), sharing the pre-spawn
  allowlist/`--yes` gates and the 0.5.1 identity handshake across both shapes;
  refusal/handshake/rendering byte-parity between edges is pinned by
  `test/opencode.v2shape.test.ts` while the V1 path stays 16/16 on unmodified
  tests. Root `index.ts` re-export shipped for V2 directory discovery (which
  bypasses the exports map; live-proven on `@opencode-ai/cli` beta-19271).
- Fix: the live V1 probe is anti-vacuous — opting in (`BORDER_OPENCODE_PROBE=1`)
  without a resolvable binary or built dist now FAILS naming the remedy instead
  of skipping green-adjacent (`BORDER_OPENCODE_BIN` override added).
- Docs: support matrix (V1 object entry ≥ 1.18.29; V2 project-local verified;
  `/border` command V1-only pending the V2 delivery API).

### 0.6.0 (2026-09-25)
- Add: **the exfil lens** — five rules (`exfil-rfc1918`, `exfil-ssh-target`,
  `exfil-home-path`, `exfil-cred-location`, `exfil-host-profile`, `exfil-machine-binding`) that flag
  exfil-shaped literals on about-to-be-public surfaces, the gap classic secret
  scanners leave open because an internal IP is not a credential. The observed
  severity of every (rule × facet × channel) cell lives in one machine-readable
  home, `src/exfil/severity.ts`, rendered — never re-decided — by the check
  pipeline, the new read-only `border exfil <rev|url>` CLI (tip tree by default,
  `--deep` history, URL modes into a destroyed temp clone) and the README table,
  each cell pinned by a docs guard. The tree HIGH family ships as vendored
  twins (gitleaks TOML + secretlint patterns, ids byte-equal, verdict parity
  tested); the commit-message facet is native-exclusive with a `:message` id
  family so allow-list waivers can never cross facets; tag notes stay with the
  pre-existing `tag-message-secret` engine leg. All exfil sources are
  fingerprinted into `rulesHash`.
- Add: **post-push landing verification** — after git legs move, the remote tip
  is re-observed and scanned with the same machinery; clean appends an
  append-only `t:"landing"` record and preserves the exit, a blocking hit exits
  1 ("ALREADY PUBLIC; border detects, never erases"), an unobservable tip exits
  2 with no record minted. Executed-push rows are never mutated; DRY-RUN lands
  nothing.
- Add: **fixture band + assembly doctrine** — 10.200.0.0/16 is reserved as the
  always-exempt-on-tree test range (exemption mirrored natively in both twins,
  message facet deliberately not exempt), and the test corpus assembles every
  other leak shape at runtime (`assembleOctet`/`assembleHost`) so checked-out
  bytes carry no complete leak tokens: border's own lens is green against
  border's own corpus. Golden-suite coverage includes an opt-in truth lane
  (`BORDER_EXFIL_TRUTH=1`) with a documented red-anchor lifetime clause.
- Note: this release line traces to the 0.5.1 impersonation-wave audit; that
  wave's H-3 follow-up — scrubbing this repo's own historical tip surfaces —
  landed here as byte edits with the extracted values withheld from public
  records by design (see the sanitized `.omo/evidence/` trail, not this log).

### 0.5.1 (2026-09-24)
- Fix: **plugin impersonation — the `border` tool could spawn the host binary instead of the
  gate.** On Route B the 0.5.0 adapter resolved its packaged CLI as `process.execPath +
  dist/index.js`, but inside the opencode plugin host `process.execPath` is the opencode
  (bun-compiled) binary — sessions saw opencode's banner for `--help` and opencode usage
  errors for every other command, while the tool's schema still promised border's
  fail-closed contract. The resolution order is now: `BORDER_BIN` (wins alone; a broken
  override never silently falls back) → packaged `dist/index.js` exec'd directly via its
  shebang, else under `PATH` `node` → `border` on `PATH`. `process.execPath` is removed from
  the adapter, pinned by a source-level regression test, and **every candidate must pass an
  identity handshake** (`--help` answering with border's banner + `usage: border`, exit 0,
  20 s cap) before any user argv is spawned — failure reports `cannot-answer` at exit 2 and
  runs nothing else (spawn failures now map to 2, not 127, aligning the tool with the CLI's
  exit-code contract). Regression tests cover the unspawnable-override and the
  opencode-style-impostor fixtures; the impostor logs prove user argv never reaches it.
  Honest boundary: the handshake catches mistaken identity (host binaries, PATH accidents),
  not a deliberately forged banner.

### 0.5.0 (2026-09-12)
- Add: OpenCode plugin adapter (`exports["./server"]` + `/border` + `border` tool) loadable
  two ways with zero manual install — config-declared `"plugin": ["border-customs@0.5.0"]`
  (opencode downloads the package; the plugin spawns its own packaged CLI via a
  package-relative `dist/index.js` resolution, `BORDER_BIN` override, PATH fallback) or
  `border opencode install` (marker-identified idempotent file drop, foreign files refused,
  never overwritten). Trigger: an agent session drives the gate without a shell-out or an
  install ritual; `push --yes` stays terminal-only by design — the tool refuses it.

### 0.4.2 (2026-09-12)
- Fix: `npm publish` no longer prints the misleading "bin[border] script name
  dist/index.js was invalid and removed" warning — package.json now carries the
  canonical bare-relative bin form npm normalizes to anyway (mechanism traced to
  @npmcli/package-json publish-side; artifacts were never broken; an always-on
  test locks the form).
- Change: RubyGems freshness (skip-ledger) parity compares a normalized CONTENT
  digest instead of raw file bytes — `gem build` stamps the building toolchain
  (RubyGems <3.6 embeds the build second in gzip headers), so raw-sha repack
  parity could never be honored on those machines. The ledger digest and the
  publish-time same-bytes re-hash stay RAW: what gets uploaded is still exactly
  the certified bytes, and any unparseable artifact fails closed to a full
  re-check.

### 0.4.1 (2026-09-11)
- Add: release-coherence rule family — every version source inside a published artifact
  must agree (pyproject vs MODULE vs filename, gemspec vs gem metadata, Cargo.toml vs
  crate filename, package.json self-consistency; the git-tag half is a publish-workflow
  hard gate). Trigger: the aihr incident where a wheel labeled 0.2.2 shipped modules
  self-reporting 0.2.1 — every pinned consumer silently got old behavior.
- Add: `border roundtrip` local-artifact input — an argument resolving to an existing
  file (.whl/.tgz/.crate/.gem, closed table) proves unpublished bytes end-to-end; the
  streaming sha256 of those exact bytes is the ledger identity and the report carries
  `source:local:<abs>` provenance. Honest boundary documented: the local PyPI-wheel lane
  is residue-INERT by construction (pip fully tracks and prunes; verified live on pip
  24.0 AND 25.0.1) — planted-detection demos belong to the hook-executing lanes
  (npm postinstall, gem extconf, crates build.rs).
- Change: pypi roundtrip lane dep-closure calibration — pip's resolver report demotes
  dependency-storm files to LOW `dep-owned` rows, so genuine orphans stand alone; the
  demotion requires a legitimate claimant dist-info (pin Name+Version match, canonical
  dirname, unique, own site-packages root, not the target) after an independent verifier
  proved a shadow `*-9.9.9.dist-info` could otherwise launder hostile writes.

### 0.4.0 (2026-09-10)
- Add: `border roundtrip <[ecosystem:]name@version>` — fact-proof valve. Installs the
  package inside a throwaway Docker container, content-hashes the whole filesystem before
  and after uninstall, and reports exactly what the uninstaller left behind. Persistence
  surfaces (rc/profile mutations) => CRITICAL; orphan files => HIGH. Verdicts record to
  the ledger by default (`--no-record` opts out); Docker absent => fail-closed, never clean.
- Add: `residue.requireProof` — when on, a residue-capable artifact only passes `border
  check` with a fresh recorded roundtrip proof (bound to rulesHash; flipping the config
  invalidates cached verdicts). Missing proof => CRITICAL `roundtrip-proof-missing`.
- Opt-in test legs: BORDER_ROUNDTRIP_DOCKER=1 (8 real container legs, 4 ecosystems).

### 0.3.2 (2026-09-10)
- Fix: CLI invoked through the npm `.bin` shim silently exited 0 without running
  (entrypoint detection now realpath-canonicalizes both sides). Regression-locked by a
  pack -> install -> shim-invocation test (`BORDER_PACK_TEST=1`, wired into CI).
- Fix: `publint` is an exact-pinned runtime dependency, so `border scan`/npm checks work
  out of the box in consumer installs; README documents the engine posture truthfully.
- Add: release-coherence seed test pinning the scan User-Agent version to package.json.

### 0.3.1 (2026-09-10)
- Add: `border scan [ecosystem:]name@version` — static residue inspection of third-party
  registry packages (npm/PyPI/crates.io/RubyGems), ledger-free by design.
- Docs: README scan section; crates envelope normalization now logs scrubbed-file hashes.

### 0.3.0 (2026-09-09)

- **Residue gate (artifact stage).** The blanket install-hook CRITICAL becomes a classified
  family of seven closed `residue-*` rules across tiers T1–T4 plus cross-manager, pairing,
  and gem-unmatched lanes (see "The residue scan"): a hook matching the closed T1 safe-shape
  signature drops to MEDIUM; every unknown shape keeps the original CRITICAL row verbatim.
  Pairing (`# BEGIN <id>` marker blocks) is **detected only** — `residue-pairing-missing`
  fires on the orphaned WRITE, a verified pair still pays its T3 HIGH; the waiver downgrade
  path is the 0.4.0 roundtrip valve. Detection classes: C5 pairing discipline, C9 indirection
  spellings, C10 comment/quote boundaries — evidence frozen in `src/artifacts/RESIDUE-CONTRACT.md`.
- New `residue: { enabled }` config key (default on; strict; the ONLY skip path for the family,
  and flipping it invalidates cached PASS rows because the toggle rides the fingerprint). The
  residue rule table and classifier sources are now part of the ledger `rulesHash`: editing a
  signature forces a re-check even at an unchanged commit and tree.
- Boundary stated plainly: static analysis proves *capability*, not *fact*; border is not a
  malware sandbox and never executes what it reads.

### 0.2.0 (2026-09-05)

- Two new push channels, same doctrine end to end: **crates** (public crates.io only;
  literal `Cargo.toml` coordinates; pre-publish repackage digest-assert) and **rubygems**
  (rubygems.org or any `targets.rubygems.host` gemcutter-compatible host; literal-only
  gemspecs; `s.date` rejection).
- Platforms are now descriptors in a channel registry: each channel owns its config schema,
  env expansion, coordinate reading, probe, artifact stage, publish argv, and ledger fields
  in one file. The git/npm/pypi legs share the same publish core they already used; their
  behavior is unchanged.
- Ledger `confirmedVia` gained `crates-json` and `rubygems-json`; 0.1.x ledgers parse
  unchanged.
- New prerequisites when those targets are configured: `cargo` on `PATH` (measured against
  1.93.1 via rustup) and `gem` (measured against RubyGems 3.6.7 on ruby 3.3.8); other
  versions are untested by the gate's same-bytes proofs.

### 0.1.0

- Initial release: git, npm, and PyPI push channels behind the fingerprint PASS gate.

