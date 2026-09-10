# border inspect roadmap — scan CLI / roundtrip proof / allowlist retirement / release-coherence

Origin: user approved the 4-item improvement order verbatim ("按你说的顺序来").
Approved scope: (1) third-party `border scan`, (4) fixture-creds runtime-join [IN FLIGHT,
bg_8afeeba9, outside this plan], (2) 0.4.0 sandbox roundtrip, (3) push-channels allowlist
retirement, (5) release-coherence rule. Item (7) §8-widening explicitly REJECTED (doctrine:
real cases drive audit rounds). Repo: /home/lab/workspace/harness/border. All product work
delegated; every worker DONECLAIM gets an independent fresh-session verifier reading only
disk (established R-series protocol).

## Ground facts (verified this session)

- `ChannelStageOptions` = {repoDir, cfg, env?, sanitizer?, skipGitleaks?, skipSecretlint?}
  (src/channels/types.ts:67) — stage() needs NOTHING else; channel manifest reads go
  through `git show HEAD:` (npm.ts:62, pypi.ts:73) ⇒ scan mode must materialize the
  fetched package as a committed temp git repo, then call `channel.stage()` directly —
  NEVER the full check pipeline (registry probes/push legs/ledger must not run: a probe
  answering "version exists" is meaningless for third-party packages).
- SUBCOMMANDS lives in src/cli/types.ts:16 (9 callers); cli.ts is the frozen G9 flag
  table; positional pattern established by llm-ingest.
- extractArchive/findNativeMissArchives/removeSandbox exist (src/artifacts/extract.ts:26-68);
  residue classifiers take a package dir + identity (residueFindings o.root/o.identity).
- fetcher seam pattern: PypiFetcher injected-fetcher with mandatory-UA note for crates
  (types.ts:43-63). No new deps: global fetch only.

## Wave 1 — `border scan <spec>` (ships 0.3.1)

- [x] W1.1 fetch+materialize core (new src/scan/): spec parser
  `[ecosystem:]name@version` (default npm; scoped `@scope/pkg@ver` disambiguated by LAST
  @; ecosystems npm|pypi|crates|rubygems; anything else exit 2 usage), registry endpoints
  (npm registry.npmjs.org/<p>/<v> JSON → dist.tarball; pypi /pypi/<n>/<v>/json → sdist
  .tar.gz URL only, wheel out of scope with documented reason: capability lives in setup
  code; static.crates.io/crates/<n>/<n>-<v>.crate with UA header; rubygems.org/downloads/
  <n>-<v>.gem), size cap 200MiB + timeout 60s + fail-closed exit 2 on any fetch/extract
  error, temp dir via mkdtemp with finally-cleanup (no QA asset survives).
- [x] W1.2 scan command handler: materialize → `git init -q && git add -A && git -c
  user.email=border@local -c user.name=border commit -qm scan` → synthesize BorderConfig
  in-memory (targets.<eco> minimal strict-schema shape, residue defaults, llm off) →
  channel.stage() → render findings through the SAME report renderer as check (tier,
  path, evidence line, sanitizer applied; --json machine mode). Exit: 0 clean-or-info-only,
  1 blocking (HIGH/CRITICAL), 2 cannot-fetch/scan. Zero ledger writes (grep-assert the
  scan path never imports ledger). No --version flag additions.
- [x] W1.3 tests: unit with injected fetcher stubs (scoped name, crates UA, size cap,
  sdist-only selection, bad spec shapes); materializer E2E on runtime-generated fixture
  archives (tar/gzip built in-test — NO binary fixtures in git, planted T4 marker in a
  fake setup.py must surface as residue-rc-edit CRITICAL); offline default (network E2E
  opt-in behind explicit env var, same doctrine as verdaccio legs); cli.test.ts surface
  (scan in SUBCOMMANDS, unknown-arg exit 2). typecheck+build RC0; full suite = 511+new /
  fail-set unchanged (C5 pair only locally).
- [ ] W1.4 dogfood + docs: run `border scan puppeteer@23.11.1` and `playwright@1.55.0`
  (npm) + `border scan pypi:nltk@3.9.1` — paste real outputs into evidence; README scan
  section (semantics: capability, not fact — roundtrip valve is 0.4.0); version bump
  0.3.1 in package.json ONLY (release-coherence W4 would flag drift — keep single source);
  commit+push with bypass registration if scanner regex re-trips; tag v0.3.1 → CI publish
  → registry verify install+scan.

## Wave 2 — 0.4.0 sandbox roundtrip (the fact-proof valve)

- [x] W2.0 SPIKE first (evidence doc, no product code): per-ecosystem isolation primitive
  decision — candidates: throwaway-HOME host sandbox (npm --prefix / python venv / gem -i
  + GEM_HOME / cargo --root + CARGO_HOME) vs docker full-FS snapshot (image: node:24-
  slim, python:3.12-slim, ruby:3.4-slim, rust:1-slim). Snapshot = sha256 manifest over
  {HOME tree, /tmp, /usr/local, /etc (docker only)} install→uninstall→re-snapshot; diff =
  residue manifest. Acceptance: uninstall of a T3-capable planted package shows EXACTLY
  the planted tree (no false negatives from overlayfs copy-up artifacts — measure on THIS
  machine, docker availability proven? VERIFY in spike step 0: `docker info` RC; if
  absent, host-mode is the only lane and /etc+systemd surfaces are UNOBSERVABLE ⇒
  roundtrip verdict cannot-verify exit 2, never clean). Document per-ecosystem fidelity
  gaps honestly.
- [ ] W2.1 src/roundtrip/: orchestrator (build artifact via channel stage-repack reuse or
  fetch via W1 code, container/host exec per W2.0 choice, install, snapshot, uninstall,
  snapshot, diff-classify: persistence surfaces (rc-delta, cron, systemd, PATH) = CRITICAL
  residue-fact; new-file residue = HIGH; byte-identical-rc ⇒ reversibility proof PASS).
  CLI `border roundtrip <spec>` reuses spec parser + flags. Fail-closed: any step failure
  or unobservable surface ⇒ exit 2.
- [ ] W2.2 gate valve wiring: config `residue.requireProof: true` (strict, rulesHash-
  included) — when set AND residue scan found T3/T4 capability, channel PASS additionally
  requires a fresh roundtrip verdict (ledger key = artifact sha256 + rulesHash + proof
  digest). Default OFF for 0.4.0 (opt-in; doctrine unchanged: static layer stays
  mandatory, proof is the elevator).
- [ ] W2.3 reversibility acceptance fixture — RE-ANCHORED by spike verification (see
  VERDICT K5): the shipped aihr wheel owns NO rc write at ANY level (cli_setup.py shells
  out to the npm registrar `opencode-hr`, cli_setup.py:37/:120; zero removal/revert
  functions shipped; reference hr-setup-env.py.reference is NOT in the wheel) — so the
  demo target is the REGISTRAR CHAIN: container (python:3.12-slim+node) → install
  opencode-hr registrar → observe rc/config BEGIN/END mutation → exercise its removal
  symmetry (registrar uninstall if shipped; else document gap honestly as this roadmap's
  founding roundtrip finding — pair-inversion missing = residue-persistence fact) →
  byte-restored + zero residue ⇒ PASS. Evidence doc + wiki G1. Tests: roundtrip unit w/
  stubbed runner; one real pypi-venv roundtrip E2E (offline fixture pkg, in-tree-only
  writes ⇒ empty diff verdict). Ship 0.4.0 same release choreography as W1.4.

## Wave 3 — allowlist v2 retirement (push-channels scope)

- [ ] W3.1 verdaccio PUT root-cause on runners: forensics commit re-adding -A22 dumps to
  a temp dispatch; hypothesis list to falsify in order: npm 11 vs 12 argv/provenance
  negotiation, loopback bind vs `localhost` IPv6 resolution, runner proxy env
  (HTTP_PROXY unset but npm globalconfig?), verdaccio sqlite/logs under /tmp cleanup race.
  Fix at source (test or product), revert forensics, dry-run green with AC trio gone.
- [ ] W3.2 golden normalization: replace raw-sha goldens with NORMALIZED digests — .gem:
  sha over uncompressed contents.tar.gz + metadata MINUS `rubygems_version`/
  `gem_version` fields; channels golden: strip env-fingerprint components from the check
  key (enumerate which hash inputs carry toolchain truth — audit first, then normalize);
  re-capture goldens ONCE, verify stable across local + runner (one CI round proves it).
- [ ] W3.3 allowlist v2 → allowlist v0: with 6 env reds gone, revert gate to sanctioned-
  pair only; when border-push-channels lands C5-1/C5-4 green (separate plan, not here) →
  plain `npm test`. Update workflow comments + ledger retirement log. If the 2 C5s still
  red, gate keeps the exact pair + this plan's evidence that nothing else regressed.

## Wave 4 — release-coherence rule (0.4.x)

- [ ] W4.1 static cross-check at publish stage (new rule family residue-adjacent, own
  rule ids release-coherence-*): every version source in the artifact must agree —
  package.json vs git tag; pyproject [project].version vs __init__.__version__ vs
  *.egg-info/PKG-INFO; Cargo.toml vs tag; gemspec vs tag. CRITICAL on drift (aihr 0.2.1-
  wheel-labeled-0.2.2 is the founding case, cite the incident page). Twin-package cross-
  manager equality (wheel version == npm twin package.json version) is config-gated
  opt-in (`release.twin: [...]`, strict) — cross-manager equality is the one place a
  declaration IS enforceable statically.
- [ ] W4.2 tests (closed-table drift fixtures per ecosystem), rulesHash inclusion,
  README, dogfood on hr repo layout, ship 0.4.1.

## Cross-wave invariants

No new runtime deps (fetch/tar via node builtins + existing shims); fail-closed beats
silent-clean everywhere; every wave ends with: typecheck+build RC0, full suite with
fail-set exactly the sanctioned pair, commit+push (bypass-register any NEW synthetic
literals), evidence JSON in .omo/evidence/, ledger line, wiki status lines en495/zh496
updated at each shipped version. Workers: deep for W1.1-2/W2/W3.2/W4, quick for docs.
Verifiers: fresh independent sessions, disk-only. Plan checkboxes owned by root only.
