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
- [x] W1.4 dogfood + docs (done 2026-09-10, commits a265dc0+ecc7e23, evidence DOGFOOD-W1.4.md;
  released via 0.3.1 + silent-bin hotfix 0.3.2 d443c2c)
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
- [x] W2.1 src/roundtrip/ (done 2026-09-10 commit 0b688fc: orchestrator 206p + manifest/docker
  legs, 22 units + 8 REAL docker E2E legs green all four ecosystems, planted-file acceptance
  exactly-2-rows npm/pypi/gem/crates, vacuous-pass guard; 622/610/2/10 root-verified)
  fetch via W1 code, container/host exec per W2.0 choice, install, snapshot, uninstall,
  snapshot, diff-classify: persistence surfaces (rc-delta, cron, systemd, PATH) = CRITICAL
  residue-fact; new-file residue = HIGH; byte-identical-rc ⇒ reversibility proof PASS).
  CLI `border roundtrip <spec>` reuses spec parser + flags. Fail-closed: any step failure
  or unobservable surface ⇒ exit 2.
- [x] W2.2 gate valve wiring (done 2026-09-10 commit 68911c2: residue.requireProof strict
  default-OFF, rulesHash-bound (flip 68f54a94→b8496d05), roundtrip-proof-missing/-stale
  CRITICAL natives pre-allowlist, ledger RoundtripRecord + --no-record opt-out, 24 tests
  + 3 live mutation confirms; trigger broadened to all-blocking-residue-* (honest deviation))
  included) — when set AND residue scan found T3/T4 capability, channel PASS additionally
  requires a fresh roundtrip verdict (ledger key = artifact sha256 + rulesHash + proof
  digest). Default OFF for 0.4.0 (opt-in; doctrine unchanged: static layer stays
  mandatory, proof is the elevator).
- [x] W2.3 reversibility acceptance fixture — RE-ANCHORED by spike verification (see
  VERDICT K5): DONE 2026-09-11 (bg_2f2be816, 1h18m, evidence-only, zero repo mutation).
  Founding verdict: registrar chain LEFTOVER-MODIFIED on its real persistence surface
  (`opencode-hr uninstall` leaves `{"plugin": []}` configs, re-formats user bytes via
  install-cli.js:93; pair-inversion EXISTS, byte-reversibility DOES NOT); shell rc/PATH
  VACUOUSLY restored — no published artifact writes rc (K5 confirmed from wheel bytes;
  BEGIN/END writer ships only at hr HEAD 41167c9, UNRELEASED — G-RELEASE/G-WRITER gaps);
  real border roundtrip ran E2E: npm leg PASS 0 rows (blind to bin-invoked verbs), pypi
  leg FAIL 2211 rows = 2210 pip dep-storm + 1 GENUINE orphan dir /usr/local/share/aihr
  caught only by the roundtrip (worker's /root-scoped instrument missed it — valve
  justified on its own family). 5 gaps filed: G-LOCAL G-RUN G-RELEASE G-CALIB G-WRITER.
  Doc W2.3-REGISTRAR-REVERSIBILITY.md (19,757B) + w23-transcripts/ (14 files). Honest
  limits carried by the new W2.4 follow-up + README fidelity envelope.
- [ ] W2.4 calibration follow-ups from W2.3 (0.4.1 candidates, in priority order):
  (a) [x] G-CALIB pypi lane — DONE 2026-09-11 (46b5fdf): dep-closure calibration +
  shadow-dist-info legitimacy stack; verifier CONVERGED-equivalent after fix round;
  live jupyter-core 54 LOW/0 blocking, benign parity byte-proofed.
  (b) G-LOCAL — `border roundtrip` accept local artifact path/tarball (wheel install
  from file) so unpublished/hardened artifacts can be proven.
  (c) G-RUN/G-WRITER/G-RELEASE are HR-repo-side items (registrar BEGIN/END wiring,
  writer release, runtime-managed-surface posture) — track in harness/hr, not here.

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

- [x] W4.1 static cross-check at publish stage (DONE 2026-09-11 9969836: artifact-internal
  self-consistency + config-gated twin; 'vs git tag' half enforced by publish workflow —
  see tag-consistency grep row in ledger; verifier CONVERGED 0.93) (new rule family residue-adjacent, own
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
