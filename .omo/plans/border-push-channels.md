# border-push-channels - Work Plan

## TL;DR (For humans)

**What you'll get:** `border` grows from three hardcoded push channels (git / npm / PyPI) to a channel-registry architecture with two new publish targets: **crates.io** (`cargo package`/`cargo publish`) and **RubyGems** (`gem build`/`gem push`). A repo picks any combination in `border.yaml` (`targets.npm`, `targets.pypi`, `targets.crates`, `targets.rubygems`, plus any number of git remotes) and each run can narrow scope with `--targets`. Every new channel goes through the same fail-closed pipeline the existing ones enforce: coordinates read at HEAD, registry pre-flight (already-published version = loud block, squatted name = loud block, unreachable registry = refuse to guess), build-once artifacts into `.border/dist/`, same-bytes re-hash before any irreversible upload, credentials never touched by border.

**Why this approach:** the platform set is currently a closed union hardcoded across ~9 files (config schema, CLI flag table, push-state machine, publish ordering, ledger enums, freshness, artifact stages). Adding platforms by copy-paste multiplies that; a registry turns every future platform into one descriptor + one test file. We keep git as a first-class channel behind the same lookup, but the deep interface is for publish-style legs because that is where the duplication lives.

**What it will NOT do:** no user-defined/custom shell channels (they cannot prove same-bytes — option C was rejected); no private cargo-registry support in v1 (custom registry names hide their index URL in `~/.cargo/config.toml`; probing them would silently skip version-exists, which is fail-open); no non-literal version resolution (Cargo workspace-inherited versions, gemspec dynamic versions ⇒ typed config error, never a guess); no signing, no tokens in argv/env that border constructs, no retries.

**Effort:** Medium (6 todos, 3 waves; ~2 new channels + 1 architecture refactor of 9 hardcoded touchpoints)
**Risk:** Medium — refactoring a security gate risks silently weakening it. Mitigated by: (a) todo C2 is behavior-preserving with a golden-fingerprint test (byte-identical keys for existing configs before/after), (b) new-channel semantics pinned by an empirical spike contract doc (same convention as `src/engines/ADAPTER-CONTRACT.md`), (c) fail-closed polarity tests per channel (every unclassifiable probe outcome exits 2, never "absent").
**Decisions to sanity-check:** (1) channel ids are `crates` and `rubygems` (registry names, not tool names — matches the existing `pypi` precedent even though the tool is twine/cargo); (2) `cargo publish` re-packages internally, so crates' same-bytes proof rides on `cargo package` determinism (pinned by spike; if the spike disproves determinism the publish leg hard-fails and we redesign rather than paper over); (3) `gem build` evaluates the repo's gemspec Ruby code — accepted because `python -m build` already executes the repo's build code (same trust class, pre-existing precedent).

---

> TL;DR (machine): Refactor the hardcoded `"git"|"npm"|"pypi"` union into a channel registry (src/channels/); config schema derived from registry (still zod-strict — typo keys exit 2); add crates.io (cargo) and rubygems.org (gem) publish channels with full gate→coords→probe→build-once→same-bytes→spawn-inherit→push-record pipeline; extend ledger enums, exposureSet, freshness, extract-shim; golden-key regression guard on the refactor.

## Scope

### Must have

- **Channel registry** `src/channels/` exporting, per publish channel, a descriptor:
  ```ts
  export type PublishChannel = {
    readonly id: string;                                  // "npm" | "pypi" | "crates" | "rubygems"
    readonly order: number;                               // fixed publish order: git(0) → npm(1) → pypi(2) → crates(3) → rubygems(4)
    readonly configSchema: z.ZodTypeAny;                  // validated at targets.<id>; .strict()
    readonly envExpandFields: readonly string[];          // e.g. ["registry"], ["repository"], ["host"] — ONLY these get ${VAR} expansion
    readonly artifactExtensions: readonly string[];       // [".tgz"] | [".whl",".tar.gz"] | [".crate"] | [".gem"]
    readonly confirmedVia: PushConfirmedVia;              // "npm-view" | "pypi-json" | "crates-json" | "rubygems-json"
    readonly defaultUrl: string;                          // NPM_DEFAULT_REGISTRY / PYPI_DEFAULT_REPOSITORY / https://crates.io / https://rubygems.org
    coords(repoDir, cfg, env): PublishCoords;             // name+version read AT HEAD (`git show`), never the worktree
    probe(o: ChannelProbeOptions): Promise<Finding[]>;    // version-exists + name-foreign-owner + name-available, fail-closed
    stage(o: ChannelStageOptions): Promise<ChannelStageResult>; // build-once into .border/dist + artifact byte scan (check pipeline)
    publish(i: PublishInput): Promise<BorderExit>;        // the existing gate→rehash→probe→warn→spawn→record core, argv from this channel
    publishArgv(files, cfg): readonly string[][];         // per-file argv for dry-run print AND the real spawn (ONE source, dry-run honesty)
    exposureItem(coords): string;                         // `npm:x@1`, `crates:x@1`, …
  };
  ```
  git is registered as `GitChannel` (id "git", order 0) exposing only the fields the generic layers need (`configured`, target-id derivation); its deep logic stays in `src/push/git.ts`/`src/pushstate.ts` untouched.
- **Config**: `borderConfigSchema.targets` becomes `{ git: … }` plus one optional strict object per **registered** publish channel — the object shape is assembled FROM the registry (so adding a channel = one descriptor; the schema, `--targets` validation, `hasTargets`, `computeEffectiveTargets`, and CLI usage all follow). `targets.crates`: `{ name? }` only in v1. `targets.rubygems`: `{ name?, host? }` (`${VAR}` expansion on `host`). Unknown key `targets.cargo`/`targets.gems` ⇒ `unknown-key` exit 2 as today. All existing border.yaml files keep parsing byte-identically.
- **crates channel pipeline**: coords from `git show HEAD:Cargo.toml` `[package]` `name`/`version` (workspace `version.workspace = true` or absent literal ⇒ ConfigError exit 2); probe `GET https://crates.io/api/v1/crates/<name>/<version>` (200 present / 404 absent) + `GET …/crates/<name>` (claimed/available + owner signals via the shared `extractOwnerSignals`/`ownerVerdict`), request `User-Agent` header per crates.io API policy; stage `cargo package --allow-dirty --no-verify` with `CARGO_TARGET_DIR=.border/tmp/cargo-target` then move the `.crate` into `.border/dist/`; publish = **pre-publish repackage + digest assert vs the PASS record, then `cargo publish --allow-dirty --no-verify`** (see spike AC); confirmedVia `crates-json`; freshness policy pinned by spike (repack-digest if package is deterministic — the expectation; else key-match like pypi, documented).
- **rubygems channel pipeline**: coords from the `*.gemspec` at HEAD (`git ls-tree HEAD` discovers it; literal `s.name = "…"` / `s.version = "…"` regex only — dynamic version ⇒ ConfigError exit 2 with a pointer to the workaround); probe `GET {host}/api/v2/rubygems/<name>/versions/<version>.json` (200/404) + `GET {host}/api/v1/gems/<name>.json`; stage `gem build <gemspec> -o .border/dist/` (executes gemspec code — accepted precedent: `python -m build`); publish `gem push <file.gem> [--host <url?>]` uploading EXACTLY the recorded file (true same-bytes, npm/twine class); confirmedVia `rubygems-json`; freshness key-match class (gem build embeds build date — spike confirms).
- **Ledger**: `PUSH_CONFIRMED_VIA` += `"crates-json"`, `"rubygems-json"` (append-only parser must keep accepting all old values verbatim); `exposureSet` grows `crates:<n>@<v>` / `rubygems:<n>@<v>` items ONLY when those channels are configured (existing keys unchanged); `ARTIFACT_TARGETS` derived from registry.
- **Artifact scanning**: `.crate` and `.gem` added to the gitleaks native-miss dispatch in `src/artifacts/extract.ts` (`.crate` = gzip tar → `tar -xzf`; `.gem` = plain tar wrapping `data.tar.gz`/`metadata.gz` → `tar -xf`, inner `.tar.gz` handled natively at depth; spike verifies gitleaks really misses these extensions before the shim claims them — extension-based dispatch, per the existing spike lesson).
- **CLI**: `VALID_TARGETS` built from the registry; usage line `--targets <git,npm,pypi,crates,rubygems>` generated, not typed.
- **pushstate + commands/push**: `registryState`/`derivePushState`/`dryRunRegistryLegs`/`--yes` executor iterate the registry (`order`-sorted) instead of the `["npm","pypi"] as const` literals; publish refusal semantics unchanged (any BLOCKED ⇒ nothing pushed; per-leg failure ⇒ immediate return, later legs never run).
- **Docs**: README section per new channel (config snippet, env var, toolchain prereq: `cargo` on PATH / `gem` on PATH — missing ⇒ typed exit 2 at stage, mirroring twine-absent), `src/channels/CHANNEL-CONTRACTS.md` spike evidence, version bump 0.1.0 → 0.2.0.
- **Tests**: per-channel table-driven probe polarity tests against loopback stub servers (pattern: existing pypi stub in `test/registry.test.ts`), fake-binary seams (`cargoBinPath`/`gemBinPath` à la `npmBinPath`/`twineBinPath`), config schema cases (new keys, strict rejection, `${VAR}` on host), golden-fingerprint guard (C2), honesty e2e: planted secret inside a `.crate` and a `.gem` ⇒ check exits 1, `push --yes` refuses, grep over `.border/**` proves the literal never lands on disk.

### Must NOT have (guardrails)

- No user-defined command channels (option C): a shell-out channel cannot enforce coords-at-HEAD / build-once / same-bytes / stdio-credential separation. Registry membership = built-in only.
- No cargo private/custom `--registry` support in v1 (`targets.crates` schema carries no url field; `unknown-key` rejection IS the gate). Follow-up issue, not this plan.
- No dynamic version evaluation (no `ruby -e` for gemspec loading, no cargo metadata parsing for workspace inheritance). Literal-only, fail closed with an actionable ConfigError.
- No credential handling: no `--token` flags, no `CARGO_REGISTRY_TOKEN`/`GEM_HOST_API_KEY` construction or inspection by border; uploads inherit stdio for interactive OTP (G28 unchanged).
- No behavior change to git/npm/pypi legs in C2 beyond indirection: same messages, same order, same exit codes, same ledger shapes (golden tests pin this).
- No retries, no `--force`, no new exit codes, no changes to the fingerprint six-tuple composition (only its inputs can grow with configured channels).
- Do not delete `src/push/npm.ts`'s exported pipeline helpers — generalized core moves to `src/push/core.ts`; old paths re-export for test compatibility (`runNpmPublish`/`runPypiPublish` signatures frozen).

## Todo list

> Each todo will be implemented with a dedicated subagent session, in the wave order below. TDD where a todo names failing-test-first ACs.

### Wave 1 — evidence before code

- [ ] **C1. Spike + `src/channels/CHANNEL-CONTRACTS.md`** — empirically pin, by running real `cargo` (rustup default stable) and real `gem` (rubygems) in `/tmp/opencode/spike-*` sandboxes (fixtures deleted after; facts land in the contract doc, ADAPTER-CONTRACT.md style): (a) `cargo package --allow-dirty --no-verify` byte-determinism across two runs on an unchanged tree (sha256 compare; also across a fresh clone — registry-vs-worktree parity); (b) crates.io API status-code polarity for version-present/absent and name-claimed/available incl. no-User-Agent behavior (expect 403) and 404 body shape — against the real API read-only (GETs only, no publish); (c) `.crate` = gzip tar? gitleaks `dir --max-archive-depth 2` native-miss CONFIRMED on planted secret with `.crate` extension; (d) `.gem` internal structure (outer tar, `metadata.gz`, `data.tar.gz`), gitleaks native-miss CONFIRMED, `tar -xf` shim round-trip; (e) `gem build` determinism (build twice, compare) — expect NON-deterministic (build date) ⇒ pins rubygems freshness=key-match; (f) `gem push`/`cargo publish` exact argv surface (`--host`, `--no-verify`, `--allow-dirty`) and their credential-failure modes (no-creds ⇒ nonzero, no partial upload — verify message shape for the executor's exit-1 text); (g) crates.io/rubygems rate-limit behavior on 3 rapid GETs (403/429 ⇒ must map to fail-closed EngineRunError, never absent). AC: contract doc lands with a spike table per fact, each reproducible by the exact commands recorded; NO src/ changes.

### Wave 2 — behavior-preserving refactor (the risky one, isolated)

- [ ] **C2. Channel registry + hardcode elimination** — create `src/channels/types.ts` + `src/channels/registry.ts` with the four `PublishChannel` fields' worth of npm/pypi descriptors binding to EXISTING functions (`readNpmCoords`, `probeNpm`-into-`runRegistryProbes` internals — extract per-channel probe legs out of `runRegistryProbes` into `channels/npm.ts`/`channels/pypi.ts` verbatim), `GitChannel` id wrapper, and move the shared publish pipeline (`requirePassedRecord`/`rehashRecordedArtifacts`/`blockingProbeFindings`/spawn/record skeleton in `src/push/npm.ts`) into `src/push/core.ts` parameterized by channel (`conventions` now come from `artifactExtensions`, argv from `publishArgv`). Rewire ALL hardcode touchpoints: `src/config.ts` (schema assembly from registry, `expandInConfig`, `hasTargets`, `exposureSet`), `src/check/context.ts:computeEffectiveTargets`, `src/cli.ts:VALID_TARGETS` + usage, `src/pushstate.ts` (`TargetKind = string`, `registryState`, `publishLegs`), `src/commands/push.ts` (`registryRunner` lookup, `["npm","pypi"]` literals in dry-run + --yes paths), `src/check.ts` artifact-stage dispatch, `src/ledger/freshness.ts:ARTIFACT_TARGETS`. AC: (1) `npm run typecheck`, `npm test` (all pre-C2 tests), `npm run build` green WITHOUT touching any test file except adding; (2) golden-fingerprint test: fixture repo with git+npm+pypi config produces a byte-identical check-key before and after the refactor (record the before-value in the test as a pinned literal); (3) `--targets` accepts the same inputs, rejects `--targets crates` still as… NO — after C2 `crates` is not yet registered ⇒ `unknown target` exit 2 via cli `allowed` check; C3 flips that; (4) exports `runNpmPublish`/`runPypiPublish`/`PublishTarget`/`TargetKind` keep their paths and signatures (deprecated re-export shims where bodies moved); (5) zero literal `["npm", "pypi"]` remains under src/ (grep AC).

### Wave 3 — new channels (serial: both touch shared enums)

- [ ] **C3. crates channel** — implement per Scope against `src/channels/CHANNEL-CONTRACTS.md`; register descriptor (id `crates`, order 3, configSchema `{name?}.strict()`, extensions `[".crate"]`, confirmedVia `crates-json`, defaultUrl `https://crates.io`); add stage leg to check pipeline via the C2 dispatcher (missing `cargo` binary ⇒ EngineMissing-class exit 2 naming the install hint); pre-publish digest assert per Scope; honesty test: planted secret in packaged source ⇒ `.crate` scan finding ⇒ check 1, push refused. AC: polarity table tests (200/404/403/timeout/malformed ⇒ present/absent/block per contract) on a loopback stub; `cargo publish` never spawned in tests (fake binary seam only); dry-run prints exact argv from `publishArgv` with zero network.
- [ ] **C4. rubygems channel** — same pattern (id `rubygems`, order 4, configSchema `{name?, host?}.strict()` with `${VAR}` on host, extensions `[".gem"]`, confirmedVia `rubygems-json`, defaultUrl `https://rubygems.org`); `gem build` stage (gemspec located via `git ls-tree HEAD --name-only` filtered `*.gemspec`; ZERO or MULTIPLE gemspecs at HEAD without `name` configured ⇒ ConfigError exit 2 "ambiguous gemspec — set targets.rubygems.name"); publish uploads exactly the `.border/dist/*.gem` recorded file (`gem push <file>`, true same-bytes); honesty test as C3. AC: stub-server polarity table incl. host override + sanitization of userinfo in any printed url (reuse sanitizeUrl path); dynamic-version gemspec ⇒ typed exit 2; missing `gem` ⇒ exit 2 hint.

### Wave 4 — integration + docs

- [ ] **C5. Cross-channel integration tests** — full 5-target fixture repo (git bare remote + verdaccio + pypi stub + crates stub + rubygems stub via seams): `--targets crates,rubygems` subset discipline (git-only PASS must not authorize them — fingerprint scope binding), all-BLOCKED refusal, PARTIAL semantics (crates publish fails ⇒ rubygems never spawns), ordering assertion (registry `order` respected), ledger round-trip of new confirmedVia values through the strict parser, exposureSet inclusion matrix (add `crates` to config ⇒ key changes ⇒ old PASS can't authorize — cache-invalidation AC), `border status` table lists new legs. AC: suite green; existing e2e.honesty unaffected.
- [ ] **C6. Docs + release surface** — README.md: new `border.yaml` keys, prereq table (cargo/gem versions used in the spike), per-channel "what border will run" dry-run examples, the option-C rejection paragraph (why no custom channels — user-facing rationale for the earlier ask), migration note "0.2.0 adds channels; existing configs unchanged"; `skills/border/SKILL.md` target list update; package.json 0.2.0; CHANGELOG (if exists, else README section). AC: `grep -rn 'npm,pypi' README.md` shows only historical-context hits; docs match cli usage output verbatim (test pins usage string? — align, do not fork text).

## Execution graph (waves)

- **Wave 1** — C1 alone (no src risk).
- **Wave 2** — C2 alone; MUST land green before any new channel (it is the blast-radius owner).
- **Wave 3** — C3 then C4, SERIAL (shared: `PUSH_CONFIRMED_VIA`, extract.ts dispatch list, registry file, cli usage — conflicts would arise if parallel).
- **Wave 4** — C5 after C4; C6 after C5 (docs pin final behavior).
- No todo depends on a C6 output. Parallel-safe pair: none in this plan (the shared-file serialization is deliberate).

## Verification gates

1. `npm run typecheck` && `npm test` (full suite; C2 adds ~4 test files, each channel ~2) && `npm run build` — every todo's commit boundary.
2. Golden-key test (C2) and honesty tests (C3/C4/C5) are BLOCKING: they encode "the refactor did not weaken the gate" and "secrets never ride a new channel".
3. Final manual dry-run dogfood on THIS repo (git+npm+pypi unchanged config): `border push` prints identical plan as pre-C2 (compare captured output saved in C2 test fixture).
4. grep ACs: no `["npm", "pypi"]` / `"npm" | "pypi"` literal remains in src/ (C2); no `--token`/`api_key` string in src/ (all channel todos); crates/rubygems appear exactly once each in the registry file (single source of platform knowledge).

## Risks & mitigations

- **R: C2 refactor silently changes verdict semantics** (e.g. rehash conventions keyed differently, probe polarity flipped). **M:** behavior-preserving rule: C2 commits move code, change zero logic; golden-fingerprint + full existing suite untouched; Momus + self-review diff per touchpoint.
- **R: `cargo publish` internally repacks and a race window exists between our digest assert and its upload.** **M:** documented residual (bounded by unchanged tree + digest equality seconds earlier); matches the pypi freshness precedent class; if C1 disproves package determinism the whole channel pauses for redesign (gate: C3 cannot start against a FAIL on spike item (a)).
- **R: crates.io blocks/patterns API traffic from CI-like UAs; probes hit 403 ⇒ false exit-2 wall.** **M:** C1 item (g) measures it with the real UA shape first; fail-closed remains fail-closed — a blocked probe never becomes "absent".
- **R: `gem build` evaluates arbitrary repo Ruby code during check** (supply-chain attack surface on the operator's machine). **M:** accepted-precedent (python -m build does the same today); contract doc states it loudly; README lists it; NOT gated behind --ignore-scripts because gemspecs are not data — out of scope to fix, documented.
- **R: Ledger enum extension breaks the strict parser on forward/back compat.** **M:** additive-only; C5 parses pre-existing ledgers (fixture from this repo's own .border/ copied) verbatim.

## Immediate resolvable unknowns

- C1 spike items (a)–(g) are the ONLY unknowns; all are resolved by local binaries + read-only HTTPS before any src/ line changes. No other open question blocks implementation.
