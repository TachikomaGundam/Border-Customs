# W3.2 — golden normalization: channels key + .gem stage/freshness; allowlist v3 → v4

Scope: **W3.2** (replace the raw-sha goldens of the last three environment-reds) and the
**gem-duo + channels-golden HALF of W3.3** (allowlist v3 → v4). Repo
`/home/lab/workspace/harness/border`. Branch `forensics/w32-normalization` (fix+allowlist
commits) — NOT merged (human gate). Author: autonomous W3.2 worker, 2026-09-12.
Template: `W3-VERDACCIO-FORENSICS.md` (branch-limited forensics + runner proof + handoff).

## Verdict (one line)

All three reds were **environment truth pinned into goldens**: the channels check key
hashes the ABSOLUTE path of every fingerprint source (location-bound BY DESIGN), and the
`.gem` goldens assumed `gem build` RAW-byte determinism, which holds only on the measured
RubyGems 3.6.7 (runner image builds with 3.4.20, which stamps the build second into the
metadata `date` and the gzip headers and serializes six deprecated fields EMPTY). Normalized
goldens + a normalized `.gem` CONTENT digest make all three green on BOTH machines
(runner proof: run `34629359428`, `release gate green: 707 tests / 695 pass / exactly 2
sanctioned failure(s)` — the set is exactly {C5-1, C5-4}).

## Flaky-green root cause (the gate-coin-flip, stated and reproduced)

`test/channels.rubygems.test.ts` asserted raw cross-build `.gem` sha equality
(`second.sha256 === first.sha256`). On the dev box (RubyGems 3.6.7) `gem build` is fully
deterministic: gzip header MTIME pinned to 1980-01-01, inner-tar member mtime pinned to
1980-01-02, metadata `date: 1980-01-02` (measured, `/tmp/w32audit` artifacts). On the
GitHub-hosted ubuntu-24.04 image RubyGems is **3.4.20** (runner-image README
`Ruby 3.2.3 / RubyGems 3.4.20`), which embeds the **build instant**: metadata
`date: <now>`, gzip MTIME = now. Two `gem build` calls straddling a second boundary yield
different bytes ⇒ the test is RED; landing in one second yields identical bytes ⇒ GREEN —
a coin flip. Because the ALLOWLIST is an EXACT-SET gate, the green flip makes the gate fail
with a `-stage` diff (observed both ways in W3.1: absent in `34614069251`, present in
`34616009447`). **Reproduced locally at zero dispatch cost** by building the same fixture
under RubyGems 3.4.20 (`rubygems-update-3.4.20.gem` extracted, `RUBYOPT=-I<lib> gem build`):
two builds 2s apart differ from byte 147; the dev-box 3.6.7 builds are byte-identical.

## .gem normalization (stage + freshness goldens)

`src/ledger/freshness.ts` `gemContentDigest(bytes)`: sha256 over

1. the outer .gem parsed as plain ustar by member NAME (outer tar headers never read);
2. `data.tar.gz` GUNZIPPED, then canonicalized per entry in archive order:
   name, typeflag, exec bits (`mode & 0o111`), linkname, sha256(content);
3. `metadata.gz` GUNZIPPED, minus lines matching `^(rubygems_version|gem_version|date):`
   (unconditional — toolchain/build-instant stamps) and
   `^(autorequire|description|email|homepage|post_install_message|signing_key):[ ]*$`
   (EMPTY deprecated keys: 3.4.20 emits them, 3.6.7 drops them — measured cross-build
   delta; a gemspec SETTING one of these still rides the digest);
4. `checksums.yaml.gz` EXCLUDED (it hashes the raw gz member bytes = stamps).

Malformed input ⇒ null ⇒ parity unprovable ⇒ fail-closed FULL re-check (never a skip).
The ledger record and the publish-time re-hash stay RAW: `border push --yes` still uploads
the exact certified bytes (unchanged product doctrine; only the skip-ledger repack
comparison and the test goldens normalize).

### .gem digest input audit — what drifts, what is tolerated vs still caught

| Digest input | Carries toolchain/environment truth? | Normalization applied | Still catches |
| --- | --- | --- | --- |
| outer tar header bytes (member mtimes) | y (some builders) | never read (member lookup by name) | — |
| `metadata.gz` / `data.tar.gz` GZIP header MTIME | y — 3.4.20 = build second, 3.6.7 = pinned 1980-01-01 | gunzip before hashing | content beneath |
| `checksums.yaml.gz` member | y (hash of the raw gz bytes) | excluded from digest | — |
| inner tar per-entry MTIME | y (3.4.20 = source-file mtime ⇒ checkout second) | dropped | — |
| inner per-entry uid/gid/uname/gname | y (builder identity) | dropped | — |
| inner per-entry mode group/other bits | y (umask-derived: 0664 dev vs 0644 runner) | reduced to exec bits `&0o111` | exec-bit flips |
| inner entry name / typeflag / order / content | n — payload truth | KEPT verbatim | byte flips, renames, inserted files, reorder, symlinks |
| metadata `rubygems_version:` | y (3.6.7 vs 3.4.20 — the plan-named stamp) | line dropped | — |
| metadata `gem_version:` (legacy stream) | y (plan-named stamp) | line dropped | — |
| metadata `date:` | y (3.4.20 = build second; 3.6.7 = pinned) | line dropped | — |
| metadata six deprecated keys, EMPTY form | y (3.4.20 emits, 3.6.7 drops) | dropped ONLY while empty | set values (mutation-tested) |
| metadata everything else (name/version/platform/files list/authors/summary/deps/extensions/require_paths/required_* versions/specification_version/…) | n (payload+spec substance) | KEPT verbatim | gemspec identity drift, files-list drift, serializer body changes |
| pax/GNU extended-header entries (x/g/L/K) | y (timestamp/long-name plumbing) | skipped | — |

### Mutation proofs (pinned as a test, run green on dev box AND runner)

`test/channels.rubygems.test.ts` — "W3.2 digest mutation…" (uses a test-LOCAL ustar
reader/writer, independent of the product parser):

| Tamper | Expected | Result (dev box + runner run 34629359428) |
| --- | --- | --- |
| one digit flipped inside `lib/answer.rb` in the UNCOMPRESSED contents tar | golden MUST fail (digest ≠) | ✅ digest moved |
| `rubygems_version: 3.6.7 → 9.9.9` | MUST pass (tolerated) | ✅ digest unchanged |
| injected legacy `gem_version:` line | MUST pass | ✅ unchanged |
| `date:` re-stamped to 2031 | MUST pass | ✅ unchanged |
| gzip header MTIME rewritten (both members, arbitrary epochs) | MUST pass (the in-run second-boundary flake itself) | ✅ unchanged |
| `checksums.yaml.gz` member dropped (stale-vs-rebuilt) | MUST pass | ✅ unchanged |
| six deprecated keys injected EMPTY | MUST pass | ✅ unchanged |
| `email:` SET to a value | MUST fail | ✅ digest moved |
| extra file appended to contents tar | MUST fail | ✅ digest moved |
| metadata `summary:` text tampered | MUST fail | ✅ digest moved |
| non-tar garbage / missing metadata.gz | MUST yield null (fail closed) | ✅ null |

Cross-builder proof (before dispatch): identical `gemContentDigest`
(`e9e42748ad…7319`) for the same fixture built with RubyGems **3.6.7** and **3.4.20**,
and across two 3.4.20 builds straddling a second. The stage golden
`1458976b12ddc416cab3cf18067a9611906abc0cd2c7d5322bd72219b2ebd951` (dev-box capture of the
test fixture gem) then went green on the runner's 3.4.20 builder unchanged — the
environment-portability proof the plan asked for.

### Where the raw goldens moved (freshness test)

- `stage:` — kept all raw same-build ledger checks (`artifact.sha256 === sha256File(file)`);
  replaced the raw cross-build equality with content-digest equality + the stored golden.
- `freshness:` — repack-vs-stage parity now compares `contentDigest` (repack side computed
  in `packRubygemsArtifacts` before tmp cleanup; record side re-derived from the
  `.border/dist` file bytes inside `verifyArtifactFreshness`). The test record is seeded
  from the STAGE artifact (repo-relative `.border/dist/...` path — the shape
  `recordCheckRun` writes) instead of the bare repack names. Dirty-tree and changed-bytes
  fail-closed cases unchanged (and are now deterministic on every builder).

## Channels golden: key-input audit (enumerate first, then normalize)

The failing assert was `fp.key === GOLDEN_KEY`. The key is
`sha256(stableStringify({headSha, porcelainDigest, rulesHash, exposureSet, refSet,
effectiveTargets}))` (`src/ledger.ts:73` → `computeCheckKey`); `rulesHash` comes from
`computeRulesHash` (`src/redact.ts:183-209`): lines `config:<digest>`,
`rule:<abs path>:<file sha>`, `prompt:<abs path>:<file sha>`, `engine:<name>:<version>`,
sorted, hashed.

| Key component / rulesHash input | Carries toolchain/environment truth? | Evidence / normalization |
| --- | --- | --- |
| `headSha` | n — fixture commit time-fixed (`GIT_AUTHOR/COMMITTER_DATE=2026-01-01T00:00:00Z`) and identity-pinned (`git -c user.name/email`, `gitInit -b main`); git records mode 644/755 only, so umask cannot move the tree | pinned verbatim `b838689d96b1a1cda8d2919ec3c716f23210a5f2` |
| `porcelainDigest` | n — fixture repo is under `test/tmp` (not shared with the outer repo); untracked entries collapse to `?? <dir>/` lines (`.npm-cache/`, `build/`, `pushdemo.egg-info/`), names machine-independent (setuptools 78.1.1 pinned both sides) | pinned verbatim `5782837b399a70eb135d2f1c2ac96ba010ff6e13f1800e14e6b8b9416effd8e3` |
| `rulesHash` ← `config:` line | n — sha of canonical JSON of the effective config (no paths) | rides the normalized pin |
| `rulesHash` ← `rule:`/`prompt:` line PATHS | **y — THE drift**: absolute paths (`/home/lab/...` vs `/home/runner/work/...`); dev-box-only constant by construction (header of the old test said so) | canonicalized to repo-root-relative labels in a recomputed NORMALIZED rulesHash, pinned `a2b167c44bc8371029647790cc6a836aaecebdd1f17ff9eca3dfa00f6709412d` |
| `rulesHash` ← `rule:`/`prompt:` FILE DIGESTS | n (identical blobs in both checkouts) | ride the normalized pin — an edit to ANY residue/release/vendored/prompt source still rotates it (stale-PASS mechanism preserved) |
| `rulesHash` ← `engine:` lines | vacuous here — the fixture sets `engines.require: []`, so `probeEngines` returns `{}` and no engine lines exist (verified locally; the normalized recipe still mirrors the engine loop so a future require-set edit rides the pin) | pinned via recipe mirror |
| `exposureSet` | n — sanitized fixture URL + `npm/pypi name@version` from fixture files | kept verbatim |
| `refSet` | n — `refs/heads/main` only (branch name pinned by `git init -b main`; no tags) | pinned verbatim |
| `effectiveTargets` | n | pinned `["git","npm","pypi"]` |
| DRY-RUN stdout + exit | n — filenames + config URLs | kept verbatim (unchanged goldens) |

The raw `GOLDEN_KEY` is retired (dev-box-only value; provenance chain kept in the test
comment). The suite now pins every component above AND independently recomputes
`sha256(stableStringify({…six fields…, rulesHash: fp.rulesHash}))` against `fp.key`, plus
asserts `fp.rulesHash === computeCheckRulesHash(<probed inputs>)`. Net coverage vs the old
single hash: key field-set/order/serialization drift — still caught (composition
recompute); any fingerprint-source byte drift — still caught (normalized pin); checkout
path string — the ONLY tolerated input (and the ledger's real key still contains it
verbatim — border's per-checkout PASS invalidation is UNCHANGED product behavior; only
this TEST tolerates it). No need to stop-and-report: the env truth (path labels) is fully
normalizable without gutting the pin.

## Dispatch log (runner, branch-limited, 3 runs)

| Run | Purpose | Result |
| --- | --- | --- |
| `34625533451` | dispatch #1: decomposed channels golden + first .gem normalization (minus rubygems_version/gem_version/date only) | gate red as expected; **channels golden + gem freshness FLIPPED GREEN on the runner**; `+stage` remained — the 3.4.20-vs-3.6.7 metadata stream carries six EMPTY legacy keys the first recipe did not neutralize. Log slice: `w32-runlogs/red-stage-34625533451.log` |
| `34628338539` | dispatch #2: + empty-legacy-key filter (fix pre-proven locally by building under rubygems-update 3.4.20: b1 == b34a == b34b digests) | gate red, but the sanctioned trio is now ALL GREEN (`stage` gone from actuals); NEW unrelated red `I4 dry-run registry lines…` (see Residual). Log slice: `w32-runlogs/green-trio-red-i4-34628338539.log` |
| `34629359428` | dispatch #3 (clearly converging per the brief): stability proof, no code change vs #2 | **GREEN: `release gate green: 707 tests / 695 pass / exactly 2 sanctioned failure(s) matching the allowlist`** — exact set == {C5-1, C5-4}; `Publish skipped (dry run via workflow_dispatch)` → `dry-run: publish only on v* tag push`. Log slice: `w32-runlogs/final-green-34629359428.log` |

Gating verified BEFORE the first dispatch (same as W3.1): `on:` triggers are `push: tags
['v*']` and `workflow_dispatch` only (publish.yml:24-28); the publish step is
`if: github.event_name == 'push'` (:227) and the dispatch path prints the dry-run note
(:231-234) — no `workflow_dispatch` can ever publish.

## ALLOWLIST v3 → v4 (`.github/workflows/publish.yml`)

Dropped (retired at source by this wave): `channels golden: …`,
`stage: real gem build …`, `freshness: rubygems repacks …` + their dev-box-golden comment lines.
Kept EXACT-SET (unchanged titles, `# PLANNED WIP red` comments verbatim): `C5-1 subset
discipline`, `C5-4 ordering`. All fail-closed machinery (counts balance, newly-passing ⇒
red, exit-1 expectation) untouched.

## Residual / notes (NOT fixed — out of this wave's named scope)

- **NEW runner flake discovered: `I4 dry-run registry lines…` (test/push.integration.test.ts:415).**
  Green on dispatch #1 and #3, RED on dispatch #2 with byte-identical test code (W3.1 fix
  untouched since 583c76c) and my #1→#2 delta provably unable to reach the npm/verdaccio
  path (gem-only digest filter + rubygems test + workflow comment). Local reproduction
  attempts (isolated runs incl. CPU-loaded) stayed green; the TAP YAML error detail is not
  recoverable because the gate step deletes its `$TEST_LOG` (`tail -n 20` shows only the
  summary). Owner suggestion: give the gate step a `grep -A25 '^not ok '` dump on diff
  failure (a publish.yml change beyond the ALLOWLIST lines, hence deliberately NOT done here).
  The exact-set gate converts ANY such flake into a red gate — same failure class W3.2 just
  eliminated for the gem duo, one file further out.
- `stage:` TAP title still reads "deterministic sha256" — the determinism is now content-
  normalized; title kept stable on purpose (allowlist history greppability).
- The freshness proof for `.gem` on environments whose builder embeds real per-entry
  SOURCE mtimes inside data.tar.gz: those fields are dropped from the parity digest by
  design (they are checkout-time truth, not git truth — git never stores mtimes). The
  publish re-hash (raw) and the fingerprint key (HEAD+porcelain content) still certify the
  exact bytes shipped.

## Handoff

- Branch `forensics/w32-normalization` (pushed):
  - `4c916a9` test(w3.2): normalize the three dev-box goldens; allowlist v3->v4
  - `58b173f` fix(w3.2): .gem content digest also drops RubyGems 3.4.x empty legacy keys
  - (this file) — NOT merged (human gate).
- Same branch diff applied UNCOMMITTED to the `main` working tree for root verify+commit.
- Product change (flagged loudly in the DONECLAIM as audit-proven product-side):
  `src/ledger/freshness.ts` — the rubygems skip-ledger parity moved from raw-sha to the
  normalized content digest. Rationale: with raw parity, `border check` on any
  rubygems-<3.6 environment (e.g. the runner image) could NEVER honor a gem-bearing skip
  (second-boundary byte drift ⇒ always full re-check), silently voiding the documented
  repack-freshness feature; publish-time same-bytes proof and ledger digests remain raw.
  Local 3.4.20/3.6.7 cross-build proof above is the pre-CI verification.
