# border

A fail-closed pre-push gate for git, npm, PyPI, crates.io, and RubyGems. It scans your repo for secrets and
supply-chain risk, then refuses to let anything leave the machine unless a fresh, unbroken
check passed for exactly the state you are about to publish.

```bash
npm install -g border-customs
cd /path/to/your/repo
border check
```

Requires Node >= 22 and the `gitleaks` binary on `PATH` (border vendors the rule config for
gitleaks 8.30.1; the binary itself is yours to install, same as `git`). secretlint runs
in-process as a bundled dependency. Each registry leg additionally shells out to its platform's
own publisher, which must be on `PATH` whenever that target is configured; a missing publisher
binary is exit 2, never a skipped leg:

| Registry target | Publisher border runs | Version the same-bytes proofs were measured on |
| --- | --- | --- |
| `npm` | `npm` | (unchanged since 0.1.0) |
| `pypi` | `python3 -m build` / `python3 -m twine` | (unchanged since 0.1.0) |
| `crates` | `cargo` | cargo 1.93.1 (rustup) |
| `rubygems` | `gem` | RubyGems 3.6.7 on ruby 3.3.8 |

Other toolchain versions of `cargo` and `gem` are untested by those byte-determinism proofs.
Optional engines are listed in [Configuration](#configuration).

## The problem it solves

The usual secret workflow is leak-then-repent: `git push`, notice the AWS key in the diff
review (or not), then `git filter-repo`, force-push, revoke the credential, and email the
security list. Post-hoc scrubbing fails for two mechanical reasons. Force-pushing a public
branch is history rewriting: clones, forks, CI caches, and package mirrors already hold the
bad objects. And published package versions are effectively forever: npm's unpublish policy
forbids reusing a `name@version` once it was ever used, and PyPI yanking is non-destructive.
The only cheap fix is to not cross the boundary, and the only boundary that matters is the
one between this machine and the world.

Git's own `pre-commit` and `pre-push` hooks help, but they gate the *command*, not the
*state*, and they trust whatever ran last. border inverts that: a push is only allowed when
a check passed for the exact fingerprint of what would be pushed, where "what would be
pushed" includes the six things people forget:

- **Untracked and dirty files are inputs too.** History scanning alone misses the `.env`
  that was never committed but will ride along in a `git add -A`. border fingerprints the
  full `git status --porcelain` digest and scans the working tree directly.
- **Deleted-but-pushed blobs.** A secret removed in a later commit still ships in the
  history of the ref being pushed. The history leg scans everything the push would
  transmit, not just HEAD.
- **Archives.** Tarballs and zips inside the repo are unpacked and scanned with
  `<archive>!<inner-path>` attribution.
- **The published bytes, not the source tree.** `npm pack`, `python -m build`,
  `cargo package`, and `gem build` rewrite what ships. border packs/builds once into
  `.border/dist/`, scans those exact bytes, and re-hashes them again at publish time.
- **The registry.** Pushing `package.json` at version `1.2.3` when `1.2.3` already exists
  on the registry is a supply-chain event (silent stale artifact, or squatted name). border
  fails the check on "version exists, bump required" and on foreign ownership of your name.
- **Identity.** A repo whose pushed commits are authored by an identity outside your
  allow-list is on fire, and `PASS` from an earlier state does not vouch for it at push
  time; border re-scans identity on the transmit set before every real push.

## Principle

One sentence: **a PASS is a statement about a fingerprint, not about the past.**

```
checkKey = sha256( headSha
                 ⊕ porcelainDigest      # every tracked/untracked/staged byte-change
                 ⊕ rulesHash            # config digest + vendored rules + engine versions + prompt template
                 ⊕ exposureSet          # sanitized remote URLs + npm/pypi/crates/rubygems name@version
                 ⊕ refSet               # branch being pushed + every local tag
                 ⊕ effectiveTargets )   # git, npm, pypi, crates, rubygems as configured for this run
```

Move *any* of those six and the key moves, the stored PASS no longer covers the state, and
border makes you re-check. Committing, editing an untracked file, renaming a remote,
bumping a version, adding a tag, editing `border.yaml`, or an engine version bump all
invalidate. There is no time-based expiry and no "looks the same": the check either covers
this exact state or it does not.

Everything else in the design follows from making that statement unbreakable: the ledger is
append-only and corruption-tolerant, degraded tools poison the verdict instead of hiding
it, and the two registry-facing legs (pre-flight and publish) both have to agree.

## Architecture: what `border check` runs, in order

1. **Config load.** `border.yaml` parsed with zod in strict mode. Unknown keys, bad types,
   or unset `${ENV}` placeholders are hard errors (exit 2), never defaults. If no config
   exists but git remotes do, border infers a `git`-only config and says so on stderr. A
   hidden local overlay `.border/config.local.yaml` is deep-merged for machine-local pins.
2. **Engine policy probe.** Every required engine (default `gitleaks` + `secretlint`,
   overridable with `--require-engine`) must answer a version probe. A missing or broken
   probe yields a `DEGRADED-ENGINE` CRITICAL finding and forces **exit 2 with the verdict
   marked UNTRUSTWORTHY**: border refuses to emit a PASS it cannot mechanically justify.
   An engine whose version output cannot be parsed also exits 2 rather than assuming a
   current tool.
3. **Hostile-config guard.** Before trusting any scan, the HEAD tree is checked for a
   committed `.gitleaksignore` or `.gitleaks.toml`. Those files make gitleaks itself
   obey the repo it should be auditing (verified empirically: one committed ignore file
   turned 1 finding into 0). Their mere presence is a CRITICAL `repo-self-ignores-findings`
   finding, because refusing to trust them is the only fail-closed option. border always
   passes its own vendored config explicitly, so repo-shipped rules cannot replace it.
4. **gitleaks legs.** History scan over the refs a push would transmit (secrets in
   commits unreachable from HEAD still count), working-tree directory scan (archive depth
   2, plus border's own extractor for formats gitleaks misses such as `.tgz`), and a tag
   *message* leg (annotation bodies are pushed with the tag and are not covered by file
   scans). Findings inside extracted archives are re-attributed to `archive!<inner>`.
5. **secretlint leg.** Runs in-process on the git-listed file set with the recommended
   preset, `no-homedir`, `no-dotenv`, plus `border.yaml` rules turned into patterns
   (hosts, IPs, paths). The upstream AWS access-key ID rule ships force-enabled, and
   every secretlint hit's echoed raw value is stripped from messages before persistence.
6. **Native rules.** AI-session artifact detection on a *closed* matcher list
   (`.omo/**`, `**/transcripts/**`, `*.session.jsonl`, `opencode.json(c)`, `.opencode/**`,
   env files except `.env.example`/`.env.sample`, junk like `probe*`/`*.rej`/
   `node_modules/**`, plus your `rules.pathPatterns` through the same compiler). Identity
   allow-listing over commit authors, merge committers, and annotated-tag taggers, checked
   against the history of every ref *and* against the object set a remote does not already
   have (the transmit set). Oversized-file, checked-in-binary, and notebook-output rules
   round it out.
7. **Registry pre-flight** (npm, PyPI, crates.io, and RubyGems targets). Three outcomes per
   target: version already published ⇒ CRITICAL `version-exists` ("bump version required");
   name owned by someone outside your `rules.authors` allow-list ⇒ CRITICAL
   `name-foreign-owner`; ambiguous ownership signals ⇒ also CRITICAL, because guessing wrong
   is how squats ship. Critically, **silence never means absent**: an empty stdout from
   `npm view`, a non-200 non-404 PyPI response, a crates.io 403 (the API rejects requests
   without a self-identifying User-Agent; border sends one, and a 403 still stops the gate
   instead of being read as "not published"), a rubygems 404 whose body text does not match
   one of that API's exact *absent* messages (its 404s are text, not JSON, and an
   unrecognized one is never guessed), a timeout, or unparseable JSON all fail closed as
   exit 2. An unreachable registry blocks the push instead of letting it run blind.
8. **Artifact stage.** If registry targets are configured, packages are built **once** into
    `.border/dist/` (`npm pack --ignore-scripts`, `python -m build --no-isolation`,
    `cargo package --allow-dirty --no-verify`, `gem build <name>.gemspec -o .border/dist/`),
    that exact byte-stream is scanned (gitleaks + secretlint over the extracted contents),
    manifest-diffed (lifecycle `preinstall`/`install`/`postinstall`/`prepare` hooks are
    CRITICAL; entries outside the `files` whitelist are HIGH; PyPI sdists get a
    `sdist-unexpected-file` HIGH because setuptools builds from the working tree and is
    `.gitignore`-blind), the npm and PyPI artifacts are additionally checked with
    `publint` / `twine check --strict`, and everything is recorded as
    `{file, sha256, bytes}` in the ledger.
    At publish time the *same bytes* are re-hashed: any mismatch is exit 2, before the wire.
    The crates leg carries one extra assertion because `cargo publish` repackages from the
    manifest instead of uploading the staged file: immediately before the spawn, border
    re-runs the check's exact `cargo package` into a throwaway directory and refuses to
    publish if the fresh digest differs from the certified `.crate`. `gem push` uploads the
    recorded `.gem` byte-for-byte, so it needs no such re-assertion.
9. **Report.** Findings carry `valueDigest` (sha256 of the matched value) and a masked
   snippet: fully blocked for short values, else `first4…last4`. Raw secret bytes never
   leave process memory. A per-run `TextSanitizer` holds the digest-to-value registry and
   replaces every flagged literal in *all* rendered text, including agent-written strings in
   the LLM layer, so a secret cannot reappear inside a message about itself. `report.json`
   (canonical, byte-stable for machines) and `report.md` land under `.border/runs/`.
10. **Ledger record.** A PASS is appended to `.border/ledger.jsonl` together with the key
    and artifact digests. Degraded and NO-OP runs can never write a PASS.

```bash
$ border check          # full scan, ~seconds on a mid-size repo
$ border check          # identical state: no re-scan
SKIP 35ffb3cb — PASS 2026-09-04T18:11:44.976Z report .border/runs/35ffb3cb-.../report.json
```

The **skip-ledger** is what makes the gate cheap enough to run on every push: a repeat
`border check` on an unchanged fingerprint replays the recorded verdict in well under a
second. The replay is not blind trust. Before honoring a skip border re-derives the live
fingerprint (including engine probes), refuses skips recorded in the other LLM mode, and
re-packs npm, crates, and rubygems artifacts to prove the recorded digests still match fresh
byte-for-byte (a dirty tree, a drifted `package.json`, or a changed npm version all force a
full re-check; `cargo package` is deterministic per HEAD and stamps the sha into
`.cargo_vcs_info.json`, and `gem build` is byte-deterministic only because RubyGems embeds a
fixed default date, which is why a gemspec that assigns `s.date` is rejected outright rather
than certified; PyPI builds are not byte-reproducible, so their skip proof is head+porcelain
equality, and publish still re-hashes the exact dist files). A corrupt ledger line is dropped with a loud
warning, never a crash, and never a silently empty history.

### The residue scan (0.3.0)

The artifact stage no longer treats every install-time hook as one blanket CRITICAL. Packed
and built bytes are additionally run through a **closed signature table** that classifies what
an installer *does*, per tier — the split behind opencode-ai's in-tree `postinstall.mjs`
(legit) vs. a `curl … | bash` rc-appender (not):

| Tier | Rule | Severity | One-liner |
| --- | --- | --- | --- |
| T0 | *(no finding)* | — | Silent install: recorded in the ledger, never flagged. |
| T1 | `residue-in-tree-hook` | MEDIUM | Hook that only touches its own package tree and matches one closed safe-shape signature (the opencode-ai anatomy). Unknown hook shapes keep the original CRITICAL row verbatim — T1 is the ONLY downgrade in 0.3.0. |
| T2 | `residue-install-download` | HIGH | Install-time network fetch: bytes that never passed registry review run on every consumer install. |
| T3 | `residue-out-of-tree-write` | HIGH | Writes outside the package dir: shell rc files, `profile.d`, `git config --global`, `authorized_keys`, `%APPDATA%`, PATH-carrier lines (`setx /F PATH`, `HKCU\Environment`, …). |
| T4 | `residue-persistence-primitive` | CRITICAL | Any reference to cron / `systemctl --user` / `launchctl` / XDG autostart / `schtasks` / registry Run keys in install-time code or anything it reaches. Malware class: no legitimate pass exists. |
| cross | `residue-cross-manager-write` | HIGH | A lifecycle/build script spawning a *foreign* package manager (`pip install --user` from npm…): files land on another ledger and reclaim by this ledger is impossible by construction. |
| pairing | `residue-pairing-missing` | HIGH | A `# BEGIN <id>` marker-block WRITE whose symmetric REMOVE path or CLI inverse is absent. Detection only: a verified pair still pays the T3 HIGH — waiver downgrade is 0.4.0's roundtrip valve. |
| gem | `residue-gem-unmatched-extension` | MEDIUM | A Ruby `extensions:`/build hook the classifier cannot resolve — surfaced, never silently clean. |

The pairing classes behind these rows (multi-channel PASS **C5** subset/ordering discipline;
**C9** interpolated-and-indirected root spellings; **C10** comment/quote-boundary shapes that
once silent-passed) are frozen with their evidence in
[src/artifacts/RESIDUE-CONTRACT.md](src/artifacts/RESIDUE-CONTRACT.md).

**Fail-closed:** a residue scan whose rule table or classifier sources cannot be read is exit 2,
never a silent pass — and the classifier source bytes are part of the ledger `rulesHash`, so
editing any signature invalidates every cached PASS even at the same commit.
**Opt-out:** `residue: { enabled: false }` in `border.yaml` (strict; unknown sibling keys exit 2)
hides exactly the rows above from the report and verdict and nothing else; flipping it changes
the fingerprint and forces a re-check rather than honoring a stale PASS.

**Boundary honesty.** Static analysis proves *capability*, not *fact*: a T2 row says the
installer *can* fetch and run remote bytes at install time, not that it shipped malware, and a
clean residue scan is an absence of matched signatures, never a certificate of benign intent.
The signature table is deliberately closed, and the list of shapes it **cannot see** —
content-writes, handle-variants, dead spellings, interpolation-then-slash, span-quirk
over-blocks, IO-instance writers, user-shadowed bare verbs — lives in
[RESIDUE-CONTRACT.md §8](src/artifacts/RESIDUE-CONTRACT.md); this README points, it does not
restate. The empirical roundtrip (install → snapshot → uninstall → rc-delta-zero) is the 0.4.0
valve. **border is NOT a malware sandbox**: it never executes, intercepts, or sandboxes the
code it reads; it matches text and blocks the push.

#### Proof valve: `residue.requireProof` (0.4.0)

Static analysis stops at capability. `residue: { requireProof: true }` (strict; default **off**)
raises the bar for publish channels: when the residue scan flags a blocking-capable finding on a
staged artifact, `border check` can no longer PASS that channel on signatures alone — the
artifact's sha256 must also carry a **fresh empirical roundtrip verdict** in the ledger.

The check gate NEVER runs Docker itself (there is nothing to trust it to run); the proof is
pre-supplied out-of-band by `border roundtrip <spec>`, which installs the real bytes, diffs the
filesystem, and appends a `t:"roundtrip"` ledger record — `{artifactSha256, verdict:
clean|residue, rulesHash, ts, rows}` — keyed by the exact bytes it fetched. A `residue` verdict
still counts as a proof-of-fact: the valve demands *evidence someone looked*, and the finding
itself keeps blocking until it stops tripping the scan.

- Missing proof ⇒ new native CRITICAL `roundtrip-proof-missing`; proof whose `rulesHash` no
  longer matches (classifier, engine, or config changed — including the flag flip itself) ⇒
  `roundtrip-proof-stale`. Freshness is exactly the fingerprint pattern: rotating the policy
  invalidates cached verdicts, PASSes included.
- `border roundtrip` records by default (`--record` is the default; opt out with `--no-record`).
- Both new rules are ordinary findings: the allow-list can waive them and every waiver is
  enumerated in `allowHits` — no hidden channel.

### Running `border roundtrip`

`border roundtrip <[ecosystem:]name@version>` fetches the real registry bytes, installs them in a
throwaway Docker container (per-ecosystem image, whole-filesystem content-hash manifest before
install and after the manager's own uninstall), prints the residue manifest, and records the
verdict. Known fidelity envelope, from the W2.0 spike and the W2.3 registrar-chain demo:

- Docker is required; absence or any step failure ⇒ exit 2, never a silent `clean`.
- npm/gem/crates lanes diff exactly; the pypi lane reports pip's left-behind **transitive
  dependencies** as orphan rows (calibration to a target-only diff is a known follow-up —
  the over-report direction is deliberately conservative).
- Only manager-lifecycle surfaces are observed: persistence performed by explicitly-invoked
  bins (not npm hooks) is outside what the roundtrip watches — W2.3 measured exactly this
  blind spot on our own registrar and documented its `{"plugin": []}` config residue.
- A `clean` verdict is proof-of-fact about one artifact version on one machine class, not a
  security guarantee.

## Architecture: `border push`

`border push` is a state machine over per-target states, recomputed from live git queries,
never from cache:

| State | Meaning |
| --- | --- |
| `PUSHED` | remote already holds every ref at the local value (checked via `git ls-remote`, full-ref compare, tags compared *peeled*) |
| `PENDING` | this target needs to move, and the current fingerprint has a PASS behind it |
| `BLOCKED` | no PASS for this state (run `border check`), or a registry finding says stop |

- Bare `border push` is a **DRY-RUN**: it prints the exact `git push --dry-run` /
  `npm publish` / `twine upload` / `cargo publish` / `gem push` lines it would run, refuses
  to act, and exits with the gate's verdict. `--yes` is what executes. The real line shapes
  per channel are in [What `border push` actually runs](#what-border-push-actually-runs).
- Multi-remote git push is **all-or-nothing before anything moves**: every remote × every
  ref must be a fast-forward, checked up front. If any remote diverged, border prints
  `DIVERGED` with the offending shas and pushes nothing. **It never force-pushes; there is
  no flag for it.**
- Registry legs go through the same gate as push: a PASS record for the current key, then
  the artifact re-hash match against `.border/dist/`, then an immediate version-exists
  re-probe (the registry is allowed to change between check and publish), then the upload
  with `stdio: inherit` so `npm`, `twine`, `cargo`, and `gem` OTP and credential prompts
  reach you untouched. border never reads, stores, or handles registry tokens (including
  `CARGO_REGISTRY_TOKEN` and `GEM_HOST_API_KEY`, which the publisher tools own). Published versions are not
  retried on failure because a half-published version can never be republished.
- If one remote of several succeeded before a failure, border says so explicitly (PARTIAL)
  and exits 1; a rerun of `border push --yes` picks up only the still-PENDING targets.

### What `border push` actually runs

Every DRY-RUN line is rendered from the same argv source as the real publish spawn (one line
per recorded artifact row, execution order `git` remotes, then npm, PyPI, crates, rubygems).
For a repo configured like the five-target `border.yaml` in
[Configuration](#configuration), the plan prints as:

```bash
$ border push
border DRY-RUN: no --yes, so nothing runs — this is the plan (m-R5-a) contract
  DRY-RUN: git push --dry-run origin --follow-tags  (https://github.com/acme/widgets.git)
  DRY-RUN: npm publish .border/dist/widgets-1.2.3.tgz --registry https://registry.npmjs.org
  DRY-RUN: twine upload --repository-url https://pypi.org .border/dist/widgets-1.2.3-py3-none-any.whl .border/dist/widgets-1.2.3.tar.gz
  DRY-RUN: cargo publish --allow-dirty --no-verify
  DRY-RUN: gem push .border/dist/widgets-1.2.3.gem --host https://gems.acme.example
```

- `cargo publish` is the one line with no filename: the command takes no positional `.crate`
  (verified against cargo 1.93.1 `--help`; it always repackages from the manifest), so the
  pre-publish repackage digest-assert described in step 8 of the check pipeline is what pins
  the upload back to the certified bytes. Divergence is exit 2 before anything is sent.
- `twine upload` is a single row carrying every recorded `.whl`/`.tar.gz`; `npm publish` and
  `gem push` get one row per staged file.
- A `--registry` / `--repository-url` / `--host` flag appears only when the config sets it.
  With `targets.npm.registry`, `targets.pypi.repository`, and `targets.rubygems.host` unset,
  the lines are the bare `npm publish <file>`, `twine upload <files...>`, and
  `gem push <file>`, and the tool's own defaults decide where bytes go.
- If the fingerprint has no PASS covering a target, dry-run cannot list its artifacts and
  prints `DRY-RUN: <target> registry leg: run 'border check --force' first — dry-run cannot
  list artifacts` in place of the command lines.

## Architecture: the LLM layer (optional, agent-executed)

border itself **never calls any model API**. The `--llm` layer is a two-file handoff with
the operator's own agent (Claude, Codex, a human with a chat tab):

```bash
border check                    # must pass for the current state first
border llm-request              # writes .border/runs/<key8>-.../llm-request.json
#    → your agent reads the bundle, follows the embedded prompt template,
#      and authors findings.json (a strict array; [] is a valid PASS statement)
border llm-ingest findings.json # validates, re-scrubs, recomputes the verdict
```

The request bundle is a *masked* review context: the diff versus the remote tip (or a
stated full-tree diff on first push, truncated over 10 MiB with an explicit marker), the
deterministic findings, artifact digests, and the review prompt with its sha256. Values the
deterministic engines flagged appear only as `[REDACTED:<sha8>]`. The ingest side validates
every agent finding against the schema, rejects any finding whose `path` is not in the
bundle (an agent inventing locations is a hard error, exit 2), forces `engine: "agent"`,
computes digests itself rather than trusting agent-supplied ones, re-runs the sanitizer over
agent free text, and records an `llm: true` PASS that plain checks cannot ride and vice
versa. The residual risk is stated in the bundle itself: masking only covers values the
deterministic layers already found, so an undiscovered secret in diff context *can* reach
your LLM endpoint. That is the accepted boundary of this optional layer; the deterministic
layers remain the actual gate.

## Commands

```
border <command> [options]
```

| Command | Purpose |
| --- | --- |
| `check` | run the secret + supply-chain gate on the pending scope |
| `push` | gate-verified push; DRY-RUN unless `--yes` |
| `status` | newest gate records per target |
| `llm-request` | emit the masked review bundle for LLM-authored commits |
| `llm-ingest <findings.json>` | validate agent findings and record the combined verdict |
| `scan <[ecosystem:]name@version>` | inspect a third-party published artifact for residue before installing it |

Every subcommand accepts the same global flags (verified against `border <cmd> --help`):

| Flag | Effect |
| --- | --- |
| `--config <path>` | config file; default `./border.yaml` |
| `--targets <list>` | comma-separated `git,npm,pypi,crates,rubygems` subset restricting this run's scope; a named target that is not configured is exit 2 |
| `--force` | ignore the skip-ledger, re-run the full check |
| `--yes` | execute mutations (push only); without it a push is always DRY-RUN |
| `--require-engine <list>` | replaces the required-engine set from config; unknown or unprobeable names degrade the run (exit 2) |
| `--llm` | opt this check into the LLM review layer (a plain check can never satisfy an llm-recorded skip) |
| `--json` | machine-readable report on stdout (check, scan) |
| `--help, -h` | usage table |

### Exit codes (the contract)

| Code | Meaning |
| --- | --- |
| `0` | PASS (or no-op): MEDIUM / LOW / INFO findings are allowed and listed |
| `1` | gate-blocked: HIGH or CRITICAL findings; or a push refused (BLOCKED targets); or a partial push |
| `2` | the gate could not answer: config error, missing/degraded engine, unreachable registry, malformed input, concurrent lock holder |

The `2` class matters as much as `1`: a tool error never exits 0, and no exit-0 run ever
rests on a leg that silently skipped. Engine exit codes are translated against a closed
matrix (`gitleaks` 0/1, `trufflehog` 0/183, `secretlint` 0/1); *anything* else, including a
126 from gitleaks, is exit 2, never "clean".

### `border scan` — inspect a third-party package before installing it

```bash
border scan puppeteer@23.11.1   # npm is the default ecosystem
border scan pypi:requests@2.32.3
border scan crates:serde@1.0.219
border scan rubygems:rails@7.1.1
```

`border scan <[ecosystem:]name@version>` fetches that exact published artifact from its
registry, materializes it in a throwaway temp directory, and runs the same engine stack
`check` runs — secrets plus the T0–T4 residue classifiers — over the bytes you are about
to install. `--json` emits the standard machine-readable report.

**Capability, not fact.** A scan verdict proves what the package *can* do — persist past
uninstall, write outside the install tree, run hooks on every consumer install — because
those shapes are readable in the published bytes. Proof that a package *did* persist is
the uninstall-roundtrip valve, and it ships in 0.4.0; until then treat a scan as pre-install
risk triage, never as post-mortem evidence.

Scan touches neither side of your work: it reads no ledger and writes no skip records (every
scan is a full scan), and it creates no `.border/` in your repo — the fetched artifact and
its temp git tree live in the sandbox and are destroyed when the run ends. Exit codes follow
the same contract: `0` clean, `1` blocking (HIGH/CRITICAL) findings, `2` the scan could not
genuinely run — unreachable registry, malformed spec, a tree shape the engines cannot
consume. A scan that could not run never prints a clean verdict.

crates artifacts get one **envelope normalization** before staging: a registry `.crate`
ships three files — `Cargo.toml.orig`, `.cargo-ok`, `.cargo_vcs_info.json` — that
`cargo package` rejects as reserved, so scan drops them before the rebuild and logs each
dropped file to stderr with the sha256 of its original bytes
(`border scan: crates envelope normalized: <file> sha256=<hex>`); the rebuild regenerates
them from the normalized manifest, so no scanned byte is silently lost.

### Engines in consumer installs

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

## Configuration

Everything border can be told lives in `border.yaml` at the repo root. Unknown keys are
rejected at load (a typo in a gate config is a gate you did not ask for). `${VAR}`
expansion applies only to remote URLs and registry/repository/host values, and an unset variable
is a hard error, never an empty string.

Minimal, a git-only repo:

```yaml
version: 1
targets:
  git:
    remotes:
      - name: origin
        url: git@github.com:acme/widgets.git
rules:
  authors:
    emails: [devs@acme.example]   # identity allow-list: commits authored by
    names: [Acme Dev]             # anyone else are CRITICAL findings
  hosts: []                       # extra detection patterns (internal hostnames…)
  ips: []
  pathPatterns: []
```

`rules` is required by design: a gate with silent defaults is a gate you did not ask for.

A repo that publishes a package, with the full surface (every one of the five channels, new in
0.2.0; a config without `crates`/`rubygems` behaves exactly as it did on 0.1.0):

```yaml
version: 1
targets:
  git:
    remotes:
      - name: origin
        url: https://github.com/acme/widgets.git
  npm:
    registry: https://registry.npmjs.org    # optional; any npm-protocol registry works
  pypi:
    repository: https://pypi.org            # optional; TestPyPI or private indexes work
  crates:                                   # optional; public crates.io only — there is
    name: widgets                           #   deliberately no url/host key; overrides
                                            #   the Cargo.toml [package] name when set
  rubygems:                                 # optional; exactly one *.gemspec at HEAD,
    name: widgets                           #   this only disambiguates multi-gemspec repos
    host: "${GEM_HOST}"                     # optional; any gemcutter-compatible push host,
                                            #   ${VAR} expansion allowed on this field only
rules:
  authors:                                  # identity allow-list
    emails: [devs@acme.example]
    names: [Acme CI]
    allowBots: true
  hosts: ["git.internal.acme.example"]      # turned into detection patterns
  ips: ["10.20.30.40"]
  pathPatterns: ["/Users/*", "*.pfx"]
  maxFileKB: 500                            # oversized-file threshold (default)
allow:                                      # enumerated suppressions, never blanket
  - { rule: "junk-artifact", match: "*", file: "test/fixtures/**" }
engines:
  require: [gitleaks, secretlint]           # trufflehog: true adds the third-party engine
residue:
  enabled: true                             # default; false hides ONLY the residue-* rows
```

Notes that change behavior:

- `targets.git.remotes: []` (explicit, empty) is a *deliberate* repo-local scope: all
  history/tree/identity/artifact legs still run, only the exposure set is empty. A
  completely missing config with real remotes falls back to config-from-`git remote` with
  a loud stderr warning.
- `targets.crates` reads its coordinates from `git show HEAD:Cargo.toml` and accepts only a
  literal `[package] version`; a workspace-inherited or computed version is exit 2 telling
  you to set a literal one. There is no crates.io host/registry key *by design*: the channel
  is pinned to public crates.io, and an unknown key there is rejected at load rather than
  quietly ignored (or silently trusted as a private-registry config the pre-flight cannot
  probe).
- `targets.rubygems` discovers `*.gemspec` files at HEAD; exactly one may exist unless
  `targets.rubygems.name` selects one, and `s.name`/`s.version` must be literals (computed
  versions are exit 2, border never evaluates gemspec code to find out). A gemspec assigning
  `s.date` is rejected wholesale: `gem build` is byte-deterministic precisely because it
  embeds a fixed default date, so an explicit `s.date` breaks the digest proof border would
  otherwise be certifying. `host` redirects both the probes and `gem push --host`, and is
  the only `${VAR}`-expandable field of the two new targets.
- Every `allow` entry must be scoped (a `file` pin); `{rule: "*", match: "*"}` with no
  file is rejected at load. Suppressed findings are enumerated in the report's
  `allow-hits` section, so an exit 0 never hides what it hid.
- `rules.hosts/ips/pathPatterns` feed the same matcher pipeline as the built-ins, so your
  patterns get the same archive attribution and the same allow-listing semantics.
- `residue.enabled` (0.3.0) is the only sanctioned skip of the residue scan; its default is
  `true`, an unknown sibling under `residue:` is a typed exit 2, and — unlike an `allow`
  entry, which suppresses findings while *listing* them — turning it off changes the
  fingerprint, so no PASS certified with residue on can ever skip a run that has it off.
- 0.2.0 adds the `crates` and `rubygems` channels; existing configs are unchanged. Channels
  are opt-in by the presence of their `targets.<id>` section, and the ledger's append-only
  format means old records keep parsing: `confirmedVia` gained two enum members
  (`crates-json`, `rubygems-json`), 0.1.x ledgers are accepted as-is and never rewritten.

## Integration

**Git hook.** The gate is one command, so the classic one-liner is exactly:

```bash
printf '#!/bin/sh\nexec border check --force\n' > .git/hooks/pre-push && chmod +x .git/hooks/pre-push
```

`check` exits nonzero whenever the push it would gate is not covered, so any push through
the hook must first pass. Drop `--force` to get sub-second skip-ledger replay instead of a
re-scan on every `git push`.

**CI.** `border check --json` emits the stable report object; gate on the exit code, parse
`verdict`/`counts` for dashboards. In CI you typically want `--force` on a cache-less
runner, plus your `gitleaks` binary provisioned in the image (a degraded run exits 2, which
most CI maps to red; that is the point).

**Agents.** `skills/border/SKILL.md` ships with the repo: it teaches an operator agent (the
same one that wrote the commit) how to run the five subcommands, how to produce a valid
`llm-ingest` findings file, and the two standing rules for agents driving pushes: never pass
`--yes` without a visible human go-ahead, and never push over an exit-2 gate.

## What this is not

- **Not a vault or secret manager.** It detects credentials on their way out; it does not
  store, rotate, or inject them.
- **Not a history rewriter.** If a secret is already in a pushed commit, the fix
  (`git filter-repo` plus credential rotation) is explicitly out of scope and named in the
  finding text. border refuses rather than rewrites.
- **Not an escape hatch.** There is no force-push flag, no `--i-know-what-im-doing`, no
  per-run expiry of a missing PASS. The refusal paths are the product. If a check cannot be
  trusted (engine gone, registry unreachable), the result is stop, not proceed.
- **Not a config runner.** You cannot define a custom channel or override what border
  shells out to (a `push.command`-style escape hatch is deliberately absent). A user-defined
  command would void the two properties the gate exists to provide: the same-bytes proof
  (only a built-in channel descriptor knows which artifact bytes the check certified and can
  re-hash exactly those before the wire) and the fail-closed registry pre-flight (only a
  built-in knows each registry's response polarity: which status and which body string mean
  *absent*, and that everything else is silence, which never means absent). Free-form
  commands would turn "a PASS covers this exact state" into "a PASS covers whatever your
  script happened to run": a config runner wearing a gate's clothes. Channels are built-in
  only; adding one means shipping a descriptor whose probe, packaging, and byte-determinism
  were measured against the real registry first.
- **Not a replacement for review or branch protection.** It gates *this machine's* push
  surface; server-side controls still own everything else.

## Security posture

- **Redaction is the default output channel.** Findings, reports, status lines, and agent
  text all flow through masked snippets (`valueDigest` + `first4…last4`, full block for
  short values) and the run-scoped sanitizer; raw matched bytes never leave memory.
- **Fail-closed doctrine.** "Silence never means absent" is applied mechanically: empty
  registry stdout, unparsed versions, non-translatable exit codes, unresolvable ownership,
  corrupt-but-present rules inputs, all become exit 2 or a CRITICAL, never a pass.
- **No telemetry, no callbacks.** `border check` touches the network only for the
  registry pre-flight, against the URLs the channels define: `registry.npmjs.org`,
  `pypi.org`, and `rubygems.org` are overridable (private indexes; `targets.rubygems.host`),
  and the crates.io leg is pinned to public `crates.io` with no override by design.
- **No credential handling.** Subprocess publishes inherit stdio so tokens and OTP prompts
  go between you and `npm`/`twine`/`cargo`/`gem`, never through border.
- **State is inert.** Everything border writes lives in `.border/` (ledger, run archives,
  dist, lock), which carries its own `.gitignore` with `*` so a `git add -A` cannot stage
  it, and which every scan leg refuses to treat as a finding source or an allow-list
  target. A repo that *tracks* `.border/**` is itself a CRITICAL finding. A single-writer
  lock makes concurrent runs exit 2 instead of racing.

## Changelog

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

## License

MIT, see [LICENSE](LICENSE).

## 中文概要

border 是一个 fail-closed(失败即拦截)的推送前门禁 CLI:`npm install -g border-customs` 安装,在仓库里跑 `border check`。它扫描 git 历史、工作区(未跟踪文件同样是一等输入)、归档、tag 注释和将要发布的 npm/PyPI/crates/RubyGems 字节,检出密钥与供应链风险;只有当"当前状态指纹"存在新鲜且完整的 PASS 记录时才允许 `border push --yes` 放行。指纹是 sha256(head、porcelain 摘要、规则哈希、暴露面、ref 集合、有效目标)六元组,任何一处变动,旧的 PASS 立即失效,必须重查。流水线:gitleaks(历史+工作区+tag,内置 8.30.1 规则,仓库自带的 ignore 文件直接判 CRITICAL)+ secretlint(进程内,AWS Key 规则强制开启)+ 原生规则(AI 会话产物闭集、提交身份白名单含传输对象检查)+ 注册表预检(版本已存在=必须 bump,名称被外人占有=拒绝;空响应/超时/解析失败一律 exit 2,沉默绝不等于不存在)。构件只构建一次进 `.border/dist/`,扫描的就是发布的字节,发布时再哈希比对,不一致直接拒发。跳过台账让重复检查不到 1 秒,但回放前先重算指纹并重新 pack 验证新鲜度。报告只输出掩码片段(sha256 摘要 + 前4…后4)。push 是多目标状态机,多 remote 先做全有或全无的 fast-forward 预检,永不 force-push;npm/twine/cargo/gem 的凭据经 stdio 透传,border 从不触碰。0.2.0 新增 crates.io 与 RubyGems 通道(公开 crates.io 固定、rubygems 可用 host 覆盖私有镜像),既有配置行为不变。0.3.0 新增残留扫描(residue gate):发布字节里的安装期钩子按 T0-T4 闭集签名表分类(闭集 T1 树内钩子降为 MEDIUM,未知形态原样保留 CRITICAL),外加跨包管理器写入、配对标记缺失(`# BEGIN` 块只检测不豁免)与 gem 不可解析扩展共七条 `residue-*` 规则;`residue.enabled` 是唯一豁免开关且改动指纹使旧 PASS 失效,规则表与分类器源码进入 rulesHash,改一个签名即强制重查。静态分析只证明"能力"不证明"事实",border 不是恶意软件沙箱,从不执行被读代码。0.4.0 新增证明阀
`residue.requireProof`(默认关,strict):开启后,发布构件若触发阻断级 `residue-*` 发现,通道 PASS
还要求账本里存在按其 sha256 索引且 rulesHash 新鲜的 `border roundtrip` 实测记录——check 自身从不
运行 Docker,证据由 `border roundtrip` 离线写入(默认记账,`--no-record` 关闭),clean 与 residue
两种裁决都算"事实已在";缺记录判 `roundtrip-proof-missing`、rulesHash 过期判
`roundtrip-proof-stale`(均 CRITICAL/native,与普通发现同受白名单管辖并在 allowHits 枚举),翻转
该配置即轮换 rulesHash,所有缓存 PASS 自动失效。`border roundtrip` 本身保真边界:Docker 必需、
缺失即 exit 2 绝不假装干净;pypi 通道会把 pip 遗留的传递依赖如实报成孤儿行(收窄到目标包自身是
已知后续项);只有包管理器生命周期触发的写入被观测,显式调用的 bin 自写配置不在射程——W2.3 在
自家 registrar 链上实测到该盲区并留下了 `{"plugin": []}` 残留证据。clean 是"某一版本构件在某类
机器上"的事实证明,不是安全担保。可选 LLM 层 border 自身从不调用模型 API:`llm-request` 导出掩码审阅包,`llm-ingest` 严格校验 agent 结论并重算裁决。退出码即合同:0 通过、1 拦截、2 门禁无法作答,任何"工具不健康"都不可能被误读为干净。MIT 许可,无遥测,除你配置的注册表预检外不联网。
