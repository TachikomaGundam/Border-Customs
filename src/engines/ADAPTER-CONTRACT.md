# Engine adapter contract — gitleaks 8.30.1 (todo 4 spike, empirical)

All facts below were produced by running the real binary
(`gitleaks version 8.30.1`, provisioned `~/.local/bin/gitleaks` per todo 1)
against planted fixtures on 2026-09-04. Spike fixtures lived under
`/tmp/opencode/spike4` (deleted); the permanent test suite lives in
`test/engines.gitleaks.test.ts` with fixtures under `test/tmp/` (never `/tmp`
— keeps the grep-empty AC meaningful).

## Command shapes (the only ones border uses)

```
history leg: gitleaks git <repo> --log-opts "<ref-range>" --no-banner -f json \
               --report-path - --config assets/gitleaks-defaults-v8.30.1.toml \
               --gitleaks-ignore-path <empty-file>
tree/artifact leg: gitleaks dir <dir> --max-archive-depth 2 --no-banner -f json \
               --report-path - --config assets/gitleaks-defaults-v8.30.1.toml \
               --gitleaks-ignore-path <empty-file>
```

- `--source` does NOT exist in 8.30.1 — target is positional.
- `-f json` WITHOUT `--report-path -` writes NOTHING to stdout. `--report-path -`
  is the stdout mechanism; an on-disk `--report-path <file>` is FORBIDDEN in
  border (G23: a plaintext report file would persist raw secrets).
- `--max-archive-depth` DEFAULTS TO 0 (no archive traversal). The explicit `2`
  is load-bearing; omitting it silently degrades the gate.
- NO `--redact`: it collapses the reported value so `valueDigest` would become
  sha256("REDACTED"). Raw `Secret`/`Match` stay process-memory only; border
  computes `redact(value) => {valueDigest, snippet}` at ingest and registers
  the raw value with the optional `TextSanitizer`.
- Exit translation (G11): `0` ⇒ clean, `1` ⇒ findings, ANYTHING else (spike
  confirmed e.g. `126` usage error) ⇒ `GitleaksRunError` ⇒ border exit 2.
  Never interpret non-0/1 as clean.
- Spawn env: `GITLEAKS_CONFIG` / `GITLEAKS_CONFIG_TOML` (and any `GITLEAKS_*`)
  stripped from the child env; `PATH` + `HOME` kept. Missing binary ⇒
  `EngineMissingError` (probes `gitleaks`, then `~/.local/bin/gitleaks`).
- `--version` string (`"gitleaks version 8.30.1"`) is collected via
  `gitleaksVersion()` for the G21 rulesHash `engineVersions` map.
- Vendored config: `assets/gitleaks-defaults-v8.30.1.toml`,
  sha256 `e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`
  (todo 1 evidence). An empty/`rules = []` config is strictly forbidden —
  zero rules = silent fail-OPEN.

## Report JSON shape (both legs)

Keys: `RuleID, Description, StartLine, EndLine, StartColumn, EndColumn, Match,
Secret, File, SymlinkFile, Commit, Entropy, Author, Email, Date, Message, Tags,
Fingerprint`. Border mapping ⇒ `Finding`:
`rule=RuleID`, `severity=CRITICAL` (all gitleaks hits block), `path=File`,
`line=StartLine`, `commit=Commit` (empty string ⇒ omitted; dir leg always
empty), `message=Description`, `engine="gitleaks"`, `valueDigest/snippet=redact(Secret
|| Match)`.

## Spike table — artifact formats through `gitleaks dir --max-archive-depth 2`

| Format (planted high-entropy AWS key inside) | Native result | Border path |
|---|---|---|
| plain file | ✅ detected (`aws-access-token` + `generic-api-key`) | dir leg |
| `.tar.gz` | ✅ `File: …/a.tar.gz!payload.txt` | dir leg (native) |
| `.tgz` | ❌ **MISS** — 0 findings, exit 0 | **extract shim** (`tar -xzf` → scan → reattribute `<archive>!<inner>`) |
| `.zip` | ✅ `…/a.zip!gz.txt` | dir leg (native) |
| `.tar` (uncompressed) | ✅ | dir leg (native) |
| `.gz` (single-file gzip) | ✅ | dir leg (native) |
| `.tar.bz2` | ✅ | dir leg (native) |
| zip inside tar.gz (nested, depth 2) | ✅ `nested.tar.gz!inner.zip!in-file` | dir leg (native) |
| gzip bytes renamed `.mybin` | ❌ MISS — dispatch is **extension-based, not magic-based** | not applicable to border artifacts; recorded as the root cause of the `.tgz` miss |

Consequences encoded in code: `src/artifacts/extract.ts` exists solely because
of the `.tgz` row — the **npm `pack` format** — with `NATIVE_MISS_EXTENSIONS =
[".tgz"]`. `.tgz` inside a `.tgz` is NOT extracted recursively (shim depth 1;
native depth-2 covers `!`-nested formats inside extracted trees).
The shim extracts one archive at a time into `mkdtemp` under
`<stateDir>/tmp/` (`.border/tmp/`), removes each sandbox in `finally` on both
success and failure paths, and prunes the tmp root only when empty (sibling
runs may share it). Finding paths from extracted scans NEVER contain the
sandbox path — they are rewritten to `<archive>!<inner>` before return.

### Spike gotchas recorded

- **Content dedup**: two archives holding byte-identical secret values inside
  ONE scan report yield ONE finding (spike: byte-copy `secret.tgz` of
  `secret.tar.gz` vanished from the report). Every fixture therefore plants a
  fresh random pair (`randAwsPair()`), never a reused literal.
- A bare `AKIA…` id line alone matched only via the vendored `aws-access-token`
  regex when the `aws_secret_access_key` line was present; `generic-api-key`
  fires on the high-entropy secret. Fixtures assert `>= 1` finding, not a rule
  count.
- `gitleaks dir` on a repo root reports **0** for a secret that exists only in
  git objects (spike: deleted-at-HEAD leak, dir leg exit 0 / git leg exit 1).
  The history leg is irreplaceable; dir-over-worktree is not a substitute.
- Loose git objects are zlib-compressed: `grep -rl <literal> <fixture>` after
  any scan returns nothing even inside `.git` — the residue AC is grep-safe.

## Hostile-config invariance (why `detectHostileConfig()` exists)

- A `<target>/.gitleaksignore` committed in the repo is obeyed
  **UNCONDITIONALLY** (additive with `-i`, `root.go:304-320` logic): spike
  before/after `1 → 0` findings, exit `1 → 0` — a silent fail-OPEN. The empty
  `--gitleaks-ignore-path` file does NOT defend against it. ⇒ border refuses
  to trust the target repo: `git ls-tree -r HEAD --name-only` + presence of
  `.gitleaksignore` OR `.gitleaks.toml` anywhere in the HEAD tree ⇒ CRITICAL
  finding `repo-self-ignores-findings` (path + HEAD sha). The scan legs still
  run — the detector's finding blocks regardless of what the engine says.
- Auto-discovered rules files are NEUTRALIZED by passing the vendored
  `--config` explicitly (spike proof: fixture HEAD carrying
  `title="empty"\nrules = []` `.gitleaks.toml`: without `--config` the git leg
  printed an EMPTY stdout (0 usable findings); with vendored `--config` the
  planted key was STILL reported, exit 1). This is why BOTH legs always pass
  `--config`.
- No generated `.gitleaks.toml` beyond the two empty ignore files; `.border/`
  exclusion of extracted/temp paths stays a border-side hard filter (todo 10)
  because the v8 config schema offers no exclude-dirs.

## Todo-6 consumption points

`EngineMissingError` (re-exported from `src/engines/support.ts`) thrown by
`scanGitHistory` / `scanTree` / `gitleaksVersion` / `detectHostileConfig` (git
or tar binary absent) and `scanTree`'s `tar` spawn; `GitleaksRunError.exitCode`
for the exit-2 mapping.
