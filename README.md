# border

A fail-closed pre-push gate for git, npm, and PyPI. It scans your repo for secrets and
supply-chain risk, then refuses to let anything leave the machine unless a fresh, unbroken
check passed for exactly the state you are about to publish.

```bash
npm install -g border-customs
cd /path/to/your/repo
border check
```

Requires Node >= 22 and the `gitleaks` binary on `PATH` (border vendors the rule config for
gitleaks 8.30.1; the binary itself is yours to install, same as `git`). secretlint runs
in-process as a bundled dependency. Optional engines are listed in
[Configuration](#configuration).

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
- **The published bytes, not the source tree.** `npm pack` and `python -m build` rewrite
  what ships. border packs/builds once into `.border/dist/`, scans those exact bytes, and
  re-hashes them again at publish time.
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
                 ⊕ exposureSet          # sanitized remote URLs + npm/pypi name@version
                 ⊕ refSet               # branch being pushed + every local tag
                 ⊕ effectiveTargets )   # git, npm, pypi as configured for this run
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
7. **Registry pre-flight** (npm/PyPI targets only). Three outcomes per target: version
   already published ⇒ CRITICAL `version-exists` ("bump version required"); name owned by
   someone outside your `rules.authors` allow-list ⇒ CRITICAL `name-foreign-owner`;
   ambiguous ownership signals ⇒ also CRITICAL, because guessing wrong is how squats ship.
   Critically, **silence never means absent**: an empty stdout from `npm view`, a non-200
   non-404 PyPI response, a timeout, or unparseable JSON all fail closed as exit 2. An
   unreachable registry blocks the push instead of letting it run blind.
8. **Artifact stage.** If npm/PyPI targets are configured, packages are built **once** into
   `.border/dist/` (`npm pack --ignore-scripts`, `python -m build --no-isolation`), that
   exact byte-stream is scanned (gitleaks + secretlint over the extracted contents),
   manifest-diffed (lifecycle `preinstall`/`postinstall` hooks are CRITICAL; entries
   outside the `files` whitelist are HIGH; PyPI sdists get a `sdist-unexpected-file` HIGH
   because setuptools builds from the working tree and is `.gitignore`-blind), checked with
   `publint` / `twine check --strict`, and recorded as `{file, sha256, bytes}` in the ledger.
   At publish time the *same bytes* are re-hashed: any mismatch is exit 2, before the wire.
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
re-packs npm artifacts to prove the recorded tarball digests still match fresh byte-for-byte
(a dirty tree, a drifted `package.json`, or a changed npm version all force a full re-check;
PyPI builds are not byte-reproducible, so their skip proof is head+porcelain equality, and
publish still re-hashes the exact dist files). A corrupt ledger line is dropped with a loud
warning, never a crash, and never a silently empty history.

## Architecture: `border push`

`border push` is a state machine over per-target states, recomputed from live git queries,
never from cache:

| State | Meaning |
| --- | --- |
| `PUSHED` | remote already holds every ref at the local value (checked via `git ls-remote`, full-ref compare, tags compared *peeled*) |
| `PENDING` | this target needs to move, and the current fingerprint has a PASS behind it |
| `BLOCKED` | no PASS for this state (run `border check`), or a registry finding says stop |

- Bare `border push` is a **DRY-RUN**: it prints the exact `git push --dry-run` /
  `npm publish` / `twine upload` lines it would run, refuses to act, and exits with the
  gate's verdict. `--yes` is what executes.
- Multi-remote git push is **all-or-nothing before anything moves**: every remote × every
  ref must be a fast-forward, checked up front. If any remote diverged, border prints
  `DIVERGED` with the offending shas and pushes nothing. **It never force-pushes; there is
  no flag for it.**
- Registry legs go through the same gate as push: a PASS record for the current key, then
  the artifact re-hash match against `.border/dist/`, then an immediate version-exists
  re-probe (the registry is allowed to change between check and publish), then the upload
  with `stdio: inherit` so `npm`/`twine` OTP and credential prompts reach you untouched.
  border never reads, stores, or handles registry tokens. Published versions are not
  retried on failure because a half-published version can never be republished.
- If one remote of several succeeded before a failure, border says so explicitly (PARTIAL)
  and exits 1; a rerun of `border push --yes` picks up only the still-PENDING targets.

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

Every subcommand accepts the same global flags (verified against `border <cmd> --help`):

| Flag | Effect |
| --- | --- |
| `--config <path>` | config file; default `./border.yaml` |
| `--targets <list>` | comma-separated `git,npm,pypi` subset restricting this run's scope; a named target that is not configured is exit 2 |
| `--force` | ignore the skip-ledger, re-run the full check |
| `--yes` | execute mutations (push only); without it a push is always DRY-RUN |
| `--require-engine <list>` | replaces the required-engine set from config; unknown or unprobeable names degrade the run (exit 2) |
| `--llm` | opt this check into the LLM review layer (a plain check can never satisfy an llm-recorded skip) |
| `--json` | machine-readable report on stdout (check) |
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

## Configuration

Everything border can be told lives in `border.yaml` at the repo root. Unknown keys are
rejected at load (a typo in a gate config is a gate you did not ask for). `${VAR}`
expansion applies only to remote URLs and registry/repository values, and an unset variable
is a hard error, never an empty string.

Minimal, a git-only repo:

```yaml
version: 1
targets:
  git:
    remotes:
      - name: origin
        url: git@github.com:acme/widgets.git
```

A repo that publishes a package, with the full surface:

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
```

Notes that change behavior:

- `targets.git.remotes: []` (explicit, empty) is a *deliberate* repo-local scope: all
  history/tree/identity/artifact legs still run, only the exposure set is empty. A
  completely missing config with real remotes falls back to config-from-`git remote` with
  a loud stderr warning.
- Every `allow` entry must be scoped (a `file` pin); `{rule: "*", match: "*"}` with no
  file is rejected at load. Suppressed findings are enumerated in the report's
  `allow-hits` section, so an exit 0 never hides what it hid.
- `rules.hosts/ips/pathPatterns` feed the same matcher pipeline as the built-ins, so your
  patterns get the same archive attribution and the same allow-listing semantics.

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
  registry pre-flight, against URLs you configured (`npmjs.org`/`pypi.org` defaults, fully
  overridable to private indexes).
- **No credential handling.** Subprocess publishes inherit stdio so tokens and OTP prompts
  go between you and `npm`/`twine`, never through border.
- **State is inert.** Everything border writes lives in `.border/` (ledger, run archives,
  dist, lock), which carries its own `.gitignore` with `*` so a `git add -A` cannot stage
  it, and which every scan leg refuses to treat as a finding source or an allow-list
  target. A repo that *tracks* `.border/**` is itself a CRITICAL finding. A single-writer
  lock makes concurrent runs exit 2 instead of racing.

## License

MIT, see [LICENSE](LICENSE).

## 中文概要

border 是一个 fail-closed(失败即拦截)的推送前门禁 CLI:`npm install -g border-customs` 安装,在仓库里跑 `border check`。它扫描 git 历史、工作区(未跟踪文件同样是一等输入)、归档、tag 注释和将要发布的 npm/PyPI 字节,检出密钥与供应链风险;只有当"当前状态指纹"存在新鲜且完整的 PASS 记录时才允许 `border push --yes` 放行。指纹是 sha256(head、porcelain 摘要、规则哈希、暴露面、ref 集合、有效目标)六元组,任何一处变动,旧的 PASS 立即失效,必须重查。流水线:gitleaks(历史+工作区+tag,内置 8.30.1 规则,仓库自带的 ignore 文件直接判 CRITICAL)+ secretlint(进程内,AWS Key 规则强制开启)+ 原生规则(AI 会话产物闭集、提交身份白名单含传输对象检查)+ 注册表预检(版本已存在=必须 bump,名称被外人占有=拒绝;空响应/超时/解析失败一律 exit 2,沉默绝不等于不存在)。构件只构建一次进 `.border/dist/`,扫描的就是发布的字节,发布时再哈希比对,不一致直接拒发。跳过台账让重复检查不到 1 秒,但回放前先重算指纹并重新 pack 验证新鲜度。报告只输出掩码片段(sha256 摘要 + 前4…后4)。push 是多目标状态机,多 remote 先做全有或全无的 fast-forward 预检,永不 force-push;npm/twine 的凭据经 stdio 透传,border 从不触碰。可选 LLM 层 border 自身从不调用模型 API:`llm-request` 导出掩码审阅包,`llm-ingest` 严格校验 agent 结论并重算裁决。退出码即合同:0 通过、1 拦截、2 门禁无法作答,任何"工具不健康"都不可能被误读为干净。MIT 许可,无遥测,除你配置的注册表预检外不联网。
