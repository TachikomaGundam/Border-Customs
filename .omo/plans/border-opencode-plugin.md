# Plan: border opencode plugin adapter — install-free loading (v0.5.0)

## Source of truth
`/home/lab/workspace/handoff/opencode-plugin-loading.md` (v1.18.30 实证版). Reference
implementation on this machine: `@tachikomagundam/abathur@0.2.3`
(`harness/Abathur/plugin/abathur.ts`, `src/commands/opencode.ts`, `src/test/opencode.test.ts`).
Empirical pre-checks already done (2026-09-12):
- publint 0.3.24 returns "All good!" on a probe package carrying
  `exports["./server"]: "./plugin/x.ts"` + dep `@opencode-ai/plugin` (the exact shape below).
- registry resolves `@opencode-ai/plugin` (1.17.4 → 1.18.30).

## Goal (the user's ask, verbatim intent)
"对于 opencode 插件，需要一个方法免安装使用" — border's OpenCode plugin must be loadable
with ZERO manual install. Two handoff-sanctioned routes, both delivering the same module:

- **Route B (the 免安装 route):** one line in `opencode.jsonc`:
  `"plugin": ["border-customs@0.5.0"]`. opencode's arborist downloads the package into
  `<CACHE>/packages/<spec>/node_modules/border-customs/`; the plugin entry is
  `exports["./server"]`. The plugin then spawns the CLI **from its own package directory**
  (`../dist/index.js` relative to the plugin module — shipped inside the same tarball), so
  the user needs neither a global install nor a PATH entry. This is the piece abathur does
  NOT have (abathur requires the CLI on PATH); it is the actual "免安装" upgrade.
- **Route A (file drop):** `border opencode install|status|uninstall` — the §5 installer
  discipline (marker identity, idempotent, foreign-file refusal, uninstall-own-only).
  The CLI on PATH (or `BORDER_BIN`) is required here — same posture as abathur.

## Hard contract (shared by all deliverables — byte-exact)
- `PLUGIN_MARKER = "// border-opencode-plugin v"` — first line of `plugin/border.ts`
  reads `// border-opencode-plugin v0.5.0` (version parity with package.json pinned by test).
- `COMMAND_MARKER = "<!-- border-opencode-command -->"` — line 1 (byte-0) of
  `plugin/border-command.md`; NO frontmatter (abathur's working precedent: gray-matter
  only demands byte-0 `---` IF frontmatter exists; plain-comment first line is scanned fine).
  Lines 2.. = the plugin's exported `COMMAND_TEMPLATE` verbatim (byte-mirror test).
- Plugin module (V1 format): `export default { id: "border", server: async () => ({ config, tool }) }`.
- CLI resolution order inside the plugin (`resolveBin()`):
  1. `BORDER_BIN` env (non-empty) — explicit override wins on every route;
  2. packaged sibling: `new URL("../dist/index.js", import.meta.url)` if it exists
     (Route B + dev-repo layout) — spawned as `[process.execPath, distPath, ...argv]`
     (argv-only, no shell; the runtime hosting the plugin — node or bun — executes the ESM bundle);
  3. `"border"` on PATH (Route A) — spawned directly (npm bin shim).
  ENOENT on 3 ⇒ structured note: `set BORDER_BIN, or 'border opencode install', or npm i -g border-customs`.
- Tool `border`: args `{ command: string, extra?: string[] }`; allowlist
  `["check","push","status","llm-request","llm-ingest","scan","roundtrip","--help"]`;
  refuses `push` (or any) argv containing the token `--yes` — a real push is the human gate,
  terminal-only (mirrors abathur's promote/tombstone stance, matches skills/border/SKILL.md's
  standing rule "never pass --yes without a visible human go-ahead").
- Spawn discipline: `execFile`, `shell:false`, timeout 300 s, output cap 64 KiB per stream;
  result text = `$ border <argv>` / `exit: N` / `note: …` (if any) / `--- stdout ---` /
  `--- stderr ---` (empty ⇒ `(empty)`). Exit-code legend in tool description:
  0 pass | 1 gate-blocked or partial push | 2 gate could not answer.
- `config` hook: `cfg.command ??= {}; cfg.command.border ??= { description, template: COMMAND_TEMPLATE }`
  — `??=` keeps a Route-A `commands/border.md` authoritative (§4 ruling; file > jsonc > hook-fill).
- Installer destination rule: `<XDG_CONFIG_HOME ?? HOME/.config>/opencode/{plugins,border.ts, commands/border.md}`
  (XDG-aware — deliberate upgrade over abathur's HOME-only; the §6 probe recipe sets XDG_CONFIG_HOME).

## Deliverables

### D1. Packaging — `package.json` (+ lockfile)
- `version` 0.4.2 → 0.5.0.
- add `exports`: `{ ".": "./dist/index.js", "./server": "./plugin/border.ts", "./package.json": "./package.json" }`
  (`./server` MUST stay the pure-string form — opencode's entrypoint resolver reads the string;
  object form risks the `main`-fallback-CLI trap per §1).
- add dependency `"@opencode-ai/plugin": "^1.17.4"` (Route B arborist sibling-install requirement, §2).
- `files`: `["dist", "plugin"]`.
- `npm install` to refresh `package-lock.json`.
- Nothing else changes. Do NOT add `engines.opencode` (缺省 = max compat, §1).

### D2. `plugin/border.ts` (new)
Self-contained V1 plugin per the hard contract. ~200 lines, comment header states the two
routes (abathur's header is the tone model). Exports: default module + `COMMAND_TEMPLATE`
(named, for the byte-mirror test; harmless to opencode).

### D3. `plugin/border-command.md` (new)
Marker line + `/border` template: interpret `$ARGUMENTS` as one `border` CLI invocation
(first word = command word, rest = argv tokens), call the tool, report exit code + relevant
lines; no args ⇒ `--help` summary; `push --yes` is refused by the tool and belongs to a
terminal (also: a bare `border push` from the tool is DRY-RUN by the CLI's own contract).

### D4. `src/commands/opencode.ts` (new) + CLI wiring
Installer as a border-style `CommandHandler` (reads `ctx.positionals[0]`, writes via
`ctx.stdout/ctx.stderr`, returns `BorderExit`; misuse throws `UnknownArgError` ⇒ exit 2 + usage):
- `install`: resolve packaged assets via `assets.ts`-style first-existing candidates
  (`<here>/../plugin/…`, `<here>/../../plugin/…`); read BOTH before writing ANY; validate
  every destination before touching any (lstat: existing path must be a plain regular file —
  dir/symlink refused); marker identity — foreign (no marker) refused naming the path,
  nothing written; per target print `installed | updated | up to date`; trailing notes:
  restart-opencode + (dev-repo) "run npm run build first if dist/ is missing" only where honest.
- `status`: one line per target `path: state  installed=<sha256|-> packaged=<sha256>`.
- `uninstall`: refuse foreign targets; remove only marked files; `absent (nothing to remove)` no-op.
- Wiring: `SUBCOMMANDS += "opencode"` (src/cli/types.ts), registry entry (src/commands/index.ts),
  usage() command line + the trailing `subcommands:` list line (src/cli.ts — table edit only,
  the parser stays frozen).
- No new global flags.

### D5. `test/opencode.test.ts` (new) — pins + behavior
1. Hygiene pins (the §2/§3 分水岭 guards): `exports["./server"] === "./plugin/border.ts"`
   (strict string), `dependencies["@opencode-ai/plugin"]` present, `files` includes `"plugin"`,
   plugin first line starts with PLUGIN_MARKER + carries package.json version, md byte-0 is COMMAND_MARKER,
   md === COMMAND_MARKER + "\n" + COMMAND_TEMPLATE (byte-mirror via importing `COMMAND_TEMPLATE`).
2. Plugin behavior (import `plugin/border.ts` under the ts loader): server() shape;
   config hook fills `command.border` only when absent (pre-set value survives — `??=` pin);
   tool.execute with `BORDER_BIN` = fixture node script (`test/fixtures/opencode/echo-argv.mjs`,
   shebang, chmod 0x755): argv passthrough, exit-code rendering, non-zero exit passes through
   (gate verdict), `--yes` refusal (fixture must NEVER be spawned), disallowed command refusal,
   ENOENT note shape with `BORDER_BIN=/nonexistent`.
3. Packaged-sibling resolution: with `BORDER_BIN` unset and repo `dist/index.js` present,
   `command:"--help"` exits 0 with `usage: border` in stdout (skip with honest message when
   dist/ unbuilt — it is gitignored; publish CI builds before pack).
4. Installer lifecycle (sandboxed `ctx.env` HOME/XDG to `test/tmp`): install writes both
   targets byte-identical; second install ⇒ two `up to date` lines; edited-marker-file with
   different bytes ⇒ `updated`; foreign file ⇒ exit 2 naming path, foreign bytes survive,
   sibling target untouched (atomicity); symlink target ⇒ exit 2; status prints states+shas;
   uninstall removes marked, keeps foreign, absent-safe; `opencode` with no/unknown subaction
   ⇒ exit 2; unknown extra positional ⇒ exit 2.

### D6. `test/opencode.probe.test.ts` (new, opt-in `BORDER_OPENCODE_PROBE=1`) — §6 recipe
Temporary HOME+XDG → install via the built dist bundle → spawn `opencode serve --port <free>`
with a plugin-free control config → `GET /command` shows name=border EXACTLY once (§4 duplicate
rule) → `GET /experimental/tool/ids` contains `border` → SIGTERM cleanup. Skips when
`opencode` is not on PATH. Default suite green without it (same posture as BORDER_ROUNDTRIP_DOCKER).

### D7. Docs
- README: command table gains `opencode` row; new **Integration → OpenCode plugin (install-free)**
  section: Route B one-liner (recommend pinning the exact version, §7), what it registers
  (`border` tool + `/border`), the `push --yes` terminal-only policy, Route A installer,
  the §6 verification recipe, honest note that the tool carries bash-equivalent CLI privilege
  for the allowlisted commands and the real gate is the CLI itself.
- Changelog 0.5.0 entry; 中文概要 gains the plugin paragraph (repo bilingual pattern).
- `skills/border/SKILL.md`: one-line pointer that sessions may drive border via the plugin's
  `border` tool / `/border` instead of bash, same standing rules.

## Out of scope (next features, deliberately deferred)
- §8 装载清单登记 / 双路线自动探测 / 门禁 / 重复检测 as *border inspecting other plugins*
  (a `border inspect opencode` surface) — separate plan after this ships.
- Publishing/tagging (human gate; CI publishes on `v*` tag with Trusted Publishing).
- Route B end-to-end probe via local verdaccio (nice-to-have; release-time consumer
  verification covers it, per repo ritual).

## Sequencing
S0 (lead, now): D1. S1: D2+D3+D4+D5 (one coherent implementation unit — the byte contract
couples all four files; single agent). S2 (parallel with S1): D7 prose from this spec.
S3 (lead): full verify — `npm run typecheck`, `npm test`, publint on `npm pack`, probe leg
`BORDER_OPENCODE_PROBE=1` on this machine, `border check` self-gate; then report.

## Acceptance
- Fresh `npm test` + `npm run typecheck` green; publint clean on the packed tarball.
- Route A proof on this machine: sandboxed-HOME probe shows the `border` tool registered
  and `/border` present exactly once.
- Route B ready-by-inspection: exports/dep/files pins pass (cache layout verified at release).
- No existing behavior touched: cli.ts parser/flags, all current command modules, ledger,
  residue/release-coherence families untouched; `border check --force` on this repo passes.
