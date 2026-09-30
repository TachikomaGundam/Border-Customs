# F-EXFIL-ALLOWLIST — ruling packet: does the `exfil` face enter the plugin closed allowlist? (order 10)

date 2026-09-30 · status: **RULING REQUESTED** (deferral clause: `.omo/plans/border-exfil-lens.md:56` —
"插件 allowlist 不加（边界：不动插件；ledger 记 follow-up 单独波裁）") · repo: /home/lab/workspace/harness/border

## The question

CLI gained `exfil` in 0.6.0 (read-only exfil lens) and `opencode` was already absent from the
plugin's closed command list. Today's allowlist (plugin/border.ts `ALLOWED_COMMANDS`, 9 entries):
`check, push, status, llm-request, llm-ingest, scan, roundtrip, --help` (+ handshake strings).
Should `exfil` join it? Should `opencode`?

## Decision rule proposed (institutionalize, so future commands aren't re-argued from zero)

A CLI command is allowlist-eligible iff ALL four questions answer no:
1. **MUTATES** anything outside its own temp sandbox (ledger append counts; config writes count)?
2. **HANDLES CREDENTIALS** interactively or stores tokens?
3. **EXECUTES untrusted bytes** that border does not own? (note the incumbent bar: `roundtrip`
   is ALREADY allowed and installs arbitrary artifacts — inside Docker — so ③'s practical bar
   is high)
4. **WRITES local data to arbitrary destinations** (egress with local payload)?

## Risk sheet for `exfil <rev|url> [--deep]` (facts, src/commands/exfilGit.ts + README)

| Facet | Evidence |
|---|---|
| read-only | no ledger writes, no config mutation; temp clone destroyed on exit |
| spawn hygiene | argv-only git, GIT_* env stripped, `GIT_TERMINAL_PROMPT=0` (credential prompt hangs impossible — fail closed), `GIT_CEILING_DIRECTORIES`, 55 s per-call cap under 60 s doctrine |
| network | URL modes initiate outbound git fetch to operator-specified hosts (SSRF-shaped *reachability*, read direction only; `file://`/scp-shaped accepted by design). Same trust class as `scan` (registry fetch) and weaker than `roundtrip` (executes install hooks in Docker) |
| local disclosure | clone of a FOREIGN url negotiates only the temp repo (empty) — local refs/objects are not in the exchange; output = masked findings over the fetched tree |
| agent value | session-driven "is this surface publishable" is THE plugin use case; excluding exfil does NOT prevent it (agents keep bash; allowlist is documented fool-proofing, not a boundary) — exclusion only diverts the traffic OFF the audited path (identity handshake + exit-code contract + output caps) |

**Rule verdict**: ① no ② no ③ no ④ no → **eligible**.

## Options

- **R0 keep closed** — zero change; cost: allowlist stays internally inconsistent (exfil ranked
  *more* dangerous than roundtrip/docker — untenable), agents use it ungated via bash anyway.
- **R1 (recommended) — add `exfil` only.** One array entry; refusal message + both edges render
  from the same array (v2shape parity pins it); update README closed-list sentence (L754) + zh
  概要 + `border-command.md` usage text if it enumerates; tests: opencode.test allowlist set
  assertion +-1. `opencode` STAYS OUT (install/uninstall mutate `$XDG_CONFIG_HOME` files → fails ①).
  `border opencode inspect` (wave B) is likewise out of the plugin face (it reads caches/configs
  of the host — read-only ✓ but its value is operator-terminal; revisit only via this same rule).
- **R2 add exfil with argv shape-gating (local revs only, URLs refused)** — adds a real policy
  split the CLI contract doesn't have; contradicts "gates live in the CLI, the plugin is UX";
  two-source truth for one rule (L-SINGLE-SOURCE). Only choose R2 if the owner judges arbitrary
  outbound git URLs from sessions unacceptable — in which case R0 is the honest statement anyway.

## Implementation ordering (upon approval)

Bundle into the wave-B minor (0.8.0) — same changeset family (plugin surface + README + tests);
standalone 0.7.2 only if wave B stalls after Momus. Release-wheel law applies to whichever:
lease → packet → human `border push --yes`-line terminal step.

— Abathur, border maintenance seat. Owner ruling: [ ] R0  [ ] R1  [ ] R2 (mark one, reply)
