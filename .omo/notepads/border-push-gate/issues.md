# Issues — border-push-gate

Problems and gotchas encountered during work on this plan.

_Auto-scaffolded by /start-work. Append new entries below - never overwrite._

---

---

## todo 6 (2026-09-04) — engine policy + trufflehog

- **validateFinding has NO rule-charset regex** despite the todo-6 briefing
  warning about `^[a-z0-9-]+$`: the only hard constraints are severity enum,
  valueDigest 64-hex, path/commit string, line integer. Conformed trufflehog
  rules to `trufflehog/<lowercase-dash>` anyway (consistency with gitleaks ids);
  `DEGRADED-ENGINE` uppercase is legal and kept verbatim per plan text. Later
  workers: do not "fix" findings.ts to add a charset rule without auditing
  secretlint rules (`@secretlint/secretlint-rule-aws/...` contains `/` and `@`).
- **Exit-183-with-empty-stdout parses CLEAN** (`[]`), it does not throw. Cost
  me a broken sanity assert: canned-empty + exit 183 ⇒ zero findings is the
  correct behavior; only unparseable JSON *lines* fail closed.
- `tools/register-ts.mjs` loader only maps `.ts` — a `.mts` scratch QA script
  dies with ERR_UNKNOWN_FILE_EXTENSION. Name throwaway TS scripts `.ts`.
- **Cross-worker residue**: the sample literal `AKIAI4Q3EXAMPL3K7X2Q` (used by
  todos 4/5 fixtures) still sits in `/tmp/girepo`, `/tmp/artdir`, `/tmp/e2e`,
  `/tmp/opencode/spike-out.txt` from Sep-3 spike runs — earlier tasks were
  supposed to keep fixtures under test/tmp. Not produced by todo 6; whoever
  owns cleanup should sweep those /tmp dirs (they are NOT G23 secrets, just
  planted sample keys, but they trip residue greps).
- secretlint has no `--version`; its "version" for rulesHash is the lock
  fingerprint — an `EngineRunError` from `secretlintVersionFingerprint` is a
  *probe failure* (DEGRADED-ENGINE finding), never an unparseable-version
  hard error. Policy distinguishes: probe-throws ⇒ finding; probe-returns-
  garbage-version-string ⇒ EnginePolicyError exit 2.

---

## todo 8 (2026-09-04) — AI-session + junk artifact rules

- **`git ls-tree -r --long` size separator gotcha**: output is
  `100644 blob <sha>       3\tpath` — the size is RIGHT-ALIGNED SPACE-PADDED,
  only the path is tab-separated. A `<sha>\t<size>\t` regex silently yields
  ZERO entries: the tree leg, oversized/binary/notebook rules all evaporate
  while history-leg path findings keep the test looking half-alive. Matcher
  that works: `/^(\d{6}) (\w+) ([0-9a-f]{40})\s+(\d+)\t(.+)$/` + type=="blob"
  (gitlinks mode 160000 have no size field — filtered, not parsed).
- **pathPatterns consumer shape**: config schema is `z.array(z.string())`
  (todo 2, strict). scanAiArtifacts therefore accepts
  `string | {pattern, severity?, message?}` — bare strings default CRITICAL
  (G35: pathPatterns ARE the closed-list addition vehicle; also mirrors
  secretlint's CRITICAL internal-host mapping). Todo 10 can pass
  `config.rules` straight through (structural typing). Later todos: do NOT
  re-validate the union at the call site.
- **engine label for native rules := "ai-artifacts"** (todo 9 sibling should
  pick its own, e.g. "identity"; todo 3/17 rendering must not assume
  engine==gitleaks for native findings). target is "git" per task spec.
- **dedupe key = (rule, normalized-path)**: one finding per pair; commit =
  HEAD sha when tree-resident else lex-smallest adding commit. History-only
  paths get NO content rules (NUL/ipynb read HEAD-tree blobs only) — the
  closed list is path-based so AC2-class leaks stay fully covered.
- **`.border/` prefix is skipped here** per todo-10's "native rules skip the
  prefix" contract; the CRITICAL `repo-tracks-border-state` guard is todo 10's
  job for committed `.border/**`. Don't duplicate the finding in todo 10.
- spawnSync `encoding:"buffer"` + `input: Buffer` is the ONLY safe mode for
  cat-file --batch: utf8 decoding mangles NUL bytes and would blind the
  checked-in-binary sniffer.
- sibling snapshot at commit time: 103/103 pre-existing green + identity 18/18;
  `npm run typecheck` and test/cli.test.ts fail ONLY inside todo-7's
  in-flight surface (src/cli.ts, src/commands/*.ts missing modules) —
  pre-existing on this worktree, not introduced by todo 8.

## INCIDENT (2026-09-04) — todo-10 phantom sandbox
- First todo-10 worker ran 39min and returned a coherent, code-consistent
  DoneClaim — but zero artifacts exist in the real repo (no objects, no
  files, no reflog entries). Root must treat worker-claimed commits as
  UNVERIFIED until `git log --oneline -2` IN ROOT SHOWS THEM.
- Mitigations adopted for all future dispatches: (1) worker's FIRST action
  = echo `git -C /home/lab/workspace/harness/border log --oneline -1` +
  `pwd` + include both in DoneClaim; (2) commit production code as soon as
  tests-green, before writing evidence/docs; (3) DoneClaim must paste ACTUAL
  final `git log --oneline -3` output, not narrated hashes.

## todo 18 — open follow-ups for todos 20/21 (packaging)
- assets/prompts/llm-review.md is unreadable from the esbuild dist bundle (fileURLToPath walk
  lands outside the package). Handled fail-closed (MISSING_TEMPLATE ⇒ llm-request exit 2;
  rulesHash omits the prompt input when the file is absent, mirroring GITLEAKS_VENDORED_CONFIG
  treatment). Todo 20/21 must copy assets/** into dist (or inline it) and then cli.dist tests
  can assert full llm-request behavior instead of honest-failure behavior.
- BORDER_PROMPT_TEMPLATE_PATH env seam exists for hermetic template-digest tests; keep it
  documented if the registry/packaging story changes the resolution order.

## todo 13 — briefing/plan conflicts + phantom artifacts (resolved per plan)
- Briefing scope (probeAvailable ⇒ WARNING 'registry-probe-unavailable' verdict stays PASS,
  3-retry backoff+jitter, 4-file src/registry/ split) contradicts plan L188-194
  (fail-closed exit 2 on ANY probe failure, single src/registry.ts, no retries beyond 1).
  Briefing defers to plan ("the plan text is authoritative") ⇒ plan implemented; commit
  message uses the plan-pinned string, not the briefing variant.
- Phantom claims verified FALSE and ignored: stash@{0} 'todo-13 partial attempt' does not
  exist (stash list empty), src/registry/ absent, and the push.ts placeholder line
  'registry pre-flight wired in todo 13' appears nowhere in src/ ⇒ push.ts untouched
  (todo 17 owns pre-flight assembly per plan).
- Sibling contamination in flight: check.ts worktree carried an uncommitted rulesHash hunk
  and ledger.check.test.ts fixtures would have probed REAL registry.npmjs.org ('widgets'
  is a live package ⇒ instant CRITICAL). Fixed both fixtures to a loopback 404 stub;
  staged my check.ts hunk only (hash-object + update-index), never their hunks.
