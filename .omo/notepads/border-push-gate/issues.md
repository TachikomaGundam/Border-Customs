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
