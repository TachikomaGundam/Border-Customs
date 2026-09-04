# Decisions — border-push-gate

Architectural choices and rationales discovered during work on this plan.

_Auto-scaffolded by /start-work. Append new entries below - never overwrite._

---

## todo 14 — configDigest: canonical-JSON wins over border.yaml byte-digest (2026-09-04)
Todo 10 left runCheck digesting base border.yaml BYTES (overlay/env caveat flagged for todo 14).
DECISION: switched runCheck to computeConfigDigest(load) (todo-10 helper, canonical stableStringify
of the EFFECTIVE merged config). Byte digest cannot certify G21 because `.border/config.local.yaml`
overlays (G15) are untracked files the base bytes never see — a rules-only overlay edit (e.g.
pathPatterns) would keep a poisoned PASS skippable. Env-expanded `${VAR}` remotes would mostly
self-heal via exposureSet, but digest consistency across the whole pipeline (executeCheck already
hashes the effective config) removes the split-brain class entirely. Proven at CLI level: adding a
second remote via config.local.yaml with head/porcelain/border.yaml bytes ALL identical ⇒ re-check.
Trade-off accepted: comment/format-only border.yaml edits no longer invalidate — those cannot
change gate behavior, which is exactly the G21 rule ("any change that alters effective gate
behavior MUST invalidate", nothing says cosmetic bytes must).

## todo 14 — skip authority = NEWEST record for the key, verdict must be PASS (2026-09-04)
Plan line 197: "Lookup = newest check-record with matching key AND verdict PASS…". Task brief
hypothesized "cached FAIL must also SKIP with exit 1" — checked against the plan text, REJECTED:
the plan restricts skippable records to PASS. Stronger reading implemented and unit-locked: the
NEWEST record with the key is the only verdict that counts (a FAIL after a PASS revokes it —
never read "newest PASS" past a newer FAIL, which would re-certify a just-blocked state).
Consequence: blocked states re-run the pipeline every time (correct — the operator must SEE the
findings, and fixes are validated against a fresh scan, not replayed verdicts).

## todo 14 — consultSkipLedger is best-effort BY CONTRACT (2026-09-04)
Fingerprint-phase throws (missing vendored rules toml in dist bundles, probe spawn errors) are
caught ⇒ SkipDecision{skip:null} ⇒ execution falls through to executeCheck, where the same
failure takes its ESTABLISHED structured exit-2 path. The ledger may refuse to skip; it may never
re-route an error or certify. This rule was earned: naively consulting first turned the dist
bundle's fail-closed "engine run error" (pinned by cli.dist.test.ts) into an unstructured
"unexpected error" — caught by full-suite run, not by the new tests alone.
