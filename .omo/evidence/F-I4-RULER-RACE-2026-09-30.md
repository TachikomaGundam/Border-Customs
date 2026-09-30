# F-I4 — v0.7.0 release-gate red: verdaccio-log ruler race (root cause + fix receipt)

verified 2026-09-30 (Asia/Shanghai) · session: border maintenance (order 7) · review-by 2026-12-30

## Incident (verbatim CI receipt, gh run view 36671401844 --log-failed)

```
not ok 382 - I4 dry-run registry lines: no-record honesty, then missing-bytes exit 2, then exact npm publish line with ZERO verdaccio hits
  location: '/home/runner/work/Border-Customs/Border-Customs/test/push.integration.test.ts:308:1'
  error: |-
    dry-run made ZERO verdaccio requests (no probe, no re-pack network)
    6 !== 2
  expected: 2
  actual: 6
```

(`:308/:335` are transpiled positions via tools/register-ts.mjs; the on-disk TS test starts at
line 415 on the SAME bytes as the tag: `git show v0.7.0:test/push.integration.test.ts | md5sum`
= `549aa07325c68d1c53fe40deae2458ce` = local `md5sum test/push.integration.test.ts`.)

Only I4 was unsanctioned red; C5-1 + C5-4 in the same run are the pre-registered allowlist pair.

## Ruler anatomy

`requestCount()` counts `"http <--"` lines in verdaccio's stdout log FILE. Verdaccio logs each
response AFTER the response bytes go out; the counter's consistency is the log-writer's event
loop, not the client's await. One GET produces TWO countable lines (`http <-- 200 ... bytes: 0/0`
+ `http <-- 404 ...`).

## Local instrumented measurement (variant test, same helpers, per-phase log deltas)

```
after (a): +6 lines  (ready block 1×3 + (a) gate-check probe 2×3)   <- (a) MUST probe: full
                                                                       pipeline, no prior record, exit PASS asserted
after (b): +0   after stage: +3   drain1: +3
hits0=8
after (c): +0 lines   <- the dry-run itself is genuinely request-free (both drains, real traffic)
after drain2: +3
```

## Attribution arithmetic (the unique self-consistent solution)

CI observed hits0=2, final=6. Steady state of legitimate traffic = ready(2) + (a)-probes(4) = 6 —
EXACTLY the CI final value. So at CI snapshot time (a)'s four probe lines had not yet reached the
log file; they arrived before the final read. The alternative reading ((c) really probed) would
require (a)'s lines to ALSO be present at hits0 (same FIFO order, both awaited) → hits0 ≥ 6,
contradicted; and (c) probing twice more would give final ≥ 10, contradicted.

Product-contract check: `runPublishCore` (src/push/core.ts:218) returns right after printing the
argv rows when `!i.yes` — zero network on the dry-run path by construction. `git diff
v0.6.0..v0.7.0 -- src/` = one line (scan UA bump); the handoff's landing/exfil suspects move no
bytes on this path. **Verdict: broken ruler (eventually-consistent counter under a saturated
runner), not a dry-run leak.** Dev-box timing luck hid it (794-test local suite green).

## Fix (v0.7.1) — repair the ruler, zero semantic relaxation

- `LiveVerdaccio.drain()`: FIFO barrier — sentinel GET on a `drain-<rand>` path, poll until its
  log line is visible. Single ordered writer ⇒ sentinel visible ⇒ every earlier line in the file.
- I4 takes both snapshots behind a barrier (pre-hits0 drains (a)+stage traffic; post-(c) drains
  any late line before the equality check).
- `requestCount()` excludes `drain-` lines (measurement artifacts are not traffic under test).
- Assertion strength unchanged: `final == hits0` still means ZERO registry requests from the
  dry-run — now measured against a consistent snapshot. No fail-closed guarantee was relaxed.

## Post-fix receipts (this machine, 2026-09-30; raw /tmp logs transient, key lines inlined)

- `node --test test/push.integration.test.ts`: I1/I2/I3/I4 = 4/4 ok (I4 with barriers armed).
- Full suite `npm test`: `# tests 794  # pass 779  # fail 2  # skipped 13`; the I4 line:
  `ok 382 - I4 dry-run registry lines: ... ZERO verdaccio hits`; `not ok` titles sorted =
  C5-1 + C5-4 exactly (sanctioned pair) — baseline 794/779/2(恰C5对)/13 preserved.
- `npm run typecheck` RC0 · `npm run build` RC0.
- Gate self-receipt after commit+tag: `border check --force` exit 0 (direct RC capture — the
  first attempt's apparent `RC=0` was `tail`'s exit code through a pipe, caught by reading the
  ledger; the honest re-run exposed the REAL blocker: commits authored with the repo's stale
  git config identity `TachikomaGundam@users.noreply.github.com` tripped
  `identity-not-allowlisted` CRITICAL). Both unpushed local commits were rebased to the
  allowlisted identity (Wiki.js <wiki@sumteclab.com>, the identity of the whole prior chain),
  v0.7.1 re-pointed (remote had zero v0.7.1 tags — nothing public rewritten), and
  `check --force` then PASSed: key `200c29d9`, 0 CRITICAL/HIGH rows.
- Residual finding for the owner: this repo's LOCAL git config (`git config user.name/email`)
  still points at the non-allowlisted identity — the gate will catch any future slip, but
  pinning the repo config to Wiki.js <wiki@sumteclab.com> would stop it at the source
  (config edits are the owner's call; not changed here by tool-guideline discipline).

## Follow-up registered (not in this fix's scope)

- Runner-only-test skip masking (local 13 vs CI 12 skips): the suite's local-green claim cannot
  certify the release-gate surface; a forced-local verdaccio leg or CI-parity opt-in is worth a
  future order (§4 of the handoff note).
