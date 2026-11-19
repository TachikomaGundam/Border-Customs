# Design: push-outcome accounting & gate parity (2026-11-08 Sibyl ticket)

Field forensics: Sibyl's release wheel 2026-11-08. The owner's `border.yaml` carries the
defect's own words — a signed allowlist workaround annotated
"Workaround for a KNOWN border push-path defect (counts already-public objects as
transmitted; ticket open)" — while `.border/ledger.jsonl` holds 34 lines and NOT ONE push
result for the 08:48 refusal or the ~14:31 executor death. Ledger evidence: Sibyl
`.border/ledger.jsonl`, runs `2b68a08e-*`/`21274ab5-*`/`1d660ff6-*`.

## Wounds → invariants

W1 (parity). Invariant: **the push gate and the check face decide identity exposure with ONE
predicate — `isBlocking` (src/findings.ts).** `gateTransmitIdentities` counted EVERY
scanIdentity finding including the INFO `identity-already-public` rung, so a fingerprint the
check PASSES (all offenders already on the remote, zero new objects) was refused by
`push --yes`. Fix: filter findings by `isBlocking` before deciding; only first-time exposure
(CRITICAL) blocks — unchanged fail-closed for genuine egress. Disease class: decision logic
re-derived at a second site instead of consuming the single-source predicate (second
occurrence family).

W2 (accounting). Invariant: **every `border push --yes` run that derives push-state appends
exactly one `t:"push-result"` ledger line — landed / blocked / partial / failed / noop — with
verdict, targets, branch, reason (G20-sanitized) and the git exit code when a spawn failure
decided the outcome.** Today only success mints a line (`recordPushSuccess`). The dry-run
contract (zero mutation, zero writes) is unchanged. Pre-derivation early exits (no targets
discovered, `NO-OP 0`) mint nothing: there is no fingerprint key yet and nothing was even
attempted — the boundary is documented, not silent.

W3 (named diagnostics). Invariant: **before any `git push` spawns, the branch refspec and
every leg url are pre-checked; unresolvable inputs produce diagnostics naming the ref, the
remote, and what is missing — and land in the ledger via W2.** No new push channel: tag
moves/deletes stay OUT of border's frozen surface (`pushArgv` four slots, AC6). The DIVERGED
report now distinguishes branch-non-ff from a moved tag and names the missing channel.
A `--ref <refspec>` channel is a policy change (it would carry force-shaped operations
through a gate whose doctrine is "border never force-pushes") — this design issues it as a
named policy request for the owner's ruling instead of implementing it.

W4 (self-found, same family). The no-targets NO-OP path swallowed a failing drift probe
(`catch { orphans = [] }`) and then CERTIFIED "nothing to push" with exit 0 — absence
certified by a broken instrument. Invariant: **a NO-OP claim needs a working probe.** A
repository whose drift probe fails exits 2 with the probe's error named; "not a git
repository" (probe structurally unnecessary: a non-repo cannot hold remote-tracking refs)
keeps the NO-OP contract.

## Shape

- `src/ledger/records.ts`: `PushResultRecord` (`t:"push-result"`, closed verdict enum,
  optional `key` — absent when derivation threw before the fingerprint existed; `targets`
  required non-empty; `branch?`; `reason?` sanitized+truncated at the mint site; `gitExit?`
  non-negative integer or null). `buildPushResultRecord` is the only mint (gate precedent:
  `buildLandingRecord`). Reader parses it; older binaries skip the unknown type with their
  existing loud per-line warning (roundtrip/landing precedent).
- `src/push/git.ts`: `PushExecResult` failures carry `exit: number | null` (null = killed or
  spawn-failure — indeterminate). New `preflightPushRefs` (W3), pure reads, no spawn of push.
- `src/pushstate.ts`: `gateTransmitIdentities` consumes `isBlocking`; also threads `env` into
  `scanIdentity` (seam parity with the check face).
- `src/commands/push.ts`: one `recordOutcome` closure; every return point of
  `executeYesPush` mints its line; preflight wired before the push loop; DIVERGED lines name
  tag-kind divergences; dry-run gains the detached-HEAD parity warning `--yes` already gives.

## Blast radius & rollback

Ledger file grows one additive line type (repo-local, `.border/` hard-excluded from scans).
No argv changes on `git push` (grep guard intact), no exit-code remaps except W4's named
exit-2 branch, no config schema change. `PushExecResult` gains a required field on the
failure arm — compile-time call-site check catches any consumer. Rollback = revert the
commit; old readers already tolerate the new record type, so no data repair is needed.

## Out of scope (named)

- `--ref <refspec>` channel: policy request, see ticket reply.
- `border status` rendering of `push-result` rows: consumers can read the ledger today;
  display follow-up.
- Sibyl's allowlist workaround lines: owned by the Sibyl seat — removable once the fix
  ships (their comment says so).
