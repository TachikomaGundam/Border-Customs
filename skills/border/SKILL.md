---
name: border
description: |
  Operate the `border` push gate: deterministic secret/identity/artifact scanning
  before any git/npm/PyPI push, plus the optional agent-executed LLM review layer.
  Use when asked to check a repo before pushing, run/ingest an llm-review bundle,
  push through the gate with confirmation, or inspect gate status. Triggers:
  border check, border push, llm-request, llm-ingest, push gate, pre-push scan.
---

# border — the push gate an agent operates (but never *is*)

`border` is a deterministic CLI gate. **border never calls an LLM API itself** —
the `--llm` layer is executed by YOU, the operator's agent, through two file
handoffs (`llm-request` / `llm-ingest`). Install: this repo's `npm link` or
`node src/index.ts` from a checkout; every command runs inside the target repo.

## The five subcommands

```
border check [--config <yaml>] [--targets git,npm,pypi] [--force] [--llm] [--json] [--require-engine <name>]
border push  [--yes] [--targets ...]
border status
border llm-request
border llm-ingest <findings.json>
```

Exit codes are the contract: **0** pass/no-op · **1** blocked by findings ·
**2** tool/config error (the gate could not answer).

## check — the actual gate

`border check` fingerprints the repo (HEAD, working tree, rules, exposure set,
refs, targets → one `key`) and scans history + tree + artifacts with gitleaks,
secretlint, trufflehog (optional) and native identity/artifact rules.

* A PASS is ledgered under `.border/ledger.jsonl`. A later `border check` on the
  **identical fingerprint** prints `SKIP <key8> — PASS <ts> report <path>` and
  replays the cached verdict instead of re-scanning. SKIP is not a re-scan: if
  anything moved (new commits, edited border.yaml/rules, template change), the
  key changes and the full scan runs again. `--force` bypasses the lookup.
* `--llm` changes which ledger record the SKIP consults (an llm pass records
  `llm:true`; a plain check must never ride it, and vice versa).
* Degraded required engines ⇒ exit 2 regardless of verdict; a degraded run is
  never ledgered.

## The LLM pass (agent-executed, optional)

When the flow demands review beyond pattern rules (or `border check --llm` will
not SKIP because no llm record exists):

1. `border check` must have recorded the current state (llm-request refuses with
   exit 2 otherwise — the bundle derives from the recorded ctx).
2. `border llm-request` writes
   `.border/runs/<key8>-<ts>/llm-request.json`: the fingerprint fields, the ref
   set and exposure set, the review diff (`git diff --stat` + per-file unified
   patches against the newest remote-tracking tip — or, on a first push with no
   remote-tracking tip, a FULL-TREE diff stated as such in `base.mode`), the
   artifact listing (names + sha256 only), the deterministic findings, and the
   prompt-template path + digest. Patches are >10 MiB-truncated with an explicit
   marker.
3. **Read the bundle. Follow `promptTemplate`** (its path points at
   `assets/prompts/llm-review.md`). Author your findings as a strict JSON array
   — each item `{rule, severity, target, path?, line?, commit?, message,
   snippet?}`; `path` MUST be one of the bundle's `fileDeltas`. Do not set
   `engine` or `valueDigest`; never paste raw secrets into message/snippet.
   `[]` is a valid PASS statement. Write the file **outside the repo tree**
   (e.g. beside it) so you do not dirty the fingerprint you are certifying.
4. `border llm-ingest <findings.json>` — every item is validated against the
   Finding schema and the bundle's file list (unknown path ⇒ exit 2 naming the
   item index), your text is re-scrubbed, `engine:"agent"` is forced, the
   verdict is recomputed over deterministic + agent findings, and an
   `{llm:true}` record + `report.json` are persisted in the run dir. Exit 0/1 =
   the recomputed PASS/FAIL; exit 2 = malformed input (nothing was recorded).
5. If ingest says the HEAD moved or no bundle exists, redo steps 2–4 against the
   current state — never ingest against a stale bundle.

### Data boundary (verbatim — the accepted-by-design limit of this layer)

> the bundle carries real reviewable source; masking covers only values the
> deterministic engines already flagged — a residual, still-undiscovered secret
> in diff context CAN reach the operator-configured LLM endpoint. That is the
> accepted-by-design boundary of the optional --llm layer; the deterministic
> layers remain the actual gate.

Masking means flagged values appear as `[REDACTED:<sha8>]`; everything else in
the diff is real source. Treat the bundle as if it were going to your own
review LLM — because it is.

## push — confirmation flow

`border push` (no `--yes`) is a **dry run**: zero mutations, and its exit code
mirrors the gate verdict (clean ⇒ 0, blocked ⇒ 1, gate unavailable ⇒ 2). Show
the human the dry-run plan (targets, refs, versions, the check key it is riding)
and get explicit confirmation; only then run `border push --yes`, which executes
git remotes → npm → PyPI in order after an all-or-nothing pre-flight, verifying
published bytes hash-match the recorded artifacts and writing push records.
Never pass `--yes` on a user's behalf without their visible go-ahead, and never
push over an exit-2 (unavailable) gate.

## status

`border status` prints the newest check/push records per target — use it to
answer "is this repo safe to push / what did the last gate say?"

## Gotchas

* `.border/**` is self-ignored (`*`); its report archives prune to the newest
  20 run dirs per key8. Findings files belong outside the repo anyway.
* From the esbuild `dist` bundle the prompt template asset is not yet packaged
  (todos 20/21): `llm-request` fails closed with `MISSING_TEMPLATE` rather than
  emitting an unanswerable bundle — run from source (`node src/index.ts` /
  `npm link`) for the llm layer until then.
