# check ↔ landing lens parity — receipt 2026-10-04

Commits: `f7dcb78` (fix + tests + docs), `50393f3` (pre-existing redset repairs).
Branch-local only — nothing pushed, no tag, no publish (hard limits honored).

## Root cause (evidence-backed; corrects the ticket's premise on one point)

Incident timeline (Abathur `.border/ledger.jsonl`, UTC 2026-10-04):
`04:36:59Z` check **PASS 0 blocking** (key8 579dcc27 @ head 5bd65ce0) →
`04:47:48Z` push landed → `04:47:54Z` **landing blocked, 20 findings** on
`loop/bank.py` (exfil-rfc1918 / exfil-ssh-target, gitleaks+secretlint twins).

Machine evidence (`/home/lab/workspace/harness/Abathur/.border/runs/579dcc27-2026-10-04T04-36-59-231Z/report.json`):
the PASS report's `allowHits` carry `exfil-rfc1918` entryIndex 642/643 (counts 16+16,
sample `loop/bank.py`) and `exfil-ssh-target` entryIndex 647 (count 8, same file).
So the pre-push lens DID surface the exact landing-reported findings — the owner's
allow pins suppressed them, and landing never consults the allow list. The ticket's
"the pre-push check lens never surfaced" is corrected by this record; the divergence
was real, but its primary mechanism is a **double standard in the allow list**, with a
secondary latent **disk/history-vs-tip gap** (bytes living only in the HEAD tree — e.g.
introduced by a merge commit's resolution, since deleted from disk — are invisible to
`git log -p` history and to every disk leg; `border exfil HEAD` on the incident tip
reported exactly the landing's 20 blocking, proving the landing lens's power).

## Fix shape (minimal semantic change; no severity mapping touched)

1. **Check runs the landing-grade tip lens.** New `src/check/tipTreeLens.ts`
   materializes HEAD's tree via the shared `scanTipTree` (`src/commands/exfil.ts`,
   same machinery landing uses) and its findings merge into the pipeline **before the
   allow-list and the verdict** — so config pins exempt matching tip findings by
   rule+file+digest exactly like every other pipeline finding; blocking mapping and
   exit codes unchanged. Leg runs when `effectiveTargets` contains `git`; exact-twin
   disk findings are deduped by identity; twin sub-legs inherit the existing
   broken-engine skips; any git plumbing failure throws ConfigError ⇒ **exit 2 loud**
   (existing degraded semantics, never a silent clean).
2. **scanTipTree grows optional `{sanitizer, skipGitleaks, skipSecretlint}`** — all
   defaults preserve pre-fix behavior byte-for-byte for landing and `border exfil`.
3. **Landing honors the same pins.** `runLandingVerification` applies
   `applyAllowList(findings, cfg.allow)` (wired from `loaded.config.allow` by
   `src/commands/push.ts`) before counting blocking, and echoes every exemption
   loudly (`rule#entryIndex:count`) — never silent. Doctrine untouched: executed push
   records are never rewritten; blocking hits still exit 1 "ALREADY PUBLIC; border
   detects, never erases"; unreachable still exits 2 minting nothing; append-only.
   With `allow=[]` (every pre-existing test seam) behavior is identical to pre-fix.
4. **Ledger key carries a lens identity.** `computeCheckKey` folds in
   `CHECK_LENS_ID = "range+tip-tree/1"` (in `src/check/rulesHash.ts`), so pre-fix
   range-only PASS records can never auto-certify pushes under the augmented lens —
   exactly one forced re-check per repo at upgrade (skip-ledger, push BLOCKED check,
   publish ledger gate, landing provenance all flow through this key).
5. README updated (en leg 7 + zh 概要) with the parity contract.

## Tests (written failing-first)

`test/check.tipLens.test.ts`:
- T1 `tip lens in check: bytes visible ONLY in the HEAD tree now block the gate (landing-grade parity)`
- T2 `allow-pin parity: the same rule+file+digest pin exempts matching tip findings in check AND in landing (loud, never silent)`
- T3 `skip-ledger lens identity: pre-fix range-only keys can never certify the tip-augmented lens; post-fix records self-skip`
- T4 `degraded tip leg fails loud; broken twin engines skip only their own tip sub-leg (existing degraded semantics preserved)`

Red phase (pre-fix): runner exited 1 — `Cannot find module '../src/check/tipTreeLens.ts'`;
after wiring the lens was absent, T1/T2 asserted-fail against pre-fix check behavior (T1's
pre-fix check PASSes where it must FAIL — see verification (a)). Green phase: 4/4 pass.
Existing landing suite (`exfil.landing.test.ts`) intentionally unmodified — doctrine tests
pass untouched.

## Verification — the four required outputs

### (a) Reproduction (fixture: file in HEAD tree only, disk+history invisible)

Fixture = init → side branch → main commit → `--no-ff` merge whose **resolution** stages
`leaky.txt` (runtime-assembled RFC1918 literal, F3 doctrine) → file removed from disk,
uncommitted. `git log -p` provably contains no leaky.txt hunk. Same fixture, both binaries:

OLD check (pre-fix dist `/tmp/opencode/border-dist-prefix/dist/index.js`,
sha256 `3e4b6a7f…9fa5f55`, run with the same cwd/config as the repo's bin):
`border check PASS: 0 finding(s), 0 blocking` — exit 0.

NEW check (`node dist/index.js check --force` post-fix):
`border check FAIL: 2 finding(s), 2 blocking` — exit 1, both blocking =
`CRITICAL exfil-rfc1918` on `leaky.txt` (one per twin engine, secretlint + gitleaks).

### (b) Build + full suite

- `npm run build` — clean (esbuild + assets, exit 0). `npm run typecheck` — exit 0.
- Pre-fix baseline (isolated worktree at HEAD 3c95bfd): `# tests 858 / # pass 842 / # fail 2 / # skipped 14`
  — the 2 failures are the **archived known-red C5 legs** (`CI-RUNNER-REDSET-2026-09-09.txt`
  lines 26/50: C5-1 record filter, C5-4 `twine:--version` spawn drift). Not caused by, and
  not masking, this change.
- Final suite post-fix: `SUITE_RC=0` — `# tests 862 / # pass 848 / # fail 0 / # skipped 14`
  (skips = engine-availability guards, same 14 as baseline). C5 repairs in `50393f3`
  restored the two red legs to their documented intent (test-side only).

### (c) Live smoke on the real gate

Command: `cd /home/lab/workspace/harness/Abathur && node /home/lab/workspace/harness/border/dist/index.js check --config /home/lab/workspace/harness/Abathur/.omo/border.yaml`

Verbatim result: `border check FAIL: 128 finding(s), 10 blocking` — exit 1. **The task's
"must still PASS" premise is contradicted by the current machine state** (L-OBJECT-FACTS):
the tip was cleaned this morning, and it is still clean — `loop/bank.py` carries 0 RFC1918
literals (fixture 0.0.0.x→RFC5737 move, landing record `2026-10-04T04:53:02Z` verdict
clean @ b708830). The 10 blocking come from **daytime drift after that PASS** (Abathur
moved b708830→f97792a, 5 commits at 12:55–14:05 +08):
`4× CRITICAL identity-not-allowlisted` (commits authored `abathur-seat <seat@host.example>`,
not in rules.authors), `2× CRITICAL path-pattern (rules.hardcodedPath)` + `2× CRITICAL
HOMEDIR` (new files `graders/pcb-agent/grader-v2.mjs`, `loop/constitution_g20.md`),
`1× exfil-rfc1918` + `1× exfil-ssh-target` from uncommitted same-morning appends to
`.omo/evidence/INTENT-LEDGER.md` (on-disk lens, pinned values edited → digests rotate).
**Not attributable to the tip leg**: the same command on the pre-fix dist emits
byte-identical output (`diff` of the two full transcripts: clean, 128 lines each).
Investigated, not papered over; re-waiving another seat's config/pins or rewriting its
ledger is owner/human authority (L-SURFACE-ATTRIBUTION / L-TESTIMONY-NOT-EVIDENCE), so
nothing here was touched. Side effects of the prescribed smoke: it appended one honest
t:check FAIL record (+ FAIL report dir) to Abathur's append-only ledger — certifies
nothing, blocks stale-skip only.

The clean state the premise referred to, verified verbatim under the NEW dist (detached
worktree of Abathur at b708830 with the machine-local `--config`):
`border check PASS: 113 finding(s), 0 blocking` — exit 0, and the landing-grade lens alone
on the same tip: `border exfil HEAD PASS: 113 finding(s), 0 blocking` — identical counts:
check's tip leg predicts the landing scan exactly, and no pre-existing green flips red
under the new lens.

### (d) This receipt

`/home/lab/workspace/harness/border/.border-notes/check-tip-lens-2026-10-04.md` (this file).

## Named residual gaps

1. **History-vs-tip, non-tip depths:** merge-commit-introduced bytes in *interior* history
   (never at the tip, never on disk) remain invisible to every lens including landing —
   pre-existing, untouched, now bounded by the tip leg only at the tip.
2. **Tag object trees:** landing verifies branch tips; annotated-tag payload trees are not
   scanned by landing nor by the new check leg (tag *messages* are, existing leg).
   Symmetric on both sides — same named follow-up as landing's registry-byte follow-up.
3. **Registry publish-byte landing:** still the plan's open follow-up (unchanged).
4. **Pin-set staleness window:** pins edited after a PASS change the config digest ⇒ the
   live key rotates ⇒ old records stop certifying — handled by existing key discipline,
   no new gap, stated for completeness.
5. **Abathur live state:** FAIL-10 per (c) awaits owner action (clean the new bytes or
   author new pins); border deliberately did not self-waive.
