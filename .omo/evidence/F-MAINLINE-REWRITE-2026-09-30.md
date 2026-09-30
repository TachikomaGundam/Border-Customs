# F-MAINLINE-REWRITE — border repo's remote main force-replaced by an identity-rewritten lineage (2026-09-30, OPEN, human ruling)

verified 2026-09-30 (Asia/Shanghai) · session: border maintenance (orders 1–7 chain) · review-by 2026-12-30

## What happened (machine receipts)

During the v0.7.1 release push (`git push origin main v0.7.1`, 2026-09-30 ~15:54 local):
- `v0.7.1` tag pushed fine (remote tag 53157cea → commit 4a3f674) and CI run 36686422413
  SUCCEEDED on it → npm 0.7.1 published (see F-I4-RULER-RACE doc + INTENT-LEDGER order 7).
- `main` was REJECTED non-fast-forward. After fetch: remote main = `8d8c5d0`, a lineage with
  **zero common ancestry with our local main** (`git merge-base main origin/main` → NONE).

## Forensics

1. **Twin lineage**: remote carries the full project history 09-04→09-30 with commit titles
   identical to ours but authored `TachikomaGundam <TachikomaGundam@users.noreply.github.com>`.
   Per-pair content diff (4 checked: 5542a55/9eb9fc6, 9601214/8d8c5d0, f0927f6/4a791d9,
   b9ddf67/48ea745): `git diff --stat` EMPTY — **trees byte-identical, identity+parent hashes differ**.
2. **Rewrite signature**: every twin's committer-date EQUALS the corresponding local commit's
   author-date to the second (8d8c5d0 = 12:55:26+08:00 ≡ 9601214 %aI). That is
   `--committer-date-is-author-date` / filter-branch-style identity rewriting, done elsewhere,
   not a fresh parallel development.
3. **When remote flipped**: v0.7.0's red CI run 36671401844 (started 05:00:16Z) executed
   `headSha=5542a55` — proof the remote v0.7.0 tag pointed at OUR Wiki.js lineage at 05:00Z.
   Today's fetch shows remote `refs/tags/v0.7.0` = 2c8ef1e8 → twin `9eb9fc6`: the tag was
   MOVED, and main replaced, between 05:00Z and 07:54Z.
4. Actor surface: GitHub account TachikomaGundam (owner's) — could be the owner deliberately
   normalizing identity to their GitHub account, another machine/copy, or an unattended
   process. The handoff file (written ~05:00Z) recorded remote main=9601214 — consistent with
   the flip happening AFTER it.

## Consequences (as of this record)

- The released line is coherent: npm 0.7.1 = tag v0.7.1 = commit 4a3f674 with the full
  Wiki.js-lineage fix chain (provenance-verified, three-way shasum, V2 live active).
- But remote `main` does NOT contain the 0.7.1 fix commits nor the incident registrations
  (e60e68e/4a3f674 live only on the v0.7.1 tag lineage; remote main tip = twin 8d8c5d0, i.e.
  content-equivalent to 9601214 only).
- Local main (Wiki.js lineage) is unpushable without either accepting the rewrite or a
  human force-restore. border itself NEVER force-pushes; this maintenance session pushed nothing else.

## Ruling menu (human terminal; agent executes on explicit order)

**A. Accept rewritten lineage** (owner wants GitHub-attributable history):
   1. `git rebase --onto origin/main 9601214 main` — replays e60e68e+4a3f674 (+ this
      incident's docs commits) onto 8d8c5d0; trees preserved.
   2. POLICY FRICTION: the repo's own gate allowlists only `Wiki.js <wiki@sumteclab.com>`;
      a history leg over the rebased lineage sees Tachikoma-authored commits. Decide: extend
      `rules.authors` in border.yaml (a pinned-policy edit by the owner — enumerated, rides
      rulesHash, invalidates cached PASSes) OR re-sign future work under Wiki.js anyway
      (transmit-set checks would pass; full-history legs would not).
   3. v0.7.0/v0.7.1 tag placement inconsistency remains (v0.7.1 → pre-rebase commit).
      Optionally human deletes+retargets tags (tag rewrite = human-only).
**B. Treat as unauthorized clobber** (restore):
   1. Human force-pushes Wiki.js lineage: `git push --force-with-lease origin main` (from this
      machine's repo, tip now includes docs commits) and retags v0.7.0 → 5542a55 (delete
      remote tag first), keeping released v0.7.1 as-is (published bytes immutable).
   2. Rotate any credential that could have written the rewrite if the actor is unidentified
      (check GitHub security log: git over SSH key events ~05:00–07:54Z today).
**C. Leave main parked, decide later** — npm line already correct; no data lost (both
   lineages fully local); risk = future sessions cloning remote see the rewritten history.

## Not-doing (recorded)

- No force-push, no tag rewrite, no allowlist edit were performed by this session.
  L-GOVERNANCE/L-TESTIMONY discipline: remote-history identity is a human-owned fact.
