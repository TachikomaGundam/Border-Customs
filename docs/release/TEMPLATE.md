# border-customs v<VERSION> — release packet receipt
- date: <ISO8601 host clock> · seat: <seat id> · lease: acquired <ver> by <seat> (<lease receipt line>)
gate: PASS
- gate run (verbatim): `node dist/index.js check --config border.yaml --json` on the release tree →
  `<verdict/counts line>` → exit <rc> (rc captured without pipe tails; PIPESTATUS or direct).
  Every new allow entry this release: one bullet each — value/family, scope, reason.
- tests (verbatim): `BORDER_PACK_TEST=1 npm test` → `# tests N / # pass N / # fail 0 / # skipped N`
- typecheck / version:check / build / npm audit --omit=dev: one line each, verbatim results.

## Contents of this release
- <what ships; pointer to the release commit message + README changelog section is acceptable>

## human execution (terminal, key stays human)
    cd <repo-root> && git push origin main v<VERSION>
then verify `npm view border-customs version` → <VERSION>; release lease after landing:
    bash <abathur-root>/scripts/release-lease.sh release

## APPENDIX <addenda as needed — each CI failure/root-cause/repair gets one dated addendum>

<!-- guard contract (scripts/git-hooks/pre-push): the file must exist at
     docs/release/<tag-version>.md in the pushing worktree and contain the line
     `gate: PASS`; the release lease must name the same version. Deletions of tags
     always pass the guard. Copy this file, fill every placeholder, delete nothing
     that was measured — the receipt records, the gate decides. -->
