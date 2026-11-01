# .omo externalization proposal — 2026-10-23 (human decision required)

## Why (third-party audit, 2026-10-17, maintainability finding)
`.omo/` carries internal agent working files into the public repo: measured today,
`git ls-files .omo` = **382 files / 3.1 MB** (blame: 229 .json, 50 .txt, 36 .md, 16 .sh,
10 .log, 6 .py…), of which **55 files contain the dev-box absolute path `/home/lab/…`**.
Border's own native rules class `.omo/**` as AI-session artifact; the repo suppresses its
own findings via an explicit allow-list in the gate config — a standing exception precedent
for the exact rule the product enforces on others.

## Options
- **A. git rm --cached .omo/** (stop tracking; keep on disk; add to .gitignore).
  Cheapest, zero history rewrite. History keeps every file (public forever — includes the
  55 dev-path files). The self-exemption allow-list entries can then retire: the scanner
  never sees an *untracked* dir? No — it scans the working tree, so a repo-local
  `.gitignore`-based exclusion stays needed for check runs; the allow-list stays, but the
  PUBLIC PACKAGE and clone size shrink.
- **B. External evidence store** (recommended): move the evidence-bearing subset (the
  `.omo/evidence/*.md` receipts that README/SECURITY/tests cite by path) into a separate
  public or private repo (e.g. `Border-evidence`), keep `.omo/` untracked locally, and have
  docs cite `<repo>@<sha>:path` instead of repo-relative paths. Fully removes the noise from
  the product repo and the exception precedent. Cost: doc-path churn (measured: the strings
  `.omo/evidence/` appear in README.md, SECURITY.md, tests, CONTRIBUTING — one scripted pass).
- **C. Status quo**: defensible (the files ARE the audit trail the project's doctrine
  demands), at the cost named above.

## Recommendation
B for `evidence/` (the citable receipts), A for the rest (`.omo/run-continuation/`,
session JSONs — pure workspace, no citation value). No history rewrite (BFG/filter-repo)
is proposed: the tracked content is working notes + dev paths, not secrets — a secret scan
of the 55 files found only paths/usernames, already public — but that call, like the
history question, belongs to the human.

## What needs YOUR explicit decision
1. Choose A / B / C (or a mix).
2. If B: repo visibility (public mirror vs private + which members).
3. History rewrite is OFF the table unless you say otherwise.

Nothing above has been executed; this file is the proposal, per the release/rewrite human
gate. `border --version` provenance + the W1 pinned-consumption docs already remove the
original reason `.omo/` receipts were kept *inside* the repo (self-contained local audit
trail), which makes B viable now in a way it was not in September.
