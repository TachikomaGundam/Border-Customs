# span-guard acceptance — handoff b61b42a (rule-class-3 false positives)

Seat: border. Date: 2026-11-02T02:1xZ (host clock, `date -u`). Handoff:
`/home/lab/workspace/harness/Abathur/handoffs/HANDOFF-BORDER-20261101-rule-class3-false-positives.md`
(commit b61b42a). Verdict: ACCEPTED AND SHIPPED (worktree; commit follows).

## What shipped (decisions taken by the handoff, executed as written)
- `src/exfil/tsSpans.ts`: TS compiler API (`ts.createSourceFile`, scriptKind by the
  handoff's closed extension list) collects string-literal / no-substitution-template /
  template-fragment spans (interpolation regions included — conservative); comments and
  identifiers are not spans. Parse diagnostics ⇒ null ⇒ caller keeps old behavior +
  one stderr WARNING per file (diagnostic verified silent on both acceptance trees:
  zero notes on border self-scan and on the full Abathur run).
- `exfil-cred-location` (rulesPath.ts): in JS/TS files a `.env` token is reported only
  when its offset lies inside a literal span. pypirc/SSHPASS untouched anywhere; all
  non-JS/TS extensions keep bare-mention behavior. Home-path and secret families untouched.
- All THREE tree faces carry filePath: check pipeline (exfilTreeScan), history blobs +
  exfil CLI (commands/exfil.ts ×2), tip-tree lens (shared scanTipTree) — the first two
  acceptance passes exposed that fixing only the pipeline leaves history/tip faces
  reporting the old way; the final Abathur diff proves all faces aligned.
- `typescript` moved dev→prod dependency; esbuild keeps it EXTERNAL (bundle stays
  1,720,689 bytes; runtime require verified: 5.9.3 from the installed package).
- `tsSpans.ts` registered in EXFIL_FINGERPRINT_SOURCES (rule semantics moved ⇒ cached
  PASSes rotate); golden rulesHash re-pinned 9f601bd2… → 9103a457ba35311d19c2652ed89e5c53f38353fd08c74ead572dfde101e26b59
  (BORDER_GOLDEN_RECENTRE=1, gitleaks 8.30.1, secretlint 13.0.5).
- tools/copy-assets.mjs: fingerprint staging now DERIVES the file list by parsing
  EXFIL_FINGERPRINT_SOURCES (second hand-mirrored-list drift incident of the same class;
  fail-closed guard proven in action — the missing asset EXITED 2, never a silent pass).

## Acceptance evidence (handoff §6, verbatim results)
1. `npm test`: `# tests 940 / # pass 927 / # fail 0 / # skipped 13` (suite +4 span-guard tests).
2. `npm run typecheck`: 0 errors.
3. Fixture presence (bare discovery swallowed by the repo's blanket `test/**` allow —
   DEVIATION: judged with an out-of-repo allow-free config, same binary same legs):
   pos/doc.md, pos/read-nested.ts, pos/read-secret.js, pos/template.js each 1 finding;
   all four neg paths 0 findings.
4. Against the Abathur tree (`node …/border/dist/index.js check`, no args, no config):
   baseline drift noted HONESTLY — the tree grew since the handoff (installed-0.8.2 run
   now reports 13,555 findings, not 20). Like-for-like diff installed-0.8.2 vs this build:
   REMOVED = exfil-cred-location MEDIUMs only (60 → 31 cred lines; member accesses across
   the whole tree incl. the six the handoff named: src/core/worktree.ts now 0 lines,
   run-bench/promote/retract among the removed); ADDED = zero non-summary lines;
   BLOCKING UNCHANGED 8933 → 8933 (nothing critical weakened); exit still 1 (real
   findings — md prose, literal paths — persist as designed).
5. Red-team: `process.env`/`os.env` receiver rule and `?.` skip preserved (old unit
   tests green); parse-failure fallback = old behavior + note (unit-pinned).
6. Fixture table: the handoff's §4 paths verbatim under test/fixtures-span-guard/
   (+ mixed/mix.js for the not-weakened proof); fixture dir excluded from tsc (data,
   not code — deliberate broken syntax).

## Deviations & residuals (named, not buried)
- §3 judged via allow-free out-of-repo config (reason above); presence/absence assertions unchanged.
- Interpolation regions inside template literals COUNT as literal (conservative-report);
  the handoff left this undecided in favor of safety; unit-pinned via pos/template.js.
- `typescript` in the production dependency graph (ruling's instruction): ~60MB installed
  tree, not bundled; bundle stays lean via external. npm audit --omit=dev re-verified below.
