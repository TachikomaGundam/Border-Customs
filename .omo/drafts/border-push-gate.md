---
slug: border-push-gate
status: approved
intent: clear
review_required: true
pending-action: review .omo/plans/border-push-gate.md
---

<!-- Migration record (2026-09-03): dir renamed boarder->border at user request; 6 sessions DB-migrated (backup opencode.db.bak-20260903-193054); draft renamed+sed'd; orphan boarder/.omo/run-continuation residuals deleted after verification (copies live in border/). -->
<!-- Metis gap analysis COMPLETE 2026-09-03: 50 gaps (8 contradictions G1-G8, 23 missing-constraints G9-G31, 5 scope-creep G32-G36, 7 assumptions G37-G43, 7 acceptance-criteria G44-G50). Full text: tool_0671a57f2001kk1wJvGi2M1ckM + visible msgs m00053/m00054. ALL resolutions adopted into plan; key fixes: skip-key extended (engine versions + remote URLs + refset), masking rule (raw secrets never on disk), .border/.gitignore='*' self-exclusion, fail-closed on missing engines, bare push = dry-run. -->
approach: Standalone TypeScript CLI `border` (Node 22, esbuild, tsc, node --test — mirrors harness conventions) with three layers: (1) deterministic checkers (gitleaks/trufflehog subprocess adapters + own TS rules for hardcoded paths/PII/artifacts), (2) LLM semantic review pass for regex-blind content, (3) push orchestrator (git multi-remote push, npm publish, PyPI publish) that is fail-closed on CRITICAL findings and dry-run-first. Config = per-repo `border.yaml`. OpenCode skill wrapper optional in later wave.
---

# Draft: border-push-gate

## Components (topology ledger)
<!-- Lock the SHAPE before depth. One row per top-level component that can succeed or fail independently. -->
- C1 config-core | `border.yaml` schema (zod) + CLI skeleton + findings model (severity, evidence loc) | active | harness/magi/package.json (stack convention)
- C2 secret-scan | gitleaks + trufflehog adapters (history + working tree), built-in TS fallback rules | active | librarian research report (see Findings)
- C3 leak-rules | deterministic non-secret checks: hardcoded abs paths, usernames/emails, internal hosts/IPs, personal info, debug artifacts (node_modules, .env, notebooks outputs, binaries, large files), git author/committer identity check | active | Findings F3
- C4 llm-review | agent-executed semantic pass over diff/tarball: comments/docs/identities regex can't catch | active | user's OpenCode fleet
- C5 push-orchestrator | git multi-remote push + npm publish + PyPI twine publish, each dry-run → gate → execute; per-platform immutability warnings | active | Findings F4/F5
- C6 report-ledger | machine-readable report (JSON+md), exit codes + append-only check/push ledger with fingerprint-based skip (no cron — user corrected: on-demand invocation) | active | user turn 2

## Open assumptions (announced defaults)
- Strictness | fail-closed: any CRITICAL blocks push; MEDIUM warns; `--allow` override requires explicit flag | publishing is irreversible; matches magi fail-closed philosophy | reversible
- Scan depth | full git history scan (not just HEAD): push sends ALL history to public remotes | deleted-but-committed secrets still leak | reversible
- Config surface | per-repo `border.yaml` (remotes, platforms, allowlists, expected authors) | repo-agnostic tool; discovered remotes in .git/config as fallback | reversible
- Stack | TS ESM Node 22 + esbuild + tsc + zod + `node --test` | magi/swarm convention (magi/package.json:7-20, swarm/package.json:12-14) | reversible

## Findings (cited - path:lines)
- F1 border/ is empty greenfield (only .codegraph/, .omo/). No existing push pipeline anywhere in harness/ (grep npm publish|twine|git push|pypi → only node_modules + PCB-Agent forensics logs).
- F2 Librarian research (session ses_f9923cd20ffehYGNTSTOSmCSx6): gitleaks = Go binary, regex rules, scans git history (`gitleaks detect`), exit-code gateable; trufflehog = verifies keys live via provider API calls (fewer false positives, needs network); secretlint = npm plugin ecosystem; detect-secrets = Python baseline workflow. npm: `files` whitelist in package.json > .npmignore; `npm pack --dry-run` to inspect tarball; lifecycle scripts (preinstall/postinstall) are top supply-chain risk; published versions IMMUTABLE (unpublish has 72h/withdraw rules); 2FA or OIDC trusted publishing. PyPI: twine upload; version numbers immutable (cannot re-use a yanked version); `twine check` validates README rendering; .gitignore does NOT apply to sdist — check MANIFEST.in/build backend; tokens scoped per-project.
- F3 Categories beyond user's list (hardcoded paths, PII, API keys): git author/committer emails & names in history; internal hostnames/private IPs/VLAN names; absolute paths exposing username (/home/lab/…); license headers + third-party license compliance; committed binaries/large files/Git-LFS; AI-session artifacts (.omo/, transcripts, opencode config with provider keys); notebook outputs embedding data; .env*/local overrides; private org/package name squatting; README/docs referencing unreleased internal projects.
- F4 magi/package.json:4 `"private": true` — magi must stay non-publishable; border must honor `private:true`/`publish: skip`.
- F5 swarm/package.json:9-11 `files:["dist"]` + license MIT — publish-ready shape; border's npm check must validate tarball contents via pack --dry-run, not repo tree.

## Decisions (with rationale)
- D1 Deterministic checkers run BEFORE LLM review and independently (CI-safe, cheap, no model needed for the hard gate); LLM layer adds, never replaces. Rationale: model output isn't a compliance gate.
- D2 Adapters shell out to gitleaks/trufflehog when installed; ship TS-regex fallback rules so border works on a bare machine. Probe capability at runtime.
- D3 npm/PyPI publish always two-phase: build+pack+scan-the-ARTIFACT, then publish only what was scanned (same tarball hash). Rationale: repo-clean ≠ tarball-clean (build backend can inject files).
- D4 Exit codes: 0 pass, 1 blocked, 2 config/tool error — gateable in cron/Action.

## Scope IN
- `border check` (all deterministic layers + optional LLM pass), `border push` (multi-remote git + npm + PyPI), `border.yaml` schema, report + evidence output, dry-run modes, first-run full-history scan, check-ledger skip mechanism (fingerprint = headSha+dirty+rulesHash+targets, per-target push state, registry version-exists pre-flight).

## Scope OUT (Must NOT have)
- No secret vault/rotation automation; no signing/cosign or in-toto provenance generation (flag as future); no managing remote platform settings (2FA/OIDC config is docs-only); no Windows-first support (Linux workstation + GitHub Actions); no git history rewriting (if history leaks, report and STOP — user decides filter-repo manually); no pushing PCB-Agent recovery logs / hr-archive-v1 contents.

- D5 (answered turn 2) Q1=CLI core + thin OpenCode skill wrapper. Q2=**on-demand only, no cron/scheduled push** — user invokes after fixing a version; scope change applied to C6. Q3=TDD with planted-leak fixture repos.

## Decisions added (turn 2)
- D6 Skip mechanism (方案 presented to user, pending veto at gate): append-only ledger `<repo>/.border/ledger.jsonl` + evidence `<repo>/.border/runs/<key8>-<ts>/report.{json,md}`; `.border/` auto-gitignored.
  - check-skip key = sha256(headSha ‖ per-target dirtyFlag ‖ rulesHash ‖ sorted targetSet). rulesHash = sha256 over border's bundled rules + LLM prompt templates + border.yaml digest → any rule/config/prompt/allowlist change invalidates cache and re-checks.
  - dirty working tree: git-target check cache may be reused only if clean; npm/PyPI pack consumes the WORKING TREE, so dirty ⇒ never skip for those targets. Amended/rebased ⇒ headSha changes ⇒ re-check (desired).
  - cached record stores verdict + severity counts + report path; PASS+matching key ⇒ skip with printed provenance (timestamp, report path); `--force` bypasses cache. LLM review verdict is cached like any checker (keyed by rulesHash incl. prompts).
  - per-target PUSH state machine: UNCHECKED → PASSED → PUSHED{remote sha / registry version, confirmed via ls-remote or registry query}. Push of a partially-pushed version re-pushes only pending targets; remote already at headSha ⇒ git target no-ops natively.
  - Registry immutability pre-flight: npm view / PyPI JSON API — if name@version already exists ⇒ FAIL loudly ("bump version required"), never silently skip (silent skip hides a forgotten version bump).

## Competitive research (turn 3 — COMPLETE; 2 librarian lanes + own search)
Full raw reports: bg_176d71dd (classic scanners) + bg_e2fe89eb (orchestrators+agent gates); truncated tails at ~/.local/share/opencode/tool-output/tool_066fd4a3c001FkjgrGEU0hx1VK & tool_066fdae5c001C1EPhdU1WU9g0S.
- VERDICT: user hunch HALF right. (a) Secret-scanning = fully commoditized, mature engines exist (REUSE, don't rebuild). (b) OUTBOUND pre-publish gate as an agent-era product = attempted by many, owned by NOBODY: every direct competitor is 0-few-star niche, single-registry, or already archived (zwyin/github-safe-publish archived within months = graveyard lesson). No tool combines: multi-registry push orchestration + artifact-content gate + AI-residue awareness + cross-tool skip ledger. border = ASSEMBLY product, and that is a feature not a bug.
- Mature engines to REUSE as adapters (all verified active 2026-09): gitleaks (MIT v8.30.1; git history+dir+stdin; --max-archive-depth scans INSIDE tarballs; .gitleaksignore = fingerprint ignore file = validation of D6 concept; exit 0/1/126, --exit-code). secretlint (MIT v13.0.5, Node-native = usable IN-PROCESS as library; rules incl @secretlint/rule-no-homedir (hardcoded home paths!), openai/anthropic/aws/npm/privatekey/conn-string rules, rule-pattern for custom regex; --no-gitignore scans built dist; exit 0/1/2). trufflehog (AGPL-3.0 v3.97.2 — 700+ detectors with LIVE API VERIFICATION; --fail exits 183; optional adapter). pre-commit-hooks (MIT; check-added-large-files 500kB default, detect-private-key). twine check (Apache; sdist/wheel metadata+README render gate, --strict). publint (MIT; npm tarball packaging correctness, --pack auto, non-zero on errors). OSSF scorecards (Apache; posture incl License + Binary-Artifacts checks; run post-publish too). npm pack --dry-run (manifest review, NO gate — wrap it).
- Platform-side blind spots (justify local gate): GitHub push protection free on public repos = secrets-only, server-side, no history-hygiene of YOUR identity; GitLab secret push protection skips: binary files, >1MiB diffs, renames, **the initial push that creates the repo**, >350k-line pushes.
- Direct competitors (survey of ~15): lon-coeng/publish-guard (MIT py; scans full history for forgotten terms/client names/author metadata — close on check side, no publish orchestration); stoneyang0213/repo-publish-guard (MIT py; 3-layer working+staging+history PII/secret scan); YottaMeta/yotta-publish-guard (MIT; **agent-skill form factor, check/pack/version/name/publish to GitHub+npm+ClawHub, dry-run-by-default, exit-2 gate, --force bypass** — structurally closest to border vision, 0 stars, wrong ecosystem, no skip ledger, no PyPI); LCYLYM/ai-release-guardian (AI-era artifact leaks: CLAUDE.md, sourcemaps, MCP configs, prompts; zero-dep CLI+Codex skill); vladnoskv/PublishGuard (npm+vsix only); commit-check (MIT pre-commit hooks check-author-email/name = author allowlist precedent); drev (MIT, AI session JSONL redaction + history scrub); supplychain-kit (Go single binary orchestrating syft+grype+trivy+osv-scanner+semgrep+gitleaks + MCP server) & shipsafe & shipwright skill (scan-battery orchestrators, no registry push state); ggshield (GitGuardian SaaS-coupled, has pre-push + AI-coding-tools real-time intercept).
- Release orchestrators (Area A): JReleaser/GoReleaser/release-it/semantic-release/lerna/changesets/nbdev/poetry/flit/twine — all active, do version/changelog/tag/publish + --dry-run + plugin verify slots (semantic-release verifyConditions/verifyRelease), BUT NONE inspects artifact CONTENT for leaks (twine check = metadata only; GoReleaser verify = post-publish asset recheck). They are complementary, not competitors.
- D7 (revises D2): ENGINE-FIRST — border's check core = adapters around gitleaks (subprocess) + secretlint (in-process lib) + twine check + publint, NOT hand-rolled regex batteries. Built-in TS rules reduced to the engine gap only: (i) AI-session path/artifact rules (.omo/, transcripts, opencode configs, .env*, probe files), (ii) git author/committer identity allowlist, (iii) internal hosts/private IPs/username-path patterns via secretlint rule-pattern config, (iv) pack-manifest diff (files entering npm/PyPI artifact). Adapters degrade gracefully when engine missing (report which engines ran; --require-engine flag hard-fails on absence). trufflehog optional (AGPL fine as subprocess; adds live key verification before pushing to public remotes).
- D8: keep own D6 ledger (no competitor has cross-tool run-state skip; gitleaks fingerprints validate the hash-key approach for per-finding ignores — complementary layers).

## Open questions
- (all resolved: D5/D6)

## Approval gate
status: approved (2026-09-03, user: "OK,能解决我提出的问题就行，动手吧" + follow-up "继续"; D6 skip-ledger scheme accepted by non-veto + explicit continue)
approach: CLI core + skill wrapper; on-demand check→confirm→push; fingerprint-keyed check ledger for duplicate-work skip (D6, as amended by Metis G21). Plan at .omo/plans/border-push-gate.md.
<!-- When exploration is exhausted and unknowns are answered, set status: awaiting-approval. -->
<!-- That durable record is the loop guard: on a later turn read it and resume at the gate instead of re-running exploration. -->

## High-accuracy review state (ulw-plan-review-round-state-contract, transition=replace, phase=review_round_initialized)

### Round 1 — CLOSED (both lanes changes-requested; all cited issues fixed)
- momus ses_f98c4d63affeoPQtzAg4ULQH1Q: **REJECT** 0 BLOCKER / 2 MAJOR / 7 MINOR (intake digest matched 801c70db…4170). oracle ses_f98c45c11ffecyMZFjk2kkJXpY: **REQUEST_CHANGES** 2 BLOCKER (B1 engines absent+no provisioning, B2 --targets scope missing from skip key ⇒ scope-confused unscanned npm artifact push) / 8 MAJOR (raw-bytes --report-path tmp; invalid exclude-dirs claim; todo15 PUSHED-on-exists contradiction; HIGH-vs-CRITICAL predicate clash; dogfood self-FAIL; URL credential persistence; border/ not-a-git-repo; stale-gitignored-dist skip hole) / 14 MINOR. Both intake-validated (descriptor chain + digest MATCH). Raw: tool-output files tool_0674e3a43001ntGlGrLefsgl3g (momus), tool_0674e1224001PX2a6GUEcbLmzW (oracle).
- FIXES APPLIED to plan (all 24 consolidated items): engine provisioning + git-init into todo1 (v8.30.1 binary, pip build/twine, require-engines fails loud); checkKey += effectiveTargets, push-scope-subset rule, llm-mode match, repack-digest artifact-freshness on SKIP (todo 14); gate predicate single-sourced CRITICAL|HIGH⇒blocked (todo 3, echoed 7/14/17); gitleaks stdout+--redact+--gitleaks-ignore-path, no --report-path, no generated .gitleaks.toml (todo 4); redact ≤12 full-mask + sanitizeUrl (todo 3+Must-have); pushstate PUSHED only with own push-record/owner else bump-FAIL (15); all-or-nothing ff guard + fixed order git→npm→pypi (16); publint/secretlint pinned-devDep invocation (11/5); lock stale-pid recovery + per-engine .border exclusion (10); llm persist contract + diff-base definition (18); dogfood enumerated allow-list w/ allow-hits proof (19); honesty fixture AKIA-shape real-engine suite (20); dep-matrix normalized to direct edges + row14+=10, row15+=13; dedup Verification header; W8 label; success criteria rewritten.

### Round 2 — CLOSED (momus APPROVE 3×MINOR adopted; oracle REQUEST_CHANGES 0B/1MAJOR/9MED — dual-approve NOT met ⇒ fix & resubmit)
- momus ses_f989ffdb2ffeThNXDMp8qf8TXo: **APPROVE** (raw tool_0677ae5d70019z9h34LILCLsom): m1 matrix row15 vs Blocked-by mismatch; m2 publint devDep unowned; m3 no extraction-temp cleanup directive.
- oracle ses_f989f9a51ffeY7Ccm8Nxi1rzKB: **REQUEST CHANGES** (raw tool_0677aec70001dk2m6maB43KKUC; verdict extraction also in visible msgs m00128/m00129): M1 todo11 manifest-diff rule self-contradicts its AC (files-glob "accounted" swallows the planted-file fixture; rule dead for its target class); M2 gitleaks --redact (default, verified report/finding.go:78-86) ⇒ valueDigest collapses to sha256("REDACTED") const, L245 snippet expectation false; M3 @secretlint/preset DOESN'T EXIST (404); M4 gitleaks dir scope over repo (.git/node_modules/ignored) unspecified; M5 dogfood allow-scope test/fixtures/** vs literals living in test/*.test.ts ⇒ self-FAIL; M6 todo16 AC reset --hard on BARE repo illegal; M7 ff-guard tag refs need peel + all-precheck-before-any-push; M8 in-process secretlint version probe undefined (use package-lock digest); M9a LLM bundle data-boundary residual-undiscovered-secrets by design (state), M9b verdaccio-stub executor-discretion = self-certification (remove); LOWs: npm-view E404-vs-network stderr parsing, PyPI owner heuristic caveat, sdist non-repro ⇒ mismatch=full-recheck not error, zod placement, version provenance=at HEAD.
- Live consensus: gitleaks v8.30.1 flags/subcommands TRUE (--max-archive-depth default 0), secretlint 13.0.5 family TRUE (preset-recommend exists), publint 0.3.24 --level+tarball TRUE, trufflehog-183 accepted.
- FIX LIST F-M1..F-M9b + F-mom1..3 + F-LOWs (5 edits): persisted fix details in this block's bullets — APPLYING to plan now; then measure digest; then Round-3 atomic init + both lanes fresh.
- (receipt 2026-09-03T23:20) ALL r2 fixes applied+verified in plan: M1 todo11 manifest-diff baseline semantics rewritten; M2/M4 todo4 --redact dropped (digests border-side at ingest), dir scan roots=worktree/extracted-dirs never .git, --config empty-rule-file pins default rules, --gitleaks-ignore-path; M3 @secretlint/preset removed (todo5 L125 + todo1 devDeps L93); M8 secretlint rulesHash=package-lock digest (todo5); M5 todo19 allow-scope→test/**; M6 todo16 bare-repo reset --hard removed (scratch-clone push); M7 todo16 ff-guard peels tags + all-precheck-before-any-push; M9a todo18 data-boundary statement verbatim; M9b verdaccio mandatory (todo17/19/20 + Verification strategy + success-criteria wording; todo1 devDeps ownership); m1 matrix row15→'13,14'; m2+m3 pinned devDep & finally-cleanup; LOWs: npm-view stderr classify, owner heuristic caveat, sdist freshness proof degrades to head+porcelain unchanged (todo14 + Must-have L29), version provenance AT HEAD (todo2 exposureSet sanitizeUrl+git-show). Structural self-check: 20 impl rows / 4 F rows / headers intact.
- Reviewer receipt note: oracle's r2 full-re-read completion text was truncated by transport cap at 'F-LOW5' — treated as read-through-findings (verdict+tally+live-verification sections intact); disclosed to both lanes on r3 dispatch.

### Round 3 — initialized (2026-09-03T23:20, re-review of post-r2 fixes)

```json
{
  "transition": "replace",
  "phase": "review_round_initialized",
  "atomic": true,
  "review_round_id": "r3-20260903T2320-borderpushgate",
  "review_authority": "user-approval-2026-09-03-review-required",
  "plan_path": ".omo/plans/border-push-gate.md",
  "plan_sha256": "121feb8b9463c9fec9b81119ea652e864afdfe22a3d91556717a2089b1b7badd",
  "acceptance_ledger_sha256": null,
  "completion_cas": {
    "run_id": "border-push-gate",
    "round_id": "r3-20260903T2320-borderpushgate",
    "phase": "review_round_complete",
    "live_plan_sha256": "121feb8b9463c9fec9b81119ea652e864afdfe22a3d91556717a2089b1b7badd",
    "acceptance_ledger_sha256": null
  },
  "lane": [
    {"lane_role": "momus", "launch_id": "lm-r3-momus-20260903T2320", "native_tool": "task", "agent_name": "momus", "native_task_id": "ses_f986977e8ffeQmuktuEEUZb4Kf", "session_id": "ses_f986977e8ffeQmuktuEEUZb4Kf", "background_task_id": "bg_e5fc0a42", "note": "fresh session — post-restart resume of r2 session impossible; r2 history inlined in prompt", "receipt": "REQUEST_CHANGES — 2 BLOCKER (npm classifier inverted fail-open; stale AC fixture) + 3 MINOR (citations, magi line-ref, Blocks convention) + 1 INFO; r2 minors 3/3 confirmed fixed", "dispatch_intent": "dual-review-r3-resubmit-momus", "dispatch_sha256": null, "receipt_sha256": null, "status": "closed", "result": "REQUEST_CHANGES"},
    {"lane_role": "oracle", "launch_id": "li-r3-oracle-20260903T2320", "native_tool": "task", "agent_name": "oracle", "native_task_id": "ses_f9868f807ffen3F5FkRehGleZw", "session_id": "ses_f9868f807ffen3F5FkRehGleZw", "background_task_id": "bg_4f81ed9c", "note": "fresh session — post-restart resume of r2 session impossible; r2 findings inlined in prompt", "receipt": "REQUEST_CHANGES — 1 BLOCKER ×4pt (gitleaks contract empirically wrong on pinned v8.30.1: empty --config fail-OPEN; git-leg .gitleaks.toml auto-load; -f json no stdout w/o --report-path -; --source nonexistent) + 2 MAJOR (AC stale; baseline needs ∪ always-packed) + 1 MINOR (todo-19 repoint); all r2 fixes verified on real binary; publint shape VALID", "dispatch_intent": "dual-review-r3-resubmit-oracle", "dispatch_sha256": null, "receipt_sha256": null, "status": "closed", "result": "REQUEST_CHANGES"}
  ]
}
```

### Round 3 — CLOSED (both lanes REQUEST_CHANGES on digest 121feb8b…badd)
- momus r3 (raw tool_067b4114e001IRvObKajfs628h): 2 BLOCKER + 3 MINOR + 1 INFO as receipt above. Fix ledger: mB1→L189 polarity; mB2=M-A→L176 AC rewrite; mm1→draft cites (L95 anchors, L119/127/135 :59→:63); mm2→L47 magi:8; mm3→L63 authority clause; INFO→L36 private split wording.
- oracle r3 (raw tool_067b433c3001g1Ikq3I7Cs1L0E, final report L810-860): B1 four-point empirical (real v8.30.1 binary + tag sources + npm registry probes): (1) empty/`rules=[]` --config REPLACES embedded defaults→zero rules→silent fail-OPEN (cmd/root.go:149-151, config/config.go:247-258) — my r2 M4 fix was WRONG; (2) git leg without --config auto-loads `<source>/.gitleaks.toml` (1→0 findings proof) — half-applied G14 defense; (3) `-f json` alone = 0 stdout bytes, reporter attaches only with --report-path, `-` IS the stdout pipe; (4) no `--source` flag — positional targets, --source→exit 126. M-A (AC), M-B (npm packs package.json/README/LICENSE/main/bin EVEN WITH files: — dry-run proof), m-a (L47→post-plan supervised run).
- r4 fixes applied (all of the above; plan now 269 lines digest aca924e3…): L117 gitleaks contract full rewrite (positional, `--report-path -` on-disk-forbidden, vendored `assets/gitleaks-defaults-v8.30.1.toml` on BOTH legs, empty-config strictly forbidden w/ evidence cite, GITLEAKS_CONFIG{,_TOML} env strip); L93 vendor+sha256→evidence+rulesHash; L173 union-baseline + positional cite; L176 AC rewrite (files:["src"]+main-packed dist/leaked-build.js, diff-HIGH and content-CRITICAL asserted separately, clean fixture main∈src); L189 polarity; L120 + AC committed-`.gitleaks.toml rules=[]` STILL-reported proof; L63 matrix-authority clause; L127/135 draft:63 repoint; L95 anchors; L32 126-never-clean contract; L36 private split; L47 magi:8 + user-supervised-first-post-plan-run.
- Truncation disclosures (for round-4 letters): momus r3 raw capture had mid-line breaks (BLOCKER-1 required-change tail reconstructed from its reasoning L442); oracle r3 raw tail clean (L810-860 extracted verbatim).

### Round 4 — initialized
```json
{
  "transition": "replace",
  "phase": "review_round_initialized",
  "atomic": true,
  "review_round_id": "r4-20260904T0030-borderpushgate",
  "review_authority": "user-approval-2026-09-03-review-required",
  "plan_path": ".omo/plans/border-push-gate.md",
  "plan_sha256": "aca924e3fff83480d54eb9a5e9d0ebd99d946b68e7f384181ae93b8ccad0bba2",
  "acceptance_ledger_sha256": null,
  "completion_cas": {
    "run_id": "border-push-gate",
    "round_id": "r4-20260904T0030-borderpushgate",
    "phase": "review_round_complete",
    "live_plan_sha256": "aca924e3fff83480d54eb9a5e9d0ebd99d946b68e7f384181ae93b8ccad0bba2",
    "acceptance_ledger_sha256": null
  },
  "lane": [
    {"lane_role": "momus", "launch_id": "lm-r4-momus-20260904T0030", "native_tool": "task", "agent_name": "momus", "native_task_id": "ses_f98369a18ffeddW5nP8CqMSrZO", "session_id": "ses_f98369a18ffeddW5nP8CqMSrZO", "background_task_id": "bg_b84e2289", "note": "fresh session — resume failed (continuation handles dead for COMPLETED bg tasks, in-process too, m00194); r3 verdicts+fix ledger inlined in prompt", "receipt": null, "dispatch_intent": "dual-review-r4-resubmit-momus", "dispatch_sha256": null, "receipt_sha256": null, "status": "complete", "result": "APPROVE (0B/0M/5minor+1nit; raw tool_067e605a700105P7dD3PAgThMM)"},
    {"lane_role": "oracle", "launch_id": "li-r4-oracle-20260904T0030", "native_tool": "task", "agent_name": "oracle", "native_task_id": "ses_f98358ab5ffeZ7JJnCu4TSUgYC", "session_id": "ses_f98358ab5ffeZ7JJnCu4TSUgYC", "background_task_id": "bg_7b3c160e", "note": "fresh session — same resume-failure fallback; r3 empirical findings+fix ledger inlined; instructed to re-verify vendored-config design on REAL v8.30.1 binary", "receipt": null, "dispatch_intent": "dual-review-r4-resubmit-oracle", "dispatch_sha256": null, "receipt_sha256": null, "status": "complete", "result": "REQUEST_CHANGES (1B/1M/2m; real-binary proof; raw tool_067e60c42001JLeTfZQfA5xTYA)"}
  ]
}
```

### Round 4 — CLOSED (momus APPROVE / oracle REQUEST_CHANGES, both on digest aca924e3…; dual approval NOT met)
- receipts: momus = APPROVE, 0B/0M/5 MINOR+1 nit (r3 items 9/9 confirmed fixed; refs 100% exist). oracle = REQUEST_CHANGES with fresh REAL-BINARY proofs (/tmp/gitleaks v8.30.1 persisted; fixtures cleaned):
  - **B-R4-1**: L117/L120 `.gitleaksignore` neutralization claim FALSE — root.go `Detector()` 300-321: `-i/--gitleaks-ignore-path` is PURELY ADDITIVE (304-315); lines 317-320 UNCONDITIONALLY AddGitleaksIgnore({source}/.gitleaksignore); git.go:34-49 passes positional repo as source ⇒ committed worktree .gitleaksignore suppresses even with -i empty-file (proof: 2→1 findings, aws-access-token silenced). History-only copies do NOT suppress (worktree copy only). FIX (adopt oracle-(a) + keep -i for CWD default '.'): border-side hostile-config detector — target HEAD tree containing `.gitleaksignore` or `.gitleaks.toml` ⇒ CRITICAL `repo-self-ignores-findings`; rewrite L120 AC accordingly; stop claiming -i defeats repo-side files.
  - **M-R4-1** (== momus minor #1): L173 union 'plus main/bin' makes AC's main-packed leak accounted ⇒ diff rule unfireable on own AC (M-A class recurs). FIX: accounted set = files-globs ∪ doc'd always-packed NAME-SET only; main/bin forced-pack entries deliberately UNACCOUNTED (that is the artifact-unexpected-file signature).
  - m-R4-1: L117 Must-NOT 'no --report-path' → 'no on-disk --report-path <file>; `-` the only permitted form' (momus dup).
  - m-R4-2: CHANGELOG* NOT always-packed on npm 11.19.1 (empirical) — reword name-set as version-dependent docs list, keep as accounted (over-accounting safe).
- momus minors adopted: draft cites draft:14→18, draft:24→28 (or anchors); matrix row3 Blocks minus 10, rows 11/12 minus 15 (direct-only purity); message string unified `version-exists` + `bump version required` (L189/L192/criterion-4); TL;DR 'Your next move' → updated at r5 init.
- Oracle r4 VERIFIED-GOOD (do not re-litigate in r5 letters): positional/`--report-path -` contract, vendored-config defeats hostile .gitleaks.toml both legs (initConfig priority --config>env>autoload), env-strip meaningful, todo-20 key fires aws rule, `AKIAIOSFODNN7EXAMPLE` is built-in-allowlisted (never use in engine-fired fixtures), `-f json`-only 0 bytes, --source→126, release source tarball fetchable, npm-view polarity OK.

### Round 5 — initialized
```json
{
  "transition": "replace",
  "phase": "review_round_initialized",
  "atomic": true,
  "review_round_id": "r5-20260904T0130-borderpushgate",
  "review_authority": "user-approval-2026-09-03-review-required",
  "plan_path": ".omo/plans/border-push-gate.md",
  "plan_sha256": "e24734bfb41eb3ca0c36d2cbcee0f02f3079f425a0307c7f170985ea1b36dfbd",
  "acceptance_ledger_sha256": null,
  "completion_cas": {
    "run_id": "border-push-gate",
    "round_id": "r5-20260904T0130-borderpushgate",
    "phase": "review_round_complete",
    "live_plan_sha256": "e24734bfb41eb3ca0c36d2cbcee0f02f3079f425a0307c7f170985ea1b36dfbd",
    "acceptance_ledger_sha256": null
  },
  "r5_fix_ledger": "digest aca924e3→e24734bf, 269 lines, 20+4 rows: (1) B-R4-1: L117 -i claim corrected (additive-only, root.go:304-315/317-320 cites) + Hostile-config detector CRITICAL repo-self-ignores-findings via git ls-tree HEAD check; L120 AC rewritten to detector-proof (engine neutralization declared IMPOSSIBLE-by-design); (2) M-R4-1: L173 accounted set = files-globs ∪ doc'd always-packed NAME-SET; main/bin force-packed but UNACCOUNTED by design; (3) m-R4-2: CHANGELOG* membership noted npm-version-dependent; (4) m-R4-1: Must-NOT 'no on-disk --report-path <file> (- only permitted)'; (5) matrix rows 3/11/12 transitive edges dropped; (6) version-exists message unified `version-exists` + `bump version required` L189+L205; (7) draft cites :24→:28, :14→:18; (8) TL;DR next-move → r5 wording; (9) '.;' join fix.",
  "lane": [
    {"lane_role": "momus", "launch_id": "lm-r5-momus-20260904T0130", "native_tool": "task", "agent_name": "momus", "native_task_id": "ses_f98091121ffeR1zOk2YD8tnepJ", "session_id": "ses_f98091121ffeR1zOk2YD8tnepJ", "background_task_id": "bg_39758c05", "note": "CORRECTION (r6 bookkeeping): the 'serial dispatch' theory was WRONG — the 'died 2s' lanes actually completed with full results; parallel dispatch is fine. This lane (bg_39758c05) returned the authoritative full-letter APPROVE; sibling bg_f5f1913d (concurrent earlier attempt) also completed: OKAY + 1 non-blocking nit (L95 draft-cite claim imprecise — left as-is).", "receipt": "verdict: APPROVE (first line exact); raw tool_0680aecc90010ZnoWE37edE1YC:312-325; receipt digest e24734bf…36dfbd", "dispatch_intent": "dual-review-r5-resubmit-momus", "dispatch_sha256": null, "receipt_sha256": null, "status": "complete", "result": "APPROVE"},
    {"lane_role": "oracle", "launch_id": "li-r5-oracle-20260904T0130", "native_tool": "task", "agent_name": "oracle", "native_task_id": "ses_f980a470affeb25KByys9B5q6p", "session_id": "ses_f980a470affeb25KByys9B5q6p", "background_task_id": "bg_314a5506", "note": "was marked QUEUED — actually dispatched and COMPLETED (22m52s). Verdict block: tool_0680b736c0017EUljAMsffk1oo:518-568.", "receipt": "verdict: REQUEST_CHANGES — 1 new BLOCKER (B-R5-1 tracked-.border/ fail-open) + 2 MINOR (m-R5-a dry-run exit-0 contradiction; m-R5-b pip PEP668) + 1 INFO (absent remote ref); ALL prior fixes verified empirically clean (npm 11.19.1 live pack, gitleaks root.go, all registry pins, @secretlint/preset 404)", "dispatch_intent": "dual-review-r5-resubmit-oracle", "dispatch_sha256": null, "receipt_sha256": null, "status": "complete", "result": "REQUEST_CHANGES"}
  ]
}
```

### Round 5 — CLOSED (momus APPROVE / oracle REQUEST_CHANGES, both on digest e24734bf…; dual approval NOT met)
- oracle r5 findings → r6 fixes APPLIED verbatim-as-prescribed: B-R5-1 → todo-10 Tracked-state guard (`git ls-files -- .border/` empty assert before engine legs ⇒ CRITICAL `repo-tracks-border-state` ≤50 paths ⇒ FAIL; rationale 'ingest filter legit only for UNTRACKED state; tracked .border collides with G22' + dogfood-passes note) + todo-10 AC hostile fixture COMMITTED `.border/planted.env` ⇒ check exits 1 (junk-report fixture explicitly marked UNTRACKED); m-R5-a → todo-7 dry-run 'exits with the verdict the gate would produce' + todo-7 AC gate-blocked-dry-run-exits-1-bare-sha-unchanged; m-R5-b → todo-1 pip `--user --break-system-packages` + PEP668 note + uv-conditional; INFO → todo-16 'remote ref ABSENT ⇒ guard trivially passes' clause.
- Oracle r5 VERIFIED-CLEAN EMPIRICS (do not re-litigate in r6 letters): npm 11.19.1 live always-packed test matches M-R4-1/m-R4-2 claims; gitleaks root.go:300-321 additivity + 317-320 unconditional ignore-apply + reporter-only-with-reportPath (`-`=stdout) confirmed in source; registry pins ALL exist (publint 0.3.24, @secretlint/* 13.0.5 family, ts 5.9.3, esbuild 0.25.12, @types/node 22.19.0, zod 4.x, verdaccio latest); @secretlint/preset→404 re-confirmed; magi:8-10 + swarm pins + register-ts.mjs real; L195 'Commit: Y' scare = read-display artifact, file byte-intact. Momus r5 VERIFIED-CLEAN: 5/5 r4 minors + nit resolved; matrix-authority convention holds; hostile-detector↔dogfood↔todo-20↔AC coherency clean.
- r6 digest measured on final text: ab4cd7d48a1b07a577158cd62c820f8cbc1185a195d793d0db874c07c47ad4e6 (269 lines, 20 impl + 4 F rows, wc/grep green).

### Round 6 — initialized
```json
{
  "transition": "replace",
  "phase": "review_round_initialized",
  "atomic": true,
  "review_round_id": "r6-20260904T0330-borderpushgate",
  "review_authority": "user-approval-2026-09-03-review-required",
  "plan_path": ".omo/plans/border-push-gate.md",
  "plan_sha256": "ab4cd7d48a1b07a577158cd62c820f8cbc1185a195d793d0db874c07c47ad4e6",
  "acceptance_ledger_sha256": null,
  "completion_cas": {
    "run_id": "border-push-gate",
    "round_id": "r6-20260904T0330-borderpushgate",
    "phase": "review_round_complete",
    "live_plan_sha256": "ab4cd7d48a1b07a577158cd62c820f8cbc1185a195d793d0db874c07c47ad4e6",
    "acceptance_ledger_sha256": null
  },
  "r6_scope": "delta review: the 6 r6 edits above (todo-1 guard/AC, todo-7 exit-mirror/AC, todo-10 tracked-state guard+AC, todo-16 absent-ref clause) folded exactly as prescribed + ripple-free; everything else = rounds-1..5 VERIFIED-CLEAN lists",
  "lane": [
    {"lane_role": "momus", "launch_id": "lm-r6-momus-20260904T0330", "native_tool": "task", "agent_name": "momus", "native_task_id": "ses_f97e8777bffeaBVGJCvp2FZ1RL", "session_id": "ses_f97e8777bffeaBVGJCvp2FZ1RL", "background_task_id": "bg_bf677467", "note": "fresh session, self-contained letter (r6 delta scope + verified-clean do-not-relitigate lists inlined)", "receipt": "verdict: APPROVE — 0B/0M/0minor/2 NIT; digest measured ab4cd7d4… MATCH; full untruncated reads of all 6 edited lines incl. tails via /tmp extraction", "dispatch_intent": "dual-review-r6-delta-momus", "dispatch_sha256": null, "receipt_sha256": null, "status": "complete", "result": "APPROVE"},
    {"lane_role": "oracle", "launch_id": "li-r6-oracle-20260904T0330", "native_tool": "task", "agent_name": "oracle", "native_task_id": "ses_f97e7dbe6ffelSopxdmiNQYGs3", "session_id": "ses_f97e7dbe6ffelSopxdmiNQYGs3", "background_task_id": "bg_836c13a6", "note": "fresh session, self-contained letter; instructed cheap empirical checks (pip flag, git ls-files no-dir behavior) + ripple greps; verdict block extraction via targeted grep of saved tool-output on completion", "receipt": "verdict: APPROVE — 4/4 closures exact-prescription, ripple audit 0 contradictions, empirics 3/3 (pip 25.1.1 flag real + EXTERNALLY-MANAGED marker; ls-files absent/untracked/tracked all correct — guard keys on OUTPUT-EMPTINESS, index-based ⇒ catches staged-but-uncommitted too); 1 INFO non-blocking; digest ab4cd7d4… MATCH", "dispatch_intent": "dual-review-r6-delta-oracle", "dispatch_sha256": null, "receipt_sha256": null, "status": "complete", "result": "APPROVE"}
  ]
}
```

### Round 6 — CLOSED — **DUAL APPROVE** (momus APPROVE 2×NIT / oracle APPROVE 1×INFO, both on digest ab4cd7d4…; LIVE revalidation post-verdict: same digest, 269 lines, 20 impl + 4 F rows, mtime unchanged)
- **FINAL APPROVED PLAN: .omo/plans/border-push-gate.md @ sha256 ab4cd7d48a1b07a577158cd62c820f8cbc1185a195d793d0db874c07c47ad4e6.**
- Accepted-not-applied findings (post-approval plan edits would break the approved digest — carried forward as executor notes): N1 L33 provisioning bullet keeps unpinned pip sketch (authoritative mechanics in todo 1 — optionally append '(exact flags per todo 1 Step 1)' at next legitimate touch); N2 L213 absent-ref clause nested in branch parenthetical — generalizes to tags by wording/rationale/AC (first push --follow-tags to empty bare must pass); INFO L33/uv wording compatible.
- Review arc: r1 both REQUEST_CHANGES (24 fixes) → r2 momus APPROVE/oracle RQ (14 fixes) → r3 both RQ (6 fixes; empirical gitleaks contract rewrite) → r4 momus APPROVE/oracle RQ (9 fixes) → r5 momus APPROVE ×2/oracle RQ (6 fixes) → **r6 DUAL APPROVE**. 6 rounds, 59 findings, every engine claim binary/source-verified on gitleaks v8.30.1 + npm 11.19.1 + pip 25.1.1.
- Session-id disclosure honored by both lanes (not fabricated). Momus lanes' /tmp scratch: /tmp/r6-truncated-lines.txt; oracle: /tmp/r6guard test repo — disposable.

