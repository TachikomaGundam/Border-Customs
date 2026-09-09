# border-residue-gate — orchestrator learnings (live)

## Gate rounds
- R2 needed 4 verify rounds; R3a already 3+ (pattern: every adversarial round finds a NEW fail-open in the just-added literal-recognition; final attack surface each time = "token text pretending to be code": dynamic regex → computed member → substring OUT_DIR look-alikes → nested block comments).
- Rust block comments NEST (/* /* */ */ is one comment, Rust Reference). First-*/ scanning resurrects commented-out env::var as live code → fail-open (R3AFIX3-B1). Scanner must depth-track.
- Origin-only confinement doctrine: matcher verifies the root's ORIGIN (live env::var call), never normalizes the path; format!("/usr/local/{}",env OUT_DIR) confines by design → must be named in §8 concretely (N1), family routed to §1.6-9 lane.

## Ops
- Daemon restarts (~1-2h) evict background registry AND resume-able sessions → always dispatch fix rounds as fresh self-contained deep workers; verifiers always fresh independent sessions reading only disk artifacts (reports/ledger/contract).
- Orchestrator writes ledger + plan checkboxes + notepad ONLY; workers never touch ledger; verifiers never edit code/commits.
- valueDigest patternId discriminator: optional key ONLY set for rs-confinement rows so all pre-R3a digests stay byte-identical (proven by row-level dump cf54bc25…, script in evidence dir).

## 04:10 — cross-ecosystem law of silent escapes (from R2×4 + R3a×4 + R3b verify rounds)
Every round, regardless of ecosystem, the SAME three families defeat a freshly-written detector:
1. SPELLING VARIANTS of a known-bad call (Gem:: vs Gem. double-colon = LIVE Ruby static dispatch; %x| vs %x( vs backtick; cp["exec"] computed member; env::var vs const alias). Rule of thumb adopted: a token-class matcher must cover the language's whole synonym set or the §8 INVISIBLE list must name the gap explicitly ("costs a row, never a silent pass" — doctrine from R3a, re-proved by R3b BLK-1/BLK-4).
2. BINDING/INDIRECTION hops (R3a-V1 build.rs rebinding ≅ R3b-BLK-2 extconf `o="/usr/local/..."; File.write(o)`). Confinement analysis must resolve operands to roots (identifier → recorded assignments, transitive, cycle-guarded), or fail closed when a bare identifier meets a rooted literal anywhere in the file.
3. PARSER-QUIET NULLS (YAML comment breaking the extensions: block-seq ⇒ [] ⇒ silent clean; truncated paren; gunzip fail). Any degenerate parse result on the *declaration* path must THROW/stop-the-gate, never read as "nothing declared" — this is a plan-AC class (BLK-3 was the first AC-violation blocker).
Operational lesson for verifiers: hand every fixer round the three-family checklist BEFORE it writes code; and every blocker fix arrives with its repro pinned as a test (RED-first), which is why convergence took N rounds but each round strictly shrank the escape surface.

## Round-8 lesson (R3b, 2026-09-09)
Doc-round naming is NOT convergence when it names findings one-by-one: $stdout.reopen escaped the write-family after File.open/write/sysopen were each closed (BLK-7, fresh-sweep class, live+silent+unnamed at the "final doc round"). Correct move when a family first surfaces: exhaustive CALL-FORM ROSTER sweep (every IO/File/FileUtils/Kernel/Process spelling × rooted-operand) box-probed live ONCE, each member either covered or named-invisible-with-adjudication. Deletion/metadata verbs (unlink/chmod/times) may be excluded but only with a stated reason — silence is never an option. Verifier standing rule earned its keep: "live-unnamed ⇒ needs-fix even at doc stage".
Also: 7/7 task-resume evictions this era — fresh self-contained ~2K-token briefs are the only reliable worker pattern; sha-baseline + reverse-substitution is the only reliable cross-round file-identity proof.

## R3b rounds 7-9 (2026-09-09)
- FAMILY doctrine (round-8 lesson, binding for future legs): per-finding doc naming is NOT convergence — when a blocker class lands (fd-hijack reopen), the whole call-form family gets ONE exhaustive box-probed roster pass (covered | named-metadata | named-dead), not piecemeal patches.
- Ceiling metric discrepancy to resolve via verify-9 reproduction: brief lineage said matcher 271 "grep-method"; fix-8 measured 159 with grep -cvE '^\s*(//|/\*|\*|$)'. Both ≤300, but ledger/plan numbers must state the metric next to the value from now on.
- Phantom-state defense paid off: fix-8 arrived to a tree at 55 tests, not the 57 its brief claimed (fix-7 was a doc-only round whose pins never existed) — worker correctly added missing C14a/b itself and recorded the deviation instead of trusting the brief. Briefs should pin test COUNTS with file sha evidence, which this one did (6/6 untouchables), letting the mismatch be provable.
- Ledger discipline: dispatch lines get corrected in-place via ledger-correction events when bookkeeping outruns reality (line 108/110).

## Round-10 doctrine (2026-09-09): completeness-by-derivation
- 9 rounds of gate history proved the same meta-failure: hand-built rosters always miss a member ($> reopen alias, Dir.delete/unlink, File.lutime in r9 alone).
- Cure: M0 machine-derivation — enumerate verb universe from Ruby's own alias tables (ObjectSpace/original_name on File/Dir/IO/Kernel/FileUtils), persist ruby-alias-table-3.3.8.txt, then verdict EVERY member: COVERED / LIVE-UNCOVERED(extend+pin RED-first) / DEAD(named w/ box evidence) / NON-ROOTED(named adjudication). Reviewer independently re-runs M0 and diffs vs roster.
- Generalization for future rules (0.3.1+ B-rules): any closed-charset claim must ship with the derivation artifact that generated the charset, not prose listing one. Same pattern applies to the PATH/rc pairing tables (B5) and version-coherence checks.
- VERIFY THE DISK, NOT THE SUMMARY: a compress summary (b45) stated 'round-11 verified & [x], R4 dispatched' while disk showed the verify-11 dispatch had never fired (ledger 'bg pending', no FIX10 report, R3b unchecked). Root cause: prior compress entry was written from intended state, not observed state. Rule: before any state-dependent action, confirm via ledger tail + file existence + checkbox grep; summaries are indexes, not ground truth.

- [R3b close, 0.3.0 wave] ROOT VERIFICATION lesson (R4-era): an independent 0-probe is WORTHLESS unless (a) the payload sits in a file the stage actually scans (root-level p.rb is out of gem scan set) and (b) a positive sanity control (File.write rooted ⇒ 1) proves the harness non-vacuous in the SAME run. First probe attempt "passed" all invisibles vacuously; sanity FAIL of the mis-set (dotted=0) exposed it. Codified: every escape-claim probe roster ships WITH one caught-control per file-set.
- Wiki: residue doctrine page lives at docs/design/border-residue-gate (en/zh). aihr Windows diagnosis page = next.
