# HANDOFF — border findings from the Abathur release-gate sessions (2026-10-18)

From: Abathur evolution seat. To: border workspace session.
Context: during Abathur's v0.3.0/v0.3.1 gate runs, the gate (border, this repo) was exercised hard.
Six findings below. All file references are absolute; all reproduction commands are runnable as-is.
None of these were fixed from the Abathur side (cross-repo discipline: report, don't touch).

---

## B0 — SECURITY ASSERTION, UNVERIFIED: does `npm pack --ignore-scripts` execute the audited repo's lifecycle hooks under npm ≤10?

Source: third-party review report (`/home/lab/tachikomagundam-仓库检视报告20261017.md`, Border-Customs section)
claims that under npm ≤10, `border check` executes code from the repo being audited (pack hook
execution). This claim has **never been independently reproduced**. It is the highest-risk open
item in the whole review set.

Relevant code: `/home/lab/workspace/harness/border/src/artifacts/npmPack.ts` `packOnce()` (~line 87-120)
runs exactly:

    npm pack <repoDir> --ignore-scripts --json --pack-destination <distDir>

The intent (comment at the function) is that `--ignore-scripts` prevents the target repo's
`prepack`/`prepare` hooks from running. The assertion says this defense fails on npm ≤10.

### Reproduction protocol (15 minutes, fail-closed)

1. Create a fixture package in a temp dir:

    mkdir -p /tmp/border-hook-probe && cd /tmp/border-hook-probe
    printf '{"name":"hook-probe","version":"0.0.1","scripts":{"prepack":"touch /tmp/border-hook-probe/PREPACK-RAN","prepare":"touch /tmp/border-hook-probe/PREPARE-RAN"}}' > package.json

2. Run with an npm 10.x binary (one exists on this machine):

    /home/lab/.local/node-v22.22.2/bin/npm pack /tmp/border-hook-probe --ignore-scripts --json --pack-destination /tmp/border-hook-probe/out

3. Check: `ls /tmp/border-hook-probe/PREPACK-RAN /tmp/border-hook-probe/PREPARE-RAN`
   - Files absent → claim FALSE for this npm version; document and close the assertion.
   - Files present → claim TRUE: `border check` on any npm target executes arbitrary repo code
     during packing on npm ≤10. This is a security-advisory-grade defect.

4. Also test npm 11 (host default) for contrast, and if possible npm 6/9 via npx for range mapping.

### If TRUE, candidate fixes (border side)

- Replace `npm pack` with a self-contained tar packer that never invokes npm against the target
  repo (border already byte-verifies the tarball; the packer only needs the `files` allowlist
  semantics), or
- run the pack inside a bubblewrap/container with the repo mounted read-only and no network, or
- require npm ≥ 11 and fail closed on older npm with a named error.

Acceptance: the reproduction script's outcome is recorded with exact npm version outputs;
if TRUE, a fix lands with a regression test that plants a hook marker and asserts it never fires.

---

## B1 — BUG: `--json` output loses the `file` field (null) on findings

Observed: `border check --json` emits findings whose `file` field is null, while the text output
shows the file correctly. During gate remediation I had to correlate JSON digests to files via
text-output ordering — fragile and unverifiable.

Evidence command (run in any gated repo with findings):

    border check --config <cfg> --json | python3 -c "import json,sys;[print(f.get('file')) for f in json.load(sys.stdin)['findings']]"

Acceptance: every finding in JSON output carries the same `file` value the text output prints.
Likely a serializer dropping a field — check the Finding type vs the JSON projection in
`/home/lab/workspace/harness/border/src/commands/check.ts` and `/home/lab/workspace/harness/border/src/findings.ts`.

---

## B2 — DESIGN: waiver pins are value-digest-based and die under any formatter

Observed: a repo-wide `biome check --write` (pure formatting, zero semantic change) invalidated
11 waiver pins at once, forcing a full re-verify + re-pin cycle. Pins hash the matched VALUE
(`redact()` sha256, `/home/lab/workspace/harness/border/src/redact.ts:24-26`); formatters that
join/split strings change the matched span, hence the digest.

Note `allow.ts:43` already supports matching against the redacted **snippet** as a glob — a
snippet-glob pin survives reflow when the distinctive head/tail survive. Consider documenting
snippet-glob pins as the formatter-resilient option, or adding a line/role anchor mode.

Acceptance: either documented guidance or a pin mode that survives a pure-format pass.

---

## B3 — FALSE POSITIVE: `[A-Za-z]:\\` drive-letter pattern fires on prose

Observed: the test message text `` `raw-repoPath:` `` (word ending in a letter, colon, backtick)
matched the drive-letter rule. The matched value was something like `h:\`` — a 3-char false hit.

Code: `/home/lab/workspace/harness/border/src/engines/secretlint.ts` DEFAULT_PATH_PATTERNS
(~line 95-101), entry `String.raw`[A-Za-z]:\\``.

Candidate fix: require a path-ish continuation after the backslash, e.g. `[A-Za-z]:\\[^\s`"'`]`,
or require the match to not be preceded by a letter (word boundary: `(?<![A-Za-z])[A-Za-z]:\\`).

Acceptance: regression test where a template literal containing `` `raw-repoPath:` `` does not fire,
and a real `C:\` path still does.

---

## B4 — OVER-MATCH: UNC pattern `\\[^\\]+\\` spans many lines greedily

Observed: in test files containing JS string escapes (`"\n"` sequences in stub-script sources),
the UNC pattern matched enormous spans — from one backslash, across newlines, to a far-away
backslash — because `[^\\]` matches `\n`. Reviewing "what did this hit" becomes guesswork.

Code: same DEFAULT_PATH_PATTERNS entry `String.raw`\\\\[^\\]+\\\\``.

Candidate fix: exclude newlines from the span: `\\\\[^\\\n]+\\\\`.

Acceptance: the previous cross-line matches in `src/test/bundle.test.ts`-style stub sources no
longer fire; a real `\\server\share` literal still fires.

---

## B5 — OPERATOR UX: no reveal mode for matched values

Observed: the masking design (only sha256 + first4/last4 snippet leave memory,
`/home/lab/workspace/harness/border/src/redact.ts`) is correct for egress safety, but during a
legitimate waiver-verification flow the operator cannot ask "what exactly matched?" without
reading border's source. I had to read `redact()` and recompute sha256 candidates by hand.

Candidate fix: an explicit local-only reveal flag (e.g. `border check --reveal` printing raw
matched values to the TTY, never to logs/JSON), gated behind an operator confirmation.

Acceptance: operator can verify a finding's exact value in one command; nothing raw is persisted.

---

## Priority suggestion

B0 first (security, currently unverified either way). B1 next (it silently undermines every
JSON-consuming workflow). B3+B4 are one file each. B2/B5 are design items.

— Abathur seat, 2026-10-18. Evidence basis: Abathur v0.3.0/v0.3.1 gate sessions; gate config
/home/lab/workspace/harness/Abathur/.omo/border.yaml; waiver class comments `class(v0.3.0-prep)`
and `class(v0.3.1-prep)` in that file.
