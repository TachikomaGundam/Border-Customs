# build-stage consent wave — 2026-10-23

Ratified by sibyl_consult `sibyl-20261023T112953Z-7ada` (APPROVE 2A/1R; the REJECT
seat's must_fix list IS the merged contract and is fully honored below). Chamber
lane run `sibyl-20261023T110726Z-f057` died pre-launch (evidence: run dir contains
only launch files); the consult lane reproduced all six claims by external re-probe.

## Kill chain closed (must_fix 1: config trust boundary)
A hostile clone ships its own border.yaml; `border check` loads it from the audited
tree by default (src/config.ts discovery), so declaring pypi/rubygems targets made
the CHECK build them: PEP 517 backends and gemspecs are code. Repro markers (2026-10-23):
`SETUP-PY-RAN` created under `python3 -m build --no-isolation` even though the build
later errored; `GEMSPEC-RAN` created by `gem build` (exit 0). crates
`cargo package --allow-dirty --no-verify` verified NON-executing.

Gate: src/check/buildConsent.ts — operator consent only from `--allow-builds` or
`BORDER_ALLOW_BUILDS=1` (outside the audited tree; any other env value fails closed
naming itself). Wired at every execution edge:
- src/check.ts stage loop (withheld ⇒ MEDIUM `build-stage-withheld` per channel, artifacts null);
- src/ledger/freshness.ts verifyArtifactFreshness (no consent ⇒ never fresh ⇒ full scan-only run);
- src/ledger.ts recordCheckRun legacy npm-repack fallback;
- src/scan/scan.ts (fetched third-party artifacts: consent or named exit 2).
scan-only PASS cannot back a registry publish: src/push/core.ts:124 already fails
closed on "PASSED check recorded no artifacts" (verified, unchanged).
npmPackSafety (npm<11 pack-phase refusal) retained as the second layer (ruling Q5).

## Marker fixture (must_fix 3, zero-execution proof)
test/build.execMarkers.test.ts: one repo, pypi backend + build.rs + gemspec markers.
Withheld ⇒ exit 0, zero markers, 3 withheld findings, record artifacts null.
Consented ⇒ SETUP-PY-RAN + GEMSPEC-RAN exist; CARGO-BUILDRS-RAN never does; the
consented crates stage flags the fixture's out-of-OUT_DIR build.rs
(residue-out-of-tree-write HIGH ⇒ exit 1 is the stage-working proof).
test/buildConsent.test.ts: consent semantics pinned (flag/env=1 only; ambiguous fail closed).
ledger.test gained: no-consent freshness ⇒ false (negative).

## README/SECURITY wording (must_fix 7, three sites)
README:29 npm paragraph, README:234 present-tense promise rewritten to the consent
model (containment-by-consent, not sandbox, not VM), Chinese changelog rows left as
history with the Unreleased entry superseding. SECURITY.md threat-model rewritten to
scan-only-default + consent-gated execution + npm probe layer.

## Suite-stability fixes found on the way
- cli.dist.test.ts rebuilt the SHARED dist/ mid-suite; measured ETXTBSY race against
  siblings spawning dist. Now it builds a private bundle + stages its own assets
  (tools/copy-assets.mjs gained an optional dest argv; tsconfig excludes test/tmp).
  Invariant: tests never mutate shared build artifacts.
- Test-consent seams made explicit (no ambient dependence):
  e2e/check.artifacts/ledger.check/residue.config/push.integration/channels.integration/
  scan/ledger/channels.crates/channels.rubygems.

## Numbers
- Full suite: `BORDER_PACK_TEST=1 npm test` ⇒ 884 tests / 871 pass / 0 fail /
  13 skipped / 227124 ms (log /tmp/border-wave1-full4.log).
- typecheck 0 errors; version:check clean at 0.8.1; build RC 0; usage lists --allow-builds.

## Not shipped (named)
- Wave 2 docker sandbox (image digest pinning, in-sandbox TCP+DNS probe, mount/env
  contract, record↔env binding): design-only, NOT implemented — consent is the
  current containment; sandbox is the planned layer.
- Wave 4 npm probe extension (workspaces/subpackages, repo .npmrc): open.
