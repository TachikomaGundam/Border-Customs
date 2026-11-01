// provenance: security ruling sibyl-20261023T112953Z-7ada (2026-10-23,
// APPROVE 2A/1R) — the config-trust-boundary must_fix, verbatim:
//   "build targets and opt-in resolve only from operator/user-level config
//    or approval stored outside the audited tree; the repo's own border.yaml
//    may request, never enable, a build stage."
//
// Why this exists: `border check` loads border.yaml from the AUDITED repo by
// default (src/config.ts discovery), so a hostile clone can declare its own
// pypi/rubygems targets and, pre-ruling, make the check build them — PEP 517
// backends and gemspecs are code, and `python3 -m build --no-isolation` /
// `gem build` executed them under the operator's credentials (markers
// SETUP-PY-RAN / GEMSPEC-RAN reproduced 2026-10-23; the pypi marker appears
// even when the build later errors). Same class as the npm-10 prepare hole
// (src/artifacts/npmPackSafety.ts).
//
// Consent sources, both OUTSIDE the audited tree (L-ENV-SEGREGATION: this is
// an E1 operator decision; an E0 candidate can never mint it):
//   * CLI flag --allow-builds (per-run, explicit);
// Anything else — including any value inside border.yaml, package.json,
// .gemspec, pyproject.toml, or the fetched artifact itself — is repo-adjacent
// input and can never enable execution. Values other than exactly "1" fail
// closed to withheld with the offending value named in the finding.
//
// A withheld run is still a scan: scan-only verdict, artifacts:null in the
// ledger, and per-channel `build-stage-withheld` MEDIUM findings. A
// scan-only PASS can never back a registry push — src/push/core.ts requires
// recorded artifact digests to re-verify (fail-closed-by-absence, unchanged).

/** Env seam for the operator consent (host shell / CI image, never the repo). */
// The ENV channel was REMOVED pre-release (sibyl §3 consent un-planting):
// a hostile repo's .envrc/direnv exports reach the environment of every tool
// the victim runs, so environment was never an operator-side source. Anchor
// for the zero-external-users claim (re-probed at wave execution): the newest
// tag carries no buildConsent.ts and `npm view border-customs version` still
// reports the pre-consent line — see .omo/evidence/border-build-consent-20261023.md.

/** Exact accepted env value; anything else (including "true") is fail-closed. */
export const BUILD_CONSENT_ENV_VALUE = "1";

/** Rule id of the audit-visible MEDIUM emitted per withheld channel. */
export const BUILD_WITHHELD_RULE = "build-stage-withheld";

export type BuildConsent =
  | { readonly allowed: true; readonly source: "flag" | "machine" }
  | { readonly allowed: false; readonly reason: string };

const WITHHELD_REASON =
  `artifact build stages (npm pack / python -m build / gem build / cargo package) execute code from the audited tree — ` +
  `border only runs them on operator-side consent (--allow-builds, or allowBuilds: true in the machine store); ` +
  `this run is scan-only and cannot back a registry publish`;

/** Resolve build consent from operator-side sources ONLY (sibyl §3): the
 *  argv flag, or `allowBuilds: true` honored from the machine store / an
 *  explicit --config outside the repo (loadConfig already resolved the
 *  tier — see src/tier.ts §3⁗; a repo-declared value never reaches here). */
export function resolveBuildConsent(o: {
  readonly allowBuildsFlag: boolean;
  readonly machineAllowBuilds: boolean;
}): BuildConsent {
  if (o.allowBuildsFlag) return { allowed: true, source: "flag" };
  if (o.machineAllowBuilds) return { allowed: true, source: "machine" };
  return { allowed: false, reason: WITHHELD_REASON };
}
