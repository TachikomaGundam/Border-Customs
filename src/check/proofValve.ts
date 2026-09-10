// provenance: border-inspect-roadmap.md W2.2 — the requireProof valve.
//
// Fail-closed-by-absence, in code: this module NEVER runs anything. It reads
// the t:"roundtrip" facts that `border roundtrip` pre-supplied to the ledger
// and turns missing/stale proof into ordinary native CRITICAL findings, so the
// verdict math and the allow-list treat them exactly like every other rule.
// Freshness = rulesHash equality (the same invalidation pattern the check
// fingerprints use: rotate the policy, invalidate the cached proof). The valve
// is armed by ANY blocking-capable residue-* finding (severity HIGH/CRITICAL;
// the rule-id home is RESIDUE_SEVERITIES — gitleaks/secretlint legs can never
// arm it, they are not residue rows), and it demands proof per STAGED ARTIFACT,
// keyed by the artifact sha256 the channel certified.
import { redact } from "../redact.ts";
import { isBlocking, type Finding } from "../findings.ts";
import { latestRoundtripForSha, type LedgerArtifact, type LedgerRecord } from "../ledger/records.ts";
import { RESIDUE_SEVERITIES } from "../rules/residueMatchers.ts";

export const ROUNDTRIP_PROOF_MISSING_RULE = "roundtrip-proof-missing";
export const ROUNDTRIP_PROOF_STALE_RULE = "roundtrip-proof-stale";

/** Closed residue rule-id set — derived from the severity home, never restated. */
export const RESIDUE_RULE_IDS: ReadonlySet<string> = new Set(Object.keys(RESIDUE_SEVERITIES));

/** True ⇒ the run saw at least one residue row with blocking severity — a capability claim that proof-req can gate on. */
export function hasBlockingResidueCapability(findings: readonly Finding[]): boolean {
  return findings.some((f) => RESIDUE_RULE_IDS.has(f.rule) && isBlocking(f.severity));
}

function proofFinding(rule: string, art: LedgerArtifact, cause: string): Finding {
  return {
    rule,
    severity: "CRITICAL",
    target: "artifact",
    path: art.file,
    engine: "native",
    message:
      `${art.file} (sha256 ${art.sha256.slice(0, 12)}…) tripped the residue scan while residue.requireProof is on, ` +
      `but ${cause}. Run 'border roundtrip <spec>' for exactly these bytes to mint the ledger proof.`,
    ...redact(`${art.sha256}:${cause}`),
    snippet: `${art.file} ${art.sha256.slice(0, 12)}`,
  };
}

/** One CRITICAL per staged artifact lacking a FRESH roundtrip record; empty when every artifact's sha256 has one whose rulesHash equals the run's. */
export function proofFindings(o: {
  readonly artifacts: readonly LedgerArtifact[];
  readonly records: readonly LedgerRecord[];
  readonly rulesHash: string;
}): Finding[] {
  const out: Finding[] = [];
  for (const art of o.artifacts) {
    const rec = latestRoundtripForSha(o.records, art.sha256);
    if (rec === null) {
      out.push(proofFinding(ROUNDTRIP_PROOF_MISSING_RULE, art, "no roundtrip proof record exists for its digest"));
    } else if (rec.rulesHash !== o.rulesHash) {
      out.push(
        proofFinding(
          ROUNDTRIP_PROOF_STALE_RULE,
          art,
          `its proof record predates the current rules policy (recorded ${rec.rulesHash.slice(0, 12)}…, required ${o.rulesHash.slice(0, 12)}…)`,
        ),
      );
    }
  }
  return out;
}
