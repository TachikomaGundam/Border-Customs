// provenance: .omo/plans/border-opencode-inspect.md T1 — aspect 6: scope.
//
// The certificate boundary (plan B3 ruling): this verdict covers the
// V1-load-surface ONLY. The blind spots are declared verbatim, never silently
// passed — it is a certificate edge, so it never FAILs and never CANNOTs.
// Consumers must not read an overall PASS as "every load mechanism on this
// machine is clean" (V2 enumeration is a separate ledger item once V2
// settles).
import type { AspectResult } from "../contract.ts";

export const SCOPE_ID = "scope" as const;
export const SCOPE_NAME = "v1-load-surface";
export const SCOPE_UNCOVERED: readonly string[] = [
  "V2 project-local .opencode/plugins/",
  "V2 npm-prefix/node_modules installs",
  "V2 lazy activation state",
];

export function verifyScope(): AspectResult {
  return {
    id: SCOPE_ID,
    verdict: "PASS",
    detail: `verdict scope = ${SCOPE_NAME}; NOT covered (declared blind, separate ledger item): ${SCOPE_UNCOVERED.join(", ")}`,
  };
}
