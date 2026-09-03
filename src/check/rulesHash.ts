// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 10
//
// G21 rule fingerprinting + the todo-14 ledger key inputs.
// configDigest deviates deliberately from "sha256 of border.yaml bytes": it is
// sha256 of the CANONICAL JSON of the EFFECTIVE config (post overlay-merge,
// post `${VAR}` expansion). Rationale: an overlay or an env-expanded remote URL
// changes the gate's real rules while leaving border.yaml bytes identical — a
// byte digest would then certify two different rule sets under one rulesHash.
// The file digest was a proxy for the effective config; hashing the effective
// config directly is its strict superset and works for the inferred fallback
// (no file exists at all).
// bundledRulePaths currently = the vendored gitleaks config; promptTemplatePaths
// is empty until todo 18 ships assets/prompts (computeRulesHash fails closed on
// missing files, so only existing inputs may be listed).
import { createHash } from "node:crypto";

import type { LoadResult } from "../config.ts";
import { GITLEAKS_VENDORED_CONFIG } from "../engines/gitleaks.ts";
import { computeRulesHash } from "../redact.ts";

export type LoadedConfig = Extract<LoadResult, { kind: "loaded" }>;

function sha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(",")}}`;
}

export function computeConfigDigest(load: LoadedConfig): string {
  return sha256(stableStringify(load.config));
}

export async function computeCheckRulesHash(input: {
  readonly engineVersions: Readonly<Record<string, string>>;
  readonly configDigest: string;
}): Promise<string> {
  return computeRulesHash({
    bundledRulePaths: [GITLEAKS_VENDORED_CONFIG],
    configDigest: input.configDigest,
    engineVersions: input.engineVersions,
    promptTemplatePaths: [],
  });
}

/**
 * The skip-ledger key (todo 14 contract): two runs share a key only when HEAD,
 * working-tree state, rules, exposure, refs and effective targets all match —
 * any change invalidates a previously recorded PASS.
 */
export type CheckKeyInput = {
  readonly headSha: string;
  readonly porcelainDigest: string;
  readonly rulesHash: string;
  readonly exposureSet: readonly string[];
  readonly refSet: readonly string[];
  readonly effectiveTargets: readonly string[];
};

export function computeCheckKey(input: CheckKeyInput): string {
  return sha256(stableStringify({ ...input }));
}
