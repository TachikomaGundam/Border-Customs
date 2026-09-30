// provenance: .omo/plans/border-opencode-inspect.md T1 — aspect 5: dual-route.
//
// Counting the registration SOURCES on the V1 surface: Route B (config plugin
// declaration) and Route A (installer file drop). BOTH at once = FAIL — the
// dual-registration window is exactly what blueprint §7 gates; opencode's
// single-Record dedupe is ITS fallback, not our permission. Unreadable
// config means the Route-B side cannot be counted: CANNOT.
import type { AspectResult, Facts } from "../contract.ts";

export function verifyDualRoute(facts: Facts): AspectResult {
  const id = "dual-route" as const;
  const { configs, routeAInstalled, routeAPlugin, pkg } = facts;
  const errored = configs.filter((c) => c.status === "error").map((c) => c.path);
  if (errored.length > 0) {
    return { id, verdict: "CANNOT", detail: `configuration unreadable (${errored.join(", ")}) — Route B presence cannot be counted` };
  }
  const declared = configs.flatMap((c) => [...c.specs]);
  const hasB = declared.length > 0;
  if (routeAInstalled && hasB) {
    return {
      id,
      verdict: "FAIL",
      detail: `both routes registered: Route A drop at ${routeAPlugin} AND Route B declaration ${declared.map((d) => `'${d}'`).join(", ")} — pick exactly one route (the dual-registration window blueprint §7 forbids)`,
    };
  }
  if (routeAInstalled) {
    return { id, verdict: "PASS", detail: `Route A only: drop at ${routeAPlugin}, no ${pkg} config declaration` };
  }
  if (hasB) {
    return { id, verdict: "PASS", detail: `Route B only: ${declared.map((d) => `'${d}'`).join(", ")}, no file drop at ${routeAPlugin}` };
  }
  return { id, verdict: "PASS", detail: "neither route registered — no border plugin load claimed on the V1 surface" };
}
