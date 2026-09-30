// provenance: .omo/plans/border-opencode-inspect.md T1 — aspect 4: route-a-parity.
//
// The file-drop route's byte truth: when the installer's plugin destination
// exists, its sha256 must equal the packaged asset's sha256 — the same
// `installed=<sha> packaged=<sha>` shape `border opencode status` renders
// (installer sha logic reused via support.sha256Hex). No drop file present
// means nothing can be stale: PASS-not-installed. This aspect never writes and
// never touches the fs — the bytes arrive as a snapshot on Facts.
import { PLUGIN_MARKER, firstLine, sha256Hex } from "../contract.ts";
import type { AspectResult, Facts } from "../contract.ts";

export function verifyRouteAParity(facts: Facts): AspectResult {
  const id = "route-a-parity" as const;
  const { routeAPlugin, routeAInstalled } = facts;
  if (!routeAInstalled) {
    return { id, verdict: "PASS", detail: `${routeAPlugin}: absent — Route A not installed, nothing to be stale` };
  }
  if (facts.packagedPlugin === null) {
    return { id, verdict: "CANNOT", detail: "the packaged plugin asset is unreadable — the border install itself looks broken, parity cannot be judged" };
  }
  const installed = facts.routeABytes;
  if (installed === null) {
    return { id, verdict: "CANNOT", detail: `${routeAPlugin}: present but unreadable — parity cannot be judged` };
  }
  const installedSha = sha256Hex(installed);
  const packagedSha = sha256Hex(facts.packagedPlugin);
  if (installedSha === packagedSha) {
    return { id, verdict: "PASS", detail: `${routeAPlugin}: up-to-date installed=${installedSha} packaged=${packagedSha}` };
  }
  const ours = firstLine(installed).startsWith(PLUGIN_MARKER);
  const shape = ours ? "outdated (marker ours, bytes differ)" : "foreign (first line lacks the marker)";
  return { id, verdict: "FAIL", detail: `${routeAPlugin}: ${shape} installed=${installedSha} packaged=${packagedSha}` };
}
