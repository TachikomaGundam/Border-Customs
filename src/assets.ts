// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 19
//
// Packaged-asset resolution. esbuild --bundle flattens src/** to dist/index.js,
// so a single `../../assets` walk-up is only ever right for ONE layout:
//   src mode (npm test):      here = src/engines      -> ../../assets ✓
//   dist mode (dev repo):     here = dist             -> ../assets ✓
//   installed mode (npm i):   here = <pkg>/dist       -> ./assets ✓ (files:["dist"]
//                             ships nothing outside dist/, so `npm run build`
//                             copies assets/ to dist/assets/ — see tools/copy-assets.mjs)
// First-existing-candidate keeps the digest stable across layouts (identical
// bytes); when nothing exists the canonical src path is returned so the
// consumer's fail-closed error names the file it wanted.

import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

function candidatesFor(moduleUrl: string, relParts: readonly string[]): string[] {
  const here = dirname(fileURLToPath(moduleUrl));
  return [
    join(here, "assets", ...relParts),
    join(here, "..", "assets", ...relParts),
    join(here, "..", "..", "assets", ...relParts),
  ];
}

/** Resolve `<root>/assets/<relParts>` across the three layouts above. */
export function resolveAsset(moduleUrl: string, relParts: readonly string[]): string {
  const candidates = candidatesFor(moduleUrl, relParts);
  return candidates.find((p) => existsSync(p)) ?? (candidates[2] as string);
}

/** Resolve a repo/package-level file (e.g. package-lock.json) across layouts. */
export function resolvePackageFile(moduleUrl: string, fileName: string): string {
  const here = dirname(fileURLToPath(moduleUrl));
  const candidates = [
    join(here, "..", fileName), // dist mode: <repo>/package-lock.json
    join(here, "..", "..", fileName), // src mode: src/engines → <repo>/…
    join(here, "assets", fileName), // installed mode: dist/assets/ copy
  ];
  return candidates.find((p) => existsSync(p)) ?? (candidates[1] as string);
}
