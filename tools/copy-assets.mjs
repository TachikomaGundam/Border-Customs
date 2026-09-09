// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 19
//
// Post-build asset staging: package.json ships files:["dist"] only, so the
// runtime assets (vendored gitleaks rules, llm prompt template) and the
// package-lock fingerprint input must live INSIDE dist/ for an installed copy.
// src/assets.ts resolves dist/assets/** as the installed-mode candidate.
import { cpSync, copyFileSync, mkdirSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dest = join(root, "dist", "assets");
rmSync(dest, { recursive: true, force: true });
mkdirSync(dest, { recursive: true });
cpSync(join(root, "assets"), dest, { recursive: true });
writeFileSync(join(dest, "package-lock.json"), readFileSync(join(root, "package-lock.json"), "utf8"), "utf8");
// R4 residue fingerprint fallback: an installed copy has no src/, so the
// rulesHash inputs (src/check/rulesHash.ts resolveResidueFingerprintFiles)
// resolve to dist/assets/residue-src/<basename>. Keep this list in sync with
// RESIDUE_FINGERPRINT_SOURCES there — a missing entry fails CLOSED at check
// time (MissingRulesInputError ⇒ exit 2), never a silent pass.
const residueSrc = join(dest, "residue-src");
mkdirSync(residueSrc, { recursive: true });
for (const [dir, base] of [
  ["rules", "residueMatchers.ts"],
  ["artifacts", "residue.ts"],
  ["artifacts", "residuePy.ts"],
  ["artifacts", "residueRust.ts"],
  ["artifacts", "residueGem.ts"],
  ["artifacts", "npm.ts"],
  ["artifacts", "pypi.ts"],
  ["artifacts", "crates.ts"],
  ["artifacts", "rubygems.ts"],
]) {
  copyFileSync(join(root, "src", dir, base), join(residueSrc, base));
}
console.log("assets staged into dist/assets/");
