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
// Optional argv[2]: alternate dest (repo-relative) for private test builds —
// a suite never restages the shared dist/assets while siblings read it.
const destArg = process.argv[2];
const dest = destArg === undefined ? join(root, "dist", "assets") : destArg.startsWith("/") ? destArg : join(root, destArg);
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
// W4.2: release-coherence fingerprint inputs — keep byte-identical to
// RELEASE_FINGERPRINT_SOURCES in src/check/rulesHash.ts; a missing entry fails
// CLOSED at check time (MissingRulesInputError ⇒ exit 2), never a silent pass.
const releaseSrc = join(dest, "release-src");
mkdirSync(releaseSrc, { recursive: true });
copyFileSync(join(root, "src", "rules", "releaseCoherence.ts"), join(releaseSrc, "releaseCoherence.ts"));
// T1 exfil lens: fingerprint inputs — keep byte-identical to
// EXFIL_FINGERPRINT_SOURCES in src/check/rulesHash.ts; a missing entry fails
// CLOSED at check time (MissingRulesInputError ⇒ exit 2), never a silent pass.
const exfilSrc = join(dest, "exfil-src");
mkdirSync(exfilSrc, { recursive: true });
// DERIVE, never mirror (L-SINGLE-SOURCE; second drift incident of the hand-copied-list
// class): read EXFIL_FINGERPRINT_SOURCES straight out of the product source.
const rulesHashSrc = readFileSync(join(root, "src", "check", "rulesHash.ts"), "utf8");
const bases = [...rulesHashSrc.matchAll(/\{\s*dir:\s*"exfil",\s*base:\s*"([^"]+)"\s*\}/g)].map((m) => m[1]);
if (bases.length < 5) throw new Error(`copy-assets: parsed only ${String(bases.length)} exfil fingerprint bases from rulesHash.ts — refusing to stage a partial set`);
for (const base of bases) {
  copyFileSync(join(root, "src", "exfil", base), join(exfilSrc, base));
}
console.log(`assets staged into ${dest}/`);
