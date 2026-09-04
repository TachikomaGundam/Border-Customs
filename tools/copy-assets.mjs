// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 19
//
// Post-build asset staging: package.json ships files:["dist"] only, so the
// runtime assets (vendored gitleaks rules, llm prompt template) and the
// package-lock fingerprint input must live INSIDE dist/ for an installed copy.
// src/assets.ts resolves dist/assets/** as the installed-mode candidate.
import { cpSync, mkdirSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dest = join(root, "dist", "assets");
rmSync(dest, { recursive: true, force: true });
mkdirSync(dest, { recursive: true });
cpSync(join(root, "assets"), dest, { recursive: true });
writeFileSync(join(dest, "package-lock.json"), readFileSync(join(root, "package-lock.json"), "utf8"), "utf8");
console.log("assets staged into dist/assets/");
