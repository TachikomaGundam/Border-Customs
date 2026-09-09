// provenance: R3a pypi leg (plan border-residue-gate §57, contract §4 T2-py family).
// NO T1 pass-lane for pypi — setuptools executes arbitrary build code, so plan §57 keeps the
// leg detection-only: the closed FAMILY table flags T2/T3/xmgr shapes inside build hooks, plus
// the artifact-wide T4 sweep. Unknown/unparseable simply produces no residue row; the pre-R3a
// pypi findings (sdist-unexpected-file / twine-check / engine rows) pass through untouched.
import { PY_BUILD_HOOK_BASENAMES, PY_BUILD_SYSTEM_SECTION } from "../rules/residueMatchers.ts";
import { FAMILY_WORDING, familyHits, readText, sectionBlock, t4HitFor, type ResidueHit } from "./residue.ts";

/** Residue hits for one extracted pypi tree (sdist or wheel), paths wrapper-stripped inner rels. */
export function residuePypiHits(pkgDir: string, innerRels: readonly string[]): ResidueHit[] {
  const hits: ResidueHit[] = [];
  for (const rel of innerRels) {
    const text = readText(pkgDir, rel);
    if (text === null) continue;
    const name = rel.split("/").pop() ?? "";
    // §57: setup.py body whole; pyproject only its [build-system] section — [project].dependencies
    // is runtime metadata, out of install-time scope (false-positive wall, tests pin it silent).
    const buildSystem = name === "pyproject.toml" ? sectionBlock(text, PY_BUILD_SYSTEM_SECTION) : "";
    if (PY_BUILD_HOOK_BASENAMES.includes(name) || buildSystem !== "") {
      hits.push(...familyHits(rel, name === "pyproject.toml" ? buildSystem : text, FAMILY_WORDING.pypi));
    }
    const t4 = t4HitFor(rel, text);
    if (t4 !== null) hits.push(t4);
  }
  return hits;
}
