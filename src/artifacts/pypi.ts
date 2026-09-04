// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 12
//
// PyPI artifact pipeline: build-once (G38) → extract → scan → twine gate.
//   build   = `python3 -m build --no-isolation --outdir <repo>/.border/dist/`.
//     Prerequisites `python3 -m build --version` / `python3 -m twine --version`
//     are probed FIRST; a missing one is PypiPrerequisiteError (border exit 2,
//     naming the module) — never a silent skip. `--no-isolation` is deliberate:
//     plan todo-12 Must-NOT forbids venv creation, and the image provisioned
//     build 1.6.0/twine 7.0.0/setuptools for python3.14 (todo 1). The build
//     backend comes from the target pyproject.toml itself — no poetry/flit
//     special-casing. dist/ is wiped before every build, so leftovers from an
//     earlier run (or an attacker's pre-seeded .tar.gz) are never scanned.
//   extract = wheel via `python3 -m zipfile -e`, sdist via extractArchive
//     (.tar.gz → `tar -xzf`), each into a mkdtemp sandbox under .border/tmp/,
//     removed in a finally-block (round-2 m3).
//   scan    = gitleaks scanTree + secretlint scanPaths per extracted tree, with
//     finding paths RE-ANCHORED to artifact-inner relpaths (sdist wrapper
//     stripped). This is load-bearing: filterBorderStateFindings(findings,
//     repoDir) (src/check/exclusions.ts) silently drops any finding whose
//     repo-relative path carries a `.border` segment — if we reported sandbox
//     paths the whole artifact gate would false-green. Duplicate (rule, relpath,
//     digest) triples across the sdist/wheel trees collapse to one finding.
//   manifest = sdist entries vs `git ls-files`; entries explained by MANIFEST.in
//     globs, pyproject readme/package-data/data-files strings, or build-
//     generated metadata (PKG-INFO, setup.cfg stub, *.egg-info/*, ...) pass;
//     anything else ⇒ HIGH `sdist-unexpected-file` — the G17/G18/G42 class:
//     setuptools walks the WORKING TREE, so .gitignore never hides a planted
//     file from the shipped artifact.
//   twine   = `python3 -m twine check --strict` over every dist file; a FAILED
//     artifact ⇒ HIGH `twine-check` finding (fail = verdict, not crash); an
//     unparseable non-zero exit is a tool crash ⇒ EngineRunError (exit 2).
// G23: every value flows through the engine adapters' redact() ingest; free
// text we author (twine blocks) is sanitized. sha256 of each produced
// .tar.gz/.whl is returned for the orchestrator's ctx.artifacts.pypi list
// (todo 17 wires ctx; buildPypiArtifacts is exported so the gate builds once).
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmdirSync, rmSync } from "node:fs";
import { basename, dirname, join, relative, resolve } from "node:path";

import { extractArchive, removeSandbox } from "./extract.ts";
import type { Finding } from "../findings.ts";
import { globToRegExp } from "../rules/artifactMatchers.ts";
import { scanTree } from "../engines/gitleaks.ts";
import { scanPaths, type SecretlintRulesInput } from "../engines/secretlint.ts";
import {
  binaryCandidates,
  EngineMissingError,
  EngineRunError,
  spawnEngine,
  type EngineOptions,
} from "../engines/support.ts";
import { redact, type TextSanitizer } from "../redact.ts";

/** Prerequisite failure — the CLI maps it to border exit 2 (library never process.exits). */
export class PypiPrerequisiteError extends Error {
  override readonly name = "PypiPrerequisiteError";
  readonly exitCode = 2 as const;
}

export type PypiArtifact = { readonly path: string; readonly kind: "sdist" | "wheel"; readonly sha256: string };
export type PypiInput = EngineOptions & {
  readonly repoDir: string;
  readonly stateDir?: string;
  readonly sanitizer?: TextSanitizer;
  readonly rules?: SecretlintRulesInput;
  readonly target?: string;
};
export type PypiScanResult = { readonly artifacts: readonly PypiArtifact[]; readonly findings: readonly Finding[] };

const ANSI_RE = /\u001B\[[0-9;]*m/g;
/** Names setuptools emits into the sdist that no source declaration lists (whitelisted metadata). */
const GENERATED_NAMES = new Set(["PKG-INFO", "SOURCES.txt", "setup.py", "setup.cfg", "pyproject.toml", "MANIFEST.in",
  "RECORD", "WHEEL", "METADATA", "top_level.txt", "dependency_links.txt", "requires.txt", "not-zip-safe"]);

function tail(text: string, max = 300): string {
  return text.replace(ANSI_RE, "").replace(/\s+/g, " ").trim().slice(-max);
}

function requireModule(o: EngineOptions, module: "build" | "twine"): void {
  let out: ReturnType<typeof spawnEngine>;
  try {
    out = spawnEngine(binaryCandidates("python3", o), ["-m", module, "--version"], o);
  } catch (err) {
    if (err instanceof EngineMissingError) {
      throw new PypiPrerequisiteError(
        `\`python3 -m ${module}\` is unavailable: python3 was not found on PATH (border exit 2 — install python3 plus the '${module}' package)`,
      );
    }
    throw err;
  }
  if (out.status !== 0) {
    throw new PypiPrerequisiteError(
      `\`python3 -m ${module} --version\` exited ${String(out.status)} — the '${module}' module is missing or broken (border exit 2). stderr: ${tail(out.stderr)}`,
    );
  }
}

/** build-once (G38): wipe stale dist, run `python3 -m build`, content-address every produced artifact. */
export function buildPypiArtifacts(o: PypiInput): { readonly artifacts: readonly PypiArtifact[]; readonly distDir: string } {
  requireModule(o, "build");
  const repoDir = resolve(o.repoDir);
  if (!existsSync(join(repoDir, "pyproject.toml"))) {
    throw new PypiPrerequisiteError(`no pyproject.toml in the repo root — the PyPI pipeline builds from pyproject's own [build-system]`);
  }
  const distDir = join(resolve(o.stateDir ?? join(repoDir, ".border")), "dist");
  rmSync(distDir, { recursive: true, force: true });
  mkdirSync(distDir, { recursive: true });
  const out = spawnEngine(binaryCandidates("python3", o), ["-m", "build", "--no-isolation", "--outdir", distDir, repoDir], o);
  if (out.status !== 0) {
    throw new EngineRunError(`\`python3 -m build\` exited ${String(out.status)} — no artifacts to gate (border exit 2). stderr: ${tail(out.stderr)}`, out.status);
  }
  const names = readdirSync(distDir).filter((n) => n.endsWith(".tar.gz") || n.endsWith(".whl")).sort();
  if (names.length === 0) {
    throw new EngineRunError(`\`python3 -m build\` produced no .tar.gz/.whl in ${distDir} (border exit 2)`, null);
  }
  const artifacts = names.map((name): PypiArtifact => {
    const path = join(distDir, name);
    return { path, kind: name.endsWith(".whl") ? "wheel" : "sdist", sha256: createHash("sha256").update(readFileSync(path)).digest("hex") };
  });
  return { artifacts, distDir };
}

function walkFilesRel(root: string): string[] {
  return readdirSync(root, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? walkFilesRel(join(root, e.name)).map((r) => `${e.name}/${r}`) : e.isFile() ? [e.name] : []);
}

/** An sdist always wraps everything in `<name>-<version>/`; strip that ONE shared
 *  top segment so wheel and sdist trees attribute the same inner relpath (and so
 *  the wrapper's version string never pollutes finding paths). */
function stripWrapper(entries: readonly string[]): { readonly root: string; readonly rest: readonly string[] } {
  const tops = new Set(entries.map((e) => (e.includes("/") ? e.slice(0, e.indexOf("/")) : "\u0000")));
  const only = tops.size === 1 ? [...tops][0] : undefined;
  return only !== undefined && only !== "\u0000"
    ? { root: only, rest: entries.map((e) => e.slice(only.length + 1)) }
    : { root: "", rest: entries };
}

/** gitleaks dir-leg paths are absolute under the scan root; reattribute `<abs>` or
 *  `<abs>!<inner>` (native-miss archive reattribution) to scan-root-relative. */
function toInner(findingPath: string | undefined, scanRoot: string): string {
  if (findingPath === undefined) return "";
  const bang = findingPath.indexOf("!");
  const head = bang === -1 ? findingPath : findingPath.slice(0, bang); const rest = bang === -1 ? "" : findingPath.slice(bang + 1);
  const rel = relative(scanRoot, head);
  const inner = rel !== "" && !rel.startsWith("..") ? rel : basename(head);
  return rest === "" ? inner : `${inner}!${rest}`;
}

function gitTracked(o: EngineOptions, repoDir: string): Set<string> {
  const out = spawnEngine(binaryCandidates("git", o), ["-C", repoDir, "ls-files"], {
    ...o,
    env: { ...(o.env ?? process.env), GIT_CEILING_DIRECTORIES: dirname(repoDir) },
  });
  if (out.status !== 0) throw new EngineRunError(`git ls-files in ${repoDir} exited ${String(out.status)} (border exit 2)`, out.status);
  return new Set(out.stdout.split("\n").filter((l) => l !== ""));
}

/** MANIFEST.in + pyproject declarations → include/exclude glob matchers over
 *  sdist-inner (project-relative) paths. distutils precedence: prune/exclude
 *  remove whatever the includes pulled in, so exclusions are checked FIRST. */
type Matchers = { readonly inc: readonly RegExp[]; readonly exc: readonly RegExp[] };

function toRe(globs: readonly string[]): RegExp[] {
  return globs.filter((g) => g !== "").map((g) => globToRegExp(g.includes("/") ? g : `**/${g}`));
}

function explainMatchers(repoDir: string): Matchers {
  const inc: string[] = [];
  const exc: string[] = [];
  const manifest = join(repoDir, "MANIFEST.in");
  if (existsSync(manifest)) {
    for (const line of readFileSync(manifest, "utf8").split(/\r?\n/)) {
      const t = line.split("#")[0]?.trim() ?? "";
      if (t === "") continue;
      const [cmd, ...args] = t.split(/\s+/);
      const dir = args[0] ?? "";
      if (cmd === "include") inc.push(...args);
      else if (cmd === "recursive-include") for (const g of args.slice(1)) inc.push(`${dir}/**/${g}`, `${dir}/${g}`);
      else if (cmd === "graft") inc.push(`${dir}/**`);
      else if (cmd === "exclude") exc.push(...args);
      else if (cmd === "global-exclude") for (const g of args) exc.push(`**/${g}`);
      else if (cmd === "prune") exc.push(`${dir}/**`);
      // ignore-* and unknown directives: distutils defaults; approximation documented here.
    }
  }
  const pyproject = join(repoDir, "pyproject.toml");
  if (existsSync(pyproject)) {
    const text = readFileSync(pyproject, "utf8");
    const readme = /^\s*readme\s*=\s*"([^"]+)"/m.exec(text);
    if (readme?.[1] !== undefined) inc.push(readme[1]);
    for (const block of text.matchAll(/readme\s*=\s*\{([^}]*)\}/g)) for (const f of block[1]?.matchAll(/"([^"]+)"/g) ?? []) inc.push(f[1] ?? "");
    for (const block of text.matchAll(/\[tool\.setuptools\.(?:package-data|data-files)\]([\s\S]*?)(?=\n\[|$)/g))
      for (const g of block[1]?.matchAll(/"([^"]+)"/g) ?? []) inc.push(g[1] ?? "");
  }
  return { inc: toRe(inc), exc: toRe(exc) };
}

function isGeneratedMetadata(inner: string): boolean {
  const segs = inner.split("/");
  return GENERATED_NAMES.has(segs[segs.length - 1] ?? "") || segs.some((s) => s.endsWith(".egg-info") || s.endsWith(".dist-info"));
}

function manifestFindings(o: PypiInput, sdistInner: readonly string[], target: string): Finding[] {
  const tracked = gitTracked(o, resolve(o.repoDir));
  const { inc, exc } = explainMatchers(resolve(o.repoDir));
  const out: Finding[] = [];
  for (const entry of sdistInner) {
    const declared = inc.some((m) => m.test(entry)) && !exc.some((m) => m.test(entry));
    if (tracked.has(entry) || isGeneratedMetadata(entry) || declared) continue;
    const { valueDigest, snippet } = redact(entry);
    out.push({
      rule: "sdist-unexpected-file",
      severity: "HIGH",
      target,
      path: entry,
      engine: "pypi-manifest",
      message: `sdist entry '${entry}' is not git-tracked and not explained by MANIFEST.in / pyproject declarations or build-generated metadata. setuptools builds sdist/wheels from the WORKING TREE (.gitignore-blind, G17/G18/G42): remove the file or commit/declare it intentionally.`,
      valueDigest,
      snippet,
    });
  }
  return out;
}

function twineCheck(o: PypiInput, artifacts: readonly PypiArtifact[], target: string): Finding[] {
  // COLUMNS/NO_COLOR: twine renders via rich, which hard-wraps long dist paths
  // mid-token at terminal width — unwrapped single-line verdicts are what the
  // PASSED/FAILED parser below consumes.
  const out = spawnEngine(
    binaryCandidates("python3", o),
    ["-m", "twine", "check", "--strict", ...artifacts.map((a) => a.path)],
    { ...o, env: { ...(o.env ?? process.env), COLUMNS: "100000", NO_COLOR: "1" } },
  );
  if (out.status === 0) return [];
  const text = `${out.stdout}\n${out.stderr}`.replace(ANSI_RE, "");
  const verdicts = [...text.matchAll(/Checking\s+(\S+):\s+(\w+)/g)];
  const failed = verdicts.filter((m) => m[2] === "FAILED");
  if (failed.length === 0) {
    throw new EngineRunError(`\`python3 -m twine check\` exited ${String(out.status)} without a parseable PASSED/FAILED verdict (border exit 2): ${tail(text)}`, out.status);
  }
  return failed.map((m): Finding => {
    const abs = m[1] ?? "";
    const base = basename(abs);
    const idx = text.indexOf(m[0]);
    const next = text.indexOf("Checking ", idx + m[0].length);
    const block = tail(text.slice(idx, next === -1 ? undefined : next), 400).replaceAll(abs, base);
    const { valueDigest, snippet } = redact(`${base}\u0000FAILED`);
    return {
      rule: "twine-check",
      severity: "HIGH",
      target,
      path: base,
      engine: "twine",
      message: o.sanitizer !== undefined ? o.sanitizer.sanitize(`twine check --strict rejected artifact '${base}': ${block}`) : `twine check --strict rejected artifact '${base}': ${block}`,
      valueDigest,
      snippet,
    };
  });
}

/** Full todo-12 pipeline: prereqs → build → extract-scan (both artifacts, deduped) → manifest-diff → twine. */
export async function scanPyPiArtifacts(o: PypiInput): Promise<PypiScanResult> {
  requireModule(o, "build");
  requireModule(o, "twine");
  const repoDir = resolve(o.repoDir);
  const stateDir = resolve(o.stateDir ?? join(repoDir, ".border"));
  const target = o.target ?? "artifact";
  const { artifacts } = buildPypiArtifacts(o);
  const tmpParent = join(stateDir, "tmp");
  mkdirSync(tmpParent, { recursive: true });

  const merged = new Map<string, Finding>();
  const absorb = (f: Finding, path: string): void => {
    const g: Finding = { ...f, ...(path !== "" ? { path } : {}) };
    merged.set(`${g.rule}\u0000${g.path ?? ""}\u0000${g.valueDigest}`, g);
  };
  try {
    for (const artifact of artifacts) {
      const sandbox = mkdtempSync(join(tmpParent, "pypi-"));
      try {
        if (artifact.kind === "wheel") {
          const z = spawnEngine(binaryCandidates("python3", o), ["-m", "zipfile", "-e", artifact.path, sandbox], o);
          if (z.status !== 0) throw new EngineRunError(`\`python3 -m zipfile -e ${basename(artifact.path)}\` exited ${String(z.status)} (border exit 2): ${tail(z.stderr)}`, z.status);
        } else {
          extractArchive(artifact.path, sandbox, o);
        }
        const { root, rest } = artifact.kind === "sdist" ? stripWrapper(walkFilesRel(sandbox)) : { root: "", rest: walkFilesRel(sandbox) };
        const scanRoot = join(sandbox, root);
        const scanOpts = { ...o, target };
        for (const f of scanTree({ ...scanOpts, dir: scanRoot, stateDir })) absorb(f, toInner(f.path, scanRoot));
        for (const f of await scanPaths({ ...scanOpts, ...(o.sanitizer !== undefined ? { sanitizer: o.sanitizer } : {}), ...(o.rules !== undefined ? { rules: o.rules } : {}), dir: scanRoot, files: rest })) absorb(f, f.path ?? "");
        if (artifact.kind === "sdist") for (const f of manifestFindings(o, rest, target)) absorb(f, f.path ?? "");
      } finally {
        removeSandbox(sandbox);
      }
    }
    for (const f of twineCheck(o, artifacts, target)) absorb(f, f.path ?? "");
  } finally {
    try {
      rmdirSync(tmpParent);
    } catch {
      // non-empty ⇒ a concurrent run owns sandboxes here; leave for the .border/tmp GC
    }
  }
  return { artifacts, findings: [...merged.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([, f]) => f) };
}
