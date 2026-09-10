// provenance: border-inspect-roadmap.md W1.2 — `border scan` materializer.
//
// Turns fetched artifact bytes into the exact input every channel stage()
// expects: a COMMITTED git repo whose tree is the package root. Channel
// stages read manifests via `git show HEAD:` (src/channels/npm.ts headFile)
// and `git ls-files` (pypi sdist manifest leg), so extraction alone is not
// enough — the tree must be committed. Identity is the fixed
// border@local/-scan triple (never the human committer; the temp repo is
// evidence, not history). Fail-closed: a tree shape the stage cannot consume
// throws a one-line Error long before a scan could fake a "clean".
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { extractArchive, findNativeMissArchives } from "../artifacts/extract.ts";
import { runGitChecked } from "../check/context.ts";
import { safeArtifactName, sha256Hex } from "./fetch.ts";
import type { ScanEcosystem } from "./spec.ts";

export type MaterializeInput = {
  readonly ecosystem: ScanEcosystem;
  readonly bytes: Buffer;
  readonly filename: string;
  readonly baseDir: string;
  readonly env?: NodeJS.ProcessEnv;
  /** Forensic-log sink for mutations of package content (crates envelope
   *  scrub). Defaults to one newline-terminated line on stderr. */
  readonly note?: (line: string) => void;
};

/** Registry envelope files `cargo package` rejects as reserved (W1.2). */
const CRATES_ENVELOPE_FILES = ["Cargo.toml.orig", ".cargo-ok", ".cargo_vcs_info.json"] as const;

const fail = (why: string): never => {
  throw new Error(`border scan cannot materialize the artifact (${why}) — refusing to stage an unusable tree (fail-closed)`);
};

const oneLine = (err: unknown): string => (err instanceof Error ? err.message : String(err)).replace(/\s+/g, " ").trim();

/** extractArchive surfaces engine stderr, which is routinely multi-line; the
 *  scan contract is ONE-line fail-closed causes (exit 2, never a fake clean). */
function extractFlat(archive: string, destDir: string): void {
  try {
    extractArchive(archive, destDir);
  } catch (err) {
    fail(`extraction of ${archive} failed: ${oneLine(err)}`);
  }
}

/** Unpack tarballs whose whole payload sits under one wrapper directory
 *  (npm `package/`, pypi `<name>-<ver>/`, crates `<name>-<ver>/`, and our
 *  own fixture trees) down to that single root; pass through flat archives. */
function unwrapSingleDir(dir: string): string {
  const entries = readdirSync(dir, { withFileTypes: true });
  const dirs = entries.filter((e) => e.isDirectory());
  if (entries.length === 1 && dirs.length === 1 && dirs[0] !== undefined) {
    return join(dir, dirs[0].name);
  }
  return dir;
}

function requireManifest(repoDir: string, ecosystem: ScanEcosystem, candidates: readonly string[]): void {
  if (!candidates.some((rel) => existsSync(join(repoDir, rel)))) {
    fail(`${ecosystem} package tree has none of [${candidates.join(", ")}] at its root`);
  }
}

export function materializePackage(o: MaterializeInput): string {
  const note = o.note ?? ((line: string): void => {
    process.stderr.write(`${line}\n`);
  });
  const safe = safeArtifactName(o.filename, `${o.ecosystem}-artifact`);
  const archive = join(o.baseDir, safe);
  writeFileSync(archive, o.bytes);

  const extractDir = join(o.baseDir, "extract");
  mkdirSync(extractDir, { recursive: true });
  extractFlat(archive, extractDir);
  let repoDir = unwrapSingleDir(extractDir);

  if (o.ecosystem === "rubygems") {
    // The published .gem is a plain tar of metadata.gz + data.tar.gz; the
    // package SOURCE tree (where the .gemspec lives when the author shipped
    // one) is inside data.tar.gz. extractArchive's .gem branch deliberately
    // unpacks only the outer members, so the inner pass is ours.
    const outer = repoDir;
    const dataCandidates = findNativeMissArchives(outer).filter((f) => f.endsWith("data.tar.gz"));
    const inner = dataCandidates[0] ?? join(outer, "data.tar.gz");
    if (!existsSync(inner)) fail(".gem archive contains no data.tar.gz");
    const gemTree = join(o.baseDir, "gem-tree");
    mkdirSync(gemTree, { recursive: true });
    extractFlat(inner, gemTree);
    repoDir = unwrapSingleDir(gemTree);
    // gemspec presence is NOT asserted here: a published .gem's data.tar.gz
    // only carries the .gemspec when the author shipped one — stage-side
    // gemspec discovery fails closed (exit 2) with its own one-line error.
  } else if (o.ecosystem === "npm") {
    requireManifest(repoDir, o.ecosystem, ["package.json"]);
  } else if (o.ecosystem === "pypi") {
    requireManifest(repoDir, o.ecosystem, ["pyproject.toml", "setup.py"]);
  } else {
    requireManifest(repoDir, o.ecosystem, ["Cargo.toml"]);
    // Registry envelope normalization (NOT a channel change): `cargo package`
    // aborts exit 101 on reserved file names the published .crate carries
    // (measured on rand_core-0.6.4: "invalid inclusion of reserved file name
    // Cargo.toml.orig"). The rebuilt .crate regenerates Cargo.toml.orig from
    // the normalized Cargo.toml, so no scan-relevant byte is lost.
    // Forensically logged (W1.4/D1): deleting bytes from a third-party
    // artifact is a mutation a reviewer must be able to audit — one line per
    // file actually present, hashing the ORIGINAL content before removal.
    for (const file of CRATES_ENVELOPE_FILES) {
      const path = join(repoDir, file);
      if (!existsSync(path)) continue;
      const original = readFileSync(path);
      rmSync(path, { force: true });
      note(`border scan: crates envelope normalized: ${file} sha256=${sha256Hex(original)}`);
    }
  }

  const env = o.env;
  const git = (args: readonly string[]): string => runGitChecked(repoDir, args, ...(env !== undefined ? [{ env }] : [{}]));
  git(["init", "-q"]);
  git(["add", "-A"]);
  git(["-c", "user.email=border@local", "-c", "user.name=border", "commit", "-qm", "border scan"]);
  return repoDir;
}
