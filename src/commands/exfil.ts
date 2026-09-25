// provenance: .omo/plans/border-exfil-lens.md T4 — `border exfil <ref|url> [ref...]`.
//
// The READ-ONLY fast face of the exfil lens (plan §S2). Scope ruling: default =
// tip tree + tag notes; --deep adds reachable-history blobs (historyRefRange
// doctrine — the given revs, NOT --all) and the `:message` commit-message
// facet. On every scanned face BOTH channels of the 分面契约 run: the native
// MEDIUM-family text scan (scanTreeText) and the TWIN engines for the HIGH
// family — engine findings are filtered to `exfil-*` ids so this stays the
// exfil LENS, not a second full gate. The tip-tree twins see the exact ref
// content via a throwaway materialization of that ref's text blobs (never the
// worktree — `border exfil <other-ref>` means the ref). Tag notes ride the
// existing engine leg verbatim (tag-message-secret, tagScan harness reuse).
// URL mode = throwaway `git init` + fetch of the given refs → scan →
// guaranteed destroy (border scan's posture: no ledger, no skip records, no
// .border/). Exit three-state: 0 no blocking findings (MEDIUM printed,
// released) | 1 blocking | 2 unreachable/timeout/bad args — every spawn
// status-checked fail-closed; a timeout is an ERROR, never a silent
// truncation (plan Must-NOT).
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { ConfigError } from "../channels/errors.ts";
import { resolveRepoDir } from "../check/context.ts";
import { scanCommitMessages } from "../check/messageScan.ts";
import { resolveExfilFingerprintFiles } from "../check/rulesHash.ts";
import { scanTagMessages } from "../check/tagScan.ts";
import { exitCodeFromVerdict, UnknownArgError, type BorderExit } from "../cli/exit.ts";
import type { CommandHandler, Ctx } from "../cli/types.ts";
import { GITLEAKS_VENDORED_CONFIG, scanGitHistory, scanTree } from "../engines/gitleaks.ts";
import { scanPaths } from "../engines/secretlint.ts";
import { scanTreeText, type ExfilFinding } from "../exfil/scan.ts";
import { computeVerdict, countFindings, type Finding, type Report } from "../findings.ts";
import { sanitizeUrl } from "../redact.ts";
import { renderReportJson } from "../report.ts";
import { blobTexts, historyBlobs, makeGit, tipTree, type BlobRef, type CliGit } from "./exfilGit.ts";

export const EXFIL_USAGE = "usage: border exfil <ref|url> [ref...] [--deep] [--json]";
/** scp-style remote or scheme URL — a positional matching this is FETCHED, not resolved locally. */
const URL_SHAPE_RE = /^(?:[A-Za-z][A-Za-z0-9+.-]*:\/\/\S+|\S+@\S+:\S+)$/;

const isExfilId = (rule: string): boolean => rule.startsWith("exfil-");

function toTreeFinding(f: ExfilFinding): Finding {
  return {
    rule: f.id,
    severity: f.severity,
    target: "tree",
    path: f.source,
    line: f.line,
    engine: f.engine,
    message: f.message,
    valueDigest: f.valueDigest,
    snippet: f.snippet,
  };
}

function scanBlobsNative(git: CliGit, blobs: readonly BlobRef[]): Finding[] {
  const texts = blobTexts(git, blobs);
  const findings: Finding[] = [];
  for (const b of blobs) {
    const text = texts.get(b.sha);
    if (text === undefined) continue;
    for (const f of scanTreeText({ text, source: b.path })) findings.push(toTreeFinding(f));
  }
  return findings;
}

/** Tip tree: native MEDIUM on the blob map + both twins on the materialized text tree (exfil ids only). */
async function scanTipTree(git: CliGit, treeRoot: string, rev: string, env: Readonly<Record<string, string | undefined>>): Promise<Finding[]> {
  const blobs = tipTree(git, rev);
  const texts = blobTexts(git, blobs);
  const native: Finding[] = [];
  const written: string[] = [];
  for (const b of blobs) {
    const text = texts.get(b.sha);
    if (text === undefined) continue;
    for (const f of scanTreeText({ text, source: b.path })) native.push(toTreeFinding(f));
    if (b.path.split("/").includes("..") || b.path === "") continue;
    const abs = join(treeRoot, b.path);
    if (existsSync(abs)) continue;
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, text, "utf8");
    written.push(b.path);
  }
  // secretlint reports the RELATIVE paths it was handed (already repo-shaped);
  // only the gitleaks dir leg yields sandbox-absolute paths that need stripping.
  const lint = (await scanPaths({ dir: treeRoot, files: written, target: "tree", env })).filter((f) => isExfilId(f.rule));
  const gl = scanTree({ dir: treeRoot, stateDir: join(treeRoot, ".border-state"), target: "tree", env })
    .filter((f) => isExfilId(f.rule))
    .map((f) => (f.path !== undefined && f.path.startsWith(`${treeRoot}/`) ? { ...f, path: f.path.slice(treeRoot.length + 1) } : f));
  return [...native, ...lint, ...gl];
}

/** Fast-face rule identity: the fingerprinted exfil core bytes + the vendored TOML carrying the twins. */
function exfilRulesDigest(): string {
  const h = createHash("sha256");
  for (const p of [...resolveExfilFingerprintFiles({}), GITLEAKS_VENDORED_CONFIG]) {
    let bytes: Buffer;
    try {
      bytes = readFileSync(p);
    } catch {
      throw new ConfigError("unreadable", `border exfil: rule input unreadable (fail closed): ${p}`);
    }
    h.update(p).update("\0").update(bytes).update("\0");
  }
  return h.digest("hex");
}

function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

type Unit = { readonly label: string; readonly rev: string };

export async function runExfilCore(ctx: Ctx): Promise<BorderExit> {
  const positionals = ctx.positionals;
  if (positionals.length === 0) throw new UnknownArgError(`border exfil expects <ref|url> [ref...] — ${EXFIL_USAGE}`);
  const deep = ctx.flags.deep === true;
  const first = positionals[0] ?? "";
  const sandbox = { dir: "", tree: "" };
  try {
    const isUrl = URL_SHAPE_RE.test(first);
    let repoDir: string;
    let units: Unit[];
    let exposure: readonly string[] = [];
    if (isUrl) {
      const url = first;
      exposure = [sanitizeUrl(url)];
      sandbox.dir = mkdtempSync(join(tmpdir(), "border-exfil-"));
      const git = makeGit(sandbox.dir, ctx.env);
      git.run(["init", "-q"]);
      git.run(["remote", "add", "origin", url]);
      const specs = positionals.slice(1).length === 0 ? ["HEAD"] : positionals.slice(1);
      units = [];
      for (const spec of specs) {
        git.run(["fetch", "-q", "--no-tags", "origin", spec]);
        units.push({ label: spec, rev: git.run(["rev-parse", "FETCH_HEAD"]).trim() });
      }
      repoDir = sandbox.dir;
    } else {
      repoDir = resolveRepoDir(ctx.cwd, { env: ctx.env });
      const git = makeGit(repoDir, ctx.env);
      units = positionals.map((ref) => ({ label: ref, rev: git.run(["rev-parse", "--verify", ref]).trim() }));
    }
    const git = makeGit(repoDir, ctx.env);

    sandbox.tree = mkdtempSync(join(tmpdir(), "border-exfil-tree-"));
    const findings: Finding[] = [];
    const seenBlob = new Set<string>();
    for (const unit of units) {
      findings.push(...(await scanTipTree(git, sandbox.tree, unit.rev, ctx.env)));
      if (deep) {
        const fresh = historyBlobs(git, unit.rev).filter((b) => {
          const key = `${b.sha}\0${b.path}`;
          if (seenBlob.has(key)) return false;
          seenBlob.add(key);
          return true;
        });
        findings.push(...scanBlobsNative(git, fresh));
      }
    }

    if (isUrl) ctx.stderr("border exfil: URL mode scanned fetched tips only — tag notes are not fetched (remote-side leg, check/push own it)");
    else findings.push(...scanTagMessages({ repoDir, target: "git", env: ctx.env }));

    if (deep) {
      // HIGH family over reachable history = the twin history leg (分面契约
      // row 1 covers blob/tree/history), filtered to the lens; plus the
      // native `:message` facet, no remotes ⇒ whole-ref doctrine.
      findings.push(...scanGitHistory({ repoDir, refRange: units.map((u) => u.rev).join(" "), target: "git", env: ctx.env }).filter((f) => isExfilId(f.rule)));
      findings.push(
        ...scanCommitMessages({
          repoDir,
          refSet: units.map((u) => u.rev),
          remotes: [],
          hosts: [],
          runGit: git.run,
          env: ctx.env,
        }),
      );
    }

    const verdict = computeVerdict(findings);
    const report: Report = {
      schemaVersion: 1,
      key: sha256Hex(`exfil:${isUrl ? "url" : "ref"}:${positionals.join(" ")}:${deep ? "deep" : "fast"}:${units.map((u) => u.rev).join(" ")}`),
      head: units[0]?.rev ?? "",
      dirty: false,
      exposureSet: exposure,
      refSet: positionals,
      rulesHash: exfilRulesDigest(),
      verdict,
      counts: countFindings(findings),
      findings,
      ts: new Date().toISOString(),
    };
    if (ctx.flags.json) ctx.stdout(renderReportJson(report));
    else {
      const scope = `${isUrl ? "URL" : "refs"} ${positionals.join(",")}${deep ? " (deep)" : ""}`;
      ctx.stdout(`border exfil ${scope} ${report.verdict}: ${String(report.counts.total)} finding(s), ${String(report.counts.blocking)} blocking`);
      for (const f of report.findings) {
        ctx.stdout(`  ${f.severity} ${f.rule} [${f.engine}] ${f.path ?? f.commit ?? f.target}${f.line !== undefined ? `:${String(f.line)}` : ""} ${f.message}`);
      }
    }
    return exitCodeFromVerdict(verdict);
  } finally {
    if (sandbox.dir !== "") rmSync(sandbox.dir, { recursive: true, force: true });
    if (sandbox.tree !== "") rmSync(sandbox.tree, { recursive: true, force: true });
  }
}

export const runExfil: CommandHandler = (ctx) => runExfilCore(ctx);
