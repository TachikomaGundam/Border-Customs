// provenance: .omo/plans/border-exfil-lens.md T2 — native exfil tree leg of the
// check pipeline (分面契约 row 1, second half): the MEDIUM family
// (exfil-home-path, exfil-cred-location, exfil-host-profile)补发s MEDIUM on the
// blob/tree face via scanTreeText. The HIGH family is NOT scanned natively
// here (v2 double-emission revoked; tree face belongs to the twins).
//
// Pipeline posture (plan §分面契约): this leg is NATIVE — it does not eat the
// engine-health suppression (check.ts's broken.has gate never skips it), so a
// degraded gitleaks/secretlint can never silence the MEDIUM family, exactly
// like aiArtifacts/identity above it. File enumeration rides git ls-files
// (tracked set — same universe as the secretlint tracked leg); .border/**
// segments are skipped here AND the caller re-filters (exclusions doctrine).
// Tracked-then-deleted races and binary blobs are skipped: NUL-content blobs
// belong to the checked-in-binary rule, not to text predicates.
import { readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

import { scanTreeText, type ExfilFinding } from "../exfil/scan.ts";
import type { Finding } from "../findings.ts";
import type { TextSanitizer } from "../redact.ts";
import { runGitChecked } from "./context.ts";

const BORDER_SEGMENT = ".border";
const MAX_SCAN_BYTES = 2 * 1024 * 1024;

export type ExfilTreeScanOptions = {
  readonly repoDir: string;
  /** Finding.target stamp (default "tree", mirroring the gitleaks tree leg). */
  readonly target?: string;
  /** rules.hosts for the ssh-target predicate (no-op here: native tree never runs it). */
  readonly hosts?: readonly string[];
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly sanitizer?: TextSanitizer;
};

function toFinding(f: ExfilFinding, target: string): Finding {
  return {
    rule: f.id,
    severity: f.severity,
    target,
    path: f.source,
    line: f.line,
    engine: f.engine,
    message: f.message,
    valueDigest: f.valueDigest,
    snippet: f.snippet,
  };
}

export function scanExfilTree(o: ExfilTreeScanOptions): Finding[] {
  const repoDir = resolve(o.repoDir);
  const gitOpts = { ...(o.env !== undefined ? { env: o.env } : {}) };
  const files = runGitChecked(repoDir, ["ls-files", "-z"], gitOpts)
    .split("\0")
    .filter((rel) => rel !== "" && !rel.split("/").includes(BORDER_SEGMENT));
  const findings: Finding[] = [];
  for (const rel of files) {
    const abs = join(repoDir, rel);
    let size = 0;
    try {
      size = statSync(abs).size;
    } catch {
      continue; // tracked-then-deleted race: nothing on disk to read
    }
    if (size > MAX_SCAN_BYTES) continue;
    let text = "";
    try {
      text = readFileSync(abs, "utf8");
    } catch {
      continue; // unreadable race: the porcelain digest makes the tree state re-check anyway
    }
    if (text.includes("\0")) continue;
    for (const f of scanTreeText({
      text,
      source: rel,
      ...(o.hosts !== undefined ? { hosts: o.hosts } : {}),
      ...(o.sanitizer !== undefined ? { onMatch: (raw: string, digest: string): void => o.sanitizer?.register(digest, raw) } : {}),
    })) {
      findings.push(toFinding(f, o.target ?? "tree"));
    }
  }
  return findings;
}
