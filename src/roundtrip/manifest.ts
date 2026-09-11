// provenance: border-inspect-roadmap.md W2.1 — manifest model + residue classifier.
//
// Pure logic over docker-exec stdout — no I/O, fully unit-testable. The line
// model is the W2.0 spike's (ROUNDTRIP-SPIKE.md): content + identity only,
// NEVER mtime/inode, so overlayfs copy-up and scanner self-noise cannot leak
// into a diff. Key = (kind, path); value = file sha256 | symlink target | '-'.
//
// Classification (plan §W2.1, doctrine-locked):
//   ADDED    (in m3, not m1) ⇒ RESIDUE, HIGH
//   MODIFIED (sha differs m1 vs m3) ⇒ persistence surface (rc / profile.d /
//            systemd / cron / PATH dirs / shell configs) ⇒ CRITICAL, else HIGH
//   REMOVED  ⇒ ignored: manager-internal bookkeeping, not a host-side fact.
import { createHash } from "node:crypto";

import type { Finding } from "../findings.ts";
import { RT_DEP_RULE, ownerOf, type DepAttribution } from "./calibrate.ts";

export const RT_ENGINE = "roundtrip";
export const RT_RESIDUE_RULE = "roundtrip-residue-file";
export const RT_MODIFY_RULE = "roundtrip-modified-file";
export const RT_PERSIST_RULE = "roundtrip-modified-persistence";

export type ManifestEntry = {
  readonly kind: "F" | "L" | "D";
  readonly path: string;
  readonly value: string;
};

const KEY_SEP = "\x1f";
const keyOf = (kind: string, path: string): string => `${kind}${KEY_SEP}${path}`;

/** Parse a manifest body (`F\tpath\tsha` / `L\tpath\ttarget` / `D\tpath\t-`). */
export function parseManifest(text: string): ReadonlyMap<string, ManifestEntry> {
  const out = new Map<string, ManifestEntry>();
  for (const line of text.split("\n")) {
    if (line.length === 0) continue;
    const parts = line.split("\t");
    if (parts.length < 3) continue;
    const kind = parts[0] as ManifestEntry["kind"];
    const path = parts[1] as string;
    const value = parts.slice(2).join("\t");
    if (kind !== "F" && kind !== "L" && kind !== "D") continue;
    out.set(keyOf(kind, path), { kind, path, value });
  }
  return out;
}

export type ManifestDiff = {
  readonly added: readonly ManifestEntry[];
  readonly removed: readonly ManifestEntry[];
  readonly modified: readonly ManifestEntry[];
};

/** Structural diff of two parsed manifests, keyed by (kind, path). */
export function diffManifests(
  before: ReadonlyMap<string, ManifestEntry>,
  after: ReadonlyMap<string, ManifestEntry>,
): ManifestDiff {
  const added: ManifestEntry[] = [];
  const removed: ManifestEntry[] = [];
  const modified: ManifestEntry[] = [];
  for (const [key, entry] of after) {
    const old = before.get(key);
    if (old === undefined) added.push(entry);
    else if (old.value !== entry.value) modified.push(entry);
  }
  for (const [key, entry] of before) {
    if (!after.has(key)) removed.push(entry);
  }
  return { added, removed, modified };
}

/**
 * Persistence surfaces a package is never allowed to mutate-or-keep: shell rc
 * files (including the ~/.config/fish tree), /etc/profile.d drop-ins, systemd
 * units, cron entries, and anything inside a PATH directory.
 */
const PERSISTENCE_PATTERNS: readonly RegExp[] = [
  /(^|\/)\.(bashrc|bash_profile|bash_login|profile|zshrc|zprofile|zshenv|kshrc|cshrc|login\.sh)$/,
  /^\/etc\/profile\.d\//,
  /^\/etc\/(bash\.bashrc|profile|environment|zsh\/zshrc|inputrc)$/,
  /^\/etc\/systemd\//,
  /(^|\/)\.config\/systemd\//,
  /(^|\/)systemd\/system\//,
  /(^|\/)(cron|cron\.d|cron\.[0-9dhmwy]+|spool\/cron)\//,
  /^\/etc\/crontab$/,
  /(^|\/)\.config\/fish\//,
  /^\/(usr\/)?(local\/)?(s?bin)\//,
  /(^|\/)\.local\/bin\//,
];

export function isPersistenceSurface(path: string): boolean {
  return PERSISTENCE_PATTERNS.some((re) => re.test(path));
}

const digestOf = (what: string): string => createHash("sha256").update(what).digest("hex");

/** Turn an m1→m3 diff into scan-shaped Findings (engine='roundtrip').
 *  W2.4(a): pypi lanes pass the m3 dep-attribution table; an ADDED row a
 *  still-installed closure dep still accounts for demotes to LOW
 *  residue-roundtrip-dep-owned (non-blocking). attribution null/omitted ⇒
 *  byte-for-byte the W2.1 machine (npm/cargo/gem, and pypi before calibration). */
export function classifyResidue(label: string, diff: ManifestDiff, attribution: DepAttribution | null = null): Finding[] {
  const findings: Finding[] = [];
  for (const e of diff.added) {
    const owner = attribution !== null ? ownerOf(e, attribution) : undefined;
    if (owner !== undefined) {
      findings.push({
        rule: RT_DEP_RULE,
        severity: "LOW",
        target: label,
        path: e.path,
        engine: RT_ENGINE,
        message: `ADDED path survives uninstall but is claimed by still-installed dependency '${owner}' (pip-accountable) — demoted, non-blocking`,
        valueDigest: digestOf(`ADDED:${e.path}:${e.value}`),
        snippet: `dep-owned: ${e.path}`,
      });
      continue;
    }
    // Fail closed on every surviving row, directories included: the spike's
    // ADDED acceptance bar counted them (ADDED(7) = 5 files + 2 dirs).
    findings.push({
      rule: RT_RESIDUE_RULE,
      severity: "HIGH",
      target: label,
      path: e.path,
      engine: RT_ENGINE,
      message: `installed file survived uninstall (ADDED in post-uninstall manifest)`,
      valueDigest: digestOf(`ADDED:${e.path}:${e.value}`),
      snippet: `residue: ${e.path}`,
    });
  }
  for (const e of diff.modified) {
    const persist = isPersistenceSurface(e.path);
    findings.push({
      rule: persist ? RT_PERSIST_RULE : RT_MODIFY_RULE,
      severity: persist ? "CRITICAL" : "HIGH",
      target: label,
      path: e.path,
      engine: RT_ENGINE,
      message: persist
        ? `uninstall mutated a persistence surface (rc/systemd/cron/PATH) — content differs pre-install vs post-uninstall`
        : `file content differs pre-install vs post-uninstall (MODIFIED, not reverted by uninstall)`,
      valueDigest: digestOf(`MODIFIED:${e.path}:${e.value}`),
      snippet: persist ? `persistence: ${e.path}` : `modified: ${e.path}`,
    });
  }
  return findings;
}
