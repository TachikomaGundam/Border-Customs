// provenance: border-inspect-roadmap.md W1.2 — `border scan` config synthesis.
//
// The in-memory BorderConfig for a scan is built through the REAL schema path
// (parseConfig → zod .strict() validateDoc), never a hand-constructed object:
// exactly one ecosystem target enabled, residue scan explicitly on, and the
// schema's defaults (engines gitleaks+secretlint, maxFileKB 500, empty rules)
// do the rest. A shape bug fails as a typed ConfigError (exit 2), not a
// silently mis-scoped scan.
import { parseConfig, type BorderConfig } from "../config.ts";
import type { ScanEcosystem } from "./spec.ts";

export function buildScanConfigYaml(eco: ScanEcosystem): string {
  return [
    "version: 1",
    "targets:",
    "  git:",
    "    remotes: []",
    `  ${eco}: {}`,
    "rules:",
    "  authors:",
    "    emails: []",
    "    names: []",
    "  hosts: []",
    "  ips: []",
    "  pathPatterns: []",
    "residue:",
    "  enabled: true",
    "",
  ].join("\n");
}

export function synthesizeScanConfig(eco: ScanEcosystem): BorderConfig {
  return parseConfig(buildScanConfigYaml(eco), "<border scan>");
}
