// R1 spike runner (SCRATCH — not production code; lives under .omo/evidence/residue-spike/).
// Invokes the CURRENT border 0.2.0 working-tree npm artifact stage
// (src/artifacts/npm.ts runNpmArtifactStage, LIFECYCLE loop at :198) directly for
// every fixture, WITHOUT the CLI's registry-probe leg (network). The stage is the
// exact code that produces lifecycle findings during `border check`; probe and
// content-scan ordering do not alter these rows.
// Run: node --import ../../tools/register-ts.mjs spike-runner.ts   (from the spike dir)
import { readdirSync } from "node:fs";
import { join } from "node:path";

import { parseConfig } from "/home/lab/workspace/harness/border/src/config.ts";
import { runNpmArtifactStage } from "/home/lab/workspace/harness/border/src/artifacts/npm.ts";

const fixturesDir = "/home/lab/workspace/harness/border/.omo/evidence/residue-spike/fixtures";
const cfg = parseConfig("version: 1\ntargets:\n  git:\n    remotes: []\n  npm: {}\nrules:\n  authors:\n    emails: []\n    names: []\n  hosts: []\n  ips: []\n  pathPatterns: []\nallow: []\nengines:\n  require: [gitleaks, secretlint]\n  trufflehog: false\n", "spike-border.yaml");

const results: unknown[] = [];
for (const name of readdirSync(fixturesDir).sort()) {
  const repoDir = join(fixturesDir, name);
  try {
    const stage = await runNpmArtifactStage({ repoDir, cfg });
    results.push({
      fixture: name,
      artifact: stage.artifact === null ? null : { file: stage.artifact.file, sha256: stage.artifact.sha256, bytes: stage.artifact.bytes },
      findings: stage.findings.map((f) => ({
        rule: f.rule,
        severity: f.severity,
        target: f.target,
        path: f.path ?? null,
        engine: f.engine,
        message: f.message,
        valueDigest: f.valueDigest,
        snippet: f.snippet,
      })),
    });
  } catch (err) {
    results.push({ fixture: name, error: String(err instanceof Error ? err.message : err) });
  }
}
console.log(JSON.stringify(results, null, 2));
