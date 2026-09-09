// N-c (VERIFIER-REPORT-R3A-FIX): THE canonical npm digest dump — recipe locked in
// src/artifacts/RESIDUE-CONTRACT.md §8 "npm digest-dump canonicalization".
// Stage the 14 npm corpus fixtures alphabetically, keep rule.startsWith("residue-") rows,
// join valueDigests in stage-emission order with "\n" (no trailing newline), sha256 the UTF-8.
// Expected: cf54bc25bf5fc9552dfd048e04297cec14af178dc3ef44767b4cf74526cdb08d
// Run: cd <border repo root> && npx tsx .omo/evidence/residue-spike/npm-digest-dump.mts
import { createHash } from "node:crypto";
import { cpSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runNpmArtifactStage } from "../../../src/artifacts/npm.ts";
import type { BorderConfig } from "../../../src/config.ts";

const CFG: BorderConfig = {
  version: 1,
  targets: { git: { remotes: [] }, npm: {} },
  rules: { authors: { emails: [], names: [] }, hosts: [], ips: [], pathPatterns: [], maxFileKB: 500 },
  allow: [],
  engines: { require: ["gitleaks", "secretlint"], trufflehog: false },
};
const CORPUS = new URL("../../../test/fixtures/residue/", import.meta.url).pathname;
const FIXTURES = [
  "a-opencode-t1", "b-t2-downloader", "c-t3-rceditor", "d-t4-bin", "e-t0-clean",
  "f1-esbuild", "f2-msgpackr-extract", "f3-thread-stream", "f4-synthetic-curlsh",
  "i-crossmgr", "j-winpath", "k-paired", "k-remove-orphan", "k-write-orphan",
];
const rows: { fx: string; rule: string; path: string; valueDigest: string }[] = [];
for (const fx of FIXTURES) {
  const repo = mkdtempSync(join(tmpdir(), "residue-"));
  cpSync(join(CORPUS, fx), repo, { recursive: true });
  const { findings } = await runNpmArtifactStage({ repoDir: repo, cfg: CFG, skipGitleaks: true, skipSecretlint: true });
  rmSync(repo, { recursive: true, force: true });
  for (const f of findings.filter((x) => x.rule.startsWith("residue-"))) {
    rows.push({ fx, rule: f.rule, path: f.path, valueDigest: f.valueDigest });
  }
}
const dump = rows.map((r) => r.valueDigest).join("\n");
console.log(JSON.stringify({ rowCount: rows.length, rows, sha256: createHash("sha256").update(dump, "utf8").digest("hex") }, null, 2));
