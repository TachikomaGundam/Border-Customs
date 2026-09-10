// provenance: border-inspect-roadmap.md W1.2 — `border scan` handler core.
//
// Third-party inspection WITHOUT the check pipeline: parse spec → synthesize
// config through the zod path → fetch (injectable seam, capped + timed) →
// materialize as a committed temp git repo → call the matching channel's
// stage() directly → render residue findings through the report renderer.
// Import-audit contract (plan W1.2): this module and src/scan/** must never
// reach src/ledger/** or src/check.ts — no probes, no ledger writes, no push
// legs. Every failure (fetch/extract/git/stage) PROPAGATES as a typed error;
// the CLI maps it to exit 2. A scan that cannot genuinely run never prints
// a "clean" verdict.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { removeSandbox } from "../artifacts/extract.ts";
import { publishChannels } from "../channels/registry.ts";
import { runGitChecked } from "../check/context.ts";
import { exitCodeFromVerdict, UnknownArgError, type BorderExit } from "../cli/exit.ts";
import type { Ctx } from "../cli/types.ts";
import { EngineRunError } from "../engines/support.ts";
import { computeVerdict, countFindings, type Report } from "../findings.ts";
import { TextSanitizer } from "../redact.ts";
import { renderReportJson } from "../report.ts";
import { buildScanConfigYaml, synthesizeScanConfig } from "./config.ts";
import { defaultScanFetcher, fetchArtifact, sha256Hex, type ScanFetcher } from "./fetch.ts";
import { materializePackage } from "./materialize.ts";
import { parseScanSpec, SCAN_SPEC_USAGE } from "./spec.ts";

export type ScanDeps = {
  readonly fetcher?: ScanFetcher;
};

export async function runScanCore(ctx: Ctx, deps: ScanDeps = {}): Promise<BorderExit> {
  const raw = ctx.positionals[0];
  if (ctx.positionals.length !== 1 || raw === undefined) {
    throw new UnknownArgError(
      `border scan expects exactly one <spec> argument (got ${String(ctx.positionals.length)}); ${SCAN_SPEC_USAGE}`,
    );
  }
  const spec = parseScanSpec(raw);

  const channel = publishChannels().find((c) => c.id === spec.ecosystem);
  if (channel === undefined) {
    throw new EngineRunError(`border scan: no channel registered for ecosystem '${spec.ecosystem}'`, null);
  }

  const cfg = synthesizeScanConfig(spec.ecosystem);
  const fetcher = deps.fetcher ?? defaultScanFetcher;
  const baseDir = mkdtempSync(join(tmpdir(), "border-scan-"));
  try {
    const { bytes, filename } = await fetchArtifact(spec, { fetcher });
    const env: NodeJS.ProcessEnv = { ...ctx.env };
    const repoDir = materializePackage({ ecosystem: spec.ecosystem, bytes, filename, baseDir, env });
    const stage = await channel.stage({ repoDir, cfg, env, sanitizer: new TextSanitizer() });

    const head = runGitChecked(repoDir, ["rev-parse", "HEAD"], { env }).trim();
    const findings = stage.findings;
    const verdict = computeVerdict(findings);
    const report: Report = {
      schemaVersion: 1,
      key: sha256Hex(`scan:${spec.ecosystem}:${spec.name}@${spec.version}:${head}`),
      head,
      dirty: false,
      exposureSet: [`${spec.ecosystem}:${spec.name}@${spec.version}`],
      refSet: [],
      rulesHash: sha256Hex(buildScanConfigYaml(spec.ecosystem)),
      verdict,
      counts: countFindings(findings),
      findings,
      ts: new Date().toISOString(),
    };

    const label = `${spec.ecosystem}:${spec.name}@${spec.version}`;
    const sanitizer = new TextSanitizer();
    const line = (text: string): string => sanitizer.sanitize(text).replace(/\s+/g, " ").trim();
    if (ctx.flags.json) {
      ctx.stdout(renderReportJson(report));
    } else {
      ctx.stdout(line(`border scan ${label} ${report.verdict}: ${String(report.counts.total)} finding(s), ${String(report.counts.blocking)} blocking`));
      for (const f of report.findings) {
        ctx.stdout(line(`  ${f.severity} ${f.rule} [${f.engine}] ${f.path ?? f.commit ?? f.target} ${f.message}`));
      }
    }
    return exitCodeFromVerdict(verdict);
  } finally {
    removeSandbox(baseDir);
  }
}
