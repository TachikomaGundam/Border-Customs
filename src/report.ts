// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 19
//
// Report rendering. report.json (JSON.stringify(report,null,2)+'\n') stays the
// CANONICAL artifact — skip-ledger and llm-bundle consumers parse it and its
// bytes must not churn. report.md is the additive human artifact rendered from
// the same Report object: grouped by severity (blocking first), fixed columns
// rule|target|location|snippet|engine, plus the G14 allow-hits section so an
// exit 0 that suppressed findings still shows exactly what it hid.
//
// Masking invariant (G23) by construction: only Finding.snippet /
// .valueDigest / sanitized message strings ever reach a cell — the raw value
// is not in a Report and cannot appear here. Cells additionally escape literal
// pipes so ledger/engine-shaped text stays one inert row (no fabricated
// columns, no markdown link injection — text is never re-interpreted).

import type { Finding, Report, Severity } from "./findings.ts";
import { SEVERITIES } from "./findings.ts";

/** Canonical machine JSON — byte-identical to what recordCheckRun persists. */
export function renderReportJson(report: Report): string {
  return JSON.stringify(report, null, 2);
}

/** Blocking-first display order for the severity groups. */
const MD_SEVERITY_ORDER: readonly Severity[] = [...SEVERITIES].reverse();

function cell(value: string): string {
  return value.replace(/[\r\n\t]+/g, " ").replace(/\|/g, "\\|");
}

function locationCell(f: Finding): string {
  const parts: string[] = [];
  if (f.path !== undefined) parts.push(f.line !== undefined ? `${f.path}:${f.line}` : f.path);
  if (f.commit !== undefined) parts.push(f.commit.slice(0, 12));
  return parts.join(" ");
}

function table(findings: readonly Finding[]): string[] {
  const lines = [
    "| rule | target | location | snippet | engine |",
    "| --- | --- | --- | --- | --- |",
  ];
  for (const f of findings) {
    lines.push(
      `| ${cell(f.rule)} | ${cell(f.target)} | ${cell(locationCell(f))} | ${cell(f.snippet)} | ${cell(f.engine)} |`,
    );
  }
  return lines;
}

/** Human-readable report.md body for one check run. */
export function renderReportMd(report: Report): string {
  const lines: string[] = [
    `# border check report`,
    "",
    `- verdict: ${report.verdict} — key \`${report.key.slice(0, 8)}\` — head \`${report.head.slice(0, 12)}\`${report.dirty ? " (dirty)" : ""}`,
    `- ts: ${report.ts} — rulesHash \`${report.rulesHash.slice(0, 12)}\``,
    `- counts: total ${report.counts.total} / blocking ${report.counts.blocking} / warnings ${report.counts.warnings}`,
    `- exposureSet: ${report.exposureSet.length === 0 ? "(empty — nothing exposed by config)" : report.exposureSet.map((u) => cell(u)).join(", ")}`,
    `- refSet: ${report.refSet.length === 0 ? "(empty)" : report.refSet.map((r) => cell(r)).join(", ")}`,
    "",
  ];
  if (report.findings.length === 0) {
    lines.push("_no findings — every engine and policy leg came back clean._", "");
  } else {
    for (const sev of MD_SEVERITY_ORDER) {
      const group = report.findings.filter((f) => f.severity === sev);
      if (group.length === 0) continue;
      lines.push(`## ${sev} (${group.length})`, "", ...table(group), "");
    }
  }
  const hits = report.allowHits ?? [];
  if (hits.length > 0) {
    const suppressed = hits.reduce((n, h) => n + h.count, 0);
    lines.push(
      `## allow-hits (${suppressed} suppressed)`,
      "",
      "Findings suppressed by `border.yaml` `allow` entries (G14). The entry index resolves the pattern and its justification comment in border.yaml.",
      "",
      "| rule | count | sample | entry |",
      "| --- | --- | --- | --- |",
    );
    for (const h of hits) {
      lines.push(`| ${cell(h.rule)} | ${h.count} | ${cell(h.sample)} | entry #${h.entryIndex} |`);
    }
    lines.push("");
  }
  return `${lines.join("\n")}\n`;
}
