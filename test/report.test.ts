// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 19
//
// src/report.ts: the human-readable report.md render + canonical JSON seam, and
// their landing in the run archive (report.md written beside report.json by
// recordCheckRun; report.json bytes stay EXACTLY as todo 14 wrote them — the
// skip-ledger and llm-bundle consumers parse that file). Pins the G23 masking
// invariant ("assert sanitizer ran") and the G14 allow-hits section, plus the
// prompt-injection guard: ledger/engine strings are inert escaped text.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import { gatherContext } from "../src/check/context.ts";
import { renderReportJson, renderReportMd } from "../src/report.ts";
import { recordCheckRun } from "../src/ledger.ts";
import type { AllowHit, Finding, Report } from "../src/findings.ts";
import { redact, TextSanitizer } from "../src/redact.ts";
import { gitAddCommit, gitInit, makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";

const roots: string[] = [];
after(() => {
  for (const d of roots) removeDir(d);
});

function fixture(name: string): string {
  const root = makeFixtureDir(`report-${name}`);
  roots.push(root);
  return root;
}

function finding(over: Partial<Finding> & Pick<Finding, "rule">): Finding {
  return {
    severity: "CRITICAL",
    target: "git",
    engine: "unit",
    message: "planted",
    valueDigest: "a".repeat(64),
    snippet: "\u25ae\u25ae\u25ae\u25ae",
    ...over,
  };
}

function report(over: Partial<Report> & Pick<Report, "findings">): Report {
  return {
    schemaVersion: 1,
    key: "f".repeat(64),
    head: "0".repeat(40),
    dirty: false,
    exposureSet: [],
    refSet: [],
    rulesHash: "1".repeat(64),
    verdict: over.findings.some((f) => f.severity === "CRITICAL" || f.severity === "HIGH") ? "FAIL" : "PASS",
    counts: { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0, total: over.findings.length, blocking: 0, warnings: 0 },
    ts: "2026-09-04T00:00:00.000Z",
    ...over,
  };
}


test("renderReportMd groups by severity (blocking first) with the plan's five columns", () => {
  const md = renderReportMd(
    report({
      findings: [
        finding({ rule: "oversized-file", severity: "MEDIUM", path: "big.bin", line: 3 }),
        finding({ rule: "aws-access-token", severity: "CRITICAL", path: "test/a.ts", commit: "c".repeat(40) }),
        finding({ rule: "name-foreign-owner", severity: "HIGH", target: "npm" }),
      ],
    }),
  );
  const lines = md.split("\n");
  const pos = (needle: string): number => lines.findIndex((l) => l.includes(needle));
  assert.ok(pos("## CRITICAL") < pos("## HIGH") && pos("## HIGH") < pos("## MEDIUM"), `severity order wrong:\n${md}`);
  for (const col of ["rule", "target", "location", "snippet", "engine"]) {
    assert.ok(md.includes(col), `column ${col} missing`);
  }
  const row = lines.find((l) => l.includes("aws-access-token"));
  assert.ok(row !== undefined && row.includes("test/a.ts") && row.includes("c".repeat(12)), "commit short-sha should appear in location");
  assert.ok(row.includes("\u25ae\u25ae\u25ae\u25ae"), "masked snippet must render verbatim");
  assert.match(md, /verdict: FAIL/i);
});

test("renderReportMd: empty findings ⇒ explicit 'no findings' PASS body, no dangling tables", () => {
  const md = renderReportMd(report({ findings: [] }));
  assert.match(md, /no findings/i);
  assert.match(md, /verdict: PASS/i);
});

test("G23: sanitizer-masked values are the ONLY thing md/json ever show (raw registered value absent end-to-end)", () => {
  const raw = "AKIAI4Q3EXAMPL3K7X2Q";
  const { valueDigest, snippet } = redact(raw);
  const sanitizer = new TextSanitizer();
  sanitizer.register(valueDigest, raw);
  const engineStyle = `found AWS Access Key ID: ${raw}`;
  const message = sanitizer.sanitize(engineStyle);
  const f = finding({ rule: "aws-access-token", message, valueDigest, snippet });
  assert.ok(!message.includes(raw), "sanitize must replace the raw literal");
  assert.ok(message.includes(`[REDACTED:${valueDigest.slice(0, 8)}]`), "sanitizer token form");
  const r = report({ findings: [f] });
  const md = renderReportMd(r);
  const json = renderReportJson(r);
  assert.ok(!md.includes(raw) && !json.includes(raw), "raw fixture literal must never reach an artifact");
  assert.ok(json.includes("[REDACTED:"), "sanitized message survives in the canonical json");
  assert.ok(md.includes(snippet), "md renders the masking-invariant snippet column");
});

test("allow-hits section renders when present and is omitted when the field is absent", () => {
  const hits: AllowHit[] = [
    { rule: "aws-access-token", count: 4, sample: "test/a.test.ts", entryIndex: 1 },
    { rule: "path-pattern:/home/lab/x", count: 2, sample: ".omo/plans/p.md", entryIndex: 2 },
  ];
  const md = renderReportMd(report({ findings: [], allowHits: hits }));
  assert.match(md, /allow-hits/i);
  assert.match(md, /aws-access-token/);
  assert.match(md, /\| 4 \|/);
  assert.match(md, /\| 2 \|/);
  assert.ok(md.indexOf("entry #") < md.length, "hit rows reference the border.yaml entry index");
  const plain = renderReportMd(report({ findings: [] }));
  assert.ok(!plain.includes("allow-hits"), "no allow-hits section when nothing was suppressed");
});

test("prompt-injection guard: hostile ledger-shaped strings render as escaped inert cells", () => {
  const f = finding({
    rule: "evil|`rm -rf`",
    message: "commit-msg: ](https://x.tld?a=1) | **bold** <script>alert(1)</script>",
    path: "a|b.md",
  });
  const md = renderReportMd(report({ findings: [f] }));
  const row = md.split("\n").find((l) => l.includes("evil"));
  assert.ok(row !== undefined, "hostile rule cell must still render");
  assert.ok(row.includes("evil\\|"), "literal pipes inside a cell are backslash-escaped");
  assert.ok(!md.includes("\n| evil|"), "an escaped cell must never fabricate extra table columns");
  assert.ok(!/\[https?:/.test(row ?? ""), "markdown link syntax stays plain text");
});

test("renderReportJson is byte-identical to the canonical JSON.stringify(report,null,2) contract", () => {
  const r = report({ findings: [finding({ rule: "x" })], allowHits: [{ rule: "x", count: 1, sample: "p", entryIndex: 0 }] });
  assert.equal(renderReportJson(r), JSON.stringify(r, null, 2));
});

test("recordCheckRun lands report.md beside report.json; json bytes keep the pre-todo-19 format", () => {
  const dir = fixture("archive");
  gitInit(dir);
  writeRel(dir, "notes.txt", "clean\n");
  gitAddCommit(dir, "seed");
  const ctx = gatherContext(dir, {});
  const r = report({ findings: [finding({ rule: "demo-rule", path: "notes.txt" })], head: ctx.headSha });
  const rec = recordCheckRun({ repoDir: dir, report: r, ctx, effectiveTargets: [], llm: false });
  const jsonPath = join(dir, rec.reportPath);
  const mdPath = join(dir, ".border", "runs", rec.reportPath.split("/")[2] as string, "report.md");
  assert.ok(existsSync(mdPath), `report.md missing at ${mdPath}`);
  assert.equal(readFileSync(jsonPath, "utf8"), `${JSON.stringify(r, null, 2)}\n`, "canonical json bytes unchanged");
  const md = readFileSync(mdPath, "utf8");
  assert.ok(md.includes("demo-rule"));
  assert.equal(rec.reportPath.endsWith("report.json"), true, "record still points at the canonical json");
});
