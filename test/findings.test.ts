// provenance: original clean-room scaffold, no external code copied
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  countFindings,
  computeVerdict,
  InvalidFindingError,
  isBlocking,
  validateFinding,
  type Finding,
  type Report,
  type Severity,
} from "../src/findings.ts";

function sev(severity: Severity): Finding {
  return {
    rule: "test-rule",
    severity,
    target: "git",
    engine: "unit",
    message: "planted",
    valueDigest: "a".repeat(64),
    snippet: "\u25ae\u25ae\u25ae\u25ae",
  };
}

test("isBlocking: CRITICAL and HIGH block, MEDIUM/LOW/INFO do not", () => {
  assert.equal(isBlocking("CRITICAL"), true);
  assert.equal(isBlocking("HIGH"), true);
  assert.equal(isBlocking("MEDIUM"), false);
  assert.equal(isBlocking("LOW"), false);
  assert.equal(isBlocking("INFO"), false);
});

test("computeVerdict: FAIL iff at least one finding is HIGH or CRITICAL", () => {
  assert.equal(computeVerdict([]), "PASS");
  assert.equal(computeVerdict([sev("INFO")]), "PASS");
  assert.equal(computeVerdict([sev("LOW"), sev("MEDIUM")]), "PASS");
  assert.equal(computeVerdict([sev("HIGH")]), "FAIL");
  assert.equal(computeVerdict([sev("CRITICAL")]), "FAIL");
  assert.equal(computeVerdict([sev("MEDIUM"), sev("HIGH"), sev("INFO")]), "FAIL");
});

test("warnings-only run: verdict PASS with warnings counted and zero blocking", () => {
  const findings = [sev("INFO"), sev("LOW"), sev("MEDIUM")];
  assert.equal(computeVerdict(findings), "PASS");
  const counts = countFindings(findings);
  assert.equal(counts.total, 3);
  assert.equal(counts.blocking, 0);
  assert.equal(counts.warnings, 3);
  assert.deepEqual(
    {
      info: counts.INFO,
      low: counts.LOW,
      medium: counts.MEDIUM,
      high: counts.HIGH,
      critical: counts.CRITICAL,
    },
    { info: 1, low: 1, medium: 1, high: 0, critical: 0 },
  );
});

test("countFindings tallies per severity plus blocking/warnings totals", () => {
  const findings: Finding[] = [
    sev("INFO"),
    sev("INFO"),
    sev("LOW"),
    sev("MEDIUM"),
    sev("MEDIUM"),
    sev("HIGH"),
    sev("CRITICAL"),
    sev("CRITICAL"),
  ];
  const counts = countFindings(findings);
  assert.equal(counts.total, 8);
  assert.equal(counts.blocking, 3);
  assert.equal(counts.warnings, 5);
  assert.equal(counts.CRITICAL, 2);
  assert.equal(counts.HIGH, 1);
  assert.equal(counts.MEDIUM, 2);
  assert.equal(counts.LOW, 1);
  assert.equal(counts.INFO, 2);
});

test("validateFinding accepts a well-formed Finding unchanged", () => {
  const finding = sev("HIGH");
  assert.deepEqual(validateFinding(finding), finding);
});

test("validateFinding rejects malformed findings with a typed error", () => {
  assert.throws(() => validateFinding(null), InvalidFindingError);
  assert.throws(() => validateFinding({ ...sev("HIGH"), rule: 42 }), InvalidFindingError);
  assert.throws(() => validateFinding({ ...sev("HIGH"), severity: "URGENT" }), InvalidFindingError);
  assert.throws(() => validateFinding({ ...sev("HIGH"), valueDigest: "not-hex" }), InvalidFindingError);
  assert.throws(() => validateFinding({ ...sev("HIGH"), path: 7 }), InvalidFindingError);
  assert.throws(() => validateFinding({ ...sev("HIGH"), line: 1.5 }), InvalidFindingError);
});

test("Report serializes to plain JSON and round-trips losslessly", () => {
  const finding = sev("CRITICAL");
  const report: Report = {
    schemaVersion: 1,
    key: "deadbeef",
    head: "0".repeat(40),
    dirty: false,
    exposureSet: ["https://r/npm"],
    refSet: ["main"],
    rulesHash: "f".repeat(64),
    verdict: "FAIL",
    counts: countFindings([finding]),
    findings: [finding],
    ts: "2026-09-04T00:00:00.000Z",
  };
  const round = JSON.parse(JSON.stringify(report)) as Report;
  assert.equal(round.schemaVersion, 1);
  assert.equal(round.verdict, "FAIL");
  assert.deepEqual(round.findings, report.findings);
  assert.deepEqual(round.counts, report.counts);
});