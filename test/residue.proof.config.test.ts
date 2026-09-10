// provenance: border-inspect-roadmap.md W2.2 — `residue.requireProof` config layer.
//
// Owns: the strict-zod shape (default FALSE, unknown sibling ⇒ exit 2, non-bool
// ⇒ exit 2 — mirrors residue.enabled), and the rulesHash fold AC: flipping the
// flag MUST rotate computeConfigDigest AND computeCheckRulesHash, invalidating
// every cached PASS (the digest seam keeps cached verdicts honest about the
// proof policy they were certified under). Outer `.optional()` is preserved:
// whole BorderConfig literals must still construct without the key.
import assert from "node:assert/strict";
import { test } from "node:test";

import { parseConfig, ConfigError, type BorderConfig } from "../src/config.ts";
import { computeCheckRulesHash, computeConfigDigest, type LoadedConfig } from "../src/check/rulesHash.ts";

function yaml(extra: readonly string[]): string {
  return [
    "version: 1",
    "targets:",
    "  git:",
    "    remotes:",
    "      - name: origin",
    "        url: origin.example:widgets.git",
    "rules:",
    "  authors:",
    "    emails:",
    "      - wiki@sumteclab.com",
    "    names:",
    "      - Wiki.js",
    "  hosts: []",
    "  ips: []",
    "  pathPatterns: []",
    ...extra,
    "",
  ].join("\n");
}

function load(extra: readonly string[]): LoadedConfig {
  return { kind: "loaded", config: parseConfig(yaml(extra)), warnings: [], source: "<inline>" };
}

test("W2.2-config: requireProof defaults FALSE and the key is optional (old literals construct)", () => {
  const noResidue = parseConfig(yaml([]));
  assert.equal(noResidue.residue, undefined, "absent `residue:` stays absent — whole-object digest keeps pre-W2.2 byte semantics for keyless configs");
  const bare = parseConfig(yaml(["residue:", "  enabled: true"]));
  assert.equal(bare.residue?.enabled, true);
  assert.equal(bare.residue?.requireProof, false, "parsed residue section materializes the false default");
  // A whole BorderConfig literal without the key must still typecheck+construct
  // (inferredConfig / pinned suites contract — same reason `residue` itself is
  // `.optional()` rather than `.default()`).
  const literal: BorderConfig = { ...noResidue, residue: { enabled: true, requireProof: true } };
  assert.equal(literal.residue?.requireProof, true);
});

test("W2.2-config: requireProof: true parses; strict schema rejects siblings and non-bools (exit 2)", () => {
  const on = parseConfig(yaml(["residue:", "  enabled: true", "  requireProof: true"]));
  assert.equal(on.residue?.requireProof, true);

  assert.throws(
    () => parseConfig(yaml(["residue:", "  requireProof: 1"])),
    (err: unknown) => err instanceof ConfigError && err.exitCode === 2,
    "non-bool requireProof is a typed exit 2, never a truthy coercion",
  );
  assert.throws(
    () => parseConfig(yaml(["residue:", "  enabled: true", "  requireProofx: true"])),
    (err: unknown) => err instanceof ConfigError && err.exitCode === 2,
    "unknown sibling under residue: is a typo, not a silently-ignored key",
  );
  assert.throws(
    () => parseConfig(yaml(["residue:", "  requireProof: \"yes\""])),
    (err: unknown) => err instanceof ConfigError && err.exitCode === 2,
    "stringly-typed booleans rejected",
  );
});

test("W2.2-hash: flipping requireProof rotates configDigest AND the full check rulesHash (cached PASS invalidation)", async () => {
  const off = load(["residue:", "  enabled: true", "  requireProof: false"]);
  const on = load(["residue:", "  enabled: true", "  requireProof: true"]);
  const absent = load(["residue:", "  enabled: true"]);
  const digestOff = computeConfigDigest(off);
  const digestOn = computeConfigDigest(on);
  const digestAbsent = computeConfigDigest(absent);
  assert.notEqual(digestOff, digestOn, "the proof flag is a digest input — it must participate in computeCheckRulesHash fold");
  assert.equal(digestOff, digestAbsent, "explicit false === absent key (both stableStringify to {enabled:true,requireProof:false} vs the parsed default)");

  const hashOff = await computeCheckRulesHash({ engineVersions: {}, configDigest: digestOff });
  const hashOn = await computeCheckRulesHash({ engineVersions: {}, configDigest: digestOn });
  assert.notEqual(hashOff, hashOn, "same engine set + same files, only the policy flag differs ⇒ the WHOLE rulesHash rotates ⇒ the ledger key refuses the cached PASS");
});
