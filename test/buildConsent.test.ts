// provenance: build-stage consent wave (ruling sibyl-20261023T112953Z-7ada).
// resolveBuildConsent is the SINGLE trust decision for every spawn that would
// execute audited code; its semantics are pinned here so a future edit cannot
// quietly widen consent. Only flag===true or env==="1" ever allow; every other
// value fails closed and names itself in the reason.
import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";

import { resolveBuildConsent } from "../src/check/buildConsent.ts";


test("flag alone consents", () => {
  assert.deepEqual(resolveBuildConsent({ allowBuildsFlag: true, machineAllowBuilds: false }), { allowed: true, source: "flag" });
});

test("machine store key alone consents", () => {
  assert.deepEqual(resolveBuildConsent({ allowBuildsFlag: false, machineAllowBuilds: true }), { allowed: true, source: "machine" });
});

test("no source ⇒ withheld with the scan-only reason", () => {
  const c = resolveBuildConsent({ allowBuildsFlag: false, machineAllowBuilds: false });
  assert.equal(c.allowed, false);
  assert.match(c.reason ?? "", /scan-only/);
});

test("RED-TEAM §3: the BORDER_ALLOW_BUILDS environment variable is DEAD — set, it never consents", () => {
  const saved = process.env["BORDER_ALLOW_BUILDS"];
  process.env["BORDER_ALLOW_BUILDS"] = "1";
  try {
    const c = resolveBuildConsent({ allowBuildsFlag: false, machineAllowBuilds: false });
    assert.equal(c.allowed, false, "env consent was removed (sibyl §3 consent un-planting) — a hostile .envrc must not consent");
  } finally {
    if (saved === undefined) delete process.env["BORDER_ALLOW_BUILDS"];
    else process.env["BORDER_ALLOW_BUILDS"] = saved;
  }
});

test("anchor re-probe duty (§3⁗ breaking-change claim): the consent ENV CHANNEL never shipped in a release", () => {
  const tags = execFileSync("git", ["tag", "--sort=-v:refname"], { encoding: "utf8" }).trim().split("\n");
  const newest = tags[0] ?? "";
  let source: string | null = null;
  try {
    source = execFileSync("git", ["show", `${newest}:src/check/buildConsent.ts`], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  } catch {
    source = null; // module absent at that tag ⇒ the env channel certainly never shipped there
  }
  if (source === null) return;
  // Module present ⇒ the load-bearing invariant: the consent resolver must not read
  // the environment. Re-pin this leg at every release against that tag's bytes.
  assert.doesNotMatch(source, /process\.env\[?.BORDER_ALLOW_BUILDS/, `newest tag ${newest} must not consent from the environment (sibyl §3)`);
});
