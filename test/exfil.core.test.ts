// provenance: .omo/plans/border-exfil-lens.md T1 — first-class unit tests for the
// exfil rule core: every rule RED on synthetic hits (10.200.x addresses,
// synthuser@ targets, obviously-synthetic hostnames — never real-world
// identifiers), every closed exemption GREEN, the :message id family
// attribution, the severity matrix lookups, the import-audit guard (style
// copied from test/scan.test.ts:258-265) and the EXFIL_FINGERPRINT_SOURCES
// registration guard. Red/exemption pairs follow the plan §规则语义表 rows.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import {
  EXFIL_CHANNELS,
  EXFIL_FACETS,
  EXFIL_HIGH_FAMILY,
  EXFIL_MATRIX,
  EXFIL_MEDIUM_FAMILY,
  EXFIL_RULE_IDS,
  EXFIL_TABLE_SEVERITY,
  emitRulesFor,
  exfilFindingId,
  observedSeverity,
} from "../src/exfil/severity.ts";
import { DEFAULT_EXEMPT_BANDS, matchCredLocation, matchHomePath, matchHostProfile, matchRfc1918, matchSshTarget } from "../src/exfil/rules.ts";
import { EXFIL_ENGINE, maskValue, scanMessageText, scanTreeText } from "../src/exfil/scan.ts";
import { redact } from "../src/redact.ts";
import {
  EXFIL_FINGERPRINT_BASENAMES,
  computeCheckRulesHash,
  resolveExfilFingerprintFiles,
} from "../src/check/rulesHash.ts";
import { BORDER_ROOT, assembleHost, assembleOctet } from "./helpers/fixtures.ts";

const TREE = { facet: "tree" } as const;
const MSG = { facet: "message" } as const;
const NOBANDS_TREE = { facet: "tree", exemptBands: [] } as const;
const SYNTH_SHA = "a".repeat(40);
const seamDirs: string[] = [];
after(() => {
  for (const d of seamDirs) rmSync(d, { recursive: true, force: true });
});

// ---------------------------------------------------------------- 1. the matrix, verbatim plan §分面契约

test("MATRIX: tree facet — twins carry the HIGH family at CRITICAL, native carries only the MEDIUM family", () => {
  for (const twin of ["gitleaks-twin", "secretlint-twin"] as const) {
    for (const rule of EXFIL_HIGH_FAMILY) {
      assert.equal(observedSeverity(rule, "tree", twin), "CRITICAL", `${rule}×${twin}: engines hardcode CRITICAL (gitleaks.ts:81 / secretlint.ts:299-309)`);
    }
    for (const rule of EXFIL_MEDIUM_FAMILY) {
      assert.equal(observedSeverity(rule, "tree", twin), null, `${rule}×${twin}: MEDIUM family is not twin-owned`);
    }
  }
  for (const rule of EXFIL_HIGH_FAMILY) {
    // v2 native tree/blob double-emission revoked by plan REV v3 → forbidden cell.
    assert.equal(observedSeverity(rule, "tree", "native"), null, `${rule}×tree×native must be unemittable`);
  }
  for (const rule of EXFIL_MEDIUM_FAMILY) {
    assert.equal(observedSeverity(rule, "tree", "native"), "MEDIUM", `${rule}×tree×native`);
  }
});

test("MATRIX: message facet — native-exclusive :message family at table severity; twins forbidden", () => {
  for (const rule of EXFIL_RULE_IDS) {
    assert.equal(observedSeverity(rule, "message", "native"), EXFIL_TABLE_SEVERITY[rule], `${rule}×message×native = table severity`);
    assert.equal(observedSeverity(rule, "message", "gitleaks-twin"), null, `${rule}×message×gitleaks-twin: twins never scan messages`);
    assert.equal(observedSeverity(rule, "message", "secretlint-twin"), null, `${rule}×message×secretlint-twin`);
  }
  assert.deepEqual(
    EXFIL_RULE_IDS.map((r) => EXFIL_TABLE_SEVERITY[r]),
    ["HIGH", "HIGH", "MEDIUM", "MEDIUM", "MEDIUM"],
    "plan rule table intent severities",
  );
});

test("MATRIX: tagNote facet — engine既有腿 owns it (tag-message-secret); NO exfil-* emission through any channel", () => {
  for (const channel of EXFIL_CHANNELS) {
    for (const rule of EXFIL_RULE_IDS) {
      assert.equal(observedSeverity(rule, "tagNote", channel), null, `tag notes stay engine-owned (tagScan.ts:26,101); ${rule}×tagNote×${channel} forbidden`);
    }
  }
});

test("MATRIX: table coverage — every (rule × facet × channel) cell is declared", () => {
  assert.deepEqual([...EXFIL_FACETS], ["tree", "message", "tagNote"]);
  assert.deepEqual([...EXFIL_CHANNELS], ["native", "gitleaks-twin", "secretlint-twin"]);
  for (const facet of EXFIL_FACETS) {
    for (const channel of EXFIL_CHANNELS) {
      const row = EXFIL_MATRIX[facet][channel];
      assert.deepEqual(Object.keys(row).sort(), [...EXFIL_RULE_IDS].sort(), `${facet}×${channel} row must enumerate all five rules`);
    }
  }
});

test("emitRulesFor: per-facet native/twin emission sets", () => {
  assert.deepEqual([...emitRulesFor("tree", "native")], EXFIL_MEDIUM_FAMILY);
  assert.deepEqual([...emitRulesFor("message", "native")], [...EXFIL_RULE_IDS]);
  assert.deepEqual([...emitRulesFor("tree", "gitleaks-twin")], EXFIL_HIGH_FAMILY);
  assert.deepEqual([...emitRulesFor("tree", "secretlint-twin")], EXFIL_HIGH_FAMILY);
  assert.deepEqual([...emitRulesFor("message", "gitleaks-twin")], []);
  assert.deepEqual([...emitRulesFor("tagNote", "native")], []);
});

test("exfilFindingId: :message id family attribution; blob-face ids stay bare (bidirectional isolation, allow.ts:38 exact match)", () => {
  assert.equal(exfilFindingId("exfil-rfc1918", "message"), "exfil-rfc1918:message");
  assert.equal(exfilFindingId("exfil-ssh-target", "message"), "exfil-ssh-target:message");
  assert.equal(exfilFindingId("exfil-home-path", "tree"), "exfil-home-path");
  assert.equal(exfilFindingId("exfil-host-profile", "tagNote"), "exfil-host-profile");
  assert.notEqual(exfilFindingId("exfil-rfc1918", "message"), "exfil-rfc1918");
});

// ---------------------------------------------------------------- 2. exfil-rfc1918

test("rfc1918 RED on synthetic hits (band@message; other arms assembled per F3)", () => {
  const msgHits = matchRfc1918("runner reached out to 10.200.30.40 for the mirror", MSG);
  assert.equal(msgHits.length, 1, "fixture-band address still red on the message facet (public surface has no fixture excuse)");
  assert.equal(msgHits[0]?.rule, "exfil-rfc1918");
  assert.equal(msgHits[0]?.line, 1);
  assert.equal(matchRfc1918(`no internal here\nsecond line\npeer ${assembleOctet("10.31.4", "5")} joined`, NOBANDS_TREE).length, 1, "10/8 branch, line 3");
  assert.equal(matchRfc1918(`build node ${assembleOctet("172.20.30", "40")} cache`, NOBANDS_TREE).length, 1, "172.16/12 branch");
  assert.equal(matchRfc1918(`wifi ap ${assembleOctet("192.168.13", "37")} rebooted`, NOBANDS_TREE).length, 1, "192.168/16 branch");
});

test("rfc1918 GREEN on every closed exemption", () => {
  const green = [
    "loopback probe 127.0.0.1 ok",
    "doc band one 192.0.2.123",
    "doc band two 198.51.100.7",
    "doc band three 203.0.113.9",
    "link-local 169.254.1.1",
    "cgnat 100.64.0.1",
    "bad octet 10.999.1.1",
    "172.32.0.1 is outside 172.16/12",
    "172.15.9.9 is outside 172.16/12",
    "192.169.1.1 is outside 192.168/16",
    `version string ${assembleOctet("1.10.20.30", "40")} must not split-match`,
  ];
  for (const line of green) {
    assert.deepEqual(matchRfc1918(line, MSG), [], `green on message facet: ${line}`);
    assert.deepEqual(matchRfc1918(line, TREE), [], `green on tree facet: ${line}`);
  }
});

test("rfc1918 exemption bands (F2/F3): tree exempts DEFAULT_EXEMPT_BANDS, message fires everything, exemptBands override forces band red", () => {
  const BAND_LINE = "fixture marker 10.200.7.8 in golden corpus";
  assert.deepEqual(matchRfc1918(BAND_LINE, TREE), [], "10.200/16 synthetic fixture band: tree-green (twin parity)");
  assert.equal(matchRfc1918(BAND_LINE, MSG).length, 1, "message facet fires");
  assert.equal(matchRfc1918(BAND_LINE, NOBANDS_TREE).length, 1, "options.exemptBands=[] re-arms the band (unit override)");
  assert.deepEqual(DEFAULT_EXEMPT_BANDS, ["127", "192.0.2", "198.51.100", "203.0.113", "10.200"], "closed production band set (twins mirror this list — parity corpus pins behaviour)");
});

// ---------------------------------------------------------------- 3. exfil-ssh-target

test("ssh-target RED: RFC1918 literal, closed suffix set, configured hosts", () => {
  const reds = [
    "synthuser@10.200.30.40", // T6 golden anchor rides the MESSAGE facet (band fires there; tree exempts per F2 parity)
    assembleOctet("synthuser@172.20.30", "40"),
    assembleHost("deploy", "synth-one", "internal"),
    assembleHost("deploy", "synth-two", "lan"),
    assembleHost("deploy", "synth-three", "local"),
    assembleHost("deploy", "synth-four", "corp"),
    assembleHost("deploy", "synth-five", "intra"),
  ];
  for (const line of reds) {
    assert.equal(matchSshTarget(line, MSG).length, 1, `red: ${line}`);
    assert.equal(matchSshTarget(line, MSG)[0]?.rule, "exfil-ssh-target");
  }
  // non-band IP hosts fire on the tree predicate too; the band does not (twin parity):
  assert.equal(matchSshTarget(assembleOctet("synthuser@172.20.30", "40"), TREE).length, 1, "172.20/12 host is no exempt band — tree predicate red");
  assert.deepEqual(matchSshTarget("synthuser@10.200.30.40", TREE), [], "F2 parity: fixture-band ssh host exempt on the tree facet (twins behave identically)");
  assert.equal(matchSshTarget(`ssh ${assembleHost("SYNTHUSER", "SYNTHDB", "INTERNAL")} -v`, MSG).length, 1, "case-insensitive host fold");
  const opts = { facet: "tree", hosts: ["synth-node-7", "synthgit.example"] } as const;
  assert.equal(matchSshTarget("rsync synthuser@synth-node-7:backup", opts).length, 1, "bare configured host (no dot) via rules.hosts");
  assert.equal(matchSshTarget("push to synthuser@synthgit.example main", opts).length, 1, "operator-listed host wins over the RFC2606 shape exemption");
  assert.deepEqual(matchSshTarget("push to synthuser@synthgit.example main", TREE).length, 0, "unconfigured .example host stays green");
});

test("ssh-target GREEN: RFC2606 exemptions + bare public domains + non-RFC1918 literals", () => {
  const green = [
    "mail synthuser@example.com first",
    "synthuser@synthbox.example",
    "synthuser@synthbox.test",
    "synthuser@synthbox.invalid",
    "synthuser@synthbox.localhost",
    "ubuntu@169.254.1.1 link-local is not RFC1918",
    "ops@100.64.0.1 cgnat is not RFC1918",
    "plain word with at sign synthuser@@synth.internal",
    "no target here, just text",
  ];
  for (const line of green) {
    assert.deepEqual(matchSshTarget(line, MSG), [], `green: ${line}`);
  }
});

// ---------------------------------------------------------------- 4. exfil-home-path

test("home-path RED: /home/<user> and C:\\Users\\<user>", () => {
  const hits = matchHomePath("copied from /home/synthuser/.ssh/config", TREE);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]?.rule, "exfil-home-path");
  assert.match(hits[0]?.matched ?? "", /^\/home\/synthuser$/);
  assert.equal(matchHomePath("profile at C:\\\\Users\\\\SynthUser\\\\Desktop", TREE).length, 1, "windows form");
  assert.equal(matchHomePath("profile at d:/users/synthuser/docs", TREE).length, 1, "case-insensitive drive + forward slashes");
  assert.equal(matchHomePath("first line\nsecond line\nlast /home/synthuser", TREE)[0]?.line, 3);
});

test("home-path GREEN: lookalikes", () => {
  for (const line of ["brew in /homebrew/Cellar", "the /home directory", "/homepage/app", "/Applications/Foo", "user guide homepage"]) {
    assert.deepEqual(matchHomePath(line, TREE), [], `green: ${line}`);
  }
});

// ---------------------------------------------------------------- 5. exfil-cred-location

test("cred-location RED: ~/.pypirc, SSHPASS, *.env location references (位置 ≠ 值)", () => {
  const reds = ["upload with ~/.pypirc configured", "runner exports SSHPASS for the pool", "read deploy/staging.env first", "the .env file holds tokens", "rotate secrets.env nightly"];
  for (const line of reds) {
    assert.equal(matchCredLocation(line, TREE).length, 1, `red: ${line}`);
    assert.equal(matchCredLocation(line, TREE)[0]?.rule, "exfil-cred-location");
  }
});

test("cred-location GREEN: near-misses, case, and the T5-calibrated JS property-access shapes", () => {
  for (const line of [
    "ship prod.env.example template",
    "set the environment variables",
    "the .environment dir",
    "sshpass cli helper",
    "dotenv notes",
    'const configured = process.env["BORDER_BIN"];',
    "const merged = o.env === undefined ? {} : { env: { ...o.env } };",
    "spawn(input?.env ?? process.env)",
  ]) {
    assert.deepEqual(matchCredLocation(line, TREE), [], `green: ${line}`);
  }
});

// ---------------------------------------------------------------- 6. exfil-host-profile

test("host-profile RED only on ≥2 distinct signals in the SAME paragraph", () => {
  const three = "The box runs Ubuntu 22.04. There is no docker installed and sudo requires a password for the deploy user.";
  const hits = matchHostProfile(three, TREE);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]?.rule, "exfil-host-profile");
  assert.equal(hits[0]?.matched, "os+version+no-docker+sudo-pattern", "evidence = signal-name cluster only");
  assert.ok(!hits[0]?.matched.includes("Ubuntu"), "raw paragraph text never rides the hit");
  const two = "Image base Debian 12, deliberately without docker.";
  assert.equal(matchHostProfile(two, TREE)[0]?.matched, "os+version+no-docker");
  assert.equal(matchHostProfile("line one Ubuntu 24.04\n\nthen no docker separately", TREE).length, 0, "blank-line-split paragraphs never combine");
});

test("host-profile GREEN on single or weaker signals", () => {
  for (const text of [
    "runs Ubuntu 22.04 only",
    "we should avoid docker images",
    "passwordless sudo? no comment",
    "the driver and drivers and driving are unrelated",
  ]) {
    assert.deepEqual(matchHostProfile(text, TREE), [], `green: ${text}`);
  }
});

// ---------------------------------------------------------------- 7. scan surfaces: attribution + forbidden cells

test("scanTreeText: MEDIUM-family attribution only; native HIGH family unemittable on tree", () => {
  const text = [
    "copied from /home/synthuser/.ssh/config",
    "runner exports SSHPASS",
    "peer 10.200.30.40 joined",
    assembleHost("synthuser", "synthdb", "internal"),
    "read staging.env",
  ].join("\n");
  const findings = scanTreeText({ text, source: "docs/example.md", hosts: [] });
  const ids = new Set(findings.map((f) => f.id));
  assert.ok(ids.has("exfil-home-path") && ids.has("exfil-cred-location"), "medium family emitted");
  assert.ok(!ids.has("exfil-rfc1918") && !ids.has("exfil-ssh-target"), "v2 double-emission revoked: native tree never fires the HIGH family");
  assert.ok(![...ids].some((id) => id.includes(":message")), "no :message ids on the tree facet");
  for (const f of findings) {
    assert.equal(f.severity, "MEDIUM");
    assert.equal(f.channel, "native");
    assert.equal(f.facet, "tree");
    assert.equal(f.engine, EXFIL_ENGINE);
    assert.equal(f.source, "docs/example.md");
    assert.match(f.valueDigest, /^[0-9a-f]{64}$/);
  }
});

test("scanMessageText: full :message family, sha attribution, no raw evidence on findings", () => {
  const text = [
    "copied from /home/synthuser/.ssh/config",
    "peer 10.200.30.40 joined",
    assembleHost("synthuser", "synthdb", "internal"),
    "read staging.env",
  ].join("\n");
  const findings = scanMessageText({ text, source: SYNTH_SHA });
  const byId = new Map(findings.map((f) => [f.id, f]));
  assert.equal(byId.get("exfil-rfc1918:message")?.severity, "HIGH");
  assert.equal(byId.get("exfil-ssh-target:message")?.severity, "HIGH");
  assert.equal(byId.get("exfil-home-path:message")?.severity, "MEDIUM");
  assert.equal(byId.get("exfil-cred-location:message")?.severity, "MEDIUM");
  for (const f of findings) {
    assert.equal(f.channel, "native");
    assert.equal(f.facet, "message");
    assert.equal(f.source, SYNTH_SHA, "path=commit sha attribution (exclusions.ts:20-25 passes it through for per-commit allow rows)");
    const rendered = `${f.id}|${f.message}|${f.source}|${f.snippet}`;
    assert.ok(!rendered.includes("10.200.30.40"), "RFC1918 literal never rides the rendered finding (G23)");
    assert.ok(!rendered.includes("/home/synthuser/.ssh"), "home path never rides the rendered finding (G23)");
  }
});

test("maskValue mirrors redact.ts (G23 invariance despite the import-audit duplicate)", () => {
  for (const value of ["short", "10.200.30.40", "exactlytwelve", "exactly-thirteen", "/home/synthuser/.ssh/config", "密钥密钥密钥密钥密钥密钥"]) {
    assert.deepEqual(maskValue(value), redact(value), `mask equivalence for len ${String([...value].length)}`);
  }
});

// ---------------------------------------------------------------- 8. import-audit guard (plan §分面契约; style of test/scan.test.ts:258-265)

test("src/exfil/** imports only node builtins and local exfil files", () => {
  const hits = spawnSync("grep", ["-rEn", 'from "[^"]*"', "src/exfil"], { cwd: BORDER_ROOT, encoding: "utf8" });
  const foreign = hits.stdout
    .split("\n")
    .filter((l) => l !== "")
    .filter((l) => !/from "node:[^"]*"/.test(l) && !/from "\.\/[^"]*"/.test(l));
  assert.deepEqual(foreign, [], `src/exfil must stay ledger-/check-/dependency-free, got: ${foreign.join("; ")}`);
  const dyn = spawnSync("grep", ["-rEn", 'import\\(|require\\(', "src/exfil"], { cwd: BORDER_ROOT, encoding: "utf8" });
  const dynHits = dyn.stdout.split("\n").filter((l) => l !== "");
  assert.deepEqual(dynHits, [], `dynamic imports/require defeat the audit, got: ${dynHits.join("; ")}`);
});

// ---------------------------------------------------------------- 9. EXFIL_FINGERPRINT_SOURCES guards

test("EXFIL-FINGERPRINT: every src/exfil/*.ts is registered; an unregistered new file fails loudly", () => {
  const files = readdirSync(join(BORDER_ROOT, "src", "exfil"))
    .filter((f) => f.endsWith(".ts"))
    .sort();
  assert.ok(files.length > 0, "src/exfil must exist");
  for (const f of files) {
    assert.ok(EXFIL_FINGERPRINT_BASENAMES.includes(f), `new exfil source ${f} must be added to EXFIL_FINGERPRINT_SOURCES in src/check/rulesHash.ts`);
  }
  for (const base of EXFIL_FINGERPRINT_BASENAMES) {
    assert.ok(files.includes(base), `stale fingerprint entry ${base} points at a deleted file`);
  }
  const live = resolveExfilFingerprintFiles({});
  assert.deepEqual([...live].map((p) => p.slice(p.lastIndexOf("/") + 1)).sort(), files, "live resolution = the registered list");
  for (const p of live) {
    assert.ok(p.includes(join("src", "exfil")), `live path must sit in src/exfil: ${p}`);
    assert.ok(existsSync(p), `fingerprint input missing: ${p}`);
  }
});

test("EXFIL-FINGERPRINT: a one-byte edit to an exfil source rotates computeCheckRulesHash", async () => {
  const seam = mkdtempSync(join(tmpdir(), "exfil-seam-"));
  seamDirs.push(seam);
  for (const p of resolveExfilFingerprintFiles({})) {
    copyFileSync(p, join(seam, p.slice(p.lastIndexOf("/") + 1)));
  }
  const base = { engineVersions: {}, configDigest: "f".repeat(64) };
  const env = { ...process.env, BORDER_EXFIL_SRC_DIR: seam };
  const h1 = await computeCheckRulesHash({ ...base, env });
  assert.equal(h1, await computeCheckRulesHash({ ...base, env }), "deterministic across runs");
  const target = join(seam, "rules.ts");
  writeFileSync(target, `${readFileSync(target, "utf8")}\n// +1 byte\n`, "utf8");
  const h2 = await computeCheckRulesHash({ ...base, env });
  assert.notEqual(h1, h2, "cached PASS must go stale when an exfil rule source moves (plan R1 / AC5)");
});

test("EXFIL-DOC: README renders every non-null EXFIL_MATRIX cell verbatim from the single home, and forbids the null facets in prose", () => {
  const readme = readFileSync(join(BORDER_ROOT, "README.md"), "utf8");
  const lines = readme.split("\n");
  let renderedCells = 0;
  for (const facet of EXFIL_FACETS) {
    for (const channel of EXFIL_CHANNELS) {
      for (const rule of EXFIL_RULE_IDS) {
        const severity = observedSeverity(rule, facet, channel);
        if (severity === null) continue;
        renderedCells += 1;
        const hit = lines.some(
          (l) => l.includes(`\`${rule}\``) && l.includes(facet) && l.includes(channel) && l.toUpperCase().includes(severity),
        );
        assert.ok(hit, `README matrix must carry the cell ${rule} × ${facet} × ${channel} → ${severity} (single-home rendering, no re-decision)`);
      }
    }
  }
  assert.equal(renderedCells, 12, "the matrix has exactly twelve observable cells (7 tree + 5 message); a new cell means a README + guard change together");
  // null-cell prose duties: the facets the core must never emit on are named as such
  const lower = readme.toLowerCase();
  assert.ok(/tag notes? [^.]*never|never [^.]*tag notes?/.test(lower), "README must state the core never scans tag notes (engine owns that facet)");
  assert.ok(lower.includes(":message") && lower.includes("allow"), "README must document the :message id family's allow-list isolation");
  assert.ok(lower.includes("10.200.0.0/16"), "fixture band doctrine must be in the README");
  assert.ok(lower.includes("assembleoctet") && lower.includes("assemblehost"), "runtime-assembly fixture doctrine must be in the README");
  assert.ok(lower.includes("border_exfil_truth"), "opt-in truth lane must be documented");
});
