// provenance: original clean-room scaffold, no external code copied
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  computeRulesHash,
  MissingRulesInputError,
  redact,
  sanitizeUrl,
  TextSanitizer,
} from "../src/redact.ts";

function sha256hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

test("redact('AKIAIOSFODNN7EXAMPLE') yields first4…last4 snippet + stable digest", () => {
  const v = "AKIAIOSFODNN7EXAMPLE";
  const out = redact(v);
  assert.equal(out.snippet, "AKIA\u2026MPLE");
  assert.equal(out.valueDigest, sha256hex(v));
  assert.equal(redact(v).valueDigest, out.valueDigest, "digest must be stable across calls");
  assert.match(out.valueDigest, /^[0-9a-f]{64}$/);
});

test("redact('short12') is fully masked with no first4/last4 leak", () => {
  const out = redact("short12");
  assert.equal(out.snippet, "\u25ae\u25ae\u25ae\u25ae");
  assert.ok(!out.snippet.includes("short") && !out.snippet.includes("ort12"), "no partial value leak in snippet");
  const serialized = JSON.stringify(out);
  assert.ok(!serialized.includes("short12"), "raw value must not round-trip via JSON");
});

test("the full 20-char string appears nowhere in JSON.stringify(output)", () => {
  const v = "AKIAIOSFODNN7EXAMPLE";
  const json = JSON.stringify(redact(v));
  assert.ok(!json.includes(v), "raw secret must not appear in serialized output");
});

test("boundary: 12 chars fully masked, 13 chars first4…last4", () => {
  assert.equal(redact("abcdefghijkl").snippet, "\u25ae\u25ae\u25ae\u25ae");
  assert.equal(redact("abcdefghijklm").snippet, "abcd\u2026jklm");
});

test("redact('') never throws and is fully masked", () => {
  const out = redact("");
  assert.equal(out.snippet, "\u25ae\u25ae\u25ae\u25ae");
  assert.equal(out.valueDigest, sha256hex(""));
});

test("redact measures length in code points: short CJK secret fully masked", () => {
  const v = "\u79d8\u5bc6\u9375\u30c6\u30b9\u30c8\u5024"; // 秘密鍵テスト値 (7 code points)
  const out = redact(v);
  assert.equal(out.snippet, "\u25ae\u25ae\u25ae\u25ae");
  assert.equal(out.valueDigest, sha256hex(v));
});

test("long CJK secret (15 code points) keeps first4…last4 by code points", () => {
  const v = "\u3042\u3044\u3046\u3048\u304a\u304b\u304d\u304f\u3051\u3053\u3055\u3057\u3059\u305b\u305d"; // あいうえおかきくけこさしすせそ
  assert.equal(redact(v).snippet, "\u3042\u3044\u3046\u3048\u2026\u3057\u3059\u305b\u305d");
});

test("redact never throws on a secret containing newlines", () => {
  const v = "multi\nline\nsecret-value";
  const out = redact(v);
  assert.equal(out.valueDigest, sha256hex(v));
  assert.equal(out.snippet, "mult\u2026alue");
});

test("sanitizeUrl strips userinfo: https://u:t0k@r/npm → https://r/npm", () => {
  const out = sanitizeUrl("https://u:t0k@r/npm");
  assert.equal(out, "https://r/npm");
  assert.ok(!out.includes("t0k"));
});

test("sanitizeUrl strips token/auth/key/secret/password/passwd query params, keeps the rest", () => {
  const out = sanitizeUrl(
    "https://r/npm?token=abc&x=1&access_token=z&auth=q&key=k&secret=s&password=p&passwd=w&safe=v",
  );
  assert.equal(out, "https://r/npm?x=1&safe=v");
});

test("sanitizeUrl strips userinfo and token params in one pass", () => {
  const out = sanitizeUrl("https://u:p@r/path?q=1&token=abc");
  assert.equal(out, "https://r/path?q=1");
});

test("sanitizeUrl fails closed on unparseable input, never echoing it", () => {
  for (const junk of ["not a url", "garbage////", "//relative/path", ""]) {
    assert.equal(sanitizeUrl(junk), "[invalid-url-redacted]");
  }
});

test("TextSanitizer replaces registered values with [REDACTED:<sha8>]", () => {
  const s = new TextSanitizer();
  const v = "letmein123";
  const digest = sha256hex(v);
  s.register(digest, v);
  const out = s.sanitize("password is letmein123 here");
  assert.ok(out.includes(`[REDACTED:${digest.slice(0, 8)}]`), `expected token in: ${out}`);
  assert.ok(!out.includes("letmein123"), "raw value must be gone from scrubbed text");
});

test("TextSanitizer with no registrations is the identity", () => {
  const s = new TextSanitizer();
  const text = "nothing to scrub here";
  assert.equal(s.sanitize(text), text);
});

test("a registered value that looks like a redaction token is scrubbed once and idempotently", () => {
  const s = new TextSanitizer();
  const likeToken = "[REDACTED:abc12345]";
  s.register(sha256hex(likeToken), likeToken);
  const text = `leaked token appears as ${likeToken} here`;
  const once = s.sanitize(text);
  assert.ok(!once.includes(likeToken), "double-mask attempt must not survive");
  assert.ok(once.includes(`[REDACTED:${sha256hex(likeToken).slice(0, 8)}]`));
  assert.equal(s.sanitize(once), once, "sanitize must be idempotent");
});

test("overlapping registered values: longest match wins, output idempotent", () => {
  const s = new TextSanitizer();
  const short = "abc123";
  const long = "prefix-abc123-suffix";
  s.register(sha256hex(short), short);
  s.register(sha256hex(long), long);
  const out = s.sanitize(`value=${long} and bare ${short}`);
  assert.ok(!out.includes(long) && !out.includes(short));
  assert.equal(s.sanitize(out), out);
});

interface RulesHashFixture {
  dir: string;
  rulePath: string;
  base: {
    bundledRulePaths: string[];
    configDigest: string;
    engineVersions: Record<string, string>;
    promptTemplatePaths: string[];
  };
}

function makeFixture(): RulesHashFixture {
  const dir = mkdtempSync(join(tmpdir(), "border-hash-"));
  const rulePath = join(dir, "rules.toml");
  writeFileSync(rulePath, "[[rules]]\nid = 'x'\n");
  return {
    dir,
    rulePath,
    base: {
      bundledRulePaths: [rulePath],
      configDigest: "config-v1",
      engineVersions: { gitleaks: "8.30.1" },
      promptTemplatePaths: [],
    },
  };
}

test("computeRulesHash is deterministic across runs", async (t) => {
  const fx = makeFixture();
  t.after(() => rmSync(fx.dir, { recursive: true, force: true }));
  const h1 = await computeRulesHash(fx.base);
  const h2 = await computeRulesHash(fx.base);
  assert.equal(h1, h2);
  assert.match(h1, /^[0-9a-f]{64}$/);
});

test("computeRulesHash changes when an engine version bumps", async (t) => {
  const fx = makeFixture();
  t.after(() => rmSync(fx.dir, { recursive: true, force: true }));
  const before = await computeRulesHash(fx.base);
  const after = await computeRulesHash({ ...fx.base, engineVersions: { gitleaks: "8.30.2" } });
  assert.notEqual(before, after);
});

test("computeRulesHash changes when one rule file's content changes", async (t) => {
  const fx = makeFixture();
  t.after(() => rmSync(fx.dir, { recursive: true, force: true }));
  const before = await computeRulesHash(fx.base);
  writeFileSync(fx.rulePath, "[[rules]]\nid = 'x'\nseverity = 'HIGH'\n");
  const after = await computeRulesHash(fx.base);
  assert.notEqual(before, after);
});

test("computeRulesHash changes when a prompt template path is added", async (t) => {
  const fx = makeFixture();
  t.after(() => rmSync(fx.dir, { recursive: true, force: true }));
  const promptPath = join(fx.dir, "llm-prompt.md");
  writeFileSync(promptPath, "# prompt template\n");
  const before = await computeRulesHash(fx.base);
  const after = await computeRulesHash({ ...fx.base, promptTemplatePaths: [promptPath] });
  assert.notEqual(before, after);
});

test("computeRulesHash changes when configDigest flips", async (t) => {
  const fx = makeFixture();
  t.after(() => rmSync(fx.dir, { recursive: true, force: true }));
  const before = await computeRulesHash(fx.base);
  const after = await computeRulesHash({ ...fx.base, configDigest: "config-v2" });
  assert.notEqual(before, after);
});

test("computeRulesHash throws a typed error when a rule file is missing", async () => {
  await assert.rejects(
    computeRulesHash({
      bundledRulePaths: ["/nonexistent/nope.toml"],
      configDigest: "c",
      engineVersions: {},
      promptTemplatePaths: [],
    }),
    MissingRulesInputError,
  );
});