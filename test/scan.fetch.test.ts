// provenance: border-inspect-roadmap.md W1.1 — `border scan` fetch layer.
//
// Every AC runs OFFLINE through the injectable ScanFetcher seam (the same
// doctrine as the crates/pypi probe fetchers): URL shapes (scoped %2F
// encoding), the mandatory descriptive crates.io User-Agent, the 200 MiB
// size cap (content-length fast path + streamed abort), pypi sdist-only
// selection, and fail-closed errors (never a silent zero-findings "clean").
import assert from "node:assert/strict";
import { test } from "node:test";

import { EngineRunError } from "../src/engines/support.ts";
import { UnknownArgError } from "../src/cli/exit.ts";
import {
  SCAN_MAX_ARTIFACT_BYTES,
  SCAN_USER_AGENT,
  cratesDownloadUrl,
  fetchArtifact,
  npmMetadataUrl,
  pypiMetadataUrl,
  readCapped,
  rubygemsDownloadUrl,
  type ScanFetchInit,
  type ScanFetcher,
  type ScanResponse,
} from "../src/scan/fetch.ts";
import type { ScanSpec } from "../src/scan/spec.ts";

// ------------------------------------------------------------- seam helpers

function response(status: number, body: Uint8Array, contentLength: number | null = body.byteLength): ScanResponse {
  return {
    status,
    contentLength,
    async *chunks() {
      yield body;
    },
  };
}

function jsonResponse(status: number, doc: unknown): ScanResponse {
  return response(status, new TextEncoder().encode(JSON.stringify(doc)));
}

type Call = { url: string; init: ScanFetchInit };

/** Scripted fetcher: exact-URL table; records every call (url + headers). */
function stub(calls: Call[], routes: Readonly<Record<string, () => ScanResponse>>): ScanFetcher {
  return async (url, init) => {
    calls.push({ url, init });
    const route = routes[url];
    if (route === undefined) throw new Error(`stub fetcher got unscripted URL: ${url}`);
    return route();
  };
}

const spec = (ecosystem: ScanSpec["ecosystem"], name: string, version: string): ScanSpec => ({ ecosystem, name, version });

test("SCAN_USER_AGENT is Latin-1-safe: undici rejects non-ASCII header values", () => {
  for (const ch of SCAN_USER_AGENT) {
    assert.ok(ch.codePointAt(0)! <= 0xff, `header value char '${ch}' would crash fetch() with a ByteString TypeError`);
  }
});

// ------------------------------------------------------------- URL builders

test("npm metadata URL keeps '@scope/' literal and encodes only the slash as %2F", () => {
  assert.equal(npmMetadataUrl("left-pad", "1.3.0"), "https://registry.npmjs.org/left-pad/1.3.0");
  assert.equal(npmMetadataUrl("@sugar/pina-pina", "1.0.0"), "https://registry.npmjs.org/@sugar%2Fpina-pina/1.0.0");
  assert.match(npmMetadataUrl("@scope/pkg", "1.0.0"), /^https:\/\/registry\.npmjs\.org\/@scope%2Fpkg\/1\.0\.0$/);
});

test("pypi metadata URL percent-encodes the project name", () => {
  assert.equal(pypiMetadataUrl("requests", "2.32.3"), "https://pypi.org/pypi/requests/2.32.3/json");
  assert.equal(pypiMetadataUrl("Django", "5.0"), "https://pypi.org/pypi/Django/5.0/json");
});

test("crates download URL is static.crates.io/crates/<name>/<name>-<ver>.crate", () => {
  assert.equal(cratesDownloadUrl("serde", "1.0.219"), "https://static.crates.io/crates/serde/serde-1.0.219.crate");
});

test("rubygems download URL is rubygems.org/downloads/<name>-<ver>.gem", () => {
  assert.equal(rubygemsDownloadUrl("rails", "7.1.1"), "https://rubygems.org/downloads/rails-7.1.1.gem");
});

// ------------------------------------------------------------- crates UA

test("crates.io fetch sends a descriptive User-Agent header (403 otherwise)", async () => {
  const calls: Call[] = [];
  const crate = new TextEncoder().encode("fake-crate-bytes");
  const fetcher = stub(calls, {
    [cratesDownloadUrl("serde", "1.0.219")]: () => response(200, crate),
  });
  const got = await fetchArtifact(spec("crates", "serde", "1.0.219"), { fetcher });
  assert.equal(Buffer.compare(got.bytes, Buffer.from(crate)), 0);
  assert.equal(got.filename, "serde-1.0.219.crate");
  const ua = calls[0]?.init.headers?.["user-agent"];
  assert.ok(ua !== undefined, "crates.io fetch MUST carry a user-agent");
  assert.match(ua, /^border-/, "descriptive border-prefixed UA, never the Node default");
});

// ------------------------------------------------------------- npm flow

test("npm flow: metadata dist.tarball then GET the tarball bytes", async () => {
  const calls: Call[] = [];
  const tgz = new TextEncoder().encode("fake-tgz-bytes");
  const fetcher = stub(calls, {
    "https://registry.npmjs.org/@sugar%2Fpina-pina/1.0.0": () =>
      jsonResponse(200, { name: "@sugar/pina-pina", version: "1.0.0", dist: { tarball: "https://registry.npmjs.org/@sugar/pina-pina/-/pina-pina-1.0.0.tgz" } }),
    "https://registry.npmjs.org/@sugar/pina-pina/-/pina-pina-1.0.0.tgz": () => response(200, tgz),
  });
  const got = await fetchArtifact(spec("npm", "@sugar/pina-pina", "1.0.0"), { fetcher });
  assert.equal(calls.length, 2, "two requests: metadata then tarball");
  assert.equal(got.filename, "pina-pina-1.0.0.tgz");
  assert.equal(Buffer.compare(got.bytes, Buffer.from(tgz)), 0);
});

test("npm metadata 404 is a fail-closed error, never an empty success", async () => {
  const calls: Call[] = [];
  const fetcher = stub(calls, {
    "https://registry.npmjs.org/ghost/9.9.9": () => response(404, new Uint8Array()),
  });
  await assert.rejects(fetchArtifact(spec("npm", "ghost", "9.9.9"), { fetcher }), EngineRunError);
});

test("npm metadata without dist.tarball fails closed with a one-line cause", async () => {
  const calls: Call[] = [];
  const fetcher = stub(calls, {
    "https://registry.npmjs.org/weird/1.0.0": () => jsonResponse(200, { name: "weird", version: "1.0.0" }),
  });
  await assert.rejects(fetchArtifact(spec("npm", "weird", "1.0.0"), { fetcher }), /dist\.tarball/);
});

// ------------------------------------------------------------- pypi sdist-only

test("pypi flow selects the sdist .tar.gz even when wheels are also listed", async () => {
  const calls: Call[] = [];
  const sdist = new TextEncoder().encode("fake-sdist-bytes");
  const fetcher = stub(calls, {
    "https://pypi.org/pypi/requests/2.32.3/json": () =>
      jsonResponse(200, {
        urls: [
          { packagetype: "bdist_wheel", filename: "requests-2.32.3-py3-none-any.whl", url: "https://files.pythonhosted.org/x/requests-2.32.3-py3-none-any.whl" },
          { packagetype: "sdist", filename: "requests-2.32.3.tar.gz", url: "https://files.pythonhosted.org/x/requests-2.32.3.tar.gz" },
        ],
      }),
    "https://files.pythonhosted.org/x/requests-2.32.3.tar.gz": () => response(200, sdist),
  });
  const got = await fetchArtifact(spec("pypi", "requests", "2.32.3"), { fetcher });
  assert.equal(got.filename, "requests-2.32.3.tar.gz");
  assert.equal(calls.length, 2);
});

test("pypi with only wheels (no sdist) exits 2 naming the missing sdist", async () => {
  const calls: Call[] = [];
  const fetcher = stub(calls, {
    "https://pypi.org/pypi/wheelonly/1.0.0/json": () =>
      jsonResponse(200, {
        urls: [{ packagetype: "bdist_wheel", filename: "wheelonly-1.0.0-py3-none-any.whl", url: "https://files.pythonhosted.org/w.whl" }],
      }),
  });
  await assert.rejects(
    fetchArtifact(spec("pypi", "wheelonly", "1.0.0"), { fetcher }),
    (err: unknown) => {
      assert.ok(err instanceof EngineRunError, "fail-closed typed error ⇒ CLI exit 2");
      assert.match((err as Error).message, /sdist/);
      return true;
    },
  );
});

test("pypi zip-only sdist is rejected (the plan pins .tar.gz sdists)", async () => {
  const calls: Call[] = [];
  const fetcher = stub(calls, {
    "https://pypi.org/pypi/zipsdist/1.0.0/json": () =>
      jsonResponse(200, { urls: [{ packagetype: "sdist", filename: "zipsdist-1.0.0.zip", url: "https://files.pythonhosted.org/z.zip" }] }),
  });
  await assert.rejects(fetchArtifact(spec("pypi", "zipsdist", "1.0.0"), { fetcher }), /sdist/);
});

// ------------------------------------------------------------- rubygems

test("rubygems flow downloads <name>-<ver>.gem with a UA and returns the bytes", async () => {
  const calls: Call[] = [];
  const gem = new TextEncoder().encode("fake-gem-bytes");
  const fetcher = stub(calls, {
    [rubygemsDownloadUrl("rails", "7.1.1")]: () => response(200, gem),
  });
  const got = await fetchArtifact(spec("rubygems", "rails", "7.1.1"), { fetcher });
  assert.equal(got.filename, "rails-7.1.1.gem");
  assert.ok(calls[0]?.init.headers?.["user-agent"] !== undefined);
});

// ------------------------------------------------------------- size cap

test("SCAN_MAX_ARTIFACT_BYTES is 200 MiB", () => {
  assert.equal(SCAN_MAX_ARTIFACT_BYTES, 200 * 1024 * 1024);
});

test("content-length above the cap is refused BEFORE the body is consumed", async () => {
  let consumed = false;
  const res: ScanResponse = {
    status: 200,
    contentLength: SCAN_MAX_ARTIFACT_BYTES + 1,
    async *chunks() {
      consumed = true;
      yield new Uint8Array(1);
    },
  };
  await assert.rejects(readCapped(res, "https://x.test/big.tgz"), (err: unknown) => {
    assert.ok(err instanceof EngineRunError);
    assert.match((err as Error).message, /200 MiB|size cap|too large/);
    return true;
  });
  assert.equal(consumed, false, "the streamed body must never be read when content-length already busts the cap");
});

test("a body streaming past the cap aborts mid-stream (no lying content-length)", async () => {
  const chunk = new Uint8Array(64 * 1024);
  const res: ScanResponse = {
    status: 200,
    contentLength: null,
    async *chunks() {
      for (let i = 0; i < 4 * 1024 + 2; i++) yield chunk; // 256 MiB + 128 KiB
    },
  };
  await assert.rejects(readCapped(res, "https://x.test/sneaky.tgz"), EngineRunError);
});

test("readCapped returns exactly the streamed bytes when under the cap", async () => {
  const a = new TextEncoder().encode("alpha-");
  const b = new TextEncoder().encode("beta");
  const res: ScanResponse = {
    status: 200,
    contentLength: a.byteLength + b.byteLength,
    async *chunks() {
      yield a;
      yield b;
    },
  };
  const got = await readCapped(res, "https://x.test/small.tgz");
  assert.equal(got.toString("utf8"), "alpha-beta");
});

// ------------------------------------------------------------- seam hygiene

test("every request carries an AbortSignal (the 60s per-request timeout seam)", async () => {
  const calls: Call[] = [];
  const fetcher = stub(calls, {
    [cratesDownloadUrl("x", "1.0.0")]: () => response(200, new Uint8Array()),
  });
  await fetchArtifact(spec("crates", "x", "1.0.0"), { fetcher });
  assert.ok(calls[0]?.init.signal instanceof AbortSignal, "fetch must be timeout-guarded");
});

test("unknown ecosystems are a programming/input error, rejected before any fetch", async () => {
  const calls: Call[] = [];
  const fetcher: ScanFetcher = async (url, init) => {
    calls.push({ url, init });
    return response(200, new Uint8Array());
  };
  await assert.rejects(
    fetchArtifact({ ecosystem: "docker" as ScanSpec["ecosystem"], name: "x", version: "1.0.0" }, { fetcher }),
    UnknownArgError,
  );
  assert.equal(calls.length, 0);
});
