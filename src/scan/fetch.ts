// provenance: border-inspect-roadmap.md W1.1 — `border scan` fetch layer.
//
// single-source: test/releaseCoherence.test.ts locks this to package.json — bump both
// (the SCAN_USER_AGENT version literal below; ecc7e23 shipped 0.3.1 with a 0.3.0 UA).
// Public-registry artifact fetch with the PypiFetcher doctrine: the whole
// network surface rides through ONE injectable ScanFetcher seam (unit tests
// script it offline; production uses global fetch — zero new dependencies).
// Fail-closed everywhere: non-200, malformed metadata, missing sdist/tarball,
// a body over the size cap or a stalled request are typed errors that the CLI
// translates to exit 2 — NEVER a silently empty artifact that would scan
// "clean". crates.io 403s the default Node UA, so every request carries a
// descriptive one (src/channels/types.ts:45-52 lesson).
import { createHash } from "node:crypto";
import { basename } from "node:path";

import { EngineRunError } from "../engines/support.ts";
import { UnknownArgError } from "../cli/exit.ts";
import { publishChannels } from "../channels/registry.ts";
import type { ScanEcosystem, ScanSpec } from "./spec.ts";

/** Hard artifact ceiling — streamed enforcement, guards against gzip bombs. */
export const SCAN_MAX_ARTIFACT_BYTES = 200 * 1024 * 1024;
/** Per-request bound; the plan forbids retries, this is the only wait. */
export const SCAN_REQUEST_TIMEOUT_MS = 60_000;
/** Descriptive UA: crates.io rejects the Node default with 403; everyone tolerates this one. */
export const SCAN_USER_AGENT = "border-customs/0.4.1 (+https://github.com/sumteclab/border; border scan)";

const CRATES_DOWNLOAD_HOST = "https://static.crates.io";

export type ScanFetchInit = {
  readonly signal: AbortSignal;
  readonly headers?: Record<string, string>;
};

export type ScanResponse = {
  readonly status: number;
  /** Parsed `content-length`, null when the server omitted or lied-unparseably. */
  readonly contentLength: number | null;
  chunks(): AsyncIterable<Uint8Array>;
};

export type ScanFetcher = (url: string, init: ScanFetchInit) => Promise<ScanResponse>;

export const defaultScanFetcher: ScanFetcher = async (url, init) => {
  if (!/^https?:\/\//.test(url)) throw new EngineRunError(`border scan refuses non-http(s) URL: ${url}`, null);
  const res = await fetch(url, {
    redirect: "follow",
    signal: init.signal,
    headers: { "user-agent": SCAN_USER_AGENT, ...(init.headers ?? {}) },
  });
  const raw = res.headers.get("content-length");
  const parsed = raw === null ? Number.NaN : Number(raw);
  return {
    status: res.status,
    contentLength: Number.isFinite(parsed) && parsed >= 0 ? parsed : null,
    chunks: () => {
      if (res.body === null) {
        return {
          async *[Symbol.asyncIterator]() {
            /* empty body */
          },
        };
      }
      return res.body as unknown as AsyncIterable<Uint8Array>;
    },
  };
};

const fail: (why: string) => never = (why) => {
  throw new EngineRunError(`border scan could not fetch the artifact (${why}) — refusing to scan a partial or absent download (fail-closed)`, null);
};

/** Accumulate a capped body; refuses up-front on content-length, mid-stream otherwise. */
export async function readCapped(res: ScanResponse, url: string, cap: number = SCAN_MAX_ARTIFACT_BYTES): Promise<Buffer> {
  if (res.status !== 200) fail(`HTTP ${String(res.status)} for ${url}`);
  if (res.contentLength !== null && res.contentLength > cap) {
    fail(`${url} announces ${String(res.contentLength)} bytes, over the 200 MiB scan size cap`);
  }
  const parts: Buffer[] = [];
  let total = 0;
  for await (const chunk of res.chunks()) {
    total += chunk.byteLength;
    if (total > cap) fail(`${url} streams past the 200 MiB scan size cap after ${String(total)} bytes`);
    parts.push(Buffer.from(chunk));
  }
  return Buffer.concat(parts);
}

async function fetchBytes(fetcher: ScanFetcher, url: string, timeoutMs: number, headers?: Record<string, string>): Promise<Buffer> {
  const res = await fetcher(url, { signal: AbortSignal.timeout(timeoutMs), ...(headers !== undefined ? { headers } : {}) });
  return readCapped(res, url);
}

async function fetchJson(fetcher: ScanFetcher, url: string, timeoutMs: number): Promise<unknown> {
  const body = await fetchBytes(fetcher, url, timeoutMs);
  try {
    return JSON.parse(body.toString("utf8")) as unknown;
  } catch {
    fail(`metadata response from ${url} is not valid JSON`);
  }
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null;

// ---------------------------------------------------------------- URL builders
// Base URLs come from the channel registry descriptors (single source of
// truth). Only the registry module is imported — reaching a channel module
// directly would invert the channels/npm.ts <-> registry.ts evaluation order
// and TDZ-crash `npmChannel` at load time.
function channelBaseUrl(eco: "npm" | "pypi" | "rubygems"): string {
  const ch = publishChannels().find((c) => c.id === eco);
  if (ch === undefined || ch.defaultUrl.length === 0) {
    throw new EngineRunError(`border scan: channel '${eco}' exposes no defaultUrl`, null);
  }
  return ch.defaultUrl;
}

export function npmMetadataUrl(name: string, version: string, base: string = channelBaseUrl("npm")): string {
  // npm's own convention: keep '@scope/' literal, percent-encode ONLY the slash.
  const enc = name.startsWith("@") ? name.replace("/", "%2F") : name;
  return `${base}/${enc}/${version}`;
}

export function pypiMetadataUrl(name: string, version: string, base: string = channelBaseUrl("pypi")): string {
  return `${base}/pypi/${encodeURIComponent(name)}/${version}/json`;
}

export function cratesDownloadUrl(name: string, version: string): string {
  return `${CRATES_DOWNLOAD_HOST}/crates/${name}/${name}-${version}.crate`;
}

export function rubygemsDownloadUrl(name: string, version: string, base: string = channelBaseUrl("rubygems")): string {
  return `${base}/downloads/${name}-${version}.gem`;
}

// ---------------------------------------------------------------- per-ecosystem fetch

export type FetchedArtifact = {
  readonly bytes: Buffer;
  readonly filename: string;
};

/** Basename-only, charset-whitelisted archive name — a hostile registry URL can never escape the sandbox. */
export function safeArtifactName(raw: string, fallback: string): string {
  const base = basename(raw.split("?")[0] ?? "").replace(/[^A-Za-z0-9._+-]/g, "_");
  return base.length > 0 && base !== "." && base !== ".." ? base : fallback;
}

export type FetchArtifactOptions = {
  readonly fetcher: ScanFetcher;
  readonly timeoutMs?: number;
};

export async function fetchArtifact(spec: ScanSpec, o: FetchArtifactOptions): Promise<FetchedArtifact> {
  const timeoutMs = o.timeoutMs ?? SCAN_REQUEST_TIMEOUT_MS;
  const label = `${spec.ecosystem}:${spec.name}@${spec.version}`;
  switch (spec.ecosystem) {
    case "npm": {
      const meta = await fetchJson(o.fetcher, npmMetadataUrl(spec.name, spec.version), timeoutMs);
      const dist = isRecord(meta) && isRecord(meta["dist"]) ? (meta["dist"] as Record<string, unknown>) : {};
      const tarball = dist["tarball"];
      if (typeof tarball !== "string" || tarball.length === 0) fail(`npm metadata for ${label} has no dist.tarball`);
      if (!/^https?:\/\//.test(tarball)) fail(`npm dist.tarball for ${label} is not an http(s) URL`);
      const bytes = await fetchBytes(o.fetcher, tarball, timeoutMs);
      const filename = safeArtifactName(tarball, `${spec.name.replace("@", "").replace("/", "-")}-${spec.version}.tgz`);
      if (!filename.endsWith(".tgz") && !filename.endsWith(".tar.gz")) fail(`npm tarball ${filename} is not a .tgz/.tar.gz`);
      return { bytes, filename };
    }
    case "pypi": {
      const meta = await fetchJson(o.fetcher, pypiMetadataUrl(spec.name, spec.version), timeoutMs);
      const urls = isRecord(meta) && Array.isArray(meta["urls"]) ? (meta["urls"] as unknown[]) : [];
      const files = urls.filter(isRecord);
      const sdists = files.filter((f) => f["packagetype"] === "sdist");
      const sdist = sdists.find((f) => typeof f["filename"] === "string" && (f["filename"] as string).endsWith(".tar.gz"));
      if (sdist === undefined) {
        fail(`no .tar.gz sdist published for ${label} — wheels are pre-built artifacts and out of scan scope (setup code lives in the sdist)`);
      }
      const url = sdist["url"];
      const name = sdist["filename"];
      if (typeof url !== "string" || typeof name !== "string") fail(`PyPI sdist entry for ${label} is malformed`);
      const bytes = await fetchBytes(o.fetcher, url, timeoutMs);
      return { bytes, filename: safeArtifactName(url, name) };
    }
    case "crates": {
      const url = cratesDownloadUrl(spec.name, spec.version);
      const bytes = await fetchBytes(o.fetcher, url, timeoutMs, { "user-agent": SCAN_USER_AGENT });
      return { bytes, filename: `${spec.name}-${spec.version}.crate` };
    }
    case "rubygems": {
      const url = rubygemsDownloadUrl(spec.name, spec.version);
      const bytes = await fetchBytes(o.fetcher, url, timeoutMs, { "user-agent": SCAN_USER_AGENT });
      return { bytes, filename: `${spec.name}-${spec.version}.gem` };
    }
    default: {
      const eco: ScanEcosystem = spec.ecosystem;
      throw new UnknownArgError(`unknown ecosystem '${String(eco)}' — border scan cannot fetch it`);
    }
  }
}

/** sha256 hex — scan report fingerprints reuse the digest doctrine (G23). */
export function sha256Hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}
