// provenance: .omo/plans/border-opencode-inspect.md T1 — the registry seam.
//
// Dist-tag/version resolution through the ScanFetcher shape (src/scan/fetch.ts
// doctrine): unit tests script it offline; production uses global fetch. Any
// non-answer (non-200, malformed JSON, missing version string, over-cap body)
// THROWS — the aspect maps every throw to CANNOT, fail-closed.
import type { ScanFetcher } from "../scan/fetch.ts";

import { DEFAULT_REGISTRY_BASE } from "./contract.ts";

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null;

export const defaultRegistryFetcher: ScanFetcher = async (url, init) => {
  if (!/^https?:\/\//.test(url)) throw new Error(`border opencode inspect refuses non-http(s) URL: ${url}`);
  const res = await fetch(url, {
    redirect: "follow",
    signal: init.signal,
    headers: { "user-agent": "border-customs (+https://github.com/TachikomaGundam/Border-Customs; border opencode inspect)" },
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

export function npmTagUrl(pkg: string, tag: string, base: string = DEFAULT_REGISTRY_BASE): string {
  const enc = pkg.startsWith("@") ? pkg.replace("/", "%2F") : encodeURIComponent(pkg);
  return `${base}/${enc}/${encodeURIComponent(tag)}`;
}

const REGISTRY_BODY_CAP = 8 * 1024 * 1024;

/** Fetch `<base>/<pkg>/<tag>` and read `.version` — throws on any non-answer (fail-closed). */
export async function fetchRegistryVersion(fetcher: ScanFetcher, url: string, timeoutMs: number): Promise<string> {
  const res = await fetcher(url, { signal: AbortSignal.timeout(timeoutMs) });
  if (res.status !== 200) throw new Error(`HTTP ${String(res.status)} from ${url}`);
  const parts: Buffer[] = [];
  let total = 0;
  for await (const chunk of res.chunks()) {
    total += chunk.byteLength;
    if (total > REGISTRY_BODY_CAP) throw new Error(`${url} exceeds the ${String(REGISTRY_BODY_CAP)} B metadata cap`);
    parts.push(Buffer.from(chunk));
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.concat(parts).toString("utf8"));
  } catch {
    throw new Error(`metadata response from ${url} is not valid JSON`);
  }
  if (!isRecord(parsed) || typeof parsed["version"] !== "string" || parsed["version"].length === 0) {
    throw new Error(`metadata response from ${url} carries no "version" string`);
  }
  return parsed["version"];
}
