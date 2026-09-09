// provenance: original clean-room implementation per .omo/plans/border-push-channels.md todo C2
//
// Channel registry — the single inventory of publish channels. Order is a
// plain number field ON each descriptor (git 0 → npm 1 → pypi 2); every
// iteration site (check pipeline stages, registry probe dispatcher, push
// dry-run / --yes loops, pushstate legs) sorts by it, so the pre-C2
// git-before-npm-before-pypi ordering cannot drift. Shared REGISTRY-domain
// truths (rule ids, retry/timeout policy, owner-verdict helpers) live here
// because they belong to no single platform; the per-platform probe bodies
// live in the descriptor modules and consume them.
import type { BorderConfig } from "../config.ts";
import type { Finding, Severity } from "../findings.ts";
import { redact } from "../redact.ts";
import { gitChannel } from "./git.ts";
import { npmChannel } from "./npm.ts";
import { pypiChannel } from "./pypi.ts";
import { cratesChannel } from "./crates.ts";
import { rubygemsChannel } from "./rubygems.ts";
import type { ChannelDescriptor, PublishChannel } from "./types.ts";
import type { PublishCoords } from "./types.ts";

// ---------------------------------------------------------------- descriptor re-exports
export { gitChannel } from "./git.ts";
export { npmChannel } from "./npm.ts";
export { pypiChannel } from "./pypi.ts";
export { cratesChannel } from "./crates.ts";
export { rubygemsChannel } from "./rubygems.ts";

export const REGISTRY_ENGINE = "registry";
export const VERSION_EXISTS_RULE = "version-exists";
export const FOREIGN_OWNER_RULE = "name-foreign-owner";
export const NAME_AVAILABLE_RULE = "name-available";
/** plan L189 + AC: exact message string, pinned. */
export const BUMP_VERSION_MESSAGE = "bump version required";

/** registry probe per-attempt bound; the plan forbids retries, this is the only wait. */
export const REGISTRY_TIMEOUT_MS = 15_000;

/** Registered channels, in flattened order (git → npm → pypi → crates → rubygems). */
export const channels = [gitChannel, npmChannel, pypiChannel, cratesChannel, rubygemsChannel] as const satisfies readonly ChannelDescriptor[];

export type ChannelId = (typeof channels)[number]["id"];
/** Publish-capable channel ids (npm | pypi; derived — no literal union). */
export type PublishChannelId = Extract<(typeof channels)[number], { readonly confirmedVia: unknown }>["id"];

export function isPublishChannel(c: ChannelDescriptor): c is PublishChannel {
  return "confirmedVia" in c;
}

/** Publish channels in their execution order (descriptor .order ascending). */
export function publishChannels(): readonly PublishChannel[] {
  return channels.filter(isPublishChannel).sort((a, b) => a.order - b.order);
}

/** All registered channels (git + publish), in execution order. */
export function allChannels(): readonly ChannelDescriptor[] {
  return [...channels].sort((a, b) => a.order - b.order);
}

/** Registry-derived --targets valid set (all registered channels). */
export function targetIds(): readonly string[] {
  return allChannels().map((c) => c.id);
}

/** PublishTarget alias — the pre-C2 narrow push-target type, now derived. */
export type PublishTarget = PublishChannelId;

/** Registry finding helper: native rules carry no path/line/commit. */
export function regFinding(target: string, rule: string, severity: Severity, message: string, value: string): Finding {
  const r = redact(value);
  return { rule, severity, target, engine: REGISTRY_ENGINE, message, valueDigest: r.valueDigest, snippet: r.snippet };
}

export function normalizeGitLocation(url: string): string {
  return url
    .trim()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//i, "") // https:// git+https:// git+ssh:// ssh:// git://
    .replace(/^ssh:\/\//i, "")
    .replace(/^[^@/]+@([^:]+):/i, "$1/") // git@host:group/ → host/group/
    .replace(/^([^/]+):/u, "$1/") // host:path (no user) → host/path
    .replace(/\.git$/i, "")
    .replace(/\/+$/i, "")
    .toLowerCase();
}

type OwnerSignals = {
  readonly emails: readonly string[];
  readonly urls: readonly string[];
};

function collectStrings(v: unknown, out: string[]): void {
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) for (const e of v) collectStrings(e, out);
  else if (typeof v === "object" && v !== null) for (const e of Object.values(v)) collectStrings(e, out);
}

/** Emails + repo URLs embedded anywhere in an owner-query body. */
export function extractOwnerSignals(body: unknown): OwnerSignals {
  const strings: string[] = [];
  collectStrings(body, strings);
  const emails = new Set<string>();
  const urls = new Set<string>();
  for (const s of strings) {
    for (const m of s.matchAll(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g)) emails.add(m[0].toLowerCase());
    for (const m of s.matchAll(/\b(?:https?|git\+https?|ssh|git):\/\/\S+/gi)) urls.add(normalizeGitLocation(m[0]));
    const scp = /^[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})[:/]\S+$/u.exec(s);
    if (scp?.[1] !== undefined) urls.add(normalizeGitLocation(s));
  }
  return { emails: [...emails], urls: [...urls] };
}

export function ownerVerdict(
  target: PublishChannelId,
  coords: PublishCoords,
  signals: OwnerSignals,
  cfg: BorderConfig,
): Finding | null {
  const wantEmails = new Set(cfg.rules.authors.emails.map((e) => e.toLowerCase()));
  const wantUrls = new Set(cfg.targets.git.remotes.map((r) => normalizeGitLocation(r.url)));
  if (signals.emails.some((e) => wantEmails.has(e)) || signals.urls.some((u) => wantUrls.has(u))) return null; // ours — silent
  if (signals.emails.length === 0 && signals.urls.length === 0) {
    // Claimed (name query answered) but nothing to compare against: documented
    // heuristic boundary — FAIL loud, never silently treat as ours or foreign.
    return regFinding(
      target,
      FOREIGN_OWNER_RULE,
      "CRITICAL",
      `name '${coords.name}' is registered but exposes no comparable owner signal (ambiguous provenance) — resolve ownership manually before publishing, refusing to guess`,
      `${coords.name}:ambiguous`,
    );
  }
  return regFinding(
    target,
    FOREIGN_OWNER_RULE,
    "CRITICAL",
    `name '${coords.name}' is already registered to a foreign owner (maintainer/repo mismatch) — publishing would target someone else's package`,
    `${coords.name}:foreign`,
  );
}