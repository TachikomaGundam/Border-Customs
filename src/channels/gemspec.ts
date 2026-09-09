// provenance: original clean-room implementation per .omo/plans/border-push-channels.md todo C4
//
// Gemspec coordinate leaf — the literal-only .gemspec doctrine shared by the
// rubygems channel descriptor (HEAD reads via `git show HEAD:<path>`) and the
// artifact stage (working-tree reads): name/version may ONLY come from a
// literal `s.name = "..."` / `s.version = "..."` assignment. A non-literal
// value (require_relative 'lib/x/version', Gem::Version.new(...), computed
// names) is a typed exit-2 ConfigError, never a guess and NEVER eval'd (the
// plan forbids `ruby -e` execution of untrusted gemspec code outside the
// build itself). s.date assignments are REJECTED wholesale (contract §(e)
// measured: an explicit s.date makes builds non-deterministic, so a certified
// digest would legitimately change between stage and freshness repack — the
// fixed default `1980-01-02 00:00:00 UTC` is the only reproducible date).
// This module imports NOTHING repo-internal but ./errors.ts — it is cycle-safe
// for both import directions (channel descriptor ↔ artifact stage).
import { ConfigError } from "./errors.ts";

/** Literal-only `s.name = "..."` (single or double quotes). */
export const GEMSPEC_NAME = /s\.name\s*=\s*["']([^"']+)["']/;
/** Literal-only `s.version = "..."` (single or double quotes). */
export const GEMSPEC_VERSION = /s\.version\s*=\s*["']([^"']+)["']/;
/** Any `s.date =` / `spec.date =` assignment ⇒ non-reproducible build (spike §e). */
export const GEMSPEC_DATE = /s\.date\s*=\s*|spec\.date\s*=/;

export type GemGemspecCandidate = {
  /** repo-relative gemspec path (relative to the repo root). */
  readonly path: string;
  /** gemspec file bytes (HEAD or working tree, per the caller's read seam). */
  readonly body: string;
};

/**
 * Pick the gemspec to publish and its literal {name, version}.
 *
 * Precedence & ambiguity (plan C4): with no targets.rubygems.name, EXACTLY
 * one *.gemspec may exist anywhere in the repo — zero or multiple is a typed
 * exit-2 ConfigError ("ambiguous gemspec — set targets.rubygems.name"). With
 * the name set, exactly one candidate must declare a literal s.name equal to
 * it. The chosen gemspec's s.version must be literal. `where` names the read
 * source for error messages ("at HEAD" vs "in the working tree").
 */
export function selectGemspec(
  candidates: readonly GemGemspecCandidate[],
  cfgName: string | undefined,
  key: string,
  where: string,
): { readonly name: string; readonly version: string } {
  const parsed = candidates.map((c) => ({
    path: c.path,
    body: c.body,
    name: GEMSPEC_NAME.exec(c.body)?.[1],
    version: GEMSPEC_VERSION.exec(c.body)?.[1],
    dateAssigned: GEMSPEC_DATE.test(c.body),
  }));

  let chosen: (typeof parsed)[number];
  if (cfgName === undefined) {
    if (parsed.length !== 1) {
      throw new ConfigError(
        "invalid-value",
        `ambiguous gemspec — set targets.rubygems.name (exactly one *.gemspec expected ${where}, found ${String(parsed.length)})`,
        { key },
      );
    }
    chosen = parsed[0] as (typeof parsed)[number];
  } else {
    if (parsed.length === 0) {
      throw new ConfigError("invalid-value", `no *.gemspec found ${where} — publish target configured but nothing to publish`, { key });
    }
    const matches = parsed.filter((p) => p.name === cfgName);
    if (matches.length === 0) {
      throw new ConfigError(
        "invalid-value",
        `no gemspec ${where} declares a literal s.name matching targets.rubygems.name '${cfgName}' — set a literal s.name in the gemspec (or fix targets.rubygems.name)`,
        { key },
      );
    }
    if (matches.length > 1) {
      throw new ConfigError(
        "invalid-value",
        `ambiguous gemspec — set targets.rubygems.name (${String(matches.length)} gemspecs ${where} declare name '${cfgName}'; give the gemspecs distinct literal names)`,
        { key },
      );
    }
    chosen = matches[0] as (typeof parsed)[number];
  }

  if (chosen.dateAssigned) {
    throw new ConfigError(
      "invalid-value",
      `gemspec ${chosen.path} ${where} assigns s.date — gem builds are byte-deterministic only with the fixed default date; remove the assignment (or pin SOURCE_DATE_EPOCH identically for every border run)`,
      { key },
    );
  }
  if (cfgName === undefined && chosen.name === undefined) {
    throw new ConfigError(
      "invalid-value",
      `gemspec ${chosen.path} ${where} has no literal s.name — computed names are not supported; publish by setting a literal s.name`,
      { key },
    );
  }
  if (chosen.version === undefined) {
    throw new ConfigError(
      "invalid-value",
      `gemspec ${chosen.path} ${where} has no literal s.version — computed versions (require_relative 'lib/x/version', Gem::Version.new(...)) are not supported; set targets.rubygems.name and publish by setting a literal s.version`,
      { key },
    );
  }
  return { name: cfgName ?? (chosen.name as string), version: chosen.version as string };
}