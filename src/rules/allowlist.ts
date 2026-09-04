// provenance: extracted from src/rules/identity.ts (todo 9) so the identity
// scanner stays under the module-size ceiling; this is the project's single
// `*`/`?` glob and the identity allowlist decision, consumed by the identity
// rule and (matchGlob) by the check-allow matcher.
import type { BorderConfig } from "../config.ts";

/**
 * allowBots covers the GitHub noreply-bot email shape, which includes
 * dependabot (`49699333+dependabot[bot]@users.noreply.github.com`) and
 * github-actions bots — `[` and `]` are glob LITERALS in matchGlob, so this
 * one pattern is the whole hardcoded allowance (plan todo 9).
 */
const BOT_EMAIL_PATTERN = "*[bot]@users.noreply.github.com";

export type AuthorsConfig = BorderConfig["rules"]["authors"];

function segmentMatchesAt(segment: string, value: string, pos: number): boolean {
  let vi = pos;
  for (const ch of segment) {
    if (vi >= value.length) return false;
    if (ch !== "?" && value[vi] !== ch) return false;
    vi += 1;
  }
  return true;
}

/**
 * Hand-rolled `*`/`?` glob (no new deps; plan: "minimatch-equivalent").
 * Anchored at BOTH ends; `*` spans any run, `?` exactly one character; every
 * other char (incl. `[`) is a literal. Split-on-`*` segments are matched
 * greedily-leftmost: between `*` gaps an earlier occurrence of a segment can
 * only ever leave MORE room for the remaining segments (the preceding `*`
 * absorbs the displaced span), so leftmost scanning is decision-complete —
 * no backtracking, O(n·m) worst case.
 *
 * Case: the matcher is deliberately CASE-SENSITIVE. Case-normalisation is
 * the caller's policy (see identityAllowed): emails compare lowercased,
 * names compare as written.
 */
export function matchGlob(pattern: string, value: string): boolean {
  const segments = pattern.split("*");
  const first = segments[0] ?? "";
  if (segments.length === 1) return segmentMatchesAt(first, value, 0) && value.length === first.length;
  const last = segments[segments.length - 1] ?? "";
  if (!segmentMatchesAt(first, value, 0)) return false;
  let pos = [...first].length;
  for (let i = 1; i < segments.length - 1; i += 1) {
    const seg = segments[i] ?? "";
    if (seg === "") continue;
    let found = -1;
    for (let p = pos; p <= value.length; p += 1) {
      if (segmentMatchesAt(seg, value, p)) {
        found = p;
        break;
      }
    }
    if (found < 0) return false;
    pos = found + [...seg].length;
  }
  const suffixStart = value.length - [...last].length;
  if (suffixStart < pos) return false;
  return segmentMatchesAt(last, value, suffixStart);
}

/**
 * An identity is allowed iff its email matches some emails[] glob
 * (case-insensitive — RFC 5321 treats the local part as case-dependent but
 * every real provider folds case, and the plan's threat is exposure, not
 * impersonation) AND its name matches some names[] glob CASE-SENSITIVELY
 * (display names are free text; exact/glob match is the operator's contract).
 * allowBots replaces both checks with the hardcoded noreply-bot email shape
 * only when explicitly true.
 */
export function identityAllowed(name: string, email: string, authors: AuthorsConfig): boolean {
  const lowerEmail = email.toLowerCase();
  if (authors.allowBots === true && matchGlob(BOT_EMAIL_PATTERN, lowerEmail)) {
    return true;
  }
  const emailOk = authors.emails.some((p) => matchGlob(p.toLowerCase(), lowerEmail));
  if (!emailOk) return false;
  return authors.names.some((p) => matchGlob(p, name));
}
