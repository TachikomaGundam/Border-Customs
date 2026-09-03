// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 8
//
// Path-shape pipeline for the CLOSED G35 artifact lists: normalization, the
// hand-rolled gitignore-flavoured glob compiler, and the matcher tables
// (closed list + border.yaml rules.pathPatterns). User patterns ride the
// EXACT same code path as the built-ins — additions ship via config, never
// as code here. Pure logic: no git, no fs.
import type { Severity } from "../findings.ts";

const AI_SESSION_RULE = "ai-session-artifact";
const ENV_RULE = "env-file-committed";
const JUNK_RULE = "junk-artifact";
const PATTERN_RULE = "path-pattern";

/** Closed G35 lists — the ONLY hardcoded patterns in the product. */
const AI_SESSION_PATTERNS = [".omo/**", "**/transcripts/**", "*.session.jsonl", "opencode.json", "opencode.jsonc", ".opencode/**"];
const JUNK_PATTERNS = ["probe*", "*.rej", "*.orig", "**/node_modules/**"];
const ENV_EXEMPT = new Set([".env.example", ".env.sample"]);

/** Rich pattern entry; the current schema ships bare strings, which default to CRITICAL. */
export type PathPatternEntry = { readonly pattern: string; readonly severity?: Severity; readonly message?: string };

export type PathMatcher = {
  readonly rule: string;
  readonly severity: Severity;
  readonly message: string;
  readonly test: (path: string) => boolean;
};

export function normalizePath(p: string): string {
  const n = p.replaceAll("\\", "/").replace(/^\.\//, "");
  return n.endsWith("/") && n.length > 1 ? n.slice(0, -1) : n;
}

function baseName(p: string): string {
  const i = p.lastIndexOf("/");
  return i === -1 ? p : p.slice(i + 1);
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** gitignore-flavoured glob: `**` crosses directories, `*`/`?` do not. */
export function globToRegExp(glob: string): RegExp {
  const segs = glob.split("/");
  let re = "";
  for (let i = 0; i < segs.length; i += 1) {
    const seg = segs[i] ?? "";
    const last = i === segs.length - 1;
    if (seg === "**") {
      re += last ? ".*" : "(?:[^/]+/)*";
      continue;
    }
    let piece = "";
    for (const ch of seg) {
      if (ch === "*") piece += "[^/]*";
      else if (ch === "?") piece += "[^/]";
      else piece += escapeRe(ch);
    }
    re += piece;
    if (!last) re += "/";
  }
  return new RegExp(`^${re}$`);
}

/** A pattern WITHOUT '/' matches the basename at any depth (gitignore semantics). */
function globMatcher(rule: string, severity: Severity, pattern: string, message: string): PathMatcher {
  const pat = normalizePath(pattern);
  const re = globToRegExp(pat);
  const anchored = pat.includes("/");
  return { rule, severity, message, test: (p) => re.test(anchored ? p : baseName(p)) };
}

export function closedMatchers(): PathMatcher[] {
  const out: PathMatcher[] = AI_SESSION_PATTERNS.map((p) =>
    globMatcher(AI_SESSION_RULE, "CRITICAL", p, `AI-session artifact on the closed list (pattern '${p}'): agent/session state must never ship.`),
  );
  out.push({
    rule: ENV_RULE,
    severity: "CRITICAL",
    message: "Environment file tracked (closed list): .env files routinely carry credentials; commit .env.example/.env.sample templates instead.",
    test: (p) => {
      const b = baseName(p);
      return (b === ".env" || b.startsWith(".env.")) && !ENV_EXEMPT.has(b);
    },
  });
  for (const p of JUNK_PATTERNS) {
    out.push(globMatcher(JUNK_RULE, "MEDIUM", p, `Junk artifact on the closed list (pattern '${p}'): patch/probe leftovers and vendored deps must not be tracked.`));
  }
  return out;
}

export function userMatchers(entries: readonly (string | PathPatternEntry)[]): PathMatcher[] {
  return entries.map((entry) => {
    const e: PathPatternEntry = typeof entry === "string" ? { pattern: entry } : entry;
    const severity: Severity = e.severity ?? "CRITICAL"; // G35: pathPatterns ARE closed-list additions
    const message = e.message ?? `Path matches border.yaml rules.pathPatterns entry '${e.pattern}'.`;
    return globMatcher(PATTERN_RULE, severity, e.pattern, message);
  });
}
