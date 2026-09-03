// provenance: original clean-room scaffold, no external code copied
//
// G23 masking invariant: raw secret bytes NEVER leave memory. Every engine
// adapter MUST route every matched value through redact() at ingest time —
// the only things that may be persisted or printed are the sha256 digest
// and the redacted snippet. TextSanitizer additionally keeps raw values in
// memory for the process lifetime ONLY, so that free text can be scrubbed
// before any output; registered raw values are never persisted anywhere.
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const FULL_MASK = "\u25ae\u25ae\u25ae\u25ae";
const ELLIPSIS = "\u2026";

/**
 * Length metric: CODE POINTS ([...value].length), not UTF-16 code units and
 * not bytes. The rule "≤12 chars fully masked" is about how much of a secret
 * a human could read or retype from the snippet: a 7-code-point CJK secret
 * is 21 UTF-8 bytes but must still be fully masked, and first4/last4 are
 * likewise code-point based so a long CJK secret never leaks half a
 * surrogate pair.
 */
export function redact(value: string): { valueDigest: string; snippet: string } {
  const valueDigest = createHash("sha256").update(value, "utf8").digest("hex");
  const points = [...value];
  const snippet = points.length <= 12 ? FULL_MASK : `${points.slice(0, 4).join("")}${ELLIPSIS}${points.slice(-4).join("")}`;
  return { valueDigest, snippet };
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const REDACTED_PREFIX = "[REDACTED:";
const REDACTED_SUFFIX = "]";
const MAX_SCRUB_PASSES = 16;

/**
 * Registry of matched values (digest → raw value) so free text can be
 * scrubbed before any output. Adapters register every value they ingest via
 * redact(); sanitize() then replaces every occurrence of each registered raw
 * value with '[REDACTED:<first 8 hex of its sha256>]' (the exact token form
 * todo 18's bundle masking contract uses).
 *
 * Raw values live in memory only for the process lifetime; nothing here
 * persists them. Registration is last-write-wins per digest.
 */
export class TextSanitizer {
  #registry = new Map<string, string>();

  register(valueDigest: string, rawValue: string): void {
    this.#registry.set(valueDigest, rawValue);
  }

  /**
   * Scrub every occurrence of every registered value out of `text`.
   *
   * Runs to a fixpoint (bounded): a registered value may itself look like a
   * token ('[REDACTED:abc12345]' — a double-mask attempt) and a token
   * produced for one registered value could textually equal a different
   * registered value, so one regex pass is not guaranteed idempotent. Each
   * pass strictly reduces the set of unrscrubbed occurrences (replacements
   * are tokens, not registered values, unless the registered value IS its
   * own token, in which case replacement is a no-op), so the loop converges;
   * MAX_SCRUB_PASSES is a hard cap against adversarial registration cycles.
   * Output is a fixpoint: sanitize(sanitize(x)) === sanitize(x).
   */
  sanitize(text: string): string {
    let current = text;
    for (let pass = 0; pass < MAX_SCRUB_PASSES; pass += 1) {
      const next = this.#scrubOnce(current);
      if (next === current) return current;
      current = next;
    }
    return current;
  }

  #scrubOnce(text: string): string {
    if (this.#registry.size === 0) return text;
    const byValue = new Map<string, string>();
    for (const [digest, raw] of this.#registry) {
      byValue.set(raw, digest);
    }
    const values = [...byValue.keys()].sort((a, b) => b.length - a.length);
    const pattern = new RegExp(values.map(escapeRegExp).join("|"), "g");
    return text.replace(pattern, (matched) => {
      const digest = byValue.get(matched);
      if (digest === undefined) return matched;
      return `${REDACTED_PREFIX}${digest.slice(0, 8)}${REDACTED_SUFFIX}`;
    });
  }
}

// Fail-closed decision: input that is neither a git scp-style remote nor a
// parseable absolute URL is replaced wholesale with this placeholder — the
// unparseable text is never echoed, because it may itself carry a secret
// (e.g. a bare `user:pass@host` line that is not a well-formed URL).
// Parse failure is the ONLY path that yields the placeholder literal.
const INVALID_URL_PLACEHOLDER = "[invalid-url-redacted]";
const SENSITIVE_PARAM_RE = /token|auth|key|secret|password|passwd/i;

// scp-style git remotes (`git@github.com:owner/repo.git`) are the most
// common remote form yet WHATWG URL cannot parse them. The host group
// excludes ':' '/' '@' and whitespace, so scheme-form URLs (`ssh://…`,
// `https://…` — userinfo after `//`) never match this shape.
const SCP_STYLE_RE = /^[A-Za-z0-9_.+-]+@([^:@/\s]+)[:/](.+)$/;

/**
 * Strip everything credential-shaped from a URL before it is persisted or
 * echoed: userinfo (`user:pass@`) and query params whose NAME matches
 * /token|auth|key|secret|password|passwd/i (covers `?token=`,
 * `?access_token=`, `?auth=`, `?key=`, `?api_key=`). Parameter VALUES are
 * removed with their names; fragment and non-matching params are kept.
 * WHATWG-parsable output is serialized (stable, deterministic; a host-only
 * URL gains a trailing '/').
 *
 * git scp-form remotes (`git@github.com:owner/repo.git`) are handled
 * explicitly: userinfo is dropped and the result is `<host>/<path>` with no
 * scheme (WHATWG URL cannot parse this form). Anything after a '?' in the
 * path is conservatively dropped. Distinct scp remotes always yield
 * distinct outputs, which exposureSet relies on to invalidate the
 * skip-ledger fingerprint when a remote is added.
 */
export function sanitizeUrl(urlText: string): string {
  const scp = SCP_STYLE_RE.exec(urlText);
  const scpHost = scp?.[1];
  const scpPath = scp?.[2];
  if (scpHost !== undefined && scpPath !== undefined) {
    const q = scpPath.indexOf("?");
    return `${scpHost}/${q === -1 ? scpPath : scpPath.slice(0, q)}`;
  }
  let url: URL;
  try {
    url = new URL(urlText);
  } catch {
    return INVALID_URL_PLACEHOLDER;
  }
  url.username = "";
  url.password = "";
  const kept: Array<[string, string]> = [];
  for (const [name, value] of url.searchParams) {
    if (!SENSITIVE_PARAM_RE.test(name)) kept.push([name, value]);
  }
  url.search = "";
  for (const [name, value] of kept) {
    url.searchParams.append(name, value);
  }
  return url.toString();
}

export class MissingRulesInputError extends Error {
  readonly inputPath: string;

  constructor(inputPath: string) {
    super(`missing rules input file: ${inputPath}`);
    this.name = "MissingRulesInputError";
    this.inputPath = inputPath;
  }
}

export type RulesHashInput = {
  bundledRulePaths: readonly string[];
  configDigest: string;
  engineVersions: Readonly<Record<string, string>>;
  promptTemplatePaths: readonly string[];
};

async function digestFile(filePath: string): Promise<string> {
  const bytes = await readFile(filePath);
  return createHash("sha256").update(bytes).digest("hex");
}

/**
 * G21: fingerprint every input that changes the gate's effective rules.
 * Lines are `kind:path:digest` for rule/prompt files (digest = sha256 of
 * file bytes; paths normalized via resolve so './x' and 'x' collide) plus
 * `config:<configDigest>` and `engine:<name>:<version>`, ALL sorted
 * lexicographically, then sha256 of the joined lines. Deterministic across
 * runs and machines; missing file ⇒ typed MissingRulesInputError (fail
 * closed — a gate that cannot fingerprint its rules proves nothing).
 */
export async function computeRulesHash(input: RulesHashInput): Promise<string> {
  const lines: string[] = [`config:${input.configDigest}`];
  const byKind: ReadonlyArray<{ kind: string; paths: readonly string[] }> = [
    { kind: "rule", paths: input.bundledRulePaths },
    { kind: "prompt", paths: input.promptTemplatePaths },
  ];
  for (const { kind, paths } of byKind) {
    for (const p of paths) {
      const filePath = resolve(p);
      let digest: string;
      try {
        digest = await digestFile(filePath);
      } catch (err) {
        if (typeof err === "object" && err !== null && (err as { code?: unknown }).code === "ENOENT") {
          throw new MissingRulesInputError(filePath);
        }
        throw err;
      }
      lines.push(`${kind}:${filePath}:${digest}`);
    }
  }
  const engineNames = Object.keys(input.engineVersions).sort();
  for (const name of engineNames) {
    lines.push(`engine:${name}:${input.engineVersions[name]}`);
  }
  lines.sort();
  return createHash("sha256").update(lines.join("\n"), "utf8").digest("hex");
}