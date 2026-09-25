// provenance: .omo/plans/border-exfil-lens.md T1 — pure predicates for the five
// exfil rules, plan §"规则语义表" (intent level; observed severity is resolved
// through severity.ts, NEVER here).
//
// Purity contract: every predicate is (text, options) → hits. No fs, no git,
// no config-module import — rules.hosts arrives as a parameter (T3's message
// leg and the later CLI pass cfg.rules.hosts in). Line numbers are 1-based.
// Hit.message is generic finding text and NEVER embeds the matched value;
// scan.ts carries the value only as sha256 digest + mask (G23 invariant).
//
// SELF-STEALTH (dogfood lesson from 0.5.1, where the identity regex tripped
// border's own drive-letter rule): this directory writes NO literal 4-octet
// dotted-quad IP strings and no absolute home paths — CIDR bands live as
// NUMBER tuples and IPv4 sources are assembled from octet character classes,
// so border's own detectors (vendored TOML generic-path rule, no-homedir,
// the repo's path-pattern rules) can never pattern-match our rule sources.
import type { ExfilFacet, ExfilRuleId } from "./severity.ts";

export type RuleHit = {
  readonly rule: ExfilRuleId;
  /** the matched raw value — digested/masked by scan.ts, never rendered. */
  readonly matched: string;
  readonly line: number;
  readonly message: string;
};

export type RuleOptions = {
  /** drives the band-exemption split (tree exempts DEFAULT_EXEMPT_BANDS, message fires everything); never selects severity. */
  readonly facet: ExfilFacet;
  /** operator's rules.hosts (config.ts:102) — exact-match ssh targets, closed set. */
  readonly hosts?: readonly string[];
  /** exemption-band override (production default DEFAULT_EXEMPT_BANDS; [] forces in-range arms red in unit tests). */
  readonly exemptBands?: readonly string[];
};

// ---------------------------------------------------------------- IPv4 machinery

const OCTET = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";
/** Full IPv4 with strict token boundaries (won't fire inside 5-dotted versions/urls). */
const IPV4_SRC = `(?<![0-9A-Za-z.\\-])${OCTET}\\.${OCTET}\\.${OCTET}\\.${OCTET}(?![0-9A-Za-z.\\-])`;

/**
 * The production closed exemption bands (F2 twin-parity + F3 fixture doctrine):
 * loopback, each RFC 5737 documentation /24, and the 10.200/16 SYNTHETIC-FIXTURE
 * band. Dotted PREFIX strings (never full quads — self-stealth); a hit is
 * exempt when its leading octets equal a band. ALL channels — native tree
 * policy and both twins — exempt exactly these; the message facet alone stays
 * band-fired (it is native-exclusive and carries the golden red anchors).
 * Unit tests may pass options.exemptBands = [] to force in-range arms red with
 * assembled (never checked-in-as-quad) literals.
 */
export const DEFAULT_EXEMPT_BANDS: readonly string[] = ["127", "192.0.2", "198.51.100", "203.0.113", "10.200"];

function bandOctets(band: string): number[] {
  return band.split(".").map(Number);
}
function inAnyBand(oct: readonly number[], bands: readonly string[]): boolean {
  return bands.some((b) => {
    const parts = bandOctets(b);
    return parts.every((v, i) => oct[i] === v);
  });
}
/** 10/8 ∪ 172.16/12 ∪ 192.168/16 — the plan's exfil-rfc1918 range set (loopback & RFC5737 are OUT of range by construction). */
function inRfc1918(o: readonly number[]): boolean {
  const [a = 0, b = 0] = o;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  return a === 192 && b === 168;
}
function octetsOf(ip: string): number[] {
  return ip.split(".").map(Number);
}
function isIpLiteral(host: string): boolean {
  return /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/.test(host);
}

/** Octet + boundary pieces shared by the JS twins (secretlint) — single source. */
const OCTET_GRP = `(?:${OCTET})`;
// Each branch is FULLY expanded (three or four octets as the prefix demands):
// an alternation branch would otherwise swallow a shared suffix only into its
// LAST arm — the precedence trap this exact line replaces.
const RFC1918_FULL = `10\\.${OCTET_GRP}\\.${OCTET_GRP}\\.${OCTET_GRP}|172\\.(?:1[6-9]|2[0-9]|3[01])\\.${OCTET_GRP}\\.${OCTET_GRP}|192\\.168\\.${OCTET_GRP}\\.${OCTET_GRP}`;
const SUFFIX_HOST = `[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\\.(?:internal|lan|local|corp|intra)`;

/**
 * The secretlint-twin pattern sources for the HIGH family (plan §分面契约 row
 * 1: emission id = pattern name, ids VERBATIM equal to the rule ids). Negative
 * classes at the IP/head position exempt exactly DEFAULT_EXEMPT_BANDS (loopback
 * / RFC5737 / 10.200/16 fixture band) — F2 verdict parity: the same bytes must
 * read the same on every channel at the tree facet; the corpus test
 * (test/exfil.pipeline.test.ts) is the real contract, id-equality alone was a
 * hole. The gitleaks TOML carries Go-RE2 variants (no lookaround) of these
 * same bodies + equivalent per-rule allowlists.
 */
const BAND_NEGATIVE = `(?!127\\.|10\\.200\\.|192\\.0\\.2\\.|198\\.51\\.100\\.|203\\.0\\.113\\.)`;
export const EXFIL_TWIN_PATTERNS: ReadonlyArray<{ readonly name: ExfilRuleId; readonly source: string }> = [
  { name: "exfil-rfc1918", source: `(?<![0-9A-Za-z.\\-])${BAND_NEGATIVE}(?:${RFC1918_FULL})(?![0-9A-Za-z.\\-])` },
  { name: "exfil-ssh-target", source: `(?<![A-Za-z0-9._+%-])[A-Za-z0-9._+%-]+@${BAND_NEGATIVE}(?:${RFC1918_FULL}|${SUFFIX_HOST})(?![A-Za-z0-9._-])` },
];

// ---------------------------------------------------------------- exfil-rfc1918

/**
 * RFC1918 literals. Closed exemptions: DEFAULT_EXEMPT_BANDS (loopback + each
 * RFC5737 /24 are OUT of range by construction; the 10.200/16 fixture band is
 * in-range and exempted on every facet EXCEPT message — commit messages are
 * the public-exposure surface with no fixture excuse, so the band FIRES there
 * ("message 面带合成 IP 树干净 ⇒ 必红" stays mechanically true, and the twins,
 * which never scan messages, match the tree-side policy exactly: F2 parity).
 */
export function matchRfc1918(text: string, o: RuleOptions): RuleHit[] {
  const re = new RegExp(IPV4_SRC, "g");
  const bands = o.exemptBands ?? DEFAULT_EXEMPT_BANDS;
  const hits: RuleHit[] = [];
  text.split("\n").forEach((body, idx) => {
    for (const m of body.matchAll(re)) {
      const ip = m[0] ?? "";
      const oct = octetsOf(ip);
      if (!inRfc1918(oct)) continue;
      if (o.facet !== "message" && inAnyBand(oct, bands)) continue;
      hits.push({ rule: "exfil-rfc1918", matched: ip, line: idx + 1, message: "RFC1918 private-network address literal on a surface about to become public." });
    }
  });
  return hits;
}

// ---------------------------------------------------------------- exfil-ssh-target

/** Closed private-suffix set (plan table): internal hostname shapes, not public domains. */
const PRIVATE_SUFFIXES: readonly string[] = [".internal", ".lan", ".local", ".corp", ".intra"];
/** RFC 2606 reserved TLDs — documentation/exemption shapes, never real targets. */
const RFC2606_SUFFIXES: readonly string[] = [".example", ".test", ".invalid", ".localhost"];
const SSH_TOKEN_RE = /(?<![A-Za-z0-9._+%-])[A-Za-z0-9._+%-]+@([A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)/g;

function hasDotSuffix(host: string, suffixes: readonly string[]): boolean {
  return suffixes.some((s) => host.length > s.length && host.endsWith(s));
}

/**
 * `user@host` where host ∈ {RFC1918 literal, operator's rules.hosts (exact,
 * case-insensitive), closed suffix set {.internal,.lan,.local,.corp,.intra}}.
 * Closed exemption: RFC 2606 (bare public domains like user@example.com are
 * out of the hit set by construction — they match nothing). An explicitly
 * operator-configured host wins over the RFC2606 shape exemption (listing it
 * IS the operator declaring it internal). IP hosts: DEFAULT_EXEMPT_BANDS
 * exempt on the tree facet (twin parity, F2); the message facet still fires
 * `synthuser@` + fixture-band address — the T6 golden red anchor rides :message.
 */
export function matchSshTarget(text: string, o: RuleOptions): RuleHit[] {
  const hosts = (o.hosts ?? []).map((h) => h.trim().toLowerCase()).filter((h) => h !== "");
  const bands = o.exemptBands ?? DEFAULT_EXEMPT_BANDS;
  const hits: RuleHit[] = [];
  text.split("\n").forEach((body, idx) => {
    for (const m of body.matchAll(SSH_TOKEN_RE)) {
      const host = (m[1] ?? "").toLowerCase();
      if (host === "") continue;
      const isIp = isIpLiteral(host);
      let fired = false;
      if (isIp ? inRfc1918(octetsOf(host)) && !(o.facet !== "message" && inAnyBand(octetsOf(host), bands)) : false) {
        fired = true;
      } else if (!isIp && hosts.includes(host)) {
        fired = true;
      } else if (!isIp && !hasDotSuffix(host, RFC2606_SUFFIXES) && hasDotSuffix(host, PRIVATE_SUFFIXES)) {
        fired = true;
      }
      if (fired) {
        hits.push({ rule: "exfil-ssh-target", matched: `${m[0]}`, line: idx + 1, message: "SSH-style user@host naming an internal-only target (RFC1918 literal, configured host, or private suffix)." });
      }
    }
  });
  return hits;
}

// ---------------------------------------------------------------- path & profile rules (250-LOC ceiling split)
//
// matchHomePath / matchCredLocation / matchHostProfile live in rulesPath.ts
// and are re-exported here so every consumer keeps importing the five
// predicates from one module. Type-only imports keep that pair acyclic.
export { matchCredLocation, matchHomePath, matchHostProfile } from "./rulesPath.ts";
