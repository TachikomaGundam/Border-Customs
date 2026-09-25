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
  /** drives the fixture-band exemption (see matchRfc1918); never selects severity. */
  readonly facet: ExfilFacet;
  /** operator's rules.hosts (config.ts:102) — exact-match ssh targets, closed set. */
  readonly hosts?: readonly string[];
};

// ---------------------------------------------------------------- IPv4 machinery

const OCTET = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";
/** Full IPv4 with strict token boundaries (won't fire inside 5-dotted versions/urls). */
const IPV4_SRC = `(?<![0-9A-Za-z.\\-])${OCTET}\\.${OCTET}\\.${OCTET}\\.${OCTET}(?![0-9A-Za-z.\\-])`;

/** RFC 5737 documentation bands (/24): TEST-NET-1..3 as number tuples, never dotted strings. */
const RFC5737_BANDS: readonly (readonly [number, number, number])[] = [
  [192, 0, 2],
  [198, 51, 100],
  [203, 0, 113],
];
/** 10.200/16 (/16 over the second octet) — the synthetic-fixture band (evidence ruling 2; v1's proposal voided). */
const FIXTURE_BAND: readonly [number, number] = [10, 200];
/** 127/8 loopback. */
function isLoopback(o: readonly number[]): boolean {
  return o[0] === 127;
}
function isRfc5737(o: readonly number[]): boolean {
  return RFC5737_BANDS.some((b) => o[0] === b[0] && o[1] === b[1] && o[2] === b[2]);
}
function inFixtureBand(o: readonly number[]): boolean {
  return o[0] === FIXTURE_BAND[0] && o[1] === FIXTURE_BAND[1];
}
/** 10/8 ∪ 172.16/12 ∪ 192.168/16 — the plan's exfil-rfc1918 range set. */
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

// ---------------------------------------------------------------- exfil-rfc1918

/**
 * RFC1918 literals. Closed exemptions (plan table): loopback, each RFC5737
 * /24, and the 10.200/16 SYNTHETIC-FIXTURE band — the fixture band is
 * exempt on the TREE facet only (it exists so the repo's own planted golden
 * fixtures stay green on the blob face, T6); commit messages are the
 * public-exposure surface with no fixture excuse, so the band FIRES there
 * (this is what makes "message 面带合成 IP 树干净 ⇒ 必红" mechanically true).
 */
export function matchRfc1918(text: string, o: RuleOptions): RuleHit[] {
  const re = new RegExp(IPV4_SRC, "g");
  const hits: RuleHit[] = [];
  text.split("\n").forEach((body, idx) => {
    for (const m of body.matchAll(re)) {
      const ip = m[0] ?? "";
      const oct = octetsOf(ip);
      if (!inRfc1918(oct) || isLoopback(oct) || isRfc5737(oct)) continue;
      if (o.facet !== "message" && inFixtureBand(oct)) continue;
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
 * IS the operator declaring it internal). The 10.200 fixture band does NOT
 * exempt here: `synthuser@` + fixture-band address is the T6 golden red anchor.
 */
export function matchSshTarget(text: string, o: RuleOptions): RuleHit[] {
  const hosts = (o.hosts ?? []).map((h) => h.trim().toLowerCase()).filter((h) => h !== "");
  const hits: RuleHit[] = [];
  text.split("\n").forEach((body, idx) => {
    for (const m of body.matchAll(SSH_TOKEN_RE)) {
      const host = (m[1] ?? "").toLowerCase();
      if (host === "") continue;
      const isIp = isIpLiteral(host);
      let fired = false;
      if (isIp ? inRfc1918(octetsOf(host)) : false) {
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

// ---------------------------------------------------------------- exfil-home-path

/** /home/<user> — class-gated so "/homebrew" or a lone "/home/" never fires. */
const HOME_POSIX_RE = /\/home\/([A-Za-z0-9._-]+)/g;
/** C:\Users\<user> (any drive letter, either slash), case-insensitive. */
const HOME_WINDOWS_RE = /([A-Za-z]:[\\/]+Users[\\/]+)([A-Za-z0-9._-]+)/gi;

export function matchHomePath(text: string, _o: RuleOptions): RuleHit[] {
  const hits: RuleHit[] = [];
  text.split("\n").forEach((body, idx) => {
    for (const m of body.matchAll(HOME_POSIX_RE)) {
      hits.push({ rule: "exfil-home-path", matched: m[0] ?? "", line: idx + 1, message: "Home-directory path exposing a local username (privacy leak — plan: grade after T5 self-calibration)." });
    }
    for (const m of body.matchAll(HOME_WINDOWS_RE)) {
      hits.push({ rule: "exfil-home-path", matched: m[0] ?? "", line: idx + 1, message: "Windows user-profile path exposing a local username (privacy leak — plan: grade after T5 self-calibration)." });
    }
  });
  return hits;
}

// ---------------------------------------------------------------- exfil-cred-location

const PYPIRC_RE = /~\/\.pypirc/g;
const SSHPASS_RE = /\bSSHPASS\b/g;
/** *.env token: path chars then ".env" ending the token (prod.env.example stays green). */
const ENVFILE_RE = /[A-Za-z0-9_.~/-]*\.env(?![A-Za-z0-9_./-])/g;

/** *.env location-shape gate (see matchCredLocation header for the calibration evidence). */
function envTokenIsLocation(tok: string): boolean {
  const stem = tok.slice(0, -".env".length);
  if (stem === "") return true;
  if (/[\/~]/.test(stem)) return true;
  const parts = stem.split(".");
  const receiver = parts[parts.length - 1] ?? "";
  if (receiver === "process" || receiver === "os") return false;
  return receiver.length >= 3;
}

/**
 * Credential-BEARING LOCATIONS referenced by the outgoing text — position, not
 * value (plan: "位置 ≠ 值"): ~/.pypirc, SSHPASS (env var name), *.env files.
 * T5-calibrated (2026-09-25 self-scan: 186/354 raw tree matches were JS
 * property access like process.env / o.env / x?.env, not disk locations):
 * a *.env token counts only when it names the file itself, carries a path
 * prefix, or has a real file-stem receiver (≥3 chars, never the process/os
 * API names); the JS optional-chain read `x?.env` never counts.
 */
export function matchCredLocation(text: string, _o: RuleOptions): RuleHit[] {
  const hits: RuleHit[] = [];
  const push = (matched: string, line: number): void => {
    hits.push({ rule: "exfil-cred-location", matched, line, message: "Reference to a credential-bearing location (env file / pypirc / SSHPASS); the location itself, value not required to fire." });
  };
  text.split("\n").forEach((body, idx) => {
    for (const m of body.matchAll(PYPIRC_RE)) push(m[0] ?? "", idx + 1);
    for (const m of body.matchAll(SSHPASS_RE)) push(m[0] ?? "", idx + 1);
    for (const m of body.matchAll(ENVFILE_RE)) {
      const tok = m[0] ?? "";
      if ((body[(m.index ?? 0) - 1] ?? "") === "?") continue;
      if (envTokenIsLocation(tok)) push(tok, idx + 1);
    }
  });
  return hits;
}

// ---------------------------------------------------------------- exfil-host-profile

/** Conservative multi-signal table (plan: 要素 ≥2 同段, closed regex set). */
const PROFILE_SIGNALS: ReadonlyArray<{ readonly name: string; readonly re: RegExp }> = [
  { name: "os+version", re: /\b(?:Ubuntu|Debian|Raspbian|CentOS|Rocky Linux|AlmaLinux|Amazon Linux|Red Hat Enterprise Linux|RHEL|Windows Server|SUSE Linux Enterprise|Fedora)\s+v?[0-9][0-9.]*/i },
  { name: "no-docker", re: /\bno docker\b|\bdocker\b[^\n]{0,24}?\bnot (?:installed|present|available|running)\b|\bwithout docker\b|\bno container (?:runtime|engine)\b/i },
  { name: "sudo-pattern", re: /\bpasswordless sudo\b|\bnopasswd\b|\bsudo\b[^\n]{0,24}?\b(?:without|needs?|requires?) (?:a )?password\b|\b(?:needs?|requires?) (?:a )?password\b[^\n]{0,12}?\bsudo\b/i },
];

/**
 * Host-fingerprint disclosure: ≥2 DISTINCT signal groups (os+version /
 * no-docker / sudo pattern) inside the SAME paragraph (blank-line-split
 * block). Deliberately conservative: one signal never fires. The matched
 * value is the SIGNAL-NAME CLUSTER, never the paragraph text (privacy +
 * nothing raw on the Finding). Phase-2 note (plan): bare user@hostname and
 * semantic combos ride ledger rows later — this predicate stays silent there.
 */
export function matchHostProfile(text: string, _o: RuleOptions): RuleHit[] {
  const hits: RuleHit[] = [];
  let paraLines: string[] = [];
  let paraStart = 1;
  const flush = (): void => {
    if (paraLines.length === 0) return;
    const para = paraLines.join("\n");
    const found = PROFILE_SIGNALS.filter((s) => s.re.test(para)).map((s) => s.name);
    if (found.length >= 2) {
      hits.push({ rule: "exfil-host-profile", matched: found.join("+"), line: paraStart, message: `Host configuration fingerprint: ${String(found.length)} profile signals (os+version / no-docker / sudo-pattern) clustered in one paragraph.` });
    }
    paraLines = [];
  };
  text.split("\n").forEach((body, idx) => {
    if (body.trim() === "") {
      flush();
      return;
    }
    if (paraLines.length === 0) paraStart = idx + 1;
    paraLines.push(body);
  });
  flush();
  return hits;
}
