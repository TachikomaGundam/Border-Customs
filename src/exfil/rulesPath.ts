// provenance: .omo/plans/border-exfil-lens.md T1/T2 — path-shape rules split out
// of rules.ts at the 250-LOC ceiling (home-path, cred-location, host-profile).
// Type-only import back into rules.ts keeps the pair runtime-acyclic.
// Self-stealth: no absolute workspace paths and no dotted quads in this file
// (see rules.ts header for the 0.5.1 dogfood lesson this obeys).
import type { RuleHit, RuleOptions } from "./rules.ts";

// ---------------------------------------------------------------- exfil-home-path

/** /home/<user> — class-gated so "/homebrew" or a lone "/home/" never fires. */
const HOME_POSIX_RE = /\/home\/([A-Za-z0-9._-]+)/g;
/** C:\Users\<user> (any drive letter, either slash), case-insensitive. */
const HOME_WINDOWS_RE = /([A-Za-z]:[\\/]+Users[\\/]+)([A-Za-z0-9._-]+)/gi;

export function matchHomePath(text: string, _o: RuleOptions): RuleHit[] {
  const hits: RuleHit[] = [];
  text.split("\n").forEach((body, idx) => {
    for (const m of body.matchAll(HOME_POSIX_RE)) {
      hits.push({ rule: "exfil-home-path", matched: m[0] ?? "", line: idx + 1, message: "Home-directory path exposing a local username (privacy leak — T5 calibration graded this rule MEDIUM per lead ruling)." });
    }
    for (const m of body.matchAll(HOME_WINDOWS_RE)) {
      hits.push({ rule: "exfil-home-path", matched: m[0] ?? "", line: idx + 1, message: "Windows user-profile path exposing a local username (privacy leak — T5 calibration graded this rule MEDIUM per lead ruling)." });
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

// ---------------------------------------------------------------- exfil-machine-binding

/**
 * L-MACHINE-LOCAL (owner ruling 2026-10-01; rule born 2026-10-02 after a
 * vendor model id sat in another repo's portable README+code default for six
 * releases unnoticed). Vendor inference-model identifiers pinned on portable
 * surfaces couple a package to ONE operator's device authorization. Context
 * gate: the line must ALSO speak of model/default/provider — prose mentions
 * of a model name stay green (location, not vocabulary — mirrors the
 * cred-location "position, not value" discipline).
 * Self-stealth: literals are built in fragments so THIS file never trips
 * its own regex.
 */
const BINDING_TOKEN = String.raw`\b(?:q` + "wen" + String.raw`|deep` + "seek" + String.raw`|kimi|g` + "lm" + String.raw`|ernie|dou` + "bao" + String.raw`|hunyuan|sp` + "ark" + String.raw`)[-\.\d][\w.-]*\b`;
const BINDING_VENDOR_RE = new RegExp(BINDING_TOKEN, "gi");
const BINDING_CONTEXT_RE = /(?:model|模型|default|默认|provider)/i;

export function matchMachineBinding(text: string, _o: RuleOptions): RuleHit[] {
  const hits: RuleHit[] = [];
  text.split("\n").forEach((body, idx) => {
    if (!BINDING_CONTEXT_RE.test(body)) return;
    for (const m of body.matchAll(BINDING_VENDOR_RE)) {
      hits.push({ rule: "exfil-machine-binding", matched: m[0] ?? "", line: idx + 1, message: "Machine binding: a vendor inference-model id pinned next to model/default/provider context — device authorization belongs in operator-local config, not portable surfaces (L-MACHINE-LOCAL)." });
    }
  });
  return hits;
}
