// provenance: sibyl Q1 ruling chain through runs 1008 + f9dc (canonical text =
// proposals v6/v7 under /home/lab/tmp/opencode/q1-sandbox-ruling-proposal-v*.md;
// the confirm-ballot for v7 runs after this wave lands — code and spec
// co-evolve under the f9dc contract).
//
// SECURITY TIER for the keys that decide whether border EXECUTES audited code
// or trusts a discovered gate policy: `targets.<ch>.sandboxImage` and the
// operator build consent. Threat model: a hostile repo steering a victim's
// scan, including hostile ENVIRONMENT manipulation (direnv/.envrc exporting
// XDG_CONFIG_HOME or BORDER_CONFIG; lax-mode store files another local user
// could have written). The rules:
//   * §3⁗  declaration-as-presence: honor states only from a QUALIFIED fd
//          read; unqualified declarations of the same key are SHADOWED (named
//          exit 2, never silently ignored); two qualified sources are
//          AMBIGUOUS (named exit 2 — no precedence exists).
//   * §3⁖  qualification walks an O_NOFOLLOW fd chain component-by-component
//          (Linux openat via /proc/self/fd/<n>), fstat-binding every check to
//          the same fds that form the read's ancestry. The TRUST ANCHOR is
//          the first euid-owned directory: above it components must be
//          root-owned with no group/other write bit; the anchor itself is
//          judged by ownership + no-write-bit (a standard 0755 home passes);
//          below it directories must be euid-owned ≤0700, files euid ≤0600.
//          No euid-owned directory anywhere ⇒ UNQUALIFIED.
//   * §3‡  the canonical store root derives from PASSWD (getent, then
//          /etc/passwd, then fail-closed undefined) — never $HOME, never
//          os.homedir() (which prefers $HOME); an active unqualified XDG
//          override shadows the canonical chain by presence alone.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { ConfigError } from "./channels/errors.ts";

const TMP_ROOTS = ["/tmp", "/var/tmp", "/dev/shm"] as const;

export type TierSource = "repo" | "machine" | "argv";

/** One security-key declaration discovered at load, before qualification. */
export type SecurityDecl = {
  readonly key: "sandboxImage" | "allowBuilds";
  readonly lane?: string;
  readonly value: string | boolean;
  readonly source: TierSource;
  /** absolute path of the declaring file (for argv: the --config target). */
  readonly path: string;
};

export type HonorState =
  | { readonly kind: "honored"; readonly value: string | boolean }
  /** declared only by UNQUALIFIED sources ⇒ named exit 2 */
  | { readonly kind: "present-unqualified" }
  /** qualified value + unqualified declarations of the same key ⇒ named exit 2 */
  | { readonly kind: "shadowed"; readonly shadowedBy: readonly string[] }
  /** two or more qualified sources declare the same key ⇒ named exit 2 */
  | { readonly kind: "ambiguous"; readonly paths: readonly string[] }
  | { readonly kind: "absent" };

/** §3‡ passwd HOME of the euid — getent, then /etc/passwd, then UNDEFINED
 *  (fail-closed). NEVER os.homedir()/process.env.HOME: os.homedir() PREFERS
 *  $HOME, an environment variable hostile repo tooling controls. */
export function passwdHome(
  exec: (cmd: string, args: readonly string[], o: { encoding: "utf8"; timeout: number }) => string = (c, a, o) => execFileSync(c, [...a], o),
  readPasswd: () => string = () => fs.readFileSync("/etc/passwd", "utf8"),
): string | undefined {
  const uid = process.geteuid?.() ?? process.getuid?.() ?? 0;
  try {
    const out = exec("getent", ["passwd", String(uid)], { encoding: "utf8", timeout: 5_000 }).trim();
    const home = out.split(":")[5];
    if (home !== undefined && home.startsWith("/")) return home;
  } catch {
    /* getent absent (NSS-less container): fall through to the file parse */
  }
  try {
    for (const line of readPasswd().split("\n")) {
      const f = line.split(":");
      if (f.length >= 6 && f[2] === String(uid) && f[5]!.startsWith("/")) return f[5];
    }
  } catch {
    /* unreadable passwd DB — fail closed */
  }
  return undefined;
}

/** Undefined ⇒ machine-tier security keys are PRESENT-UNQUALIFIED (§3‡). */
export function canonicalStoreRoot(): string | undefined {
  const home = passwdHome();
  return home === undefined ? undefined : path.join(home, ".config", "border", "machines");
}

/** XDG-influenced store root; SET-but-unqualified ⇒ active override (§3⁗). */
export function xdgStoreRoot(env: NodeJS.ProcessEnv): string | undefined {
  const xdg = env["XDG_CONFIG_HOME"];
  if (xdg === undefined || xdg === "") return undefined;
  return path.join(xdg, "border", "machines");
}

function underTmp(realpath: string): boolean {
  return TMP_ROOTS.some((t) => realpath === t || realpath.startsWith(t + "/"));
}

type Walk = { readonly ok: true; readonly dirFd: number } | { readonly ok: false; readonly reason: string };

/** §3⁖ fd-chain walk over the REALPATH's directory components. Linux-only
 *  (/proc/self/fd openat); anything else fails closed. The final component is
 *  NOT opened — the caller opens it from the returned verified dir fd. */
function walkDirs(realpath: string): Walk {
  if (process.platform !== "linux") return { ok: false, reason: `fd-chain requires linux (${process.platform})` };
  if (underTmp(realpath)) return { ok: false, reason: `under tmp root ${realpath}` };
  const euid = process.geteuid?.() ?? process.getuid?.();
  if (euid === undefined) return { ok: false, reason: "no euid available" };
  const segments = realpath.split("/").filter((s) => s !== "");
  let fd: number;
  try {
    fd = fs.openSync("/", fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
  } catch {
    return { ok: false, reason: "cannot open / for the fd chain" };
  }
  let passedAnchor = false;
  try {
    for (const seg of segments) {
      let next: number;
      try {
        next = fs.openSync(`/proc/self/fd/${String(fd)}/${seg}`, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      } catch {
        return { ok: false, reason: `segment '${seg}' untraversable (symlink, swap, or permission)` };
      }
      const st = fs.fstatSync(next);
      const writable = (st.mode & 0o022) !== 0;
      if (!passedAnchor) {
        if (st.uid === euid) {
          // THE ANCHOR: judged by ownership + no group/other write (0755/0750 pass).
          passedAnchor = true;
          if (writable) {
            fs.closeSync(next);
            return { ok: false, reason: `anchor '${seg}' is group/world-writable` };
          }
        } else if (st.uid !== 0 || writable) {
          fs.closeSync(next);
          return { ok: false, reason: `ancestor '${seg}' neither root-owned non-writable nor the euid anchor` };
        }
      } else if (st.uid !== euid || writable || (st.mode & 0o777) > 0o700) {
        fs.closeSync(next);
        return { ok: false, reason: `directory '${seg}' below anchor not euid-owned ≤0700` };
      }
      fs.closeSync(fd);
      fd = next;
    }
    return { ok: true, dirFd: fd };
  } catch (e) {
    return { ok: false, reason: `fd chain error: ${String(e)}` };
  }
}

/** §3⁖ fd-bound read of a security-tier FILE: walk the parent dirs, open the
 *  leaf O_NOFOLLOW from the verified dir fd, fstat (euid ∧ ≤0600 ∧ regular),
 *  read from that SAME fd. Checks cannot diverge from the bytes delivered. */
export function qualifyRead(filePath: string): { readonly ok: true; readonly content: string; readonly realpath: string } | { readonly ok: false; readonly reason: string } {
  let realpath: string;
  try {
    realpath = fs.realpathSync(filePath);
  } catch {
    return { ok: false, reason: "path does not resolve" };
  }
  const walk = walkDirs(path.dirname(realpath));
  if (!walk.ok) return { ok: false, reason: walk.reason };
  try {
    let fd: number;
    try {
      fd = fs.openSync(`/proc/self/fd/${String(walk.dirFd)}/${path.basename(realpath)}`, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    } catch {
      return { ok: false, reason: "leaf unopenable (symlink swap?)" };
    }
    try {
      const st = fs.fstatSync(fd);
      const euid = process.geteuid?.() ?? process.getuid?.();
      if (euid !== undefined && st.uid !== euid) return { ok: false, reason: `file owned by uid ${String(st.uid)}, not euid` };
      if ((st.mode & 0o077) !== 0) return { ok: false, reason: `file mode ${(st.mode & 0o777).toString(8)} grants group/other access (>0600)` };
      if (!st.isFile()) return { ok: false, reason: "not a regular file" };
      return { ok: true, content: fs.readFileSync(fd, "utf8"), realpath };
    } finally {
      fs.closeSync(fd);
    }
  } finally {
    fs.closeSync(walk.dirFd);
  }
}

/** §3⁖ qualification of a DIRECTORY (store roots / override roots): same
 *  chain, no leaf read. */
export function qualifyDir(dirPath: string): { readonly ok: true; readonly realpath: string } | { readonly ok: false; readonly reason: string } {
  let realpath: string;
  try {
    realpath = fs.realpathSync(dirPath);
  } catch {
    return { ok: false, reason: "directory does not resolve" };
  }
  const walk = walkDirs(realpath);
  if (!walk.ok) return { ok: false, reason: walk.reason };
  fs.closeSync(walk.dirFd);
  return { ok: true, realpath };
}

/** §3⁗ honor computation (pure; the loader does source discovery).
 *  activeUnqualifiedOverride: paths of SET-but-unqualified override roots
 *  (XDG) — they shadow by presence, files or not. */
export function honorSecurityKey(
  decls: readonly SecurityDecl[],
  activeUnqualifiedOverride: readonly string[] = [],
  qualify: (p: string) => { readonly ok: boolean } = (p) => qualifyRead(p),
): HonorState {
  const qualified: SecurityDecl[] = [];
  const unqualified: { path: string }[] = activeUnqualifiedOverride.map((p) => ({ path: p }));
  for (const d of decls) {
    // A config file INSIDE the repo is repo-tier by rule even if its modes
    // are perfect: ownership says nothing about authorship there.
    const q = d.source === "repo" ? { ok: false as const } : qualify(d.path);
    if (q.ok) qualified.push(d);
    else unqualified.push({ path: d.path });
  }
  if (qualified.length > 1) {
    return { kind: "ambiguous", paths: qualified.map((d) => d.path) };
  }
  if (qualified.length === 1) {
    if (unqualified.length > 0) return { kind: "shadowed", shadowedBy: unqualified.map((u) => u.path) };
    return { kind: "honored", value: qualified[0]!.value };
  }
  if (unqualified.length > 0) return { kind: "present-unqualified" };
  return { kind: "absent" };
}

/** Named refusals at the command seam for blocking states. `allowBuilds`
 *  callers may treat present-unqualified as withheld (failure-conservative);
 *  sandboxImage callers MUST refuse (there is no host fallback once a lane
 *  declared sandboxing anywhere). */
export function assertSecurityKey(state: HonorState, what: string, block: "refuse" | "withhold"): { readonly value: string | boolean } | undefined {
  if (state.kind === "ambiguous") {
    throw new ConfigError("invalid-value", `${what} is declared QUALIFIED by ${String(state.paths.length)} sources (${state.paths.join(", ")}) — no precedence exists between qualified sources (sibyl §3⁗ ambiguous)`);
  }
  if (state.kind === "shadowed") {
    throw new ConfigError("invalid-value", `${what} has CONFLICTING declarations: a qualified value is shadowed by unqualified source(s): ${state.shadowedBy.join(", ")} — a hostile repo or environment may be declaring it; refusing (sibyl §3⁗ shadowing)`);
  }
  if (state.kind === "present-unqualified") {
    if (block === "refuse") {
      throw new ConfigError("invalid-value", `${what} is declared only by UNQUALIFIED sources (repo config, lax-mode file, unqualified override root, or a path failing the security-tier fd-chain check) — border refuses rather than silently ignoring the declaration (sibyl §3⁗); fix: euid-owned 0600 machine store outside the repo`);
    }
    return undefined; // withheld: the conservative direction for consent
  }
  return state.kind === "honored" ? { value: state.value } : undefined;
}
