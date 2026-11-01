// Machine-side config storage (decoupling wave, HR handoff 2026-10-23).
//
// The owner ruling: border is a property of the CHECKING MACHINE, never of the
// checked product repo. The old chain (`--config > ./border.yaml > git-remote
// fallback`) steered teams to commit gate config — with its waiver lists — into
// product history (measured: a 336-entry allow-list landed in a product repo's
// tracked tree). This module resolves the machine-side rung: operator config
// files keyed by canonical remote URL, living under the operator's config home
// so no target repo ever carries gate state.
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/** Structural slice of BorderConfig remotes (src/config.ts owns the full type). */
export type RemoteLike = { readonly name?: string | undefined; readonly url: string };

/**
 * Canonical `host/path` for gate-identity purposes: credentials, port-less
 * scheme noise, the `git+` family, the `.git` suffix and trailing slashes are
 * transport spelling, not identity. Hosts lowercase (DNS is); path case is
 * preserved (registry paths are case-sensitive). `undefined` when the string
 * carries no host+path to key on.
 */
export function canonicalRemoteUrl(raw: string): string | undefined {
  let u = raw.trim();
  if (u === "") return undefined;
  if (/^file:\/\//.test(u)) {
    const p = u.slice("file://".length).replace(/\/+$/, "").replace(/\.git$/, "");
    return p === "" ? undefined : `file:${p}`;
  }
  const scheme = /^(?:ssh|git|https?):\/\//.exec(u)?.[0];
  if (scheme !== undefined) u = u.slice(scheme.length);
  u = u.replace(/^[^/@]*@/, ""); // credentials are never identity
  if (u.startsWith("git+")) u = u.slice("git+".length);
  // scp shorthand `host:path` (no slash before the colon) vs URL `host/path`.
  const scp = /^(^[^/]*?):(.+)$/.exec(u);
  if (scp !== null && !scp[1]!.includes(":")) {
    const host = scp[1]!.toLowerCase();
    const path = scp[2]!.replace(/\/+$/, "").replace(/\.git$/, "");
    return host !== "" && path !== "" ? `${host}/${path}` : undefined;
  }
  const slash = u.indexOf("/");
  if (slash <= 0) return undefined;
  const host = u.slice(0, slash).toLowerCase();
  const path = u.slice(slash + 1).replace(/\/+$/, "").replace(/\.git$/, "");
  return host !== "" && path !== "" ? `${host}/${path}` : undefined;
}

/** sha256-16 of the canonical url — filesystem-safe and stable across spellings. */
export function machineStoreKey(canonicalUrl: string): string {
  return createHash("sha256").update(canonicalUrl).digest("hex").slice(0, 16);
}

/** $BORDER_CONFIG_DIR > $XDG_CONFIG_HOME/border/machines > ~/.config/border/machines. */
export function resolveMachineStoreDir(env: Record<string, string | undefined>): string {
  const explicit = env.BORDER_CONFIG_DIR;
  if (explicit !== undefined && explicit !== "") return explicit;
  const xdg = env.XDG_CONFIG_HOME;
  if (xdg !== undefined && xdg !== "") return join(xdg, "border", "machines");
  return join(homedir(), ".config", "border", "machines");
}

/**
 * First existing `<store>/<key>.yaml` over the repo's remotes in declaration
 * order; `undefined` when the machine holds no config for any of them.
 */
export function findMachineConfig(
  remotes: readonly RemoteLike[],
  storeDir: string,
): { path: string; canonical: string } | undefined {
  for (const remote of remotes) {
    const canonical = canonicalRemoteUrl(remote.url);
    if (canonical === undefined) continue;
    const p = join(storeDir, `${machineStoreKey(canonical)}.yaml`);
    if (existsSync(p)) return { path: p, canonical };
  }
  return undefined;
}
