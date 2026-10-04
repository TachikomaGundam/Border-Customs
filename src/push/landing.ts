// provenance: .omo/plans/border-exfil-lens.md T7 — S3 post-push landing
// verification for GIT targets only (plan §S3; registry publish-byte landing
// verification is a named follow-up, deliberately NOT folded in here).
//
// Doctrine (the honest contract):
//   * the executed push record is NEVER rewritten — landing only APPENDS a
//     t:"landing" fact row (clean/blocked) or, when verification is impossible,
//     mints NOTHING and exits 2 loud: "landed, verification unavailable —
//     PASS 不背书公开面";
//   * a blocking hit on the LANDED remote tip exits 1 with "ALREADY PUBLIC;
//     border detects, never erases" — there is no rollback and no pretense of
//     one (push already moved the ref; the disclosure IS the product);
//   * a clean landing records and PRESERVES the original executor exit;
//   * the tip is rescanned with the SAME machinery as the exfil CLI ref-mode
//     (scanTipTree: native MEDIUM family + twins filtered to exfil ids) against
//     the remote's own observed tip sha — not a local guess: when the remote
//     holds a foreign commit we fetch it read-only before scanning;
//   * the tip findings flow through the SAME border.yaml allow pins the check
//     pipeline applied when it certified the push (2026-10-04 incident fix:
//     check suppressed pinned bytes while landing had no pins — a green packet
//     contradicted seconds later on the public face). Honoring a pin here is
//     never erasure: the bytes stay on the remote and the suppression is echoed
//     LOUD with rule+entry+count; ANY finding not covered by an owner-authored
//     rule+file+digest entry blocks exactly as before.
// Every seam (remote probe + tip scan + record sink) is injectable so the
// three outcomes are unit-testable without a network.
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

import { scanTipTree } from "../commands/exfil.ts";
import { makeGit } from "../commands/exfilGit.ts";
import { applyAllowList } from "../check/allow.ts";
import { latestPassCoveringTargets, readLedger } from "../ledger.ts";
import { appendRecord, buildLandingRecord, type LandingRecord } from "../ledger/records.ts";
import type { BorderConfig } from "../config.ts";
import { isBlocking, type Finding } from "../findings.ts";
import type { BorderExit } from "../cli/exit.ts";
import { EXIT_BLOCKED, EXIT_ERROR } from "../cli/exit.ts";
import type { GitRemoteTarget } from "./git.ts";

export const LANDINGS_REF_PREFIX = "refs/border-landings/";

export type LandingLeg = { readonly target: GitRemoteTarget; readonly branch: string };

export type LandingOptions = {
  readonly repoDir: string;
  readonly key: string;
  readonly legs: readonly LandingLeg[];
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly out: (line: string) => void;
  readonly err: (line: string) => void;
  /** remote tip observation: full sha, or null when the remote/ref is unreachable in time. */
  readonly observeRemoteTip?: (remote: GitRemoteTarget, branch: string) => string | null;
  /** scan the REMOTE tip's tree; throw/reject ⇒ treated as unreachable (fail closed). */
  readonly scanRemoteTip?: (remote: GitRemoteTarget, branch: string, remoteSha: string) => Promise<readonly Finding[]>;
  /** the border.yaml allow entries (default []): tip findings covered by an owner pin
   *  (rule+file+digest) are exempted AT BOTH FACES — the same entries the check verdict
   *  honored. Never silent: every suppression is echoed with rule+entry+count. */
  readonly allow?: readonly BorderConfig["allow"][number][];
  /** record sink (default: append to the ledger); tests inject a sink to assert exact rows. */
  readonly record?: (r: LandingRecord) => void;
};

/** null ⇒ every leg landed clean (executor exit preserved). Otherwise the mapped border exit. */
export async function runLandingVerification(o: LandingOptions): Promise<BorderExit | null> {
  if (o.legs.length === 0) return null;
  const rulesHash = landingRulesHash(o);
  const observe = o.observeRemoteTip ?? ((remote, branch) => defaultObserveRemoteTip(o.repoDir, remote, branch, o.env));
  const scan = o.scanRemoteTip ?? ((remote, branch, sha) => defaultScanRemoteTip(o, remote, branch, sha));
  const sink = o.record ?? ((r) => appendRecord(o.repoDir, r));
  for (const leg of o.legs) {
    const sha = observe(leg.target, leg.branch);
    if (sha === null || sha === "") {
      o.err(`border: ${leg.target.target} landed, verification unavailable (remote tip unfetchable) — exit 2; PASS not endorsed for the public face`);
      return EXIT_ERROR;
    }
    let findings: readonly Finding[];
    try {
      findings = await scan(leg.target, leg.branch, sha);
    } catch (err) {
      o.err(
        `border: ${leg.target.target} landed, verification unavailable (remote tip fetch/scan failed: ${err instanceof Error ? err.message : String(err)}; first bytes: ${sha.slice(0, 8)}) — exit 2; PASS not endorsed for the public face`,
      );
      return EXIT_ERROR;
    }
    const allow = applyAllowList(findings, o.allow ?? [], o.repoDir);
    findings = allow.kept;
    if (allow.allowHits.length > 0) {
      const hits = allow.allowHits.map((h) => `${h.rule}#entry${String(h.entryIndex)}:${String(h.count)}`).join(", ");
      o.err(`border: ${leg.target.target} landing: ${String(allow.allowHits.reduce((n, h) => n + h.count, 0))} tip finding(s) exempted by config allow pins (${hits}) — same entries the check verdict honored, echoed loud`);
    }
    const blocking = findings.filter((f) => isBlocking(f.severity)).length;
    const verdict = blocking > 0 ? "blocked" : "clean";
    sink(buildLandingRecord({ key: o.key, target: leg.target.target, ref: `refs/heads/${leg.branch}`, remoteSha: sha, verdict, blocking, rulesHash }));
    if (blocking > 0) {
      o.err(`border: ${leg.target.target} ALREADY PUBLIC; border detects, never erases — ${String(blocking)} blocking finding(s) on the landed tip ${sha.slice(0, 12)}`);
      for (const f of findings.filter((x) => isBlocking(x.severity))) {
        o.err(`border:   ${f.severity} ${f.rule} [${f.engine}] ${f.path ?? f.commit ?? f.target}${f.line !== undefined ? `:${String(f.line)}` : ""}`);
      }
      return EXIT_BLOCKED;
    }
    o.out(`border: ${leg.target.target} landing verified — remote tip ${sha.slice(0, 12)} clean (t:${verdict} record appended)`);
  }
  return null;
}

/** The rules identity that CERTIFIED this push: the newest PASS record under the live key (never a fresh re-probe, never a guess). */
function landingRulesHash(o: LandingOptions): string {
  const { records } = readLedger(o.repoDir);
  const pass = latestPassCoveringTargets(records, o.key, ["git"]);
  if (pass === null) {
    throw new Error(`landing: no PASS record under key ${o.key.slice(0, 8)} — refusing to record a landing fact against unknown rules`);
  }
  return pass.rulesHash;
}

function gitPlain(repoDir: string, env: Readonly<Record<string, string | undefined>>, args: readonly string[]): { status: number | null; stdout: string } {
  const clean: Record<string, string | undefined> = {};
  for (const [name, value] of Object.entries(env)) {
    if (!name.startsWith("GIT_")) clean[name] = value;
  }
  clean.GIT_CEILING_DIRECTORIES = dirname(resolve(repoDir));
  clean.GIT_OPTIONAL_LOCKS = "0";
  clean.GIT_TERMINAL_PROMPT = "0";
  const r = spawnSync("git", ["-C", resolve(repoDir), ...args], { encoding: "utf8", env: clean, timeout: 55_000, maxBuffer: 32 * 1024 * 1024 });
  return { status: r.status ?? 1, stdout: r.stdout ?? "" };
}

function defaultObserveRemoteTip(repoDir: string, remote: GitRemoteTarget, branch: string, env: Readonly<Record<string, string | undefined>>): string | null {
  const r = gitPlain(repoDir, env, ["ls-remote", remote.url, `refs/heads/${branch}`]);
  if (r.status !== 0) return null;
  const sha = /^[0-9a-f]{40}/.exec(r.stdout)?.[0] ?? null;
  return sha;
}

async function defaultScanRemoteTip(o: LandingOptions, remote: GitRemoteTarget, branch: string, remoteSha: string): Promise<readonly Finding[]> {
  const git = makeGit(o.repoDir, o.env);
  let rev = remoteSha;
  let ownedTempRef: string | null = null;
  try {
    try {
      git.run(["cat-file", "-e", `${remoteSha}^{object}`]);
    } catch {
      const landingRef = `${LANDINGS_REF_PREFIX}${remote.target.replace(/[^A-Za-z0-9_.-]/g, "-")}`;
      git.run(["fetch", "-q", "--no-tags", remote.url, `refs/heads/${branch}:${landingRef}`]);
      ownedTempRef = landingRef;
      rev = git.run(["rev-parse", landingRef]).trim();
    }
    const treeRoot = mkdtempSync(join(tmpdir(), "border-landing-tree-"));
    try {
      return await scanTipTree(git, treeRoot, rev, o.env);
    } finally {
      rmSync(treeRoot, { recursive: true, force: true });
    }
  } finally {
    if (ownedTempRef !== null) {
      try {
        git.run(["update-ref", "-d", ownedTempRef]);
      } catch {
        // ref cleanup is hygiene, not truth: the scan verdict is already computed and a failed delete never gates
      }
    }
  }
}
