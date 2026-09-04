// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 15
//
// Live push-state derivation for `border push` (todo 17 renders this; nothing
// here pushes, force-pushes, cherry-picks tags, or keeps state beyond the
// ledger + these probes). Target state machine UNCHECKED→PASSED→PUSHED:
//   * PUSHED is computed LIVE, never trusted from the ledger alone. git legs:
//     `git ls-remote <url>` FULL-REF comparison vs the local refSet — ALL refs
//     in refSet equal ⇒ PUSHED(no-op); tags compare as PEELED commits (the
//     `^{}` line / local %(*objectname)), so a branch-tip match with a tag
//     missing on the remote is NOT a no-op (G43); a remote ref absent is
//     behind/pending, never "equal". registry legs reuse the todo-13
//     version-exists polarity: present ⇒ PUSHED ONLY IF a t:"push" record for
//     this exact name@version exists OR registry owner==self (lost-ledger
//     recovery); present-without-our-record delegates to the loud todo-13
//     `version-exists` FAIL — a squatter's version is never silently PUSHED
//     (round-1 M4); absent ⇒ pending; unreachable ⇒ EngineRunError propagates
//     (exit 2, fail-closed polarity pinned in todo 13).
//   * PASSED comes from the todo-14 ledger (latestPassCoveringTargets under the
//     CURRENT fingerprint key — computeFingerprint re-derives it, and the key
//     already binds refSet/exposure, so a stale PASS cannot gate). A target
//     neither PASSED nor live-PUSHED is BLOCKED with an `unchecked` reason:
//     pushstate runs no todo-10..14 engines itself — EXCEPT the identity rule
//     on git legs about to transmit objects (PENDING): a ledger PASS cannot
//     vouch for identities in objects the remote has never had (first push /
//     restored tag), so scanIdentity gates the transmit set directly here.
import { gatherContext, runGitChecked } from "./check/context.ts";
import type { BorderConfig } from "./config.ts";
import type { Finding } from "./findings.ts";
import { scanIdentity } from "./rules/identity.ts";
import { computeFingerprint } from "./ledger.ts";
import {
  appendRecord,
  buildPushRecord,
  latestPassCoveringTargets,
  pushRecords,
  readLedger,
  type LedgerRecord,
  type PushConfirmedVia,
  type PushRecord,
} from "./ledger/records.ts";
import {
  FOREIGN_OWNER_RULE,
  VERSION_EXISTS_RULE,
  readNpmCoords,
  readPypiCoords,
  runRegistryProbes,
  type PublishCoords,
  type RegistryProbeOptions,
} from "./registry.ts";
import { sanitizeUrl } from "./redact.ts";
import { gitTargetId } from "./gitTargetId.ts";

/** Exit-2 class (same shape as BorderLockHeldError): a git probe that cannot
 *  answer fails closed naming the target; the CLI maps exitCode. */
export class PushStateError extends Error {
  readonly exitCode: 2 = 2;
  override readonly name = "PushStateError";
}

export type TargetKind = "git" | "npm" | "pypi";
export type TargetStatus = "PUSHED" | "PENDING" | "BLOCKED";
export type TargetGate = "PASSED" | "UNCHECKED";

export type TargetResult = {
  /** `git:<remoteName>` for remotes, plain `npm` / `pypi` for publish legs. */
  readonly target: string;
  readonly kind: TargetKind;
  readonly status: TargetStatus;
  readonly gate: TargetGate;
  /** Why: missing/diverged refs (PENDING), delegated todo-13 findings text
   *  (BLOCKED squatter), or the unchecked-gate explanation. */
  readonly reason?: string;
  /** Delegated todo-13 findings when BLOCKED by a loud registry FAIL. */
  readonly findings: readonly Finding[];
};

export type PushStateResult = {
  readonly key: string;
  readonly headSha: string;
  readonly refSet: readonly string[];
  readonly targets: readonly TargetResult[];
  readonly warnings: readonly string[];
};

export type PushStateOptions = {
  readonly repoDir: string;
  readonly cfg: BorderConfig;
  /** sha256 of the canonical effective config — the same value the check run
   *  fed into computeFingerprint, else the keys (and gates) will not match. */
  readonly configDigest: string;
  readonly effectiveTargets: readonly string[];
  readonly env?: NodeJS.ProcessEnv;
  readonly requireOverride?: readonly string[];
  /** Test seam forwarded to the todo-13 pypi leg (production = global fetch). */
  readonly fetcher?: RegistryProbeOptions["fetcher"];
};

const SHA_SHAPE = /^[0-9a-f]{40}$|^[0-9a-f]{64}$/;

/** Parse `git ls-remote` stdout (`sha \t ref` lines) fail-closed: any malformed
 *  line throws naming the target — garbage output is never read as "equal". */
export function parseLsRemote(text: string, targetId: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    const fields = line.split("\t");
    const sha = fields[0];
    const ref = fields[1];
    // HEAD is the one legit non-refs/ line git emits; it is never in refSet.
    const shapeOk = fields.length === 2 && sha !== undefined && SHA_SHAPE.test(sha) && (ref === "HEAD" || (ref !== undefined && ref.startsWith("refs/")));
    if (!shapeOk) {
      throw new PushStateError(`target '${targetId}': malformed 'git ls-remote' output line '${line.slice(0, 72)}' — refusing to interpret (fail closed)`);
    }
    if (ref !== "HEAD") out.set(ref, sha);
  }
  return out;
}

/** Local refSet → commit map; annotated tags resolve through %(*objectname). */
function localRefCommits(repoDir: string, refSet: readonly string[], env: NodeJS.ProcessEnv): Map<string, string> {
  const commits = new Map<string, string>();
  if (refSet.length === 0) return commits;
  const fmt = "--format=%(refname)%09%(objectname)%09%(*objectname)";
  for (const line of runGitChecked(repoDir, ["for-each-ref", fmt, ...refSet], { env }).split("\n")) {
    const [ref, obj, peeled] = line.split("\t");
    if (ref === undefined || obj === undefined) continue;
    commits.set(ref, peeled !== undefined && peeled !== "" ? peeled : obj);
  }
  return commits;
}

function remoteCommit(remote: ReadonlyMap<string, string>, ref: string): string | null {
  if (ref.startsWith("refs/tags/")) {
    const peeled = remote.get(`${ref}^{}`);
    if (peeled !== undefined) return peeled; // G43: tags compare as peeled commits
  }
  return remote.get(ref) ?? null;
}

function uncheckedReason(id: string): string {
  return `unchecked: no PASS record for '${id}' under the current fingerprint key — run 'border check' first`;
}

/**
 * PENDING means this push WILL upload refSet objects the remote lacks; the
 * identity allowlist must gate that transmit set even when the todo-14
 * ledger says PASSED (the PASS predates or cannot express first-push
 * content). PUSHED legs upload nothing and never reach this.
 */
function gateTransmitIdentities(t: TargetResult, identities: readonly Finding[]): TargetResult {
  if (t.status !== "PENDING" || identities.length === 0) return t;
  return {
    ...t,
    status: "BLOCKED",
    reason: `${t.reason ?? ""} — ${String(identities.length)} identity finding(s) on objects this push would transmit`,
    findings: identities,
  };
}

function gitState(o: PushStateOptions, id: string, url: string, refSet: readonly string[], locals: ReadonlyMap<string, string>, gate: TargetGate): TargetResult {
  let text: string;
  try {
    text = runGitChecked(o.repoDir, ["ls-remote", url], { env: o.env ?? process.env });
  } catch {
    // inner cause text is deliberately dropped: runGitChecked echoes the raw url
    throw new PushStateError(`target '${id}' unreachable via git ls-remote (${sanitizeUrl(url)}) — remote absent or not a git repository; border fails closed`);
  }
  const remote = parseLsRemote(text, id);
  const behind: string[] = [];
  for (const ref of refSet) {
    const local = locals.get(ref);
    const their = remoteCommit(remote, ref);
    if (local !== undefined && (their === null || their !== local)) behind.push(`${ref}@${their === null ? "absent" : "behind"}`);
  }
  if (behind.length === 0) return { target: id, kind: "git", status: "PUSHED", gate, findings: [] };
  if (gate === "UNCHECKED") return { target: id, kind: "git", status: "BLOCKED", gate, reason: uncheckedReason("git"), findings: [] };
  return { target: id, kind: "git", status: "PENDING", gate, reason: `behind: ${behind.join(", ")}`, findings: [] };
}

function registryState(kind: "npm" | "pypi", coords: PublishCoords, findings: readonly Finding[], ours: readonly PushRecord[], gate: TargetGate): TargetResult {
  const leg = (rule: string): Finding | undefined => findings.find((f) => f.target === kind && f.rule === rule);
  const present = leg(VERSION_EXISTS_RULE) !== undefined;
  if (!present) {
    if (gate === "UNCHECKED") return { target: kind, kind, status: "BLOCKED", gate, reason: uncheckedReason(kind), findings: [] };
    return { target: kind, kind, status: "PENDING", gate, reason: `version ${coords.name}@${coords.version} not published`, findings: [] };
  }
  const full = `${coords.name}@${coords.version}`;
  if (ours.some((r) => r.target === kind && r.version === full)) {
    return { target: kind, kind, status: "PUSHED", gate, reason: `registry has ${full} and ledger carries our push record`, findings: [] };
  }
  if (leg(FOREIGN_OWNER_RULE) === undefined) {
    return { target: kind, kind, status: "PUSHED", gate, reason: `registry has ${full} and owner==self (no ${FOREIGN_OWNER_RULE} finding)`, findings: [] };
  }
  const blocking = findings.filter((f) => f.target === kind && (f.rule === VERSION_EXISTS_RULE || f.rule === FOREIGN_OWNER_RULE));
  return { target: kind, kind, status: "BLOCKED", gate, reason: blocking.map((f) => `${f.rule}: ${f.message}`).join("; "), findings: blocking };
}

function gateFor(records: readonly LedgerRecord[], key: string, kind: TargetKind): TargetGate {
  return latestPassCoveringTargets(records, key, [kind]) !== null ? "PASSED" : "UNCHECKED";
}

/** Derive live push state for every effective∩configured target. Throws (exit 2)
 *  on unreachable/malformed git remotes (PushStateError) or unreachable
 *  registries (EngineRunError). Git legs run BEFORE the async registry legs so
 *  an unreachable-remote error wins any race (plan failure AC). */
export async function derivePushState(o: PushStateOptions): Promise<PushStateResult> {
  const env = o.env ?? process.env;
  const want = (kind: TargetKind): boolean =>
    o.effectiveTargets.includes(kind) &&
    (kind === "git" ? o.cfg.targets.git.remotes.length > 0 : o.cfg.targets[kind] !== undefined);
  const ctx = await gatherContext(o.repoDir, { env });
  const { fp } = await computeFingerprint(o.repoDir, o.cfg, o.configDigest, [...o.effectiveTargets], {
    env,
    ...(o.requireOverride === undefined ? {} : { requireOverride: o.requireOverride }),
  });
  const ledger = readLedger(o.repoDir);
  const records = ledger.records;
  const targets: TargetResult[] = [];

  if (want("git")) {
    const gate = gateFor(records, fp.key, "git");
    const locals = localRefCommits(o.repoDir, ctx.refSet, env);
    let identities: readonly Finding[] | null = null;
    const transmittedIdentities = (): readonly Finding[] =>
      (identities ??= scanIdentity({ repoDir: o.repoDir, refSet: [...ctx.refSet], cfg: o.cfg }));
    for (const [index, remote] of o.cfg.targets.git.remotes.entries()) {
      const id = gitTargetId(remote, index);
      const t = gitState(o, id, remote.url, ctx.refSet, locals, gate);
      targets.push(t.status === "PENDING" ? gateTransmitIdentities(t, transmittedIdentities()) : t);
    }
  }

  const publishLegs = (["npm", "pypi"] as const).filter(want);
  if (publishLegs.length > 0) {
    const findings = await runRegistryProbes({
      repoDir: o.repoDir,
      cfg: o.cfg,
      effectiveTargets: publishLegs,
      env,
      ...(o.fetcher === undefined ? {} : { fetcher: o.fetcher }),
    });
    const ours = pushRecords(records);
    for (const kind of publishLegs) {
      const coords = kind === "npm" ? readNpmCoords(o.repoDir, o.cfg, env) : readPypiCoords(o.repoDir, o.cfg, env);
      targets.push(registryState(kind, coords, findings, ours, gateFor(records, fp.key, kind)));
    }
  }

  return { key: fp.key, headSha: ctx.headSha, refSet: ctx.refSet, targets, warnings: ledger.warnings };
}

/** Resume matrix: targets `border push --yes` may attempt — PENDING only.
 *  BLOCKED targets are non-PUSHED but must NOT be pushed (unchecked content /
 *  squatted version); that distinction is exactly what the status line is for. */
export function pushableTargets(result: PushStateResult): TargetResult[] {
  return result.targets.filter((t) => t.status === "PENDING");
}

/** One-line renderer (todo 17's surface): `git:origin  PUSHED(no-op)  ...`. */
export function formatTargetLine(t: TargetResult): string {
  const status = t.status === "PUSHED" ? "PUSHED(no-op)" : t.status;
  return `${t.target}  ${status}${t.reason === undefined ? "" : `  ${t.reason}`}`;
}

/** Post-success ledger input (todo 16 supplies the confirmed proof). */
export type PushSuccessInput = {
  readonly key: string;
  readonly target: string;
  readonly remoteName: string;
  readonly url: string;
  readonly localSha: string;
  readonly remoteSha?: string;
  readonly version?: string;
  readonly confirmedVia: PushConfirmedVia;
};

/** Post-success writer: one t:"push" record appended; buildPushRecord applies
 *  sanitizeUrl, so a credential-bearing url can never enter the ledger (G20). */
export function recordPushSuccess(repoDir: string, i: PushSuccessInput): PushRecord {
  const rec = buildPushRecord(i);
  appendRecord(repoDir, rec);
  return rec;
}
