// provenance: 2026-11-08 owner escalation (Sibyl release field test) — parseLsRemote
// extracted from src/pushstate.ts to a dependency-free leaf so the identity rule can
// share ONE live-remote parser without an ESM cycle (pushstate imports rules/identity).
// The extraction is byte-honest: pushstate re-exports both names for its importers.
//
// `git ls-remote` is the single truth for what a remote already holds; every parser
// here fails closed: garbage output is never read as an answer.

/** Exit-2 class (same shape as BorderLockHeldError): a git probe that cannot
 *  answer fails closed naming the target; the CLI maps exitCode. */
export class PushStateError extends Error {
  readonly exitCode: 2 = 2;
  override readonly name = "PushStateError";
}

export const SHA_SHAPE = /^[0-9a-f]{40}$|^[0-9a-f]{64}$/;

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
