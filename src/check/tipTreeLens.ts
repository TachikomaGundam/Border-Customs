// provenance: check-tip-lens fix (2026-10-04 incident).
//
// The check-side seam over the SHARED tip-lens machinery (commands/exfil.ts
// scanTipTree — the exact function the S3 landing verification runs against the
// remote tip). Doctrine it closes: a green `border check` must PREDICT the
// landing scan. Pre-fix, check certified a range/disk lens while landing judged
// the whole pushed tip — two lenses, two standards, one gate.
//
// Failure posture mirrors the rest of the pipeline's git plumbing: every git
// spawn here is makeGit's fail-closed argv form, so a corrupt object store or an
// unreadable rev THROWS (ConfigError ⇒ CLI exit 2 loud). A silent empty scan is
// the failure mode this whole fix exists to make impossible. The twin sub-legs
// honor the existing broken-engine skip semantics (the caller passes the probe's
// flags — a missing gitleaks never crashes the gate, exactly like the history/tree
// legs), while the native leg — pure in-process text scan — can never be skipped.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { scanTipTree } from "../commands/exfil.ts";
import { makeGit } from "../commands/exfilGit.ts";
import type { Finding } from "../findings.ts";
import type { TextSanitizer } from "../redact.ts";

export type TipTreeLensOptions = {
  readonly repoDir: string;
  /** the revision whose TREE is the landing-grade object — pre-push this is local HEAD,
   *  the exact commit `border push` would fast-forward the configured branch to. */
  readonly rev: string;
  readonly env?: Readonly<Record<string, string | undefined>>;
  /** run findings ride the pipeline's TextSanitizer (G23/F4: twin raw values register,
   *  location-class values never do — scanTipTree enforces the rule internally). */
  readonly sanitizer?: TextSanitizer;
  /** engine-policy skips, mirroring the pipeline's broken.has() legs (never native). */
  readonly skipGitleaks?: boolean;
  readonly skipSecretlint?: boolean;
};

/** Scan the full tree of `rev` with the landing-grade machinery. Throws on any git failure — the CLI maps that to exit 2. */
export async function scanTipTreeLens(o: TipTreeLensOptions): Promise<Finding[]> {
  const env = o.env ?? (process.env as Readonly<Record<string, string | undefined>>);
  const git = makeGit(o.repoDir, env);
  const treeRoot = mkdtempSync(join(tmpdir(), "border-check-tip-tree-"));
  try {
    return await scanTipTree(git, treeRoot, o.rev, env, {
      ...(o.sanitizer !== undefined ? { sanitizer: o.sanitizer } : {}),
      ...(o.skipGitleaks === true ? { skipGitleaks: true } : {}),
      ...(o.skipSecretlint === true ? { skipSecretlint: true } : {}),
    });
  } finally {
    rmSync(treeRoot, { recursive: true, force: true });
  }
}
