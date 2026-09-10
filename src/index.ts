#!/usr/bin/env node
// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 7
//
// Thin bin entry (package.json bin: border → dist/index.js). All parsing and
// dispatch lives in src/cli.ts; this file only decides "am I the entrypoint"
// and maps run()'s return onto process.exitCode. No process.exit anywhere —
// exit codes are the contract (src/cli/exit.ts), writers are injectable.
import { realpathSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

import { run } from "./cli.ts";

export { SUBCOMMANDS, usage, run } from "./cli.ts";
export type { CommandHandler, Ctx, Flags, Subcommand, Writer } from "./cli.ts";
export { EXIT_PASS, EXIT_BLOCKED, EXIT_ERROR, translateError } from "./cli/exit.ts";

/** Entry-detection inputs, injectable so the predicate is unit-testable. */
export interface EntryProbe {
  /** process.argv[1] — the path the process was INVOKED with (may be a symlink). */
  readonly argv1: string | undefined;
  /** import.meta.url of the module deciding whether it is the entrypoint. */
  readonly moduleUrl: string;
  /** Canonicalizer (fs.realpathSync.native in production); may throw ENOENT. */
  readonly realpath: (p: string) => string;
}

// CONSUMER-SHIM FAILURE MODE (silent-bin incident, published border-customs
// @0.3.0/@0.3.1, reproduced 2026-09-10 against the npm-packed artifact):
// npm installs bin entries as symlinks — node_modules/.bin/border ->
// ../border-customs/dist/index.js — the shebang exec passes the LINK path as
// argv[1], while Node realpaths the main module so import.meta.url points at
// the TARGET. The old `import.meta.url === pathToFileURL(argv[1]).href`
// check therefore returned false, main() was skipped, and the CLI exited
// rc=0 with ZERO stdout/stderr — a security gate failing OPEN:
//   $ ./node_modules/.bin/border --help                  -> rc=0 0B out 0B err
//   $ ./node_modules/.bin/border scan puppeteer@23.11.1  -> rc=0 0B out 0B err
// Fix: realpath-canonicalize BOTH sides before comparing. Pinned by
// test/entryPoint.test.ts (predicate + node-semantics oracle) and
// test/releaseArtifacts.test.ts (pack → shim e2e, BORDER_PACK_TEST=1).
export function isMainModule({ argv1, moduleUrl, realpath }: EntryProbe): boolean {
  if (argv1 === undefined) return false;
  const canonical = (p: string): string => {
    try {
      return realpath(p);
    } catch {
      return p; // ENOENT-safe: fall back to the raw spelling, never throw at entry time
    }
  };
  return (
    pathToFileURL(canonical(argv1)).href ===
    pathToFileURL(canonical(fileURLToPath(moduleUrl))).href
  );
}

if (isMainModule({ argv1: process.argv[1], moduleUrl: import.meta.url, realpath: realpathSync.native })) {
  const outcome = run(process.argv.slice(2));
  process.exitCode = outcome instanceof Promise ? await outcome : outcome;
}
