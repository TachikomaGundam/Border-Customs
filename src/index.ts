#!/usr/bin/env node
// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 7
//
// Thin bin entry (package.json bin: border → dist/index.js). All parsing and
// dispatch lives in src/cli.ts; this file only decides "am I the entrypoint"
// and maps run()'s return onto process.exitCode. No process.exit anywhere —
// exit codes are the contract (src/cli/exit.ts), writers are injectable.
import { pathToFileURL } from "node:url";

import { run } from "./cli.ts";

export { SUBCOMMANDS, usage, run } from "./cli.ts";
export type { CommandHandler, Ctx, Flags, Subcommand, Writer } from "./cli.ts";
export { EXIT_PASS, EXIT_BLOCKED, EXIT_ERROR, translateError } from "./cli/exit.ts";

function isMainModule(): boolean {
  const entry = process.argv[1];
  return entry !== undefined && import.meta.url === pathToFileURL(entry).href;
}

if (isMainModule()) {
  const outcome = run(process.argv.slice(2));
  process.exitCode = outcome instanceof Promise ? await outcome : outcome;
}
