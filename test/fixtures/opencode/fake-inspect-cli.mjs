#!/usr/bin/env node
// provenance: .omo/plans/border-opencode-inspect.md T5 — fake border CLI for the
// drift-watch shell tests. Prints FAKE_INSPECT_JSON verbatim on stdout and logs
// every invocation's argv (one line per spawn) to FAKE_INSPECT_LOG, so tests can
// prove the shell spawns exactly `opencode inspect --json` and nothing else.
// FAKE_INSPECT_RC (default 0) simulates the inspect exit-code contract.
import { appendFileSync } from "node:fs";

const log = process.env["FAKE_INSPECT_LOG"];
if (log !== undefined && log.length > 0) {
  appendFileSync(log, `${process.argv.slice(2).join(" ")}\n`);
}
process.stdout.write(`${process.env["FAKE_INSPECT_JSON"] ?? "{}"}\n`);
process.exit(Number(process.env["FAKE_INSPECT_RC"] ?? "0"));
