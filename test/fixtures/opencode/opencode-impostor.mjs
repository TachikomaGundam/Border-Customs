#!/usr/bin/env node
// provenance: 2026-09-22 impersonation-incident regression fixture.
// Behaves like a HOST binary that grabbed the spawn slot (what process.execPath
// did inside the opencode plugin host): `--help` answers with a non-border
// banner at exit 0 — exactly the shape that fooled the 0.5.0 adapter. Every
// invocation is logged to IMPOSTOR_LOG so tests can prove user argv was never
// handed to the impostor (only the handshake probe may appear).
import { appendFileSync } from "node:fs";

const log = process.env["IMPOSTOR_LOG"];
const argv = process.argv.slice(2);
if (log !== undefined && log.length > 0) {
  appendFileSync(log, `${argv.join(" ")}\n`);
}
if (argv.length === 1 && argv[0] === "--help") {
  process.stdout.write("opencode — AI coding agent\n\nUsage: opencode <command>\n\nCommands:\n  run\n  serve\n  upgrade\n");
  process.exit(0);
}
process.stderr.write("opencode: unknown command — showing usage\n");
process.exit(1);
