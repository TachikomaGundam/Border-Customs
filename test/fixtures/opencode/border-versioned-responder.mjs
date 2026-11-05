#!/usr/bin/env node
// provenance: border dual-face remediation wave 2026-11-05 (B1) — fake border CLI that
// answers --help as border (handshake PASS), answers --version with the FAKE_STAMP
// stamp (default 0.0.0), and echoes argv for anything else, exiting FAKE_EXIT.
const argv = process.argv.slice(2);
if (argv.length === 1 && argv[0] === "--help") {
  process.stdout.write("border — fake gate (test fixture)\n\nusage: border <command> [options]\n");
  process.exit(0);
}
if (argv.length === 1 && argv[0] === "--version") {
  process.stdout.write(`border ${process.env["FAKE_STAMP"] ?? "0.0.0"}+feedface\n`);
  process.exit(0);
}
for (const token of argv) {
  process.stdout.write(`argv: ${token}\n`);
}
process.exit(Number(process.env["FAKE_EXIT"] ?? "0"));
