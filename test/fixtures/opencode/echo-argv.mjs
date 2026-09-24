#!/usr/bin/env node
// provenance: original clean-room implementation per .omo/plans/border-opencode-plugin.md
// Tiny fake border CLI for plugin tests. The bare `--help` invocation answers
// with border's identity signature (banner + usage line) at exit 0, so the
// plugin's identity handshake passes; any other argv echoes one token per line,
// optionally writes a fixed stderr line (ECHO_STDERR=1), exits with FAKE_EXIT
// (default 0). Splitting the two keeps probe and verdict legs independent.
const argv = process.argv.slice(2);
if (argv.length === 1 && argv[0] === "--help") {
  process.stdout.write("border — fake gate (test fixture)\n\nusage: border <command> [options]\n");
  process.exit(0);
}
for (const token of argv) {
  process.stdout.write(`argv: ${token}\n`);
}
if (process.env["ECHO_STDERR"] === "1") {
  process.stderr.write("fixture stderr line\n");
}
process.exit(Number(process.env["FAKE_EXIT"] ?? "0"));
