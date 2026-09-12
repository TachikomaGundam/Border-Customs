#!/usr/bin/env node
// provenance: original clean-room implementation per .omo/plans/border-opencode-plugin.md
// Tiny fake border CLI for plugin tests: echoes argv token per line, optionally
// writes a fixed stderr line (ECHO_STDERR=1), exits with FAKE_EXIT (default 0).
for (const token of process.argv.slice(2)) {
  process.stdout.write(`argv: ${token}\n`);
}
if (process.env.ECHO_STDERR === "1") {
  process.stderr.write("fixture stderr line\n");
}
process.exit(Number(process.env.FAKE_EXIT ?? "0"));