#!/usr/bin/env node
// provenance: .omo/plans/border-opencode-inspect.md T5 — a --help responder that
// PASSES the identity handshake (border banner first line + `usage: border`),
// the honest-CLI twin of opencode-impostor.mjs. Used as BORDER_BIN by the
// CLI-surface inspect tests so the handshake aspect resolves hermetically
// without requiring a built dist on a fresh checkout.
process.stdout.write("border — fail-closed gate: nothing leaves this machine unchecked\n\nusage: border <command> [options]\n");
process.exit(0);
