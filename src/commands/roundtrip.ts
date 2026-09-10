// provenance: border-inspect-roadmap.md W2.1 — `border roundtrip` command adapter.
import type { CommandHandler } from "../cli/types.ts";
import { runRoundtripCore } from "../roundtrip/orchestrate.ts";

export const runRoundtrip: CommandHandler = (ctx) => runRoundtripCore(ctx);
