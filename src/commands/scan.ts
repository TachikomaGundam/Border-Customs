// provenance: border-inspect-roadmap.md W1.2 — `border scan` command adapter.
import type { CommandHandler } from "../cli/types.ts";
import { runScanCore } from "../scan/scan.ts";

export const runScan: CommandHandler = (ctx) => runScanCore(ctx);
