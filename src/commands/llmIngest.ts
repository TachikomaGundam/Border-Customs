// provenance: stub from plan todo 7, wired by plan todo 18 (ingest contract in src/llm.ts)
//
// `border llm-ingest <findings.json>` — thin CLI seam over runLlmIngestCore.
// cli.ts and the commands/index.ts registry are frozen; only this handler body
// changed.
import type { BorderExit } from "../cli/exit.ts";
import type { Ctx } from "../cli/types.ts";
import { runLlmIngestCore } from "../llm.ts";

export async function runLlmIngest(ctx: Ctx): Promise<BorderExit> {
  return runLlmIngestCore(ctx);
}
