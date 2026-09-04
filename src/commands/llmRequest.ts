// provenance: stub from plan todo 7, wired by plan todo 18 (bundle contract in src/llm.ts)
//
// `border llm-request` — thin CLI seam over runLlmRequestCore. cli.ts and the
// commands/index.ts registry are frozen; only this handler body changed.
import type { BorderExit } from "../cli/exit.ts";
import type { Ctx } from "../cli/types.ts";
import { runLlmRequestCore } from "../llm.ts";

export async function runLlmRequest(ctx: Ctx): Promise<BorderExit> {
  return runLlmRequestCore(ctx);
}
