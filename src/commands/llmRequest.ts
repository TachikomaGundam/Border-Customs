// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 7
//
// `border llm-request` — stub until plan todo 18 (masked provenance bundle).
import { EXIT_ERROR, type BorderExit } from "../cli/exit.ts";
import type { Ctx } from "../cli/types.ts";

export function runLlmRequest(ctx: Ctx): BorderExit {
  ctx.stderr("border: 'llm-request' is not implemented yet (plan todo 18 wires the bundle contract)");
  return EXIT_ERROR;
}
