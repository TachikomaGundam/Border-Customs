// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 7
//
// `border status` — stub until plan todo 19 (reports + newest-ledger table).
import { EXIT_ERROR, type BorderExit } from "../cli/exit.ts";
import type { Ctx } from "../cli/types.ts";

export function runStatus(ctx: Ctx): BorderExit {
  ctx.stderr("border: 'status' is not implemented yet (plan todo 19 wires the ledger table)");
  return EXIT_ERROR;
}
