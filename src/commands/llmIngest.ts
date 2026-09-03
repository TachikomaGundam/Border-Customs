// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 7
//
// `border llm-ingest <findings.json>` — stub until plan todo 18; malformed
// input will map to exit 2 via translateError(InvalidFindingError) once wired.
import { EXIT_ERROR, type BorderExit } from "../cli/exit.ts";
import type { Ctx } from "../cli/types.ts";

export function runLlmIngest(ctx: Ctx): BorderExit {
  ctx.stderr("border: 'llm-ingest' is not implemented yet (plan todo 18 wires the ingest contract)");
  return EXIT_ERROR;
}
