// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 7
//
// `border check` — stub until plan todo 10 (ref-scan + tree-scan pipeline)
// fills this file. Fail-closed honesty: until the gate exists, check reports
// "not implemented" with exit 2 and prints nothing on stdout, so no caller
// (push dry-run included, via ctx.handlers.check) can mistake it for a PASS.
import { EXIT_ERROR, type BorderExit } from "../cli/exit.ts";
import type { Ctx } from "../cli/types.ts";

export function runCheck(ctx: Ctx): BorderExit {
  ctx.stderr("border: 'check' is not implemented yet (plan todo 10 wires the gate pipeline)");
  return EXIT_ERROR;
}
