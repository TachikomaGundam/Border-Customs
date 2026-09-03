// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 7
//
// The global command registry. cli.ts dispatches ONLY through this map, so a
// later todo wires real behavior by editing its own command module — cli.ts
// never changes (plan AC: "wire via thin run(ctx) registry"). Tests swap an
// entry with setHandler() and get the restore function back.
import type { CommandHandler, Subcommand } from "../cli/types.ts";

import { runCheck } from "./check.ts";
import { runLlmIngest } from "./llmIngest.ts";
import { runLlmRequest } from "./llmRequest.ts";
import { runPush } from "./push.ts";
import { runStatus } from "./status.ts";

export const handlers: Record<Subcommand, CommandHandler> = {
  check: runCheck,
  push: runPush,
  status: runStatus,
  "llm-request": runLlmRequest,
  "llm-ingest": runLlmIngest,
};

/** Test seam: replace one handler, get a restore closure back. */
export function setHandler(name: Subcommand, handler: CommandHandler): () => void {
  const previous = handlers[name];
  handlers[name] = handler;
  return () => {
    handlers[name] = previous;
  };
}
