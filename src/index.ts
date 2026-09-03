#!/usr/bin/env node
// border — fail-closed push gate CLI entry point.
// Argument parsing/real gate wiring arrives in plan todo 7; this entry is the
// honest CLI surface: help lists every subcommand, anything not wired up fails
// loudly with exit 2 instead of faking success.
import { pathToFileURL } from "node:url";

export const SUBCOMMANDS = [
  "check",
  "push",
  "status",
  "llm-request",
  "llm-ingest",
] as const;

export type Subcommand = (typeof SUBCOMMANDS)[number];

type Writer = (line: string) => void;

function isSubcommand(value: string): value is Subcommand {
  return (SUBCOMMANDS as readonly string[]).includes(value);
}

export function usage(): string {
  return [
    "border — fail-closed gate: nothing leaves this machine unchecked",
    "",
    "usage: border <command> [options]",
    "",
    "commands:",
    "  check          run secret + supply-chain gate on the pending scope",
    "  push           gate-verified fast-forward push to remotes",
    "  status         show gate state, config, and engine versions",
    "  llm-request    emit the provenance request for LLM-authored commits",
    "  llm-ingest     record provenance captured by the harness",
    "",
    "subcommands: check, push, status, llm-request, llm-ingest",
  ].join("\n");
}

export function run(argv: readonly string[], stdout: Writer, stderr: Writer): number {
  const [command] = argv;
  if (command === "help" || command === "--help" || command === "-h") {
    stdout(usage());
    return 0;
  }
  if (command === undefined || !isSubcommand(command)) {
    stderr(`border: unknown command '${command ?? ""}' — run 'border --help' for usage`);
    return 2;
  }
  stderr(`border: '${command}' is not implemented yet (pending border-push-gate plan wiring)`);
  return 2;
}

function isMainModule(): boolean {
  const entry = process.argv[1];
  return entry !== undefined && import.meta.url === pathToFileURL(entry).href;
}

if (isMainModule()) {
  process.exitCode = run(
    process.argv.slice(2),
    (line) => {
      console.log(line);
    },
    (line) => {
      console.error(line);
    },
  );
}
