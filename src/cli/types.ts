// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 7
//
// The run(ctx) contract — the seam that keeps cli.ts frozen while later todos
// (10 check, 15/16/17 push, 18 llm, 19 status) fill in src/commands/*.ts.
// A handler:
//   * receives parsed G9 flags, cwd/env and its writers — never touches
//     process.argv/process.exit itself;
//   * returns a BorderExit (0|1|2, src/cli/exit.ts) or a promise of one;
//   * throws typed errors (ConfigError/EnginePolicyError/EngineRunError/...)
//     which cli.run maps to exit 2 via translateError.
// Dry-run rule (G10, round-5 m-R5-a): `push` WITHOUT --yes performs ZERO
// mutations and exits with the verdict the gate would produce — clean⇒0,
// gate-blocked⇒1, gate-unavailable⇒2. It must never print a misleading 0.
import type { BorderExit } from "./exit.ts";

export const SUBCOMMANDS = ["check", "push", "status", "llm-request", "llm-ingest"] as const;

export type Subcommand = (typeof SUBCOMMANDS)[number];

/** Parsed form of the G9 flag table (cli.ts owns validation; handlers just read). */
export type Flags = {
  readonly config?: string;
  readonly targets?: readonly string[];
  readonly force: boolean;
  readonly yes: boolean;
  readonly requireEngine?: readonly string[];
  readonly llm: boolean;
  readonly json: boolean;
};

export type Writer = (line: string) => void;

/** One-line handler contract for `border push`'s DRY-RUN default (G10/m-R5-a). */
export type CommandHandler = (ctx: Ctx) => BorderExit | Promise<BorderExit>;

/**
 * Everything a command handler may observe. `handlers` is the live registry,
 * so a command can invoke a sibling (push dry-run → check gate verdict) and
 * still be redirected by test spies without editing cli.ts.
 */
export type Ctx = {
  readonly command: Subcommand;
  readonly flags: Flags;
  /** Positional args after the subcommand (e.g. `llm-ingest <findings.json>`). */
  readonly positionals: readonly string[];
  readonly cwd: string;
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly stdout: Writer;
  readonly stderr: Writer;
  readonly handlers: Record<Subcommand, CommandHandler>;
};
