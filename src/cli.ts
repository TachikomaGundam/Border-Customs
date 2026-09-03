// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 7
//
// The CLI surface (G9 flag table, five subcommands) and its dispatch. This
// file is deliberately FROZEN after todo 7: every command lives behind the
// registry in src/commands/index.ts, so todos 10/15/18/19 replace handler
// behavior by editing their own command module — never the parser here.
// Only node:util parseArgs; no frameworks, no colors. Unknown subcommand or
// flag is a tool error: exit 2 + usage, never a silent ignore.
import { parseArgs } from "node:util";

import { handlers } from "./commands/index.ts";
import { EXIT_ERROR, EXIT_PASS, translateError, UnknownArgError } from "./cli/exit.ts";
import { SUBCOMMANDS, type CommandHandler, type Ctx, type Flags, type Subcommand, type Writer } from "./cli/types.ts";

export { SUBCOMMANDS, type CommandHandler, type Ctx, type Flags, type Subcommand, type Writer } from "./cli/types.ts";

const VALID_TARGETS = ["git", "npm", "pypi"] as const;

export function usage(): string {
  return [
    "border — fail-closed gate: nothing leaves this machine unchecked",
    "",
    "usage: border <command> [options]",
    "",
    "commands:",
    "  check          run secret + supply-chain gate on the pending scope",
    "  push           gate-verified push — DRY-RUN unless --yes executes",
    "  status         show gate state, config, and engine versions",
    "  llm-request    emit the provenance request for LLM-authored commits",
    "  llm-ingest     record provenance captured by the harness",
    "",
    "flags:",
    "  --config <path>             config file (default: ./border.yaml, then git-remote fallback)",
    "  --targets <git,npm,pypi>    comma-separated subset restricting this run's scope",
    "  --force                     ignore the skip-ledger, re-run the full check",
    "  --yes                       execute mutations; a bare `border push` is always DRY-RUN",
    "  --require-engine <list>     comma-separated engines that must be healthy (else exit 2)",
    "  --llm                       include the optional LLM review layer",
    "  --json                      machine-readable report on stdout",
    "  --help, -h                  this table",
    "",
    "exit codes: 0 pass (MEDIUM/INFO/LOW allowed) | 1 gate-blocked (CRITICAL/HIGH) or partial push | 2 config/tool error",
    "",
    "subcommands: check, push, status, llm-request, llm-ingest",
  ].join("\n");
}

function isSubcommand(value: string): value is Subcommand {
  return (SUBCOMMANDS as readonly string[]).includes(value);
}

/** `--targets` / `--require-engine` share the same comma-list grammar. */
function splitList(raw: string, opts: { flag: string; item: string; allowed?: readonly string[] }): readonly string[] {
  const items = raw.split(",").map((s) => s.trim()).filter((s) => s.length > 0);
  if (items.length === 0) throw new UnknownArgError(`${opts.flag} requires a comma-separated list`);
  if (opts.allowed !== undefined) {
    for (const item of items) {
      if (!(opts.allowed as readonly string[]).includes(item)) {
        throw new UnknownArgError(`unknown ${opts.item} '${item}' (${opts.flag} allows: ${opts.allowed.join(", ")})`);
      }
    }
  }
  return items;
}

function parseFlags(argv: readonly string[]): { flags: Flags; positionals: readonly string[]; help: boolean } {
  try {
    const { values, positionals } = parseArgs({
      args: [...argv],
      allowPositionals: true,
      options: {
        config: { type: "string" },
        targets: { type: "string" },
        force: { type: "boolean" },
        yes: { type: "boolean" },
        "require-engine": { type: "string" },
        llm: { type: "boolean" },
        json: { type: "boolean" },
        help: { type: "boolean" },
      },
    });
    const { config, targets, force, yes, llm, json } = values;
    const requireEngine = values["require-engine"];
    const flags: Flags = {
      ...(config !== undefined ? { config } : {}),
      ...(targets !== undefined
        ? { targets: splitList(targets, { flag: "--targets", item: "target", allowed: VALID_TARGETS }) }
        : {}),
      force: force === true,
      yes: yes === true,
      ...(requireEngine !== undefined
        ? { requireEngine: splitList(requireEngine, { flag: "--require-engine", item: "engine" }) }
        : {}),
      llm: llm === true,
      json: json === true,
    };
    return { flags, positionals, help: values.help === true };
  } catch (err) {
    if (err instanceof UnknownArgError) throw err;
    throw new UnknownArgError(err instanceof Error ? err.message : String(err));
  }
}

/** Tool failures print ONE sanitized stderr line; argument mistakes also earn the usage table. */
function failFrom(err: unknown, stderr: Writer, stdout: Writer): number {
  const t = translateError(err);
  stderr(`border: ${t.message}`);
  if (err instanceof UnknownArgError) stdout(usage());
  return t.code;
}

async function settle(
  pending: Promise<number>,
  stderr: Writer,
  stdout: Writer,
): Promise<number> {
  try {
    return await pending;
  } catch (err) {
    return failFrom(err, stderr, stdout);
  }
}

export type RunOverrides = {
  /** Fixture cwd for handlers (default: process.cwd()). */
  readonly cwd?: string;
  /** Env handed to loadConfig etc. (default: process.env). */
  readonly env?: Readonly<Record<string, string | undefined>>;
  /** Registry swap for tests (default: the live src/commands registry). */
  readonly handlers?: Record<Subcommand, CommandHandler>;
};

export function run(
  argv: readonly string[],
  stdout: Writer = (line) => {
    console.log(line);
  },
  stderr: Writer = (line) => {
    console.error(line);
  },
  overrides: RunOverrides = {},
): number | Promise<number> {
  const first = argv[0];
  if (first === "--help" || first === "-h" || first === "help") {
    stdout(usage());
    return EXIT_PASS;
  }
  if (first === undefined || !isSubcommand(first)) {
    stderr(`border: unknown command '${first ?? ""}' — run 'border --help' for usage`);
    stdout(usage());
    return EXIT_ERROR;
  }
  const registry = overrides.handlers ?? handlers;
  let parsed: ReturnType<typeof parseFlags>;
  try {
    parsed = parseFlags(argv.slice(1));
  } catch (err) {
    return failFrom(err, stderr, stdout);
  }
  if (parsed.help) {
    stdout(usage());
    return EXIT_PASS;
  }
  const ctx: Ctx = {
    command: first,
    flags: parsed.flags,
    positionals: parsed.positionals,
    cwd: overrides.cwd ?? process.cwd(),
    env: overrides.env ?? process.env,
    stdout,
    stderr,
    handlers: registry,
  };
  try {
    const outcome = registry[first](ctx);
    return typeof outcome === "number" ? outcome : settle(Promise.resolve(outcome), stderr, stdout);
  } catch (err) {
    return failFrom(err, stderr, stdout);
  }
}
