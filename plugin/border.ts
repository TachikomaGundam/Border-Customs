// border-opencode-plugin v0.5.0
// Official opencode plugin adapter for the border fail-closed push gate.
// Registers ONE agent tool, `border`, that drives the border CLI — argv-only
// (node:child_process execFile, never a shell), top-level commands restricted
// to an allowlist, hard 300s timeout, capped output. The CLI itself remains
// the human gate: nothing here can push for real (a bare `border push` is a
// DRY-RUN by the CLI's own contract, and `--yes` is refused outright).
//
// V1 plugin format (opencode >= 1.14): default export { id, server }, where
// server(input, options) resolves to Hooks; Hooks.tool is a
// { [name]: ToolDefinition } record (see @opencode-ai/plugin).
// This file ships as-is (package.json "files") and reaches a session by two
// routes, neither compiling it through border's tsc:
// (A) copied into <CONFIG>/plugins/ by `border opencode install`, which also
//     drops commands/border.md; "@opencode-ai/plugin" then resolves in
//     opencode's config-directory node_modules.
// (B) served as the package's "./server" export when the npm package name is
//     listed in opencode.jsonc "plugin" — opencode's arborist install places
//     @opencode-ai/plugin (its runtime dependency) next to the package in the
//     cache, so the same import resolves there too. With no commands/border.md
//     on disk, the config hook below self-registers the slash command instead.
//     On this route the CLI is spawned FROM THE PACKAGE ITSELF (../dist/index.js
//     lives inside the same tarball), so no global install or PATH entry is
//     needed — that is what makes Route B genuinely install-free.

import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { tool, type Config } from "@opencode-ai/plugin";

/** Spawn cap: a CLI call that outlives this is killed and reported, never awaited forever. */
const TIMEOUT_MS = 300_000;
/** Per-stream output cap fed back into the session; keeps one tool call from flooding context. */
const MAX_OUTPUT_BYTES = 64 * 1024;

/** The eight tool-reachable top-level commands plus --help. Anything else is refused locally.
 * A real push is the human gate and is deliberately not reachable here: any argv
 * containing `--yes` is refused, and bare `border push` is DRY-RUN by CLI contract. */
const ALLOWED_COMMANDS: readonly string[] = [
  "check",
  "push",
  "status",
  "llm-request",
  "llm-ingest",
  "scan",
  "roundtrip",
  "--help",
];

/** How to reach the CLI: a binary name/absolute path, optionally under node itself. */
interface BinResolution {
  readonly bin: string;
  /** argv to prepend before the CLI's own argv (the dist entry when hosted by node). */
  readonly prefix: readonly string[];
}

/**
 * Resolution order: BORDER_BIN (non-empty) wins on every route; else the dist
 * bundle sitting next to this module in the package/repo layout (Route B and
 * dev checkout, spawned under node); else the `border` bin from PATH (Route A).
 */
function resolveBin(): BinResolution {
  const configured = process.env["BORDER_BIN"];
  if (configured !== undefined && configured.length > 0) return { bin: configured, prefix: [] };
  const distEntry = fileURLToPath(new URL("../dist/index.js", import.meta.url));
  if (existsSync(distEntry)) return { bin: process.execPath, prefix: [distEntry] };
  return { bin: "border", prefix: [] };
}

interface CliResult {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly note: string;
}

/** The subset of the execFile error shape this adapter reads (node sets `code` on failures). */
interface SpawnError extends Error {
  readonly code?: string | number | null;
  readonly killed?: boolean;
  readonly signal?: string | null;
}

/** Never rejects: every spawn failure becomes a structured result the agent can read. */
function runCli(bin: string, prefix: readonly string[], argv: readonly string[]): Promise<CliResult> {
  return new Promise((resolve) => {
    execFile(
      bin,
      [...prefix, ...argv],
      { timeout: TIMEOUT_MS, maxBuffer: MAX_OUTPUT_BYTES, shell: false },
      (error, stdout, stderr) => {
        const out = stdout.slice(0, MAX_OUTPUT_BYTES);
        const errOut = stderr.slice(0, MAX_OUTPUT_BYTES);
        if (error === null) {
          resolve({ status: 0, stdout: out, stderr: errOut, note: "" });
          return;
        }
        const failure = error as SpawnError;
        if (failure.code === "ENOENT") {
          resolve({
            status: 127,
            stdout: out,
            stderr: errOut,
            note:
              "the border CLI could not be spawned. Three remedies: set BORDER_BIN to a " +
              "real border binary, or run 'border opencode install' (route A), or " +
              "npm i -g border-customs (route A, PATH entry).",
          });
          return;
        }
        if (failure.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") {
          resolve({
            status: -1,
            stdout: out,
            stderr: errOut,
            note: `output exceeded ${MAX_OUTPUT_BYTES} bytes per stream and was truncated.`,
          });
          return;
        }
        if (failure.killed === true || (failure.signal !== undefined && failure.signal !== null)) {
          resolve({
            status: 124,
            stdout: out,
            stderr: errOut,
            note:
              `killed after ${TIMEOUT_MS / 1000}s timeout (signal ${failure.signal ?? "SIGTERM"}). ` +
              "border check and roundtrip can be long — if you need a long roundtrip, " +
              "prefer running it in a terminal.",
          });
          return;
        }
        resolve({
          status: typeof failure.code === "number" ? failure.code : -1,
          stdout: out,
          stderr: errOut,
          note:
            typeof failure.code === "number" ? "" : `spawn failed: ${failure.message}`,
        });
      },
    );
  });
}

/**
 * The /border slash-command template. ALSO published verbatim (after the marker
 * line) as plugin/border-command.md — test/opencode.test.ts pins the byte-mirror.
 */
export const COMMAND_TEMPLATE = `Drive the border fail-closed push gate through the \`border\` tool.

User request: $ARGUMENTS

Interpret the request as ONE \`border\` CLI invocation: the first word is the
command (\`check\`, \`push\`, \`status\`, \`llm-request\`, \`llm-ingest\`, \`scan\`,
\`roundtrip\`, or \`--help\`) and the rest are argv tokens. Call the \`border\` tool
with \`command\` set to the first word and \`extra\` set to the remaining tokens,
then report the CLI exit code (0 pass / 1 gate-blocked or partial push / 2 gate
could not answer) and the relevant lines of its output. If no request was given,
call the tool with \`command: "--help"\` and summarize the command list from it.
\`push --yes\` is refused by the tool — a real push is the human gate and belongs
to a terminal: if the user asks for one, tell them to run \`border push --yes\`
there. A bare \`border push\` through the tool is a DRY-RUN by the CLI's own
contract: it reports the verdict the gate would produce without touching any
remote.
`;

export default {
  id: "border",
  server: async () => ({
    // Self-registering /border: opencode calls hook.config(cfg) once per
    // instance after ALL config sources are merged — file-based commands are
    // already in cfg.command by then. `??=` keeps a Route-A commands/border.md
    // authoritative and only fills the gap for Route B; the command map is
    // keyed by name, so a same-name file + injection never duplicates.
    config: async (cfg: Config) => {
      cfg.command ??= {};
      cfg.command.border ??= {
        description: "Drive the border push gate (usage: /border <command> [args...])",
        template: COMMAND_TEMPLATE,
      };
    },
    tool: {
      border: tool({
        description:
          "Run the border fail-closed push-gate CLI on this machine. " +
          "Pass the top-level command word in `command` (one of: check, push, status, " +
          "llm-request, llm-ingest, scan, roundtrip, --help) and every remaining argv " +
          "token in `extra`. The call is spawned argv-only (no shell) with a 300s " +
          "timeout; the result always ends with the CLI exit code: 0 pass, 1 " +
          "gate-blocked or partial push, 2 gate could not answer. Honest privilege " +
          "note: this tool runs the border CLI, and the CLI IS the gate that decides " +
          "what leaves this machine — it carries the same power as the binary, so an " +
          "agent may only *ask* the gate, never bypass it. `push --yes` is " +
          "deliberately NOT reachable here: real pushes are the human gate and belong " +
          "to a terminal. A bare `border push` through this tool is a DRY-RUN by the " +
          "CLI's own contract.",
        args: {
          command: tool.schema
            .string()
            .describe("border command word, e.g. 'check' or 'push' or '--help'"),
          extra: tool.schema
            .array(tool.schema.string())
            .optional()
            .describe("remaining argv tokens, e.g. ['--force']"),
        },
        execute: async (args, context) => {
          const command = args.command.trim();
          if (!ALLOWED_COMMANDS.includes(command)) {
            return (
              `border: refused '${command}' — not an allowed command. ` +
              `Allowed: ${ALLOWED_COMMANDS.join(", ")}. Put the command word in 'command' ` +
              `and every other token in 'extra'.`
            );
          }
          const extra = args.extra ?? [];
          if (extra.includes("--yes")) {
            return (
              `border: refused '${command}' with '--yes' — a real push is the human gate ` +
              `and happens in a terminal. Run \`border push --yes\` there if a visible ` +
              `human go-ahead exists. A bare \`border push\` through this tool is a ` +
              `DRY-RUN by the CLI's own contract.`
            );
          }
          const argv: readonly string[] = [command, ...extra];
          context.metadata({ title: `border ${argv.join(" ")}` });
          const resolution = resolveBin();
          const result = await runCli(resolution.bin, resolution.prefix, argv);
          const sections = [
            `$ border ${argv.join(" ")}`,
            `exit: ${String(result.status)}`,
          ];
          if (result.note.length > 0) sections.push(`note: ${result.note}`);
          sections.push(`--- stdout ---\n${result.stdout.length === 0 ? "(empty)" : result.stdout}`);
          sections.push(`--- stderr ---\n${result.stderr.length === 0 ? "(empty)" : result.stderr}`);
          return sections.join("\n");
        },
      }),
    },
  }),
};