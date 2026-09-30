// border-opencode-plugin v0.7.1
// Official opencode plugin adapter for the border fail-closed push gate.
// Registers ONE agent tool, `border`, that drives the border CLI — argv-only
// (node:child_process execFile, never a shell), top-level commands restricted
// to an allowlist, hard 300s timeout, capped output. The CLI itself remains
// the human gate: nothing here can push for real (a bare `border push` is a
// DRY-RUN by the CLI's own contract, and `--yes` is refused outright).
//
// Dual-shape default export — one module, two host generations:
// V1 plugin format (opencode >= 1.18.29, object entry): { id, server }, where
// server(input, options) resolves to Hooks; Hooks.tool is a
// { [name]: ToolDefinition } record (see @opencode-ai/plugin). The V1 host
// ignores the extra `setup` key (this is the official dual-shape form).
// V2 plugin format (@opencode-ai/cli beta line): the loader accepts only
// { id, setup } (or { id, effect }) and silently drops anything else, so the
// SAME tool registers through setup(ctx) -> ctx.tool.transform ->
// editor.add(Info). Both edges share the pre-spawn gate (gateArgv) and the
// execute substance (buildToolResult) below, so behavior stays identical;
// test/opencode.v2shape.test.ts pins V1↔V2 rendering and refusal parity.
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
//
// NEVER spawn the host: this module runs inside the opencode process, whose
// process.execPath is the opencode (bun-compiled) binary, not node. The 0.5.0
// packaged-sibling route used process.execPath + dist/index.js as argv — on
// Route B that spawned opencode with the dist path as a subcommand: the gate
// was silently replaced by the host (impersonation incident, 2026-09-22; the
// node --test seam was blind because there execPath really is node). Since
// 0.5.1 the packaged dist is exec'd DIRECTLY (shebang) or under PATH `node`,
// and every candidate must pass an identity handshake (`--help` answering as
// border) before any user argv is ever spawned. Unverifiable ⇒ exit 2
// cannot-answer, never a fallback to some other binary.

import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { tool, type Config } from "@opencode-ai/plugin";

/** Spawn cap: a CLI call that outlives this is killed and reported, never awaited forever. */
const TIMEOUT_MS = 300_000;
/** Identity-handshake cap: a `--help` needing longer than this is not a border CLI. */
const PROBE_TIMEOUT_MS = 20_000;
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

/** How to reach the CLI: a binary name/absolute path, optionally a script prefix. */
interface BinResolution {
  readonly bin: string;
  /** argv to prepend before the CLI's own argv (the dist entry when hosted by PATH node). */
  readonly prefix: readonly string[];
  /** Human-readable candidate identity, named in the cannot-answer note. */
  readonly label: string;
}

/**
 * Candidate order: BORDER_BIN (non-empty) wins alone on every route — a broken
 * explicit override is a loud error, never a silent fallback; else the dist
 * bundle sitting next to this module, exec'd directly through its shebang and,
 * if that is not runnable, under PATH `node` (Route B + dev checkout); else the
 * `border` bin from PATH (Route A). process.execPath is deliberately absent:
 * inside a plugin host it is the HOST binary, not a JS runtime.
 */
function candidateList(): readonly BinResolution[] {
  const configured = process.env["BORDER_BIN"];
  if (configured !== undefined && configured.length > 0) {
    return [{ bin: configured, prefix: [], label: `BORDER_BIN=${configured}` }];
  }
  const distEntry = fileURLToPath(new URL("../dist/index.js", import.meta.url));
  const candidates: BinResolution[] = [];
  if (existsSync(distEntry)) {
    candidates.push({ bin: distEntry, prefix: [], label: "packaged dist/index.js (shebang exec)" });
    candidates.push({ bin: "node", prefix: [distEntry], label: "packaged dist/index.js under PATH node" });
  }
  candidates.push({ bin: "border", prefix: [], label: "border on PATH" });
  return candidates;
}

interface CliResult {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly note: string;
  /** The child could not be spawned at all (ENOENT/EACCES/ENOEXEC) — never a gate verdict. */
  readonly spawnFailed: boolean;
}

/** The subset of the execFile error shape this adapter reads (node sets `code` on failures). */
interface SpawnError extends Error {
  readonly code?: string | number | null;
  readonly killed?: boolean;
  readonly signal?: string | null;
}

/** Never rejects: every spawn failure becomes a structured result the agent can read. */
function runCli(resolution: BinResolution, argv: readonly string[], timeoutMs: number): Promise<CliResult> {
  return new Promise((resolve) => {
    execFile(
      resolution.bin,
      [...resolution.prefix, ...argv],
      { timeout: timeoutMs, maxBuffer: MAX_OUTPUT_BYTES, shell: false },
      (error, stdout, stderr) => {
        const out = stdout.slice(0, MAX_OUTPUT_BYTES);
        const errOut = stderr.slice(0, MAX_OUTPUT_BYTES);
        if (error === null) {
          resolve({ status: 0, stdout: out, stderr: errOut, note: "", spawnFailed: false });
          return;
        }
        const failure = error as SpawnError;
        if (failure.code === "ENOENT" || failure.code === "EACCES" || failure.code === "ENOEXEC") {
          resolve({
            status: 2,
            stdout: out,
            stderr: errOut,
            spawnFailed: true,
            note: `cannot-answer: the border CLI could not be spawned (${String(failure.code)}).`,
          });
          return;
        }
        if (failure.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") {
          resolve({
            status: -1,
            stdout: out,
            stderr: errOut,
            note: `output exceeded ${MAX_OUTPUT_BYTES} bytes per stream and was truncated.`,
            spawnFailed: false,
          });
          return;
        }
        if (failure.killed === true || (failure.signal !== undefined && failure.signal !== null)) {
          resolve({
            status: 124,
            stdout: out,
            stderr: errOut,
            note:
              `killed after ${timeoutMs / 1000}s timeout (signal ${failure.signal ?? "SIGTERM"}). ` +
              "border check and roundtrip can be long — if you need a long roundtrip, " +
              "prefer running it in a terminal.",
            spawnFailed: false,
          });
          return;
        }
        resolve({
          status: typeof failure.code === "number" ? failure.code : -1,
          stdout: out,
          stderr: errOut,
          note:
            typeof failure.code === "number" ? "" : `spawn failed: ${failure.message}`,
          spawnFailed: false,
        });
      },
    );
  });
}

/**
 * border's --help contract (src/cli.ts): exit 0, banner line starts with
 * `border`, usage line names `usage: border`. An impostor answering the spawn
 * slot (the 2026-09-22 incident: the opencode host banner) fails this test, so
 * user argv is never handed to a binary that cannot prove it is the gate.
 * Honest boundary: this catches mistaken identity, not a forged banner.
 */
function isBorderHelp(result: CliResult): boolean {
  if (result.status !== 0) return false;
  const firstLine = (result.stdout.match(/^\s*(.*)/) ?? ["", ""])[1] ?? "";
  return firstLine.startsWith("border") && result.stdout.includes("usage: border");
}

type Resolution =
  | { readonly ok: true; readonly resolution: BinResolution }
  | { readonly ok: false; readonly reasons: readonly string[] };

/** Positive handshakes are cached per BORDER_BIN key for the host process's
 * life; failures are never cached, so a mid-session install recovers on the
 * next call. */
let verified: { readonly key: string; readonly resolution: BinResolution } | null = null;

async function resolveVerified(): Promise<Resolution> {
  const key = process.env["BORDER_BIN"] ?? "";
  if (verified !== null && verified.key === key) {
    return { ok: true, resolution: verified.resolution };
  }
  const reasons: string[] = [];
  for (const candidate of candidateList()) {
    const probe = await runCli(candidate, ["--help"], PROBE_TIMEOUT_MS);
    if (isBorderHelp(probe)) {
      verified = { key, resolution: candidate };
      return { ok: true, resolution: candidate };
    }
    reasons.push(
      probe.status === 0
        ? `${candidate.label}: spawned but --help did not answer as border (impostor?)`
        : `${candidate.label}: probe exit ${String(probe.status)}${probe.note === "" ? "" : ` — ${probe.note}`}`,
    );
  }
  return { ok: false, reasons };
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

// --- V2 loader surface: local structural types ---------------------------------
// shape proven from @opencode-ai/plugin beta-19271 .d.ts; live-gated by
// test/opencode.v2.probe (plan T3). Deliberately NO V2 SDK import here (wave
// plan D1/R3 pending): only the two members the setup() seam touches are
// typed — ctx.tool.transform and editor.add — everything else stays opaque.

/** Parsed tool input, mirroring the V1 args schema (command required, extra optional). */
interface V2ToolArgs {
  readonly command: string;
  readonly extra?: readonly string[];
}

/** The V2 promise-entry result envelope: the rendered text in `content`. */
interface V2ToolResult {
  readonly content: string;
}

/** One tool registration handed to ToolEditor.add by the transform callback. */
export interface V2ToolInfo {
  readonly name: string;
  readonly description: string;
  /** Pure JSON Schema — ValueSchema accepts it without a schema-library import. */
  readonly input: Record<string, unknown>;
  readonly execute: (args: V2ToolArgs, context?: unknown) => Promise<V2ToolResult>;
}

export interface V2ToolEditor {
  add(info: V2ToolInfo): void;
}

interface V2ToolRegistry {
  transform(callback: (editor: V2ToolEditor) => void): Promise<unknown>;
}

export interface V2PluginContext {
  readonly tool: V2ToolRegistry;
}

/**
 * The ONE tool description, byte-shared by both edges: the V1 tool() schema
 * and the V2 Info both render exactly this text (single source of truth).
 */
const TOOL_DESCRIPTION =
  "Run the border fail-closed push-gate CLI on this machine. " +
  "Pass the top-level command word in `command` (one of: check, push, status, " +
  "llm-request, llm-ingest, scan, roundtrip, --help) and every remaining argv " +
  "token in `extra`. The call is spawned argv-only (no shell) with a 300s " +
  "timeout; the result always ends with the CLI exit code: 0 pass, 1 " +
  "gate-blocked or partial push, 2 gate could not answer. Before running your " +
  "argv the tool handshakes its binary candidate with `--help` and refuses " +
  "everything (exit 2, cannot-answer) unless the responder provably is the " +
  "border CLI — it never falls back to another binary. Honest privilege " +
  "note: this tool runs the border CLI, and the CLI IS the gate that decides " +
  "what leaves this machine — it carries the same power as the binary, so an " +
  "agent may only *ask* the gate, never bypass it. `push --yes` is " +
  "deliberately NOT reachable here: real pushes are the human gate and belong " +
  "to a terminal. A bare `border push` through this tool is a DRY-RUN by the " +
  "CLI's own contract.";

/**
 * The pre-spawn gate — the deliberate seam split, load-bearing for security:
 *   gateArgv(argv) decides WHETHER the argv may run at all (allowlist
 *   membership, `--yes` refusal) and returns the refusal text or null;
 *   buildToolResult(argv) does the actual work (handshake, spawn, render)
 *   and NEVER re-gates — it trusts its caller.
 * Every edge (today: V1 tool.execute and V2 Info.execute) MUST call gateArgv
 * BEFORE buildToolResult. A future edge that skips the gate silently gets no
 * gating; test/opencode.v2shape.test.ts pins refusal parity on both edges.
 */
function gateArgv(argv: readonly string[]): string | null {
  const command = argv[0] ?? "";
  if (!ALLOWED_COMMANDS.includes(command)) {
    return (
      `border: refused '${command}' — not an allowed command. ` +
      `Allowed: ${ALLOWED_COMMANDS.join(", ")}. Put the command word in 'command' ` +
      `and every other token in 'extra'.`
    );
  }
  if (argv.includes("--yes")) {
    return (
      `border: refused '${command}' with '--yes' — a real push is the human gate ` +
      `and happens in a terminal. Run \`border push --yes\` there if a visible ` +
      `human go-ahead exists. A bare \`border push\` through this tool is a ` +
      `DRY-RUN by the CLI's own contract.`
    );
  }
  return null;
}

/**
 * The tool-execute substance shared by both edges (wave plan D2): resolve the
 * CLI via resolveVerified (identity handshake included), spawn it argv-only
 * via runCli, render the sectioned result. No gates and no V1-only
 * context.metadata here — those stay at each edge, see gateArgv above.
 */
async function buildToolResult(argv: readonly string[]): Promise<string> {
  const resolution = await resolveVerified();
  if (!resolution.ok) {
    return [
      `$ border ${argv.join(" ")}`,
      "exit: 2",
      `note: cannot-answer — no border CLI passed the identity handshake, so nothing was run. Tried: ${resolution.reasons.join("; ")}. ` +
        "Remedies: point BORDER_BIN at a real border CLI, run 'border opencode install' (route A), or npm i -g border-customs (PATH entry).",
      "--- stdout ---\n(empty)",
      "--- stderr ---\n(empty)",
    ].join("\n");
  }
  const result = await runCli(resolution.resolution, argv, TIMEOUT_MS);
  if (result.spawnFailed) verified = null;
  const sections = [
    `$ border ${argv.join(" ")}`,
    `exit: ${String(result.status)}`,
  ];
  if (result.note.length > 0) sections.push(`note: ${result.note}`);
  sections.push(`--- stdout ---\n${result.stdout.length === 0 ? "(empty)" : result.stdout}`);
  sections.push(`--- stderr ---\n${result.stderr.length === 0 ? "(empty)" : result.stderr}`);
  return sections.join("\n");
}

/** The V2-side tool registration: same gate + same substance as the V1 tool. */
function makeV2ToolInfo(): V2ToolInfo {
  return {
    name: "border",
    description: TOOL_DESCRIPTION,
    input: {
      type: "object",
      properties: {
        command: { type: "string" },
        extra: { type: "array", items: { type: "string" } },
      },
      required: ["command"],
      additionalProperties: false,
    },
    execute: async (args: V2ToolArgs): Promise<V2ToolResult> => {
      const argv: readonly string[] = [args.command.trim(), ...(args.extra ?? [])];
      const refusal = gateArgv(argv);
      if (refusal !== null) return { content: refusal };
      return { content: await buildToolResult(argv) };
    },
  };
}

export default {
  // Shared plugin id: the V1 host reads it for the {id, server} object entry
  // and the V2 loader reads this same id for its {id, setup} schema check.
  id: "border",
  setup: async (ctx: V2PluginContext): Promise<void> => {
    // transform's return is awaited (Promise<Registration>), but the callback
    // body itself must stay SYNCHRONOUS — only editor.add inside, any async
    // work belongs in Info.execute (contract E3; pinned by v2shape test (d)).
    await ctx.tool.transform((editor: V2ToolEditor): void => {
      editor.add(makeV2ToolInfo());
    });
  },
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
        description: TOOL_DESCRIPTION,
        args: {
          command: tool.schema
            .string()
            .describe("border command word, e.g. 'check' or 'push' or '--help'"),
          extra: tool.schema
            .array(tool.schema.string())
            .optional()
            .describe("remaining argv tokens, e.g. ['--force']"),
        },
        // V1 edge: gate → V1-only metadata → shared substance (see gateArgv).
        execute: async (args, context) => {
          const argv: readonly string[] = [args.command.trim(), ...(args.extra ?? [])];
          const refusal = gateArgv(argv);
          if (refusal !== null) return refusal;
          context.metadata({ title: `border ${argv.join(" ")}` });
          return buildToolResult(argv);
        },
      }),
    },
  }),
};