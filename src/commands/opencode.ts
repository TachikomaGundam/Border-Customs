// provenance: original clean-room implementation per .omo/plans/border-opencode-plugin.md
//
// `border opencode` — installer for the official opencode plugin adapter
// (plan D4, route A file drop). Pure file management: byte-copies the
// packaged V1 plugin (`<root>/plugin/border.ts`) and slash-command template
// (`<root>/plugin/border-command.md`) into
// `<XDG_CONFIG_HOME ?? HOME/.config>/opencode/{plugins,commands}/`. No network,
// no shell, no opencode process contact.
// Identity rule: a target is ours only if its FIRST LINE carries our marker; a
// foreign file at a target path is refused (exit 2), never overwritten, never
// deleted — there is no --force anywhere.
// Destination rule: a path that exists must be a plain regular file —
// directories and symlinks are refused via lstat, never followed, entered, or
// destroyed. Atomicity rule: every destination is validated BEFORE any write;
// a single foreign/odd target writes nothing anywhere, and every write is
// preceded by a fresh identity re-check (TOCTOU).

import { existsSync, lstatSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { EXIT_ERROR, EXIT_PASS, UnknownArgError, type BorderExit } from "../cli/exit.ts";
import type { Ctx } from "../cli/types.ts";
import { runInspectCore } from "../opencode/inspect.ts";
import {
  COMMAND_MARKER,
  PLUGIN_MARKER,
  firstLine,
  opencodeConfigRoot,
  sha256Hex,
  type Env,
} from "../opencode/contract.ts";

// Markers and the config-root rule live in the src/opencode/support.ts leaf,
// shared with the inspector (single source); re-exported for existing importers.
export { COMMAND_MARKER, PLUGIN_MARKER, opencodeConfigRoot };

/** One installable artifact: packaged source -> opencode destination. */
interface AssetTarget {
  readonly fileName: string;
  readonly destination: string;
  readonly marker: string;
}

type TargetState = "up-to-date" | "outdated" | "foreign" | "absent";

// Packaged assets live at <root>/plugin/ — two levels above src/commands/ in
// src mode, one level above dist/ in dist (bundled) mode; the assets.ts idiom
// is first-existing-candidate, and the canonical src-mode path doubles as the
// fail-closed error message when nothing exists.
function resolvePluginAsset(moduleUrl: string, fileName: string): string {
  const here = dirname(fileURLToPath(moduleUrl));
  const candidates = [
    join(here, "..", "plugin", fileName), // dist mode (bundled): <root>/plugin/<f>
    join(here, "..", "..", "plugin", fileName), // src mode: <root>/plugin/<f>
  ];
  return candidates.find((p) => existsSync(p)) ?? (candidates[1] as string);
}

function targetsFor(env: Env): readonly AssetTarget[] {
  const root = join(opencodeConfigRoot(env), "opencode");
  return [
    { fileName: "border.ts", destination: join(root, "plugins", "border.ts"), marker: PLUGIN_MARKER },
    { fileName: "border-command.md", destination: join(root, "commands", "border.md"), marker: COMMAND_MARKER },
  ];
}

function carriesMarker(bytes: Buffer, marker: string): boolean {
  return firstLine(bytes).startsWith(marker);
}

/** Operational failure: human-readable stderr line + exit 2 (status.ts idiom). */
function fail(ctx: Ctx, message: string): BorderExit {
  ctx.stderr(`border: opencode: ${message}`);
  return EXIT_ERROR;
}

/** Read the packaged asset, or report a broken install. */
function readPackagedAsset(ctx: Ctx, fileName: string): Buffer | null {
  const source = resolvePluginAsset(import.meta.url, fileName);
  try {
    return readFileSync(source);
  } catch {
    ctx.stderr(`border: opencode: packaged asset is missing (${source})`);
    ctx.stderr("border: opencode: the border install looks broken — `npm i -g border-customs` or a fresh checkout should carry plugin/.");
    return null;
  }
}

/** Read an existing target; absent (or unreadable) means none. */
function readTarget(destination: string): Buffer | null {
  try {
    return readFileSync(destination);
  } catch {
    return null;
  }
}

/** A destination that exists must be a plain regular file — never a dir or symlink. */
function requirePlainDestination(ctx: Ctx, destination: string): BorderExit | null {
  let shape: ReturnType<typeof lstatSync> | undefined;
  try {
    shape = lstatSync(destination);
  } catch {
    return null; // absent — the write path creates it fresh
  }
  if (!shape.isFile() || shape.isSymbolicLink()) {
    return fail(
      ctx,
      `refusing to touch ${destination} — the path exists but is not a plain regular file (directories and symlinks are never followed, entered, or destroyed)`,
    );
  }
  return null;
}

/** Classify a target from a fresh read; `null` current bytes => absent. */
function classify(target: AssetTarget, current: Buffer | null, packaged: Buffer): TargetState {
  if (current === null) return "absent";
  if (!carriesMarker(current, target.marker)) return "foreign";
  return current.equals(packaged) ? "up-to-date" : "outdated";
}

/** Refuse when any target is unsafe (foreign content or non-regular shape) — writes nothing anywhere. */
function requireNoForeign(ctx: Ctx, targets: readonly AssetTarget[]): BorderExit | null {
  for (const target of targets) {
    const shape = requirePlainDestination(ctx, target.destination);
    if (shape !== null) return shape;
    const current = readTarget(target.destination);
    if (current !== null && !carriesMarker(current, target.marker)) {
      return fail(
        ctx,
        `refusing to touch ${target.destination} — the file exists but is not ours (its first line lacks the marker '${target.marker}'); move it aside manually, nothing was written anywhere`,
      );
    }
  }
  return null;
}

/** Read both packaged assets before any validation or write starts. */
function prepareTargets(
  ctx: Ctx,
  targets: readonly AssetTarget[],
): { readonly target: AssetTarget; readonly packaged: Buffer }[] | null {
  const prepared: { readonly target: AssetTarget; readonly packaged: Buffer }[] = [];
  for (const target of targets) {
    const packaged = readPackagedAsset(ctx, target.fileName);
    if (packaged === null) return null;
    prepared.push({ target, packaged });
  }
  return prepared;
}

function opencodeInstall(ctx: Ctx): BorderExit {
  const targets = targetsFor(ctx.env);
  const prepared = prepareTargets(ctx, targets);
  if (prepared === null) return EXIT_ERROR;
  const blocked = requireNoForeign(ctx, targets);
  if (blocked !== null) return blocked;
  for (const { target, packaged } of prepared) {
    // The classify below reads afresh, so the identity holds at write time (TOCTOU).
    const current = readTarget(target.destination);
    const state = classify(target, current, packaged);
    if (state === "foreign") {
      return fail(
        ctx,
        `refusing to touch ${target.destination} — the file exists but is not ours (its first line lacks the marker '${target.marker}'); move it aside manually, nothing was written anywhere`,
      );
    }
    if (state === "up-to-date") {
      ctx.stdout(`${target.destination}: up to date`);
      continue;
    }
    mkdirSync(dirname(target.destination), { recursive: true });
    writeFileSync(target.destination, packaged);
    ctx.stdout(`${target.destination}: ${state === "outdated" ? "updated" : "installed"}`);
  }
  ctx.stdout("note: restart opencode to load the plugin — tools and commands are scanned at startup.");
  return EXIT_PASS;
}

function opencodeStatus(ctx: Ctx): BorderExit {
  const targets = targetsFor(ctx.env);
  const prepared = prepareTargets(ctx, targets);
  if (prepared === null) return EXIT_ERROR;
  for (const { target, packaged } of prepared) {
    const current = readTarget(target.destination);
    const state = classify(target, current, packaged);
    const installedSha = current === null ? "-" : sha256Hex(current);
    ctx.stdout(`${target.destination}: ${state}  installed=${installedSha}  packaged=${sha256Hex(packaged)}`);
  }
  return EXIT_PASS;
}

function opencodeUninstall(ctx: Ctx): BorderExit {
  const targets = targetsFor(ctx.env);
  const blocked = requireNoForeign(ctx, targets);
  if (blocked !== null) return blocked;
  for (const target of targets) {
    const current = readTarget(target.destination);
    if (current === null) {
      ctx.stdout(`${target.destination}: absent (nothing to remove)`);
      continue;
    }
    if (!carriesMarker(current, target.marker)) {
      return fail(
        ctx,
        `refusing to remove ${target.destination} — the file is not ours (its first line lacks the marker '${target.marker}'); nothing was removed anywhere`,
      );
    }
    rmSync(target.destination);
    ctx.stdout(`${target.destination}: removed`);
  }
  ctx.stdout("note: restart opencode for the tool and command to disappear.");
  return EXIT_PASS;
}

export function runOpencode(ctx: Ctx): BorderExit | Promise<BorderExit> {
  // Plan T3: strip the --json flag BEFORE subcommand dispatch. cli.ts
  // parseFlags already folds known global flags into ctx.flags.json, so this
  // filter only bites if an argv ever reaches us as a positional.
  const [sub, ...restAll] = ctx.positionals;
  const rest = restAll.filter((arg) => arg !== "--json");
  const USAGE = "usage: border opencode install | status | uninstall | inspect";
  switch (sub) {
    case "install":
    case "status":
    case "uninstall":
    case "inspect": {
      if (rest.length > 0) {
        throw new UnknownArgError(`opencode ${sub}: unexpected argument '${rest[0] ?? ""}' — ${USAGE}`);
      }
      const table: Record<"install" | "status" | "uninstall" | "inspect", (c: Ctx) => BorderExit | Promise<BorderExit>> = {
        install: opencodeInstall,
        status: opencodeStatus,
        uninstall: opencodeUninstall,
        inspect: runInspectCore,
      };
      return table[sub](ctx);
    }
    default:
      throw new UnknownArgError(`opencode: unknown subcommand '${sub ?? "<none>"}' — ${USAGE}`);
  }
}