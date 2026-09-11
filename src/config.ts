// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 2,
//   re-wired per .omo/plans/border-push-channels.md todo C2 (target schema fragments,
//   ${VAR} env-expand fields, hasTargets and exposure items now flow from the channel
//   descriptors in src/channels/ — behavior byte-identical)
//
// border.yaml: zod-strict schema, discovery (--config > ./border.yaml > git
// toplevel), private `.border/config.local.yaml` overlay (deep-merged, G15),
// git-remote inference fallback, NO-OP verdict (G24) and the sanitized
// exposure set used by the fingerprint ledger (todo 14).
// Library contract: never calls process.exit — throws typed ConfigError
// (exitCode 2) which the CLI layer maps onto the process exit code.
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { parse as parseYaml, YAMLParseError } from "yaml";
import { z } from "zod";

import { sanitizeUrl } from "./redact.ts";

import { cratesChannel, npmChannel, pypiChannel, rubygemsChannel, publishChannels } from "./channels/registry.ts";

export const DEFAULT_MAX_FILE_KB = 500;
export const DEFAULT_ENGINES = ["gitleaks", "secretlint"];
export const FALLBACK_WARNING = "no border.yaml: git-remote fallback";
export const NO_OP_MESSAGE = "no targets discovered; check is a no-op";

// ---------------------------------------------------------------- schema

const gitRemoteSchema = z
  .object({ name: z.string().min(1).optional(), url: z.string().min(1) })
  .strict();

const gitRemotesSchema = z.array(gitRemoteSchema).superRefine((remotes, ctx) => {
  // Push-target ids are `git:<name>` (src/gitTargetId.ts); a duplicated name
  // collides, and the gitLegs Map in src/commands/push.ts keeps only the LAST
  // entry — the earlier remote is silently dropped (fail-open, the exact
  // accident class border exists to prevent). Reject at load instead.
  // Unnamed remotes are exempt: their ids are index-keyed `git:#N`.
  const seen = new Set<string>();
  const dupes = new Set<string>();
  for (const remote of remotes) {
    if (remote.name === undefined) continue;
    if (seen.has(remote.name)) dupes.add(remote.name);
    seen.add(remote.name);
  }
  if (dupes.size > 0) {
    ctx.addIssue({
      code: "custom",
      message: `duplicate git remote name(s) ${[...dupes].map((d) => `'${d}'`).join(", ")} in targets.git.remotes: push-target ids 'git:<name>' must be unique`,
    });
  }
});

// The assembled schema reads channel descriptors (npmChannel/pypiChannel).
// It is built lazily (memoized function, not a top-level const): config.ts
// sits inside the channel-registry ESM load cycle, and reading a channel
// binding during module evaluation would hit uninitialized bindings. No
// other module reads this schema at load time, so deferring to first
// safeParse keeps evaluation order-independent.
type BorderConfigSchema = ReturnType<typeof buildBorderConfigSchema>;
let borderConfigSchemaValue: BorderConfigSchema | undefined;
function borderConfigSchema(): BorderConfigSchema {
  borderConfigSchemaValue ??= buildBorderConfigSchema();
  return borderConfigSchemaValue;
}

function buildBorderConfigSchema() {
  return z
    .object({
      version: z.literal(1),
      targets: z
        .object({
          git: z.object({ remotes: gitRemotesSchema }).strict(),
          // Per-channel schema fragments come from the channel descriptors
          // (todo C2) — each is zod .strict() (+ .optional()), so an unknown
          // channel key or unknown field inside still lands in the same
          // `unknown-key` exit-2 ConfigError as pre-C2.
          npm: npmChannel.configSchema,
          pypi: pypiChannel.configSchema,
          crates: cratesChannel.configSchema,
          rubygems: rubygemsChannel.configSchema,
        })
        .strict(),
      rules: z
        .object({
          authors: z
            .object({
              emails: z.array(z.string()),
              names: z.array(z.string()),
              allowBots: z.boolean().optional(),
            })
            .strict(),
          hosts: z.array(z.string()),
          ips: z.array(z.string()),
          pathPatterns: z.array(z.string()),
          maxFileKB: z.number().int().positive().default(DEFAULT_MAX_FILE_KB),
        })
        .strict(),
      allow: z
        .array(
          z
            .object({ rule: z.string().min(1), match: z.string().min(1), file: z.string().min(1).optional() })
            .strict()
            // G14: the plan's Must-NOT bans the blanket `allow: [{rule:"*"}]`
            // SHAPE — an entry that suppresses by wildcard with NO scoping at
            // all. rule/match wildcards are legitimate only when a concrete
            // `file` scope pins the suppression to a location (the dogfood
            // categories (a) .omo/** and (b) test/** are exactly that), so the
            // combo is rejected only when `file` is absent. An absolute or
            // escaping `file` glob can never match a repo-relative finding
            // path — a typo posing as a rule — so it fails typed at LOAD too
            // (kind invalid-value ⇒ exit 2) instead of silently no-op'ing.
            .superRefine((entry, ctx) => {
              if (entry.file === undefined && entry.rule === "*" && entry.match === "*") {
                ctx.addIssue({ code: "custom", message: "blanket allow entry: '{rule:\"*\",match:\"*\"}' without a file scope is rejected — wildcards need a concrete file glob to bound them" });
              }
              if (entry.file !== undefined) {
                const f = entry.file;
                if (f.startsWith("/") || f.startsWith("~") || /^[A-Za-z]:[\\/]/.test(f) || f.split("/").includes("..")) {
                  ctx.addIssue({ code: "custom", message: `allow file glob must be repo-relative without '..' segments (got '${f}')` });
                }
              }
            }),
        )
        .default([]),
      engines: z
        .object({
          require: z.array(z.string()).default(DEFAULT_ENGINES),
          trufflehog: z.boolean().default(false),
        })
        .strict()
        .default(() => ({ require: [...DEFAULT_ENGINES], trufflehog: false })),
      // R4 (border-residue-gate): the residue scan is ON unless the user opts
      // out. Strict shape mirrors engines.trufflehog — an unknown sibling under
      // `residue:` is a typed exit 2, never a silently-ignored typo. Outer
      // `.optional()` (not `.default()`): a whole BorderConfig literal must
      // construct without the key (inferredConfig + pinned suites), so absence
      // IS the enabled default — `residue?.enabled !== false` at the merge
      // point in check.ts materializes that semantics. The ONLY sanctioned skip
      // of the residue scan is this toggle; a scan that cannot RUN is a FAIL
      // (fail-closed doctrine), and the digest seam keeps every cached PASS
      // honest about the residue sources it was certified against.
      // W2.2 (border-inspect-roadmap): requireProof arms the PROOF VALVE — a
      // blocking residue-* row on a staged artifact then additionally demands a
      // fresh `t:"roundtrip"` ledger record for that artifact's sha256 before
      // the channel may PASS. Default FALSE (0.3.x behavior byte-identical);
      // the valve reads `residue?.requireProof === true`, so absence IS the
      // false default — same construction contract as the outer key. The flag
      // rides the whole-object configDigest (stableStringify), so flipping it
      // rotates the check rulesHash and the ledger refuses every cached PASS.
      residue: z
        .object({
          enabled: z.boolean().default(true),
          requireProof: z.boolean().default(false),
        })
        .strict()
        .optional(),
      // W4.1 release-coherence twin obligations (plan border-inspect-roadmap §127-138):
      // the ONLY cross-manager declaration border can statically enforce — when a project
      // ships a PyPI/npm twin pair under one release train, their versions must be equal.
      // The per-artifact internal coherence rules (release-coherence-*) are ALWAYS on and
      // need no opt-in; this list is opt-in and strict — unknown keys fail typed exit 2.
      // The pair list rides the whole-object configDigest, so editing it rotates the check
      // rulesHash exactly like the residue block above.
      release: z
        .object({
          twin: z
            .array(
              z
                .object({
                  pypi: z.string().min(1),
                  npm: z.string().min(1),
                })
                .strict(),
            )
            .default([]),
        })
        .strict()
        .optional(),
    })
    .strict();
}

export type BorderConfig = z.output<BorderConfigSchema>;
export type GitRemote = BorderConfig["targets"]["git"]["remotes"][number];

// ConfigError/isRecord live in src/channels/errors.ts (a dependency-free leaf)
// and are re-exported here: the channel descriptors throw ConfigError without
// importing this module, so the two never close a static ESM cycle (todo C2).
import { ConfigError, isRecord, type ConfigErrorKind } from "./channels/errors.ts";
export { ConfigError, isRecord, type ConfigErrorKind };

function yamlToJson(text: string, source: string): unknown {
  try {
    return parseYaml(text);
  } catch (err) {
    if (err instanceof YAMLParseError) {
      const at = err.linePos?.[0];
      const where = at === undefined ? "" : ` at line ${at.line}, column ${at.col}`;
      throw new ConfigError("malformed-yaml", `malformed YAML in ${source}${where}: ${err.message}`, {
        line: at?.line,
        column: at?.col,
      });
    }
    throw err;
  }
}

function zodToConfigError(error: z.ZodError, source: string): ConfigError {
  const first = error.issues[0];
  if (first === undefined) {
    return new ConfigError("invalid-value", `invalid config in ${source}`);
  }
  if (first.code === "unrecognized_keys") {
    const key = String(first.keys[0] ?? "?");
    return new ConfigError("unknown-key", `unknown config key '${key}' in ${source}`, { key });
  }
  const path = first.path.map(String).join(".") || "<root>";
  return new ConfigError(
    "invalid-value",
    `invalid config at '${path}' in ${source}: ${first.message}`,
  );
}

function validateDoc(doc: unknown, source: string): BorderConfig {
  const result = borderConfigSchema().safeParse(doc);
  if (result.success) {
    return result.data;
  }
  throw zodToConfigError(result.error, source);
}

// ---------------------------------------------------------------- ${VAR} env expansion
// ONLY url/registry/repository fields expand; values are plain string
// substitution — config content is never evaluated.

const ENV_REF = /\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g;

function expandEnv(text: string, field: string, env: Record<string, string | undefined>): string {
  return text.replace(ENV_REF, (_match: string, name: string) => {
    const value = env[name];
    if (value === undefined) {
      throw new ConfigError("missing-env", `environment variable '${name}' is not set (referenced by ${field})`);
    }
    return value;
  });
}

function expandInConfig(cfg: BorderConfig, env: Record<string, string | undefined>): BorderConfig {
  const targets: BorderConfig["targets"] = {
    git: {
      remotes: cfg.targets.git.remotes.map((r, i) => ({
        ...r,
        url: expandEnv(r.url, `targets.git.remotes[${i}].url`, env),
      })),
    },
  };
  // Per-channel ${VAR} expansion, driven by each descriptor's envExpandFields
  // (todo C2: npm.registry / pypi.repository — nothing else may expand).
  for (const channel of publishChannels()) {
    const section = (cfg.targets as unknown as Record<string, Record<string, string | undefined> | undefined>)[channel.id];
    if (section === undefined) continue;
    const out: Record<string, string | undefined> = { ...section };
    for (const field of channel.envExpandFields) {
      const value = section[field];
      if (value === undefined) continue;
      out[field] = expandEnv(value, `targets.${channel.id}.${field}`, env);
    }
    (targets as unknown as Record<string, Record<string, string | undefined>>)[channel.id] = out;
  }
  return { ...cfg, targets };
}

export function parseConfig(
  text: string,
  source = "<inline>",
  options: { env?: Record<string, string | undefined> } = {},
): BorderConfig {
  const doc = yamlToJson(text, source);
  return expandInConfig(validateDoc(doc, source), options.env ?? process.env);
}

// ---------------------------------------------------------------- overlay deep-merge
// plain objects merge recursively; arrays and scalars replace. The MERGED
// document is schema-validated (same schema), so partial overlays are legal
// while unknown keys anywhere are still rejected by name.
// (isRecord is defined in src/channels/errors.ts — re-exported at line 126.)

function deepMergeRaw(base: unknown, overlay: unknown): unknown {
  if (isRecord(base) && isRecord(overlay)) {
    const out: Record<string, unknown> = { ...base };
    for (const [key, value] of Object.entries(overlay)) {
      out[key] = key in out ? deepMergeRaw(out[key], value) : value;
    }
    return out;
  }
  return overlay;
}

// ---------------------------------------------------------------- git plumbing

function runGit(cwd: string, args: string[]): { ok: boolean; stdout: string; stderr: string } {
  const r = spawnSync("git", args, { cwd, encoding: "utf8" });
  return { ok: r.status === 0, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

function gitToplevel(cwd: string): string | undefined {
  const r = runGit(cwd, ["rev-parse", "--show-toplevel"]);
  const top = r.stdout.trim();
  return r.ok && top !== "" ? top : undefined;
}

function parseRemoteV(text: string): GitRemote[] {
  const remotes: GitRemote[] = [];
  for (const line of text.split("\n")) {
    const m = /^(\S+)\s+(\S+)\s+\(fetch\)$/.exec(line.trim());
    if (m?.[1] !== undefined && m[2] !== undefined) {
      remotes.push({ name: m[1], url: m[2] });
    }
  }
  return remotes;
}

function headFile(toplevel: string, rel: string): string {
  const r = runGit(toplevel, ["show", `HEAD:${rel}`]);
  if (!r.ok) {
    throw new ConfigError("git-failed", `cannot read ${rel} at HEAD via git show: ${r.stderr.trim()}`);
  }
  return r.stdout;
}

function hasTargets(cfg: BorderConfig): boolean {
  return cfg.targets.git.remotes.length > 0 || publishChannels().some((c) => c.configured(cfg));
}

// ---------------------------------------------------------------- discovery

export type LoadResult =
  | { kind: "loaded"; config: BorderConfig; warnings: readonly string[]; source: string }
  // `explicit` distinguishes the two no-op causes: undefined ⇒ NOTHING was
  // discovered (todo-2 loud no-op stays exit 0 with no run); defined ⇒ a real
  // border.yaml/overlay was loaded but declares zero targets — the check flow
  // (commands/check.ts, todo 19) promotes that into a full repo-local run with
  // an empty exposureSet, because an authored config is intent, not an
  // absence. loadConfig's own contract (kind:'no-op') is unchanged.
  | { kind: "no-op"; warnings: readonly string[]; explicit?: { config: BorderConfig; source: string } };

function readFileOrUndefined(path: string): string | undefined {
  return existsSync(path) ? readFileSync(path, "utf8") : undefined;
}

function inferredConfig(remotes: GitRemote[]): BorderConfig {
  return {
    version: 1,
    targets: { git: { remotes } },
    rules: {
      authors: { emails: [], names: [] },
      hosts: [],
      ips: [],
      pathPatterns: [],
      maxFileKB: DEFAULT_MAX_FILE_KB,
    },
    allow: [],
    engines: { require: [...DEFAULT_ENGINES], trufflehog: false },
  };
}

export function loadConfig(
  options: {
    configPath?: string;
    cwd?: string;
    env?: Record<string, string | undefined>;
  } = {},
): LoadResult {
  const cwd = resolve(options.cwd ?? process.cwd());
  const env = options.env ?? process.env;
  const toplevel = gitToplevel(cwd);
  const warnings: string[] = [];

  let basePath: string | undefined;
  let baseText: string | undefined;
  if (options.configPath !== undefined) {
    basePath = resolve(cwd, options.configPath);
    baseText = readFileOrUndefined(basePath);
    if (baseText === undefined) {
      throw new ConfigError("unreadable", `config file not found: ${basePath}`);
    }
  } else {
    for (const candidate of [join(cwd, "border.yaml"), toplevel === undefined ? "" : join(toplevel, "border.yaml")]) {
      if (candidate !== "" && existsSync(candidate)) {
        basePath = candidate;
        baseText = readFileSync(candidate, "utf8");
        break;
      }
    }
  }

  const overlayDirs = [...new Set([
    ...(basePath === undefined ? [] : [dirname(basePath)]),
    cwd,
    ...(toplevel === undefined ? [] : [toplevel]),
  ])];
  let overlay: { path: string; doc: unknown } | undefined;
  for (const dir of overlayDirs) {
    const p = join(dir, ".border", "config.local.yaml");
    const text = readFileOrUndefined(p);
    if (text !== undefined) {
      overlay = { path: p, doc: yamlToJson(text, p) };
      break;
    }
  }

  let config: BorderConfig;
  let source: string;
  if (basePath === undefined && overlay === undefined) {
    const remotes = toplevel === undefined ? [] : parseRemoteV(runGit(toplevel, ["remote", "-v"]).stdout);
    if (remotes.length === 0) {
      return { kind: "no-op", warnings };
    }
    warnings.push(FALLBACK_WARNING);
    config = inferredConfig(remotes);
    source = "git-remote";
  } else {
    let doc: unknown = basePath === undefined ? overlay?.doc : yamlToJson(baseText ?? "", basePath);
    if (basePath !== undefined && overlay !== undefined) {
      doc = deepMergeRaw(doc, overlay.doc);
    }
    config = expandInConfig(validateDoc(doc, basePath ?? overlay?.path ?? "<inline>"), env);
    source = basePath ?? overlay?.path ?? "<unknown>";
  }

  if (!hasTargets(config)) {
    return { kind: "no-op", warnings, explicit: { config, source } };
  }
  return { kind: "loaded", config, warnings, source };
}

// ---------------------------------------------------------------- exposure set

/** Sorted set of public exposure points: sanitized remote URLs plus each
 *  configured publish channel's exposure item (`npm:<name>@<version>` /
 *  `pypi:<name>@<version>` — items and their HEAD coordinate readers live on
 *  the channel descriptors, todo C2, so a new platform joins exposure
 *  automatically). Remote URLs pass through sanitizeUrl before entering. */
export function exposureSet(cfg: BorderConfig, options: { cwd?: string } = {}): string[] {
  const cwd = resolve(options.cwd ?? process.cwd());
  const items = new Set<string>();
  for (const remote of cfg.targets.git.remotes) {
    items.add(sanitizeUrl(remote.url));
  }
  for (const channel of publishChannels()) {
    if (!channel.configured(cfg)) continue;
    // repoDir (cwd) is passed through for channels whose HEAD coordinate
    // reader needs git plumbing beyond a fixed manifest path (C4: rubygems
    // gemspec discovery is `git ls-tree`, unreadable via `read`); the
    // fixed-path readers (npm/pypi/crates) ignore the extra argument.
    const coords = channel.exposureCoords(cfg, (rel: string) => headFile(cwd, rel), cwd);
    items.add(channel.exposureItem(coords));
  }
  return [...items].sort();
}
