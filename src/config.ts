// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 2,
//   re-wired per .omo/plans/border-push-channels.md todo C2 (target schema fragments,
//   ${VAR} env-expand fields, hasTargets and exposure items now flow from the channel
//   descriptors in src/channels/ — behavior byte-identical)
//
// border.yaml: zod-strict schema, discovery (--config > $BORDER_CONFIG >
//   machine store keyed by canonical remote > ./border.yaml > git toplevel),
//   private `.border/config.local.yaml` overlay (deep-merged, G15),
// git-remote inference fallback, NO-OP verdict (G24) and the sanitized
// exposure set used by the fingerprint ledger (todo 14).
// Library contract: never calls process.exit — throws typed ConfigError
// (exitCode 2) which the CLI layer maps onto the process exit code.
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { parse as parseYaml, YAMLParseError } from "yaml";
import { z } from "zod";

import { sanitizeUrl } from "./redact.ts";

import { cratesChannel, npmChannel, pypiChannel, rubygemsChannel, publishChannels } from "./channels/registry.ts";
import { findMachineConfig, resolveMachineStoreDir } from "./config/machineStore.ts";
import {
  assertSecurityKey,
  canonicalStoreRoot,
  honorSecurityKey,
  qualifyDir,
  qualifyRead,
  type SecurityDecl,
} from "./tier.ts";

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
          // Rule-rename migration (HR 次级伤 4.2): allow entries keep matching a
          // renamed rule via `{oldName: currentName}` — renames must not silently
          // redden (or silently strand waivers of) already-correct repos.
          // optional (not default): an unused key must not materialize into the
          // whole-object configDigest and rotate every unrelated ledger.
          aliases: z.record(z.string().min(1), z.string().min(1)).optional(),
        })
        .strict(),
      allow: z
        .array(
          z
            .object({
              rule: z.string().min(1),
              match: z.string().min(1).optional(),
              file: z.string().min(1).optional(),
              // Path-domain waiver (HR decoupling 2026-10-23): one entry, many pins.
              // Digests are of the secret VALUE, so formatter churn cannot break
              // them; a NEW value not in the list stays red — the safety floor.
              values: z.array(z.string().regex(/^[0-9a-f]{64}$/, "allow values entries must be 64-hex value digests")).min(1).optional(),
              // UTC sunset `YYYY-MM-DD`: after this date the entry never suppresses.
              until: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "allow until must be YYYY-MM-DD (UTC expiry date)").optional(),
            })
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
              if (entry.match === undefined && entry.values === undefined) {
                ctx.addIssue({ code: "custom", message: "allow entry needs at least one of match/values — an entry that matches nothing suppresses nothing and only hides intent" });
              }
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
      // Operator build consent (§3⁗): collectible ONLY from the machine
      // store or an explicit --config outside the repo; the load-time
      // security evaluation strips it from every other source.
      allowBuilds: z.boolean().optional(),
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

// provenance: .omo/plans/border-exfil-lens.md wave-A closeout (2026-09-25 remote
// config wipe incident, E-CFG-CLOBBER in .omo/evidence/F-L4-*.md) — a repo whose
// remote.* config entries vanish keeps no positive signal in targets; the honest
// detectable signature is remote-tracking refs whose named remote is unconfigured.
// Full wipes (refs gone too) cannot be detected as drift by any local means — they
// get the status.ts visibility line instead, never a claimed guarantee.
export function remoteTrackingDrift(cwd: string): { configured: string[]; orphans: string[] } {
  const configured = parseRemoteV(runGit(cwd, ["remote", "-v"]).stdout)
    .map((r) => r.name)
    .filter((n): n is string => n !== undefined)
    .sort();
  const refs = runGit(cwd, ["for-each-ref", "--format=%(refname:lstrip=2)", "refs/remotes"]);
  const refNames = new Set<string>();
  if (refs.ok) {
    for (const line of refs.stdout.split("\n")) {
      const first = line.trim().split("/")[0];
      if (first !== undefined && first !== "") {
        refNames.add(first);
      }
    }
  }
  const configuredSet = new Set(configured);
  const orphans = [...refNames].filter((n) => !configuredSet.has(n)).sort();
  return { configured, orphans };
}

function hasTargets(cfg: BorderConfig): boolean {
  return cfg.targets.git.remotes.length > 0 || publishChannels().some((c) => c.configured(cfg));
}

// ---------------------------------------------------------------- discovery

export type LoadResult =
  | {
      kind: "loaded";
      config: BorderConfig;
      warnings: readonly string[];
      source: string;
      /** §3⁗ resolved security-tier outcomes (honored values only; refusal
       *  states threw ConfigError before this returns). */
      security: SecurityResolution;
    }
  // `explicit` distinguishes the two no-op causes: undefined ⇒ NOTHING was
  // discovered (todo-2 loud no-op stays exit 0 with no run); defined ⇒ a real
  // border.yaml/overlay was loaded but declares zero targets — the check flow
  // (commands/check.ts, todo 19) promotes that into a full repo-local run with
  // an empty exposureSet, because an authored config is intent, not an
  // absence. loadConfig's own contract (kind:'no-op') is unchanged.
  | {
      kind: "no-op";
      warnings: readonly string[];
      explicit?: { config: BorderConfig; source: string; security: SecurityResolution };
    };

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
    /** Test seam for the security-tier predicates (defaults: the real
     *  fd-chain qualification from src/tier.ts). */
    securityQualify?: (p: string) => { readonly ok: boolean };
    securityQualifyDir?: (p: string) => { readonly ok: boolean };
  } = {},
): LoadResult {
  const cwd = resolve(options.cwd ?? process.cwd());
  const env = options.env ?? process.env;
  const toplevel = gitToplevel(cwd);
  const warnings: string[] = [];

  let basePath: string | undefined;
  let baseText: string | undefined;
  const remotes = toplevel === undefined ? [] : parseRemoteV(runGit(toplevel, ["remote", "-v"]).stdout);
  if (options.configPath !== undefined) {
    basePath = resolve(cwd, options.configPath);
    baseText = readFileOrUndefined(basePath);
    if (baseText === undefined) {
      throw new ConfigError("unreadable", `config file not found: ${basePath}`);
    }
  } else if (env.BORDER_CONFIG !== undefined) {
    if (env.BORDER_CONFIG === "") {
      throw new ConfigError("unreadable", "$BORDER_CONFIG is set but empty — pointing at nothing must never silently fall through");
    }
    basePath = resolve(cwd, env.BORDER_CONFIG);
    baseText = readFileOrUndefined(basePath);
    if (baseText === undefined) {
      throw new ConfigError("unreadable", `$BORDER_CONFIG points to an unreadable file: ${basePath}`);
    }
  } else {
    const machine = findMachineConfig(remotes, resolveMachineStoreDir(env));
    if (machine !== undefined) {
      basePath = machine.path;
      baseText = readFileSync(basePath, "utf8");
      warnings.push(`machine-store config ${machine.path} (${machine.canonical})`);
    } else {
      for (const candidate of [join(cwd, "border.yaml"), toplevel === undefined ? "" : join(toplevel, "border.yaml")]) {
        if (candidate !== "" && existsSync(candidate)) {
          basePath = candidate;
          baseText = readFileSync(candidate, "utf8");
          break;
        }
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

  const security = evaluateSecurity(config, {
    cwd,
    toplevel,
    env,
    configPath: options.configPath,
    basePath,
    warnings,
    ...(options.securityQualify !== undefined ? { qualify: options.securityQualify } : {}),
    ...(options.securityQualifyDir !== undefined ? { qualifyDirFn: options.securityQualifyDir } : {}),
  });
  config = applySecurity(config, security);
  if (!hasTargets(config)) {
    return { kind: "no-op", warnings, explicit: { config, source, security } };
  }
  return { kind: "loaded", config, warnings, source, security };
}

// ---------------------------------------------------------------- security tier

export const SANDBOX_LANES = ["npm", "pypi", "crates", "rubygems"] as const;
export type SandboxLane = (typeof SANDBOX_LANES)[number];

export type SecurityResolution = {
  readonly sandbox: Partial<Record<SandboxLane, string>>;
  readonly allowBuilds: boolean;
};

type SecEvalOpts = {
  readonly cwd: string;
  readonly toplevel: string | undefined;
  readonly env: Record<string, string | undefined>;
  readonly configPath: string | undefined;
  readonly basePath: string | undefined;
  readonly warnings: string[];
  readonly qualify?: (p: string) => { readonly ok: boolean };
  readonly qualifyDirFn?: (p: string) => { readonly ok: boolean };
};

/** Declarations harvested from one candidate file (raw parse; an unparseable
 *  file that MENTIONS a security key still declares — presence, §3⁗). */
function secDeclsOfFile(filePath: string, source: SecurityDecl["source"], warnOut: string[]): SecurityDecl[] {
  let text: string;
  try {
    text = readFileSync(filePath, "utf8");
  } catch {
    return [];
  }
  let doc: unknown;
  try {
    doc = yamlToJson(text, filePath);
  } catch {
    if (/allowBuilds|sandboxImage/.test(text)) {
      warnOut.push(`unparseable config ${filePath} mentions security keys — counted as declarations (sibyl §3⁗ presence)`);
      return [{ key: "allowBuilds", value: true, source, path: filePath }];
    }
    return [];
  }
  if (typeof doc !== "object" || doc === null) return [];
  const d = doc as Record<string, unknown>;
  const out: SecurityDecl[] = [];
  if (d["allowBuilds"] === true) out.push({ key: "allowBuilds", value: true, source, path: filePath });
  const targets = d["targets"];
  if (typeof targets === "object" && targets !== null) {
    for (const lane of SANDBOX_LANES) {
      const t = (targets as Record<string, unknown>)[lane];
      if (typeof t === "object" && t !== null) {
        const img = (t as Record<string, unknown>)["sandboxImage"];
        if (typeof img === "string") out.push({ key: "sandboxImage", lane, value: img, source, path: filePath });
      }
    }
  }
  return out;
}

function insideRepo(p: string, cwd: string, toplevel: string | undefined): boolean {
  return [cwd, ...(toplevel === undefined ? [] : [toplevel])].some((r) => p === r || p.startsWith(r + "/"));
}

/** All *.yaml under a machine store dir (per-remote key files, W2 naming). */
function machineStoreCandidates(storeDir: string): string[] {
  try {
    return readdirSync(storeDir).filter((n) => n.endsWith(".yaml")).map((n) => join(storeDir, n));
  } catch {
    return [];
  }
}

function evaluateSecurity(config: BorderConfig, o: SecEvalOpts): SecurityResolution {
  const qualify = o.qualify ?? ((p: string) => ({ ok: qualifyRead(p).ok }));
  const qualifyDirFn = o.qualifyDirFn ?? ((p: string) => ({ ok: qualifyDir(p).ok }));
  const decls: SecurityDecl[] = [];
  const seen = new Set<string>();
  const addFile = (filePath: string, source: SecurityDecl["source"]): void => {
    if (seen.has(filePath)) return;
    seen.add(filePath);
    // authorship rule: any file physically inside the repo is repo-tier, no
    // matter which channel discovered it or how perfect its modes are.
    const src: SecurityDecl["source"] = insideRepo(filePath, o.cwd, o.toplevel) ? "repo" : source;
    decls.push(...secDeclsOfFile(filePath, src, o.warnings));
  };
  if (o.configPath !== undefined && o.basePath !== undefined) addFile(o.basePath, "argv");
  else if (o.basePath !== undefined && o.env["BORDER_CONFIG"] !== undefined) addFile(o.basePath, "repo");
  // the canonical machine root is ALWAYS probed for declarations — a
  // --config/BORDER_CONFIG selection does not make machine declarations vanish
  // (§3⁗ presence; it can only SHADOW or go AMBIGUOUS, never silently lose).
  const canon = canonicalStoreRoot();
  if (canon !== undefined) {
    for (const c of machineStoreCandidates(canon)) addFile(c, "machine");
  }
  const xdg = o.env["XDG_CONFIG_HOME"];
  const overrides: string[] = [];
  if (xdg !== undefined && xdg !== "") {
    const xdgRoot = `${xdg.replace(/\/+$/, "")}/border/machines`;
    if (!qualifyDirFn(xdgRoot).ok) overrides.push(xdgRoot);
    else if (canon === undefined || xdgRoot !== canon) for (const c of machineStoreCandidates(xdgRoot)) addFile(c, "machine");
  }
  if (o.basePath !== undefined) addFile(o.basePath, o.configPath !== undefined ? "argv" : "repo");
  // unselected repo configs still DECLARE (§3⁗ presence): a border.yaml the
  // selection ignored cannot silently carry sandbox keys into the future.
  addFile(join(o.cwd, "border.yaml"), "repo");
  if (o.toplevel !== undefined) addFile(join(o.toplevel, "border.yaml"), "repo");
  addFile(join(o.cwd, ".border", "config.local.yaml"), "repo");
  if (o.toplevel !== undefined) addFile(join(o.toplevel, ".border", "config.local.yaml"), "repo");

  const sandbox: Partial<Record<SandboxLane, string>> = {};
  for (const lane of SANDBOX_LANES) {
    const laneDecls = decls.filter((d) => d.key === "sandboxImage" && d.lane === lane);
    if (laneDecls.length === 0) continue;
    const state = honorSecurityKey(laneDecls, overrides, qualify);
    const honored = assertSecurityKey(state, `targets.${lane}.sandboxImage`, "refuse");
    if (honored !== undefined) {
      if (typeof honored.value !== "string") {
        throw new ConfigError("invalid-value", `targets.${lane}.sandboxImage honored value must be a string`, { key: `targets.${lane}.sandboxImage` });
      }
      sandbox[lane] = honored.value;
    }
  }
  const consentDecls = decls.filter((d) => d.key === "allowBuilds");
  let allowBuilds = false;
  if (consentDecls.length > 0) {
    const state = honorSecurityKey(consentDecls, overrides, qualify);
    const honored = assertSecurityKey(state, "allowBuilds", "withhold");
    allowBuilds = honored !== undefined && honored.value === true;
    if (state.kind === "present-unqualified") {
      o.warnings.push("allowBuilds was declared only by unqualified sources — withheld (sibyl §3⁗ conservative)");
    }
  }
  void config;
  return { sandbox, allowBuilds };
}

/** Rewrite the config so every downstream consumer sees ONLY honored
 *  security values (stage/freshness read targets.<lane>.sandboxImage). */
function applySecurity(config: BorderConfig, sec: SecurityResolution): BorderConfig {
  const targets: Record<string, unknown> = { ...config.targets };
  for (const lane of SANDBOX_LANES) {
    const t = targets[lane];
    if (typeof t !== "object" || t === null) continue;
    const img = sec.sandbox[lane];
    const { sandboxImage: _drop, ...rest } = t as Record<string, unknown>;
    targets[lane] = img === undefined ? rest : { ...rest, sandboxImage: img };
  }
  const { allowBuilds: _drop2, ...rest } = config as BorderConfig & { allowBuilds?: boolean };
  // false stays ABSENT: an old border.yaml's canonical configDigest must not
  // rotate because this wave learned a new key it never set.
  return (sec.allowBuilds ? { ...rest, allowBuilds: true, targets } : { ...rest, targets }) as BorderConfig;
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
