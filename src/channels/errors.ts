// provenance: original clean-room implementation per .omo/plans/border-push-channels.md todo C2
//
// Config-domain error + shape-guard leaf. Hoisted OUT of src/config.ts (which
// re-exports these from here) so the channel descriptors in this directory can
// throw ConfigError without importing ../config.ts — that import edge would
// close a static ESM cycle (config → channels/registry → channels/npm → config)
// whose top-level reads are uninitialized-binding hazards. This module imports
// NOTHING from the repo: it is the load-order root of the whole graph.

export type ConfigErrorKind =
  | "unknown-key"
  | "invalid-value"
  | "malformed-yaml"
  | "missing-env"
  | "unreadable"
  | "git-failed";

export class ConfigError extends Error {
  readonly exitCode: 2 = 2;
  readonly kind: ConfigErrorKind;
  readonly key: string | undefined;
  readonly line: number | undefined;
  readonly column: number | undefined;

  constructor(
    kind: ConfigErrorKind,
    message: string,
    pos?: { key?: string | undefined; line?: number | undefined; column?: number | undefined },
  ) {
    super(message);
    this.name = "ConfigError";
    this.kind = kind;
    this.key = pos?.key;
    this.line = pos?.line;
    this.column = pos?.column;
  }
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}