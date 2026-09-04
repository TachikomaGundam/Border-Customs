// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 17
//
// Same-bytes PyPI publish executor. Consumes the shared publish core in
// src/push/npm.ts (file header there carries the full contract: ledger gate ⇒
// re-hash ⇒ [dry-run | twine availability ⇒ pre-publish re-probe ⇒ warning ⇒
// spawn stdio:'inherit' ⇒ push-record]) and the G37 immutability-policy
// citations backing PUBLISH_WARNING.
//
// Recorded-artifact convention: the todo-12 build-once stage emits BOTH the
// sdist (*.tar.gz) and the wheel (*.whl) into <repo>/.border/dist; this
// executor re-hashes every CheckRecord.artifacts entry matching either
// extension and uploads exactly that set — nothing recorded ⇒ exit 2 (fails
// closed; a PyPI-only ledger without digests cannot prove same bytes).
//
// Full twine-exec e2e is NOT covered by the suite (no local PyPI index in
// devDeps — documented gap in test/push.registries.test.ts); the dry-run,
// re-hash/tamper, twine-absent and version-exists legs all run against the
// todo-13 loopback registry-stub.
//
// MUST NOT (plan): no --sign/--repository beyond the configured repository-url,
// no retry loop, no credential handling — twine reads its own keyring/.pypirc
// inside the stdio:'inherit' child (G28).
import { spawnSync } from "node:child_process";

import { EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS, type BorderExit } from "../cli/exit.ts";
import { PYPI_DEFAULT_REPOSITORY, readPypiCoords } from "../registry.ts";
import { recordPushSuccess } from "../pushstate.ts";
import {
  PUBLISH_WARNING,
  blockingProbeFindings,
  rehashRecordedArtifacts,
  requirePassedRecord,
  spawnInherit,
  writers,
  type PublishInput,
} from "./npm.ts";

export type PypiPublishInput = PublishInput & {
  /**
   * Exact twine binary seam; the env var TWINE_BIN is honored when this is
   * unset. Default (neither set): `python3 -m twine` — mirroring how the
   * todo-12 stage invokes `python3 -m build` / `python3 -m twine check`.
   */
  readonly twineBinPath?: string;
};

type TwineCommand = { readonly bin: string; readonly prefix: readonly string[] };

function resolveTwine(i: PypiPublishInput): TwineCommand {
  const bin = i.twineBinPath ?? i.env?.TWINE_BIN;
  return bin === undefined ? { bin: "python3", prefix: ["-m", "twine"] } : { bin, prefix: [] };
}

function twineAvailable(i: PypiPublishInput, command: TwineCommand): { ok: true } | { ok: false; message: string } {
  const args = [...command.prefix, "--version"];
  let status: number | null = null;
  let failed = false;
  try {
    const res = spawnSync(command.bin, args, {
      encoding: "utf8",
      stdio: "ignore",
      ...(i.env === undefined ? {} : { env: { ...i.env } }),
    });
    failed = res.error !== undefined || res.status !== 0;
    status = res.status;
  } catch {
    failed = true;
  }
  if (failed) {
    return {
      ok: false,
      message: `twine upload unavailable — \`${command.bin} ${args.join(" ")}\` failed (exit ${String(status)}); install twine (pip install twine) before running border push (border exit 2)`,
    };
  }
  return { ok: true };
}

function uploadArgv(files: readonly string[], repository: string | undefined): readonly string[] {
  // Exactly `twine upload [--repository-url <url>] <files...>` — the repository
  // flag only when configured; no --sign, no comment/attestation extras.
  return ["upload", ...(repository === undefined ? [] : ["--repository-url", repository]), ...files];
}

/**
 * PyPI leg entry point (todo 16 orchestrates git → npm → PyPI and runs every
 * remote pre-flight before any publish; this executor is single-target and
 * performs no ordering of its own). Dry-run semantics: prints the exact
 * `twine upload …` line and touches NOTHING — no twine probe, no registry.
 */
export async function runPypiPublish(i: PypiPublishInput): Promise<BorderExit> {
  const { out, err } = writers(i);
  const gate = requirePassedRecord("pypi", i);
  if (!gate.ok) {
    err(gate.message);
    return gate.exit;
  }
  const rehash = rehashRecordedArtifacts("pypi", gate.record, i.repoDir);
  if (!rehash.ok) {
    err(rehash.message);
    return EXIT_ERROR;
  }
  const repository = i.cfg.targets.pypi?.repository;
  const argv = uploadArgv(rehash.files, repository);
  if (!i.yes) {
    out(`twine ${argv.join(" ")}`);
    return EXIT_PASS;
  }
  const command = resolveTwine(i);
  const available = twineAvailable(i, command);
  if (!available.ok) {
    err(available.message);
    return EXIT_ERROR;
  }
  const blockers = await blockingProbeFindings(i, "pypi");
  if (blockers.length > 0) {
    for (const f of blockers) err(`${f.rule}: ${f.message}`);
    return EXIT_BLOCKED;
  }
  out(PUBLISH_WARNING);
  const code = await spawnInherit(command.bin, [...command.prefix, ...argv], i.repoDir, i.env);
  if (code !== 0) {
    err(`twine upload failed (exit ${String(code)}) — no retry loop; check which files landed before running border push again`);
    return EXIT_BLOCKED;
  }
  const coords = readPypiCoords(i.repoDir, i.cfg, i.env);
  recordPushSuccess(i.repoDir, {
    key: i.key,
    target: "pypi",
    remoteName: "pypi",
    url: repository ?? PYPI_DEFAULT_REPOSITORY,
    localSha: gate.record.head,
    version: `${coords.name}@${coords.version}`,
    confirmedVia: "pypi-json",
  });
  out(`published ${coords.name}@${coords.version}; push-record appended`);
  return EXIT_PASS;
}
