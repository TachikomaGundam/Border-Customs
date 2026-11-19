// provenance: .omo/plans/border-exfil-lens.md wave-A closeout — E-CFG-CLOBBER guard:
// push must refuse a false NO-OP when remote-tracking refs outlive their remote.*
// config, and status must keep the remote surface visible (plan §landing honesty).
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { remoteTrackingDrift } from "../src/config.ts";
import { EXIT_ERROR, EXIT_PASS, type BorderExit } from "../src/cli/exit.ts";
import { SUBCOMMANDS, type CommandHandler, type Ctx, type Subcommand } from "../src/cli/types.ts";
import { runPush } from "../src/commands/push.ts";
import { runStatus } from "../src/commands/status.ts";

function git(cwd: string, args: string[]): string {
  const r = spawnSync("git", ["-c", "user.email=border@local", "-c", "user.name=border", ...args], {
    cwd,
    encoding: "utf8",
    env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" },
  });
  if (r.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${r.stderr}`);
  }
  return r.stdout.trim();
}

function makeSandbox(t: { after: (fn: () => void) => void }): { dir: string; sha: string; bare: () => string } {
  const dir = mkdtempSync(join(tmpdir(), "border-drift-"));
  t.after(() => {
    rmSync(dir, { recursive: true, force: true });
  });
  git(dir, ["init", "-q", "-b", "main"]);
  writeFileSync(join(dir, "f.txt"), "one\n");
  git(dir, ["add", "f.txt"]);
  git(dir, ["commit", "-qm", "seed"]);
  const sha = git(dir, ["rev-parse", "HEAD"]);
  let bareDir: string | undefined;
  return {
    dir,
    sha,
    bare: () => {
      if (bareDir === undefined) {
        bareDir = mkdtempSync(join(tmpdir(), "border-drift-bare-"));
        t.after(() => {
          rmSync(bareDir ?? "", { recursive: true, force: true });
        });
        bareDir = join(bareDir, "remote.git");
        git(dir, ["init", "--bare", bareDir]);
      }
      return bareDir;
    },
  };
}

function makeCtx(dir: string, command: Subcommand): Ctx & { out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  const handlers = {} as Record<Subcommand, CommandHandler>;
  for (const name of SUBCOMMANDS) {
    handlers[name] = async (): Promise<BorderExit> => EXIT_PASS;
  }
  return {
    command,
    flags: { force: false, yes: false, llm: false, json: false },
    positionals: [],
    cwd: dir,
    env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" },
    stdout: (line) => out.push(line),
    stderr: (line) => err.push(line),
    handlers,
    out,
    err,
  };
}

test("DRIFT-HELPER: configured remote with matching refs is clean; ghost refs orphan", (t) => {
  const { dir, sha, bare } = makeSandbox(t);
  git(dir, ["remote", "add", "origin", bare()]);
  git(dir, ["push", "-q", "origin", "main"]);
  git(dir, ["update-ref", "refs/remotes/ghost/main", sha]);

  const ghost = remoteTrackingDrift(dir);
  if (!ghost.configured.includes("origin")) {
    throw new Error(`origin missing from configured: ${JSON.stringify(ghost)}`);
  }
  if (!ghost.orphans.includes("ghost") || ghost.orphans.includes("origin")) {
    throw new Error(`orphan set wrong: ${JSON.stringify(ghost.orphans)}`);
  }
});

test("DRIFT-PUSH: no-op targets + orphan tracking refs => exit 2, never a false NO-OP", async (t) => {
  const { dir, sha } = makeSandbox(t);
  git(dir, ["update-ref", "refs/remotes/ghost/main", sha]);
  const ctx = makeCtx(dir, "push");
  const rc = await runPush(ctx);
  if (rc !== EXIT_ERROR) {
    throw new Error(`expected cannot-answer 2, got ${rc}; out=${JSON.stringify(ctx.out)}`);
  }
  const joined = ctx.err.join("\n");
  if (!joined.includes("remote config drift") || !joined.includes("ghost")) {
    throw new Error(`drift message missing: ${joined}`);
  }
  if (ctx.out.some((l) => l.includes("NO-OP"))) {
    throw new Error("must not print NO-OP while drift signature present");
  }
});

test("DRIFT-PUSH: genuinely remote-less repo keeps the honest NO-OP 0", async (t) => {
  const { dir } = makeSandbox(t);
  const ctx = makeCtx(dir, "push");
  const rc = await runPush(ctx);
  if (rc !== EXIT_PASS || !ctx.out.some((l) => l.includes("NO-OP"))) {
    throw new Error(`expected NO-OP 0, got ${rc} out=${JSON.stringify(ctx.out)}`);
  }
});

test("DRIFT-STATUS: remotes visibility line prints configured, none, and orphans", async (t) => {
  const { dir, sha, bare } = makeSandbox(t);
  git(dir, ["remote", "add", "origin", bare()]);
  git(dir, ["update-ref", "refs/remotes/ghost/main", sha]);
  const ctx = makeCtx(dir, "status");
  const rc = runStatus(ctx);
  if (rc !== EXIT_PASS) {
    throw new Error(`status should stay readable, got ${rc}`);
  }
  const line = ctx.out.find((l) => l.startsWith("git remotes:"));
  if (line === undefined || !line.includes("origin") || !line.includes("ghost") || !line.includes("DRIFT")) {
    throw new Error(`visibility line wrong: ${JSON.stringify(ctx.out)}`);
  }

  const naked = mkdtempSync(join(tmpdir(), "border-naked-"));
  t.after(() => {
    rmSync(naked, { recursive: true, force: true });
  });
  git(naked, ["init", "-q"]);
  const ctx2 = makeCtx(naked, "status");
  runStatus(ctx2);
  const line2 = ctx2.out.find((l) => l.startsWith("git remotes:"));
  if (line2 === undefined || !line2.includes("none configured")) {
    throw new Error(`empty-remote visibility wrong: ${JSON.stringify(ctx2.out)}`);
  }
});

// Sibyl ticket 2026-11-08 wound 4: an instrument that never answers certifies
// nothing. A broken refs store must surface as probesOk=false and move the
// push NO-OP path to a named exit 2 — never a claimed-clean empty orphan set.
test("DRIFT-PROBE: broken refs store surfaces as probe failure, never a clean empty set", (t) => {
  const { dir } = makeSandbox(t);
  const clean = remoteTrackingDrift(dir);
  if (!clean.probesOk) {
    throw new Error(`clean repo must answer probesOk: ${JSON.stringify(clean)}`);
  }
  writeFileSync(join(dir, ".git", "packed-refs"), "garbage line\n");
  const broken = remoteTrackingDrift(dir);
  if (broken.probesOk) {
    throw new Error(`unanswered probe must be probesOk=false, got ${JSON.stringify(broken)}`);
  }
});

test("DRIFT-PUSH: no-op targets + probe that cannot answer => named exit 2, never NO-OP (wound 4)", async (t) => {
  const { dir } = makeSandbox(t);
  writeFileSync(join(dir, ".git", "packed-refs"), "garbage line\n");
  const ctx = makeCtx(dir, "push");
  const rc = await runPush(ctx);
  if (rc !== EXIT_ERROR) {
    throw new Error(`expected cannot-answer 2 for a broken probe, got ${rc}; out=${JSON.stringify(ctx.out)}`);
  }
  const joined = ctx.err.join("\n");
  if (!joined.includes("did not answer")) {
    throw new Error(`named probe-failure message missing: ${joined}`);
  }
  if (ctx.out.some((l) => l.includes("NO-OP"))) {
    throw new Error("a broken instrument must not certify the NO-OP");
  }
});
