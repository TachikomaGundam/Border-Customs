// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 7
//
// Shared fixtures for the CLI tests: a bare-remote git repo + clone with one
// clean commit, and a minimal valid border.yaml emitter (schema requires the
// full rules block; allow/engines take their schema defaults).
import { spawnSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { join } from "node:path";

import { makeFixtureDir, writeRel } from "./fixtures.ts";

/** git fenced to the fixture subtree — never walks up into border's own repo. */
export function gitIn(cwd: string, dir: string, args: readonly string[]): string {
  const r = spawnSync("git", ["-C", dir, ...args], {
    cwd,
    encoding: "utf8",
    env: { ...process.env, GIT_CEILING_DIRECTORIES: cwd },
  });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")} in ${dir} failed: ${r.stderr}`);
  return r.stdout ?? "";
}

/** bare remote + clone with one clean commit pushed to main. */
export function makeRemoteFixture(): { readonly work: string; readonly bare: string; readonly root: string } {
  const root = makeFixtureDir("cli-push");
  const bare = join(root, "remote.git");
  const work = join(root, "work");
  mkdirSync(bare);
  gitIn(root, bare, ["init", "-q", "--bare", "-b", "main"]);
  gitIn(root, bare, ["clone", "-q", bare, work]);
  writeRel(work, "hello.txt", "clean content\n");
  gitIn(work, work, ["add", "-A"]);
  gitIn(work, work, ["-c", "user.name=Wiki.js", "-c", "user.email=wiki@sumteclab.com", "commit", "-q", "-m", "init"]);
  gitIn(work, work, ["push", "-q", "origin", "HEAD:refs/heads/main"]);
  return { work, bare, root };
}

export function borderYaml(remotes: readonly { name: string; url: string }[]): string {
  const lines = remotes.map((r) => `      - name: ${r.name}\n        url: ${r.url}`);
  return [
    "version: 1",
    "targets:",
    "  git:",
    `    remotes:${lines.length === 0 ? " []" : ""}`,
    ...lines,
    "rules:",
    "  authors:",
    "    emails: []",
    "    names: []",
    "  hosts: []",
    "  ips: []",
    "  pathPatterns: []",
    "",
  ].join("\n");
}
