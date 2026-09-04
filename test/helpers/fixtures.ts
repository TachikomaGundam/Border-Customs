// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 4
//
// Git/archive fixture builders for real-engine adapter tests. Fixtures live
// under <border>/test/tmp/ (gitignored, removed after each test) so planted
// literals NEVER touch /tmp — that is what keeps the AC "grep -r <literal>
// /tmp empty after run" meaningful, and prevents committing secret-bearing
// fixture repos into border's own git history.
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const BORDER_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

const ALPHA_DIGIT = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
// The vendored gitleaks 8.30.1 aws-access-token rule is
// \b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b — a BASE32 window, so
// digits 0/1/8/9 in the 16-char suffix make the key regex-immune (~83% of naive
// [A-Z0-9] keys silently escape detection; probe 2026-09-04). Fixture keys MUST
// be drawn from this alphabet or the aws rule never fires deterministically.
const AWS_KEY_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function rand(alphabet: string, n: number): string {
  const bytes = randomBytes(n);
  let out = "";
  for (let i = 0; i < n; i += 1) {
    out += alphabet[(bytes[i] as number) % alphabet.length];
  }
  return out;
}

/**
 * One high-entropy AWS-shaped pair. ALWAYS create a fresh pair per fixture —
 * gitleaks 8.30.1 content-deduplicates identical secret values within one
 * scan, so reused literals mask findings (spike, ADAPTER-CONTRACT.md).
 */
export function randAwsPair(): { key: string; secret: string; text: string } {
  const key = `AKIA${rand(AWS_KEY_ALPHABET, 16)}`;
  const secret = rand(ALPHA_DIGIT, 40);
  const text = `aws_access_key_id = ${key}\naws_secret_access_key = ${secret}\n`;
  return { key, secret, text };
}

export function makeFixtureDir(prefix: string): string {
  const base = join(BORDER_ROOT, "test", "tmp");
  mkdirSync(base, { recursive: true });
  return mkdtempSync(join(base, `${prefix}-`));
}

export function removeDir(dir: string): void {
  rmSync(dir, { recursive: true, force: true });
}

export function writeRel(dir: string, relPath: string, content: string | Buffer): void {
  const full = join(dir, relPath);
  mkdirSync(dirname(full), { recursive: true });
  writeFileSync(full, content);
}

/**
 * Every git call is fenced to the fixture itself: GIT_CEILING_DIRECTORIES
 * stops repo discovery from walking up into border's OWN repository (a leak
 * here commits planted secrets into the product repo), and the explicit .git
 * check fails fast if a fixture forgot gitInit.
 */
function git(cwd: string, args: readonly string[], mustBeRepo = true): string {
  if (mustBeRepo && !existsSync(join(cwd, ".git"))) {
    throw new Error(`fixture dir ${cwd} is not a git repo — call gitInit() first (refusing to run git with repo discovery upward)`);
  }
  const r = spawnSync("git", [...args], {
    cwd,
    encoding: "utf8",
    env: { ...process.env, GIT_CEILING_DIRECTORIES: dirname(cwd) },
  });
  if (r.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed (${String(r.status)}): ${r.stderr ?? ""}`);
  }
  return r.stdout ?? "";
}

const GIT_ID = ["-c", "user.name=Wiki.js", "-c", "user.email=wiki@sumteclab.com"];

export function gitInit(dir: string): void {
  git(dir, ["init", "-q", "-b", "main"], false);
  git(dir, ["config", "user.name", "Wiki.js"]);
  git(dir, ["config", "user.email", "wiki@sumteclab.com"]);
}

export function gitAddCommit(dir: string, message: string): void {
  git(dir, ["add", "-A"]);
  git(dir, [...GIT_ID, "commit", "-q", "-m", message]);
}

export function gitRmCommit(dir: string, relPath: string, message: string): void {
  git(dir, ["rm", "-q", relPath]);
  git(dir, [...GIT_ID, "commit", "-q", "-m", message]);
}

export function gitRevParseHead(dir: string): string {
  return git(dir, ["rev-parse", "HEAD"]).trim();
}

/** Recursively collect absolute file paths under `dir` (no symlink follow). */
export function walkFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walkFiles(full));
    else if (entry.isFile()) out.push(full);
  }
  return out;
}
