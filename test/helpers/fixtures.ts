// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 4
//
// Git/archive fixture builders for real-engine adapter tests. Fixtures live
// under <border>/test/tmp/ (gitignored, removed after each test) so planted
// literals NEVER touch /tmp — that is what keeps the AC "grep -r <literal>
// /tmp empty after run" meaningful, and prevents committing secret-bearing
// fixture repos into border's own git history.
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
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
// The SECOND roulette lives on the SECRET side: the vendored generic-api-key rule
// (assets/gitleaks-defaults-v8.30.1.toml, id "generic-api-key", ~line 638) carries a
// 1446-word stopword allowlist — ANY captured value containing one of those words as
// a case-insensitive substring is skipped ("skipping finding: rule allowlist
// allowed-stopword=..." in a gitleaks trace; e.g. 'vpn' hits "dvPN7A6s...", 'vimrc'
// hits "FCTzLkcN8VoObd4Ox5XaFyzhVgUAhVimr..."). Measured miss rate 1.0%: 198/200
// random 40-char [A-Za-z0-9] secrets flagged, 2/200 skipped (probe 2026-09-09).
// Consequence: LLM-bundle masking only scrubs values the engine re-flags (fail-closed
// DATA_BOUNDARY, accepted product residual), so a test asserting "masking proof must
// scrub <secret>" overclaims unless the fixture guarantees the engine sees it. That
// precondition belongs to the fixture, not the product — use randFlaggedAwsPair().
// This is why the fix is test-side: the product behaviour is correct by design.

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
 * KEY side only is engine-flagged deterministically (aws-access-token); the
 * SECRET side still rides the generic-api-key stopword roulette below — tests
 * that assert masking/absence of `secret` need randFlaggedAwsPair() instead.
 */
export function randAwsPair(): { key: string; secret: string; text: string } {
  const key = `AKIA${rand(AWS_KEY_ALPHABET, 16)}`;
  const secret = rand(ALPHA_DIGIT, 40);
  const text = `aws_access_key_id = ${key}\naws_secret_access_key = ${secret}\n`;
  return { key, secret, text };
}

export type AwsPair = { key: string; secret: string; text: string };

/**
 * Ground-truth oracle: does the vendored gitleaks config FLAG BOTH halves of
 * `pair` when it scans pair.text as a plain file? Value semantics mirror
 * src/engines/gitleaks.ts toFinding (Secret if non-empty, else Match); true
 * iff some finding's value contains pair.key AND some finding's value contains
 * pair.secret. Binary resolution mirrors src/engines/support.ts
 * binaryCandidates + spawnEngine: "gitleaks" on PATH first, $HOME/.local/bin/
 * gitleaks as fallback, ENOENT falls through to the next candidate. Throws if
 * no candidate is runnable — callers on this machine must pre-guard with the
 * same gitleaksPresent flag the engine tests use.
 */
export function awsPairEngineFlagged(pair: AwsPair): boolean {
  // os.tmpdir() (not test/tmp): this scan must NOT inherit border's own
  // git/archive context — a bare throwaway dir is exactly what the predicate
  // needs; both temp dirs are removed in `finally`, so /tmp stays clean
  // after every run.
  const dir = mkdtempSync(join(tmpdir(), "border-flagcheck-"));
  const ignoreDir = mkdtempSync(join(tmpdir(), "border-flagcheck-ignore-"));
  try {
    writeFileSync(join(dir, "leak.env"), pair.text);
    const ignorePath = join(ignoreDir, ".gitleaksignore");
    writeFileSync(ignorePath, ""); // empty explicit ignore file: neutralise any stray discovery
    const reportPath = join(dir, "r.json");
    const baseArgs = [
      "dir", dir, "--no-banner",
      "-f", "json", "--report-path", reportPath,
      "--config", join(BORDER_ROOT, "assets", "gitleaks-defaults-v8.30.1.toml"),
      "--gitleaks-ignore-path", ignorePath,
    ];
    const home = process.env["HOME"];
    const candidates = home === undefined || home === "" ? ["gitleaks"] : ["gitleaks", join(home, ".local", "bin", "gitleaks")];
    const env: Record<string, string> = {};
    for (const [k, v] of Object.entries(process.env)) {
      // mirror stripEngineEnv: no GITLEAKS_* host override may reach the probe
      if (v !== undefined && !k.startsWith("GITLEAKS_")) env[k] = v;
    }
    let result: SpawnSyncReturns<string> | undefined;
    for (const candidate of candidates) {
      result = spawnSync(candidate, baseArgs, {
        encoding: "utf8",
        timeout: 60_000,
        maxBuffer: 32 * 1024 * 1024,
        env,
      });
      if (result.error !== undefined && (result.error as NodeJS.ErrnoException).code === "ENOENT") continue;
      break;
    }
    if (result === undefined || result.error !== undefined) {
      const reason = result?.error === undefined ? "" : ` (${String((result.error as NodeJS.ErrnoException).code ?? result.error.message)})`;
      throw new Error(
        `awsPairEngineFlagged: no runnable gitleaks among [${candidates.join(", ")}]${reason}` +
          " — callers must guard with the gitleaksPresent flag",
      );
    }
    // gitleaks exits 0 (clean) / 1 (findings); anything else is an engine error,
    // not a "not flagged" answer — fail loudly instead of silently returning false.
    if (result.status !== 0 && result.status !== 1) {
      throw new Error(`awsPairEngineFlagged: gitleaks exited ${String(result.status)}: ${(result.stderr ?? "").trim()}`);
    }
    if (!existsSync(reportPath)) return false;
    const raw: unknown = JSON.parse(readFileSync(reportPath, "utf8"));
    if (!Array.isArray(raw)) return false;
    let sawKey = false;
    let sawSecret = false;
    for (const entry of raw) {
      const rec = entry as { Secret?: unknown; Match?: unknown };
      const secretField = typeof rec.Secret === "string" ? rec.Secret : "";
      const matchField = typeof rec.Match === "string" ? rec.Match : "";
      const value = secretField !== "" ? secretField : matchField;
      if (value.includes(pair.key)) sawKey = true;
      if (value.includes(pair.secret)) sawSecret = true;
    }
    return sawKey && sawSecret;
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(ignoreDir, { recursive: true, force: true });
  }
}

/**
 * randAwsPair() filtered through the awsPairEngineFlagged oracle — the pair it
 * returns is GUARANTEED visible to the vendored gitleaks config on both sides,
 * which is the precondition masking proofs actually assert. Miss rate is ~1%
 * per draw (see stopword roulette note above), so 32 tries is ~0.36% of a
 * percent of failure; exhaustion means the rules changed underneath us.
 * Spawns one `gitleaks dir` scan per try (fast: single tiny directory).
 */
export function randFlaggedAwsPair(maxTries = 32): AwsPair {
  for (let i = 0; i < maxTries; i += 1) {
    const pair = randAwsPair();
    if (awsPairEngineFlagged(pair)) return pair;
  }
  throw new Error(
    "randFlaggedAwsPair: no engine-flagged pair in " + maxTries + " tries — gitleaks rules changed? investigate, do NOT relax the masking test",
  );
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
