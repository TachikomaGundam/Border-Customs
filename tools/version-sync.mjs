// provenance: 2026-10-17 third-party audit — seven hand-rotated version
// literals caused two real drift incidents (UA stuck at 0.3.0; lock root stuck
// at 0.1.0). package.json is the single source; this script rewrites the
// derived copies. Wire-up: npm's `version` lifecycle runs it automatically
// after `npm version <bump>`; `--check` is the CI drift gate.
//
// Deliberately NOT rewritten: changelog history and docs/release receipts are
// records of past releases, not live pins.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const checkOnly = process.argv.includes("--check");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const version = pkg.version;
const repoUrl = (pkg.repository?.url ?? "").replace(/^git\+/, "").replace(/\.git$/, "");

if (typeof version !== "string" || !/^\d+\.\d+\.\d+$/.test(version)) {
  console.error(`version-sync: package.json version is not semver: ${JSON.stringify(version)}`);
  process.exit(2);
}

const changes = [];

function rewrite(rel, fn) {
  const path = join(root, rel);
  const before = readFileSync(path, "utf8");
  const after = fn(before);
  if (after === before) return;
  changes.push(rel);
  if (!checkOnly) writeFileSync(path, after);
}

rewrite("package-lock.json", (text) => {
  const lock = JSON.parse(text);
  lock.version = version;
  if (lock.packages?.[""] !== undefined) lock.packages[""].version = version;
  return `${JSON.stringify(lock, null, 2)}\n`;
});

rewrite("plugin/border.ts", (text) =>
  text.replace(/^\/\/ border-opencode-plugin v\d+\.\d+\.\d+/m, `// border-opencode-plugin v${version}`),
);

rewrite("src/scan/fetch.ts", (text) =>
  text
    .replace(/("border-customs\/)\d+\.\d+\.\d+/g, `$1${version}`)
    .replace(/\(\+https:\/\/github\.com\/[^;]+;/, `(+${repoUrl};`),
);

rewrite("README.md", (text) =>
  text
    .split("\n")
    .map((line) =>
      /^\s*"plugin": \["border-customs@\d+\.\d+\.\d+"\]$/.test(line)
        ? line.replace(/@\d+\.\d+\.\d+/, `@${version}`)
        : line,
    )
    .join("\n"),
);

if (changes.length === 0) {
  console.log(`version-sync: clean at ${version}`);
} else if (checkOnly) {
  console.error(`version-sync: drift at ${version} in ${changes.join(", ")} — run: node tools/version-sync.mjs`);
  process.exit(1);
} else {
  console.log(`version-sync: wrote ${version} into ${changes.join(", ")}`);
}
