// provenance: todo 5 spike — empirical verification of the secretlint 13.0.5
// in-process API contract BEFORE src/engines/secretlint.ts was written.
// Run: node tools/spike-secretlint.mjs   (prints the API facts; exit 0 = contract holds)
//
// Verified facts this spike must prove (they are baked into the adapter):
//   A. @secretlint/core exports `lintSource({source, options:{config}})` ->
//      Promise<{filePath, sourceContent, sourceContentType, messages[]}>.
//   B. Rule modules export a named `creator` (v13 shape: {id, rule: creator, options?}).
//   C. preset-recommend (a preset creator) detects a planted AWS AccessKeyID.
//   D. @secretlint/secretlint-rule-pattern with the config-derived literal pattern
//      "/a\(b/" (our escapeRegex + slash-wrap output) matches the LITERAL "a(b"
//      and a slash-wrapped regex source "/C:\\Users\\\w+/" matches the Windows path —
//      i.e. NO crash from unbalanced metachars, regex sources honored.
//   E. message.range is [start,end] code offsets -> raw value = content.slice(range).
//      The rule message ECHOES the matched text (G23 hazard, adapter re-maps it).
//   F. severity on the config entry surfaces on each message ("error"|"warning").
//   G. CLI fallback (`secretlint --format json <files>`) exit codes: 0 clean /
//      1 findings / 2 crash, with JSON array on stdout — only probed, not used
//      unless the in-process API breaks.
import { lintSource } from "@secretlint/core";
import { creator as presetRecommend } from "@secretlint/secretlint-rule-preset-recommend";
import { creator as noHomedir } from "@secretlint/secretlint-rule-no-homedir";
import { creator as noDotenv } from "@secretlint/secretlint-rule-no-dotenv";
import { creator as patternRule } from "@secretlint/secretlint-rule-pattern";

const AWS_ID = ["AKIA", "I4Q3", "EXAMP", "L3K7", "X2Q"].join(""); // split so border's own dogfood scan cannot trip on this file
const AWS_TEXT = `aws_access_key_id = ${AWS_ID}\n`;

// escapeRegex mirror of the adapter's generator (kept in sync deliberately)
const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const literal = (s) => `/${escapeRegex(s)}/`;

const config = {
	rules: [
		{
			id: "@secretlint/secretlint-rule-preset-recommend",
			rule: presetRecommend,
			// SPIKE FINDING: the bundled AWS rule gates the AccessKeyID (AKIA…)
			// scanner behind options.enableIDScanRule, DEFAULT FALSE. Border turns
			// it on via per-preset-rule override — fail-closed coverage.
			rules: [{ id: "@secretlint/secretlint-rule-aws", options: { enableIDScanRule: true } }],
		},
		{ id: "@secretlint/secretlint-rule-no-homedir", rule: noHomedir },
		{ id: "@secretlint/secretlint-rule-no-dotenv", rule: noDotenv },
		{
			id: "border-pattern",
			rule: patternRule,
			severity: "error",
			options: {
				patterns: [
					{ name: "internal-host:a(b", patterns: [literal("a(b")] },
					{ name: "path-pattern:c-users", patterns: ["/C:\\\\Users\\\\\\w+/"] },
				],
			},
		},
	],
};

let failures = 0;
const check = (name, cond, extra) => {
	console.log(`${cond ? "PASS" : "FAIL"}: ${name}${extra ? ` — ${extra}` : ""}`);
	if (!cond) failures++;
};

const lint = (content, filePath) =>
	lintSource({ source: { content, filePath, contentType: "text" }, options: { config } });

// --- A/B: call shape itself throwing would exit non-zero ---
const awsRes = await lint(AWS_TEXT, "creds.txt");
check("A: lintSource returns messages array", Array.isArray(awsRes.messages), JSON.stringify(Object.keys(awsRes)));
const awsHit = awsRes.messages.find((m) => m.messageId?.includes("AWSAccessKeyID") || m.message.includes(AWS_ID));
check("C: preset-recommend catches planted AWS AccessKeyId", Boolean(awsHit), awsHit ? `${awsHit.ruleId}/${awsHit.messageId}` : "none");
check("E: range slices to the matched secret", Boolean(awsHit) && awsRes.sourceContent?.slice(awsHit.range[0], awsHit.range[1]) === AWS_ID, Boolean(awsHit) && `slice='${awsRes.sourceContent?.slice(awsHit?.range?.[0], awsHit?.range?.[1])}'`);
check("E: raw message ECHOES secret (G23 hazard confirmed)", Boolean(awsHit) && awsHit.message.includes(AWS_ID));
check("F: message carries severity", Boolean(awsHit) && typeof awsHit.severity === "string", awsHit?.severity);

// --- D: generated pattern rules ---
const patRes = await lint("connect to a(b now\ndoc at C:\\Users\\bob\\doc.txt\n", "notes.md");
const hostHit = patRes.messages.find((m) => m.message.includes("internal-host:a(b"));
check("D: escaped literal 'a(b' matches literally, no crash", Boolean(hostHit), hostHit ? `match='${patRes.sourceContent.slice(hostHit.range[0], hostHit.range[1])}'` : "none");
const winHit = patRes.messages.find((m) => m.message.includes("path-pattern:c-users"));
check("D: slash-wrapped Windows regex matches C:\\Users\\bob", Boolean(winHit), winHit ? `match='${patRes.sourceContent.slice(winHit.range[0], winHit.range[1])}'` : "none");
check("D: pattern rule loc has 1-based line + 0-based column", Boolean(hostHit) && hostHit.loc.start.line === 1 && typeof hostHit.loc.start.column === "number", JSON.stringify(hostHit?.loc?.start));

// --- clean file => 0 messages ---
const cleanRes = await lint("# benign\nnothing to see\n", "README.md");
check("clean fixture => 0 messages", cleanRes.messages.length === 0, JSON.stringify(cleanRes.messages.map((m) => m.messageId)));

// --- no-dotenv sanity: .env-named file flags even without content match ---
const envRes = await lint("A=1\n", "/x/.env");
check("no-dotenv fires for .env filename", envRes.messages.some((m) => m.ruleId.includes("no-dotenv") || m.messageId === "FOUND_DOTENV_FILE"), JSON.stringify(envRes.messages.map((m) => `${m.ruleId}/${m.messageId}`)));

// --- G: CLI fallback probe (explicit file list, --format json) ---
const { execFile } = await import("node:child_process");
const { writeFileSync, mkdtempSync } = await import("node:fs");
const { tmpdir } = await import("node:os");
const { join } = await import("node:path");
const dir = mkdtempSync(join(tmpdir(), "border-spike-cli-"));
const badFile = join(dir, "leak.txt");
writeFileSync(badFile, AWS_TEXT);
const runCli = (args) =>
	new Promise((resolve) => {
		execFile(process.execPath, [join(process.cwd(), "node_modules", ".bin", "secretlint"), ...args], (err, stdout, stderr) => {
			resolve({ code: err ? err.code : 0, stdout, stderr });
		});
	});
// CLI needs a .secretlintrc.json discovery or --config; without rules config it exits 2 (crash path) — record, do not judge.
const cliFind = await runCli(["--format", "json", badFile]);
console.log(`INFO: CLI exit=${cliFind.code} stdout head=${JSON.stringify(cliFind.stdout.slice(0, 200))}`);
check("G: CLI exit codes are 0/1/2 domain", [0, 1, 2].includes(cliFind.code), String(cliFind.code));
const { rmSync } = await import("node:fs");
rmSync(dir, { recursive: true, force: true }); // no fixture residue anywhere

console.log(failures === 0 ? "\nSPIKE: in-process API contract HOLDS (todo-5 adapter goes in-process)" : `\nSPIKE: ${failures} FAILED checks`);
process.exit(failures === 0 ? 0 : 1);
