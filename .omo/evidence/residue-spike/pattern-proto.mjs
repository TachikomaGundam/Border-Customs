// R1 spike: PROTOTYPE residue pattern families (scratch evidence, never src/).
// Mirrors the plan's "Must have" signature-table bullets so R2 ships the closed
// table in artifactMatchers.ts house style. Demonstrates every family has at
// least one hittable planted fixture (§4 negative controls).
import { readdirSync, readFileSync, statSync } from "node:fs"
import { join } from "node:path"

const planted = "/home/lab/workspace/harness/border/.omo/evidence/residue-spike/planted"

/** family -> [patternId, RegExp][] — candidate closed-list shapes. */
const FAMILIES = {
  "T2-network": [
    ["t2-js-net", /(?:require\(\s*["'](?:node:)?(?:https?|net|dns)["']\s*\)|\bfetch\s*\(|\bhttps?\.get\s*\(|\b(?:curl|wget)\s|Invoke-WebRequest)/],
    ["t2-py-net", /\b(?:urllib\.request|urllib\.error|requests\.(?:get|post)|httpx)\b/],
    ["t2-rs-net", /\b(?:reqwest|ureq)\b/],
    ["t2-rb-net", /\b(?:Net::HTTP|open-uri|URI\.open|Kernel\.open)\b/],
  ],
  "T3-out-of-tree": [
    ["t3-dotfile", /(?:\.bashrc|\.zshrc|\.zshenv|\.profile\b|\.config\/|\/etc\/profile\.d|authorized_keys|\.gitconfig)/],
    ["t3-win-path-carrier", /(?:USERPROFILE|%APPDATA%|AppData\b|setx\s+\/?F?\s*PATH|HKCU:\\?Environment|SetEnvironmentVariable)/],
    ["t3-path-export", /export\s+PATH=/],
    ["t3-git-global", /(?:git\s+config\s+--global|--global["']\s*,|["']\.gitconfig["'])/],
  ],
  "T4-persistence": [
    ["t4-unix", /\b(?:crontab\b|systemctl\s+--user|systemd\/user|LaunchAgents|launchctl\b|\.config\/autostart)/],
    ["t4-win", /\b(?:schtasks\b|CurrentVersion\\Run)/],
  ],
  "cross-manager": [
    ["xmgr-spawn", /(?:spawn(?:Sync|File(?:Sync)?)?|exec(?:Sync|File(?:Sync)?)?)\s*\(\s*["'](?:pip|npm|yarn|pnpm|gem|cargo|uv|easy_install)["']/],
    ["xmgr-shell", /(?:pip|easy_install|npm|yarn|pnpm|gem|cargo|uv)\s+(?:install|add|global\s+add)\b/],
  ],
}

const files = []
const walk = (d) => {
  for (const e of readdirSync(d)) {
    const p = join(d, e)
    if (statSync(p).isDirectory()) walk(p)
    else files.push(p)
  }
}
walk(planted)

const rows = []
const hitByFamily = new Map(Object.keys(FAMILIES).map((f) => [f, 0]))
for (const [family, patterns] of Object.entries(FAMILIES)) {
  for (const [pid, re] of patterns) {
    const hits = []
    for (const f of files) {
      const text = readFileSync(f, "utf8")
      text.split("\n").forEach((line, i) => {
        if (re.test(line)) hits.push(`${f.replace(planted + "/", "")}:${i + 1}: ${line.trim().slice(0, 72)}`)
      })
    }
    if (hits.length > 0) hitByFamily.set(family, hitByFamily.get(family) + hits.length)
    rows.push({ family, pattern: pid, hits: hits.length, first: hits[0] ?? "—", all: hits })
  }
}
console.log(JSON.stringify({ rows, hitByFamily: Object.fromEntries(hitByFamily) }, null, 2))
