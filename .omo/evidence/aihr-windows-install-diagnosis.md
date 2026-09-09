# aihr Windows install failure — diagnosis evidence (read-only)

Date: 2026-09-08 · Device: sonic@192.168.10.70 (Windows, CPython 3.14.6 MSC v1944) · Subject: `pip install aihr` then `python -m hr setup` crashes.
Governing constraints (user, verbatim intent):
- 不要直接修改目标设备 — device is read-only for diagnosis only.
- 不要在本 session 改 hr 代码 — fix must come from **border itself**: 边检升级具备检测+修复能力 → 在 hr workspace 调用边检完成修复 → 发布 → 设备重装 → 走通此闭环才算真修复（边检自进化）。

## 1. Symptom (device traceback, user-pasted)

`python -m hr setup` →
```
hr/cli_setup.py:103  res = _call(runner, ["npm", "install", "-g", *plugin_specs()], _NPM_TIMEOUT_S)   [device copy = aihr 0.2.1]
hr/cli_setup.py:53   default_runner → subprocess.run(argv, ...)
C:\Python314\Lib\subprocess.py:1553 _execute_child → _winapi.CreateProcess(...)
FileNotFoundError: [WinError 2] 系统找不到指定的文件。
```

## 2. Device evidence (read-only probe; script: /tmp/opencode/aihr_win_probe.py, piped via `ssh sonic@... "python -"`)

| Probe | Result | Meaning |
|---|---|---|
| `shutil.which("npm")` | `C:\Program Files\nodejs\npm.CMD` | npm **is** installed (npm 12.0.2) |
| `subprocess.run(["npm","--version"])` | **FileNotFoundError winerror=2** | reproduces user crash exactly |
| `subprocess.run([which_path,"--version"])` | **rc=0, "12.0.2"** | CreateProcess *can* exec an explicit `.CMD` full path |
| `reg query HKCU\Environment /v Path` | present, **lacks** `%APPDATA%\Python\Python314\Scripts` | PATH-waiver step genuinely needed (setup_env.py scope, correct) |
| `%APPDATA%\Python\Python314\Scripts\` | contains `hr.exe`, `f2py.exe`, `torchrun.exe` | wheel scripts landed; only PATH missing |
| installed `hr.__version__` | **0.2.1** | vs repo pyproject 0.2.2 + tag v0.2.2 → version-source drift (see §6) |
| installed `cli_setup.py` contains `["npm", "install", "-g"` | true | device copy has the bare-argv bug shape |

## 3. Root-cause mechanism

Windows `CreateProcess` does **not** apply `PATHEXT` resolution: a bare `argv[0] = "npm"` tries `npm.exe`, misses `npm.CMD`, → ERROR_FILE_NOT_FOUND (WinError 2). `shutil.which()` *does* apply PATHEXT and returns the full `.CMD` path, which CreateProcess executes fine (via implicit cmd.exe). Classic Python-on-Windows npm-spawn trap. `cmd.exe`/PowerShell users never see it (shell resolves npm.cmd), so every developer on POSIX/Linux+macOS is blind to it.

## 4. Source lesion list (HEAD, harness/hr/hr/cli_setup.py — pyproject 0.2.2)

All spawn sites build bare `"npm"` argv[0]; `default_runner` never resolves via `shutil.which`:

| Line | Site | Defect |
|---|---|---|
| :65 `plugin_specs(npm: str = "npm")` | argv[0] defaults to bare `"npm"` | install-path spawn (run_setup uses `plugin_specs()` as full argv at HEAD) |
| :75 | `extra = ["--include-workspace-root","false"] if Path(npm).name == "npm"` | dead condition (always true — npm literal); **plus suspect argv shape**: `--include-workspace-root` is a boolean npm flag; space-separated `false` likely parses as a *package name* — needs verification when fixed |
| :99 `_find_registrar` | `["npm","prefix","-g"]` bare | same WinError 2, reached after install would have succeeded → second landmine |
| :124 `_report_resolved_versions` | `["npm","ls","-g",...]` bare | third landmine (also runs on device 0.2.1 shape) |
| :161-164 `_npm_argv` | `npm = "npm"` hardcoded bare (+same dead cond/flag) | **uninstall-path** spawn |
| :72-76 `_call` | catches only `subprocess.TimeoutExpired` | `FileNotFoundError`/`OSError` escapes → raw Rich traceback (the UX of the incident). Needs OSError→`CommandResult(rc=127,...)` mapping |
| :198,:240 | guards `if shutil.which("npm") is None: error/skip` | **asymmetry**: guard passes on Windows (which finds npm.CMD) yet the spawn then fails anyway — guard and spawn use different resolution semantics, giving false confidence + crash |

Version shape on device (0.2.1): crash was `["npm","install","-g",*plugin_specs()]`; HEAD (0.2.2) refactored to `plugin_specs()` returning full argv — same bare-`npm` disease, different arrangement. **0.2.2 still crashes on Windows; the wheel is shipping broken on win.**

## 5. Test-seam blind spot (why CI never caught it)

`tests/test_plugin_setup.py`: every test monkeypatches `shutil.which` → `/usr/bin/npm` and injects a **fake Runner** (argv→CommandResult). The real `default_runner`/`subprocess` path is never executed; the bare-`"npm"` argv string is asserted only as data. POSIX-only dev + injected-runner design = platform spawn layer untested by construction. (tests/test_setup_env.py is pure-logic with injectable platform/home/environ/reg_mod — that half is exemplary.)

## 6. Secondary suspects (verify before/at fix time)

1. **POSIX path hardcodes for opencode dirs** — candidate Windows-portability bugs (verify against opencode's actual Windows data dirs before ruling):
   - cli_setup.py:172 `cache_root = XDG_CACHE_HOME or ~/.cache` + `/opencode/packages`
   - cli_setup.py:183 `_opencode_config_dir = OPENCODE_CONFIG_DIR or ~/.config/opencode`
   - opencode_plugin/install-cli.js:24 `OPENCODE_CONFIG_DIR ?? homedir()/.config/opencode`; :164 message `~/.cache/opencode/packages`
   - opencode_plugin/server.ts:11 `HR_HOME ?? homedir()/hr`
2. **Version-source drift**: `hr/__init__.py __version__="0.2.1"` vs `pyproject version="0.2.2"` vs tag `v0.2.2`; two egg-infos (`aihr.egg-info`, `hr_agent.egg-info`) suggest historical rename residue in-tree. Device `import hr` reported 0.2.1 despite earlier pip log claiming aihr-0.2.2 install → either the 0.2.2 wheel shipped the stale `__version__`, or an old copy shadows. Either way release metadata is not single-sourced.
3. **numba↔numpy 2.5.3 conflict** on device env (pip check ERROR at install time) — environment integrity, unrelated to the crash but gate-relevant material (`integrity-*` family candidate).

## 7. Correct fix (source-level, to be delivered BY BORDER in hr workspace)

1. Resolve npm **once per spawn through the resolution that CreateProcess lacks**: `_npm = shutil.which("npm") or "npm"` threaded into every argv[0] (plugin_specs param, :99, :124, `_npm_argv`), or central `_npm_argv()` used by all sites. Works on all OS (POSIX which → the real binary).
2. Harden `_call`: `except OSError as e: return CommandResult(127, "", f"failed to spawn {argv[0]}: {e}")` — no raw tracebacks regardless of cause.
3. Resolve the dead condition + verify/correct `--include-workspace-root false` flag shape.
4. Close the test seam: assert argv[0] of every constructed npm argv is an existing file path when driven through a `shutil.which` fake that returns `…/npm.CMD`; add a `_call` OSError→rc127 test. (Windows-only CreateProcess behavior can't run in Linux CI — pin the *resolution shape* instead.)
5. Verify secondary suspects §6.1/§6.2 while in there (separate commits; bugfix minimal).

## 8. Border improvement points derived (for joint review → border 0.3.0 plan amendment)

- **B1 `xplatform-spawn-*` rule family (detection)**: static closed-table scan of artifact sources: bare `["npm"/"npx"/"yarn"/"pnpm", …]` (and Python `subprocess.*` / JS `child_process.exec*` equivalents) used as argv **without** `shutil.which`/`.cmd` suffix/`shell=True`, in packages whose metadata claims Windows support (classifiers/osf or absence of exclusion) ⇒ HIGH `xplatform-spawn-cmd-shim`. Closed vocabulary, matcher-style (artifactMatchers precedent). This incident is the golden fixture: real aihr 0.2.2 wheel must trip it.
- **B2 persistence↔inverse pairing (detect + REQUIRE)**: T3/T4 persistence writes must ship a marker-symmetric inverse — aihr setup_env's `# BEGIN aihr PATH (hr setup)`/`END` + `--uninstall` gives border a **statically checkable pairing signature** (marker string must appear on both write and remove code paths; CLI inverse command must exist). This is the concrete first slice of the deferred "pairing" 0.4.0 valve — user's original ask (m00007) lands here, done right: pairing lives in the package's own CLI, not manager hooks.
- **B3 path-portability heuristics (detection, advisory MEDIUM)**: `~/.cache`/`~/.config`/XDG-only assumptions in win-claiming packages → the §6.1 class.
- **B4 `release-coherence` (detection, MEDIUM→HIGH)**: version-source drift §6.2: pyproject vs `__init__.__version__` vs tags vs npm-side manifests must single-source/match; dual-line repos (wheel+plugin) skew-checked at HEAD. Extends earlier G1/G2 notes.
- **B5 remediation capability (the self-evolution core)**: new border verb (design decision needed — `border fix`?) that, **inside the plugin workspace**, applies closed-set mechanical fixes for findings it raised (B1-B4 each have a deterministic patch shape: insert which-resolution, wrap _call, marker pairing…). Hard constraints to keep it fail-closed: only rule-ids with a registered fixer; patch = surgical diff, never auto-commit/publish; write nothing outside target repo; every fix leaves evidence (finding→diff→re-check pass); after which the normal check→push pipeline runs, and only the user publishes. This transforms border from gate to gate+surgeon and is the mechanism by which "边检具备修复能力，在 hr workspace 调用边检完成修复" becomes true.
- Process note: verification loop of record = border upgrade → `border check` in hr workspace trips B1-B4 → `border fix` patches → tests green → publish via border → device reinstall → `python -m hr setup` succeeds → close.
