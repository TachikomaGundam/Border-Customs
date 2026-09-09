# P2 (0.3.1 path-portability-xdg) — verified ground truth, 2026-09-09
Full raw research: /home/lab/.local/share/opencode/tool-output/tool_0841734170014WaV1iRYZNr342
Repo pins: sst/opencode→anomalyco/opencode @5cd8e68fdd72b27818d26d168b9c7a06b359567e; sharkdp/fd @b422e5d8; pypa/pip @2b28a816 (platformdirs 4.11.0 vendored); dirs-dev/dirs-rs @797467e7; soc/directories-rs @5e79dfe4.

## opencode Windows paths (Q1/Q2)
- Helper: xdg-basedir@5.1.0, consumed ONLY at packages/core/src/global.ts:10-15 (data/cache/config/state = xdgX + '/opencode' via path.join; tmp=os.tmpdir(); bin=cache/bin; log=data/log). Overrides: OPENCODE_CONFIG_DIR (global.ts:64), OPENCODE_TEST_HOME (:19).
- xdg-basedir/index.js:4-13 has ZERO win32 branch: XDG_* env ?? os.homedir()+/.config|/.local/share|/.local/state|/.cache → on Windows C:\Users\<u>\.config\opencode etc. NOT %LOCALAPPDATA%.
- Library README itself warns: 'This package is meant for Linux... use env-paths on macOS/Windows' — opencode keeps XDG everywhere deliberately; docs pages (config/troubleshooting) carry no OS-conditional prose; issues #27786/#18633 complain about XDG layout with no maintainer path-change commit.
- Desktop app differs: Electron %APPDATA%\ai.opencode.desktop (store.ts:14, migrate.ts:12-20, sidecar sets XDG_STATE_HOME).
- Windows support is first-class: test.yml + e2e matrix run windows (blacksmith windows-2025), publish.yml ships windows-x64/arm64 binaries.
- Correctness patterns opencode itself uses: win32-guarded chmod (core ripgrep/binary.ts:88), Git-Bash resolution for unix-shell spawns (core shell.ts gitbash()/Flag.OPENCODE_GIT_BASH_PATH), case-insensitive env lookup win32 (tool/shell.ts:140-144), ~\ handled in tilde expansion (:137), drive-letter path conversion (FS windowsPath regex ^[A-Za-z]:(?:[\\/]|$), /mnt/, cygdrive).

## Verified safe-API vocabulary (rule's NOT-flagged list, Q3)
- Node: os.homedir()+path.join(.,'.config',app) [portable — do NOT flag the dot-dir convention]; env-paths; @sindresorhus/xdg-basedir@5 [flag with note: author says Linux-only].
- Rust: dirs::{config,data,cache,state,home}_dir(); directories::{BaseDirs,UserDirs,ProjectDirs}::from(org,app)[.config_dir()|.data_dir()|.cache_dir()|.state_dir()]; etcetera choose_base_strategy().config_dir() (fd @b422e5d8 Cargo.toml:43/walk.rs:372). Windows: config/data→FOLDERID_RoamingAppData, cache→FOLDERID_LocalAppData, state→RoamingAppData (dirs-rs: NONE on Windows); executable_dir→None; user_*→FOLDERID_Profile fallback.
- Python: platformdirs.PlatformDirs(...).user_config_dir/user_data_dir/user_cache_dir/user_state_dir (+ module fns); pip utils/appdirs.py:12-54 vendored call sites. Windows: config/data→CSIDL_APPDATA (roaming opt-in LOCAL), cache→LOCALAPPDATA+\Cache (opinion), site_config→CSIDL_COMMON_APPDATA.

## Broken-CONSTRUCT classes (MEDIUM advisory targets, Q4)
(a) '~'-prefix string concatenation with POSIX separators (homedir()+'/.config/x' — backslash mix on win); (b) unconditional chmod+x on installed artifacts; (c) POSIX-only path literals in shipped code paths (/usr/local, /bin, /etc, $HOME literal expansion) reached on win32; (d) drive-relative or \\-vs-/ assumptions incl. ':'-splitting env lists; (e) spawning .sh/shebang artifacts assuming bash exists.
Severity anchor: opencode proves dot-dir+join(homedir) works on Windows ⇒ advisory fires on CONSTRUCTS, never on the convention; single-source path helper ⇒ silent.
