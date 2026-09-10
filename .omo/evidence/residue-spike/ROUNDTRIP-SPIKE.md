# W2.0 — Sandbox-Roundtrip Feasibility Spike (npm / pypi / rubygems / cargo)

- **Verdict:** `docker required` for full-FS roundtrip on this box (docker RC=0, overlayfs); host throwaway-HOME lanes are `cannot-verify` for root-owned surfaces and are **provably too noisy on shared `/tmp`** for a "clean" call. Container lanes hit the plan's acceptance bar: planted tree shows **exactly** — `ADDED(7) REMOVED(0) MODIFIED(0)` with a **minimum exclusion set of 8 paths**, 1–2 s per full-root manifest.
- **Scope:** evidence only, **no product code touched** (repo tree was mid-edit by another worker; no `npm test`/`npm run build`/git writes). Date 2026-09-10. All scratch under `/tmp/rt-*`, cleaned at exit (receipt at bottom).
- **Plan reference:** `border/.omo/plans/border-inspect-roadmap.md` W2.0 — install → sha256 FS manifest → uninstall → re-manifest → diff empty for compliant packages; surviving bytes = residue FACTS.

Raw transcripts for every quoted line: [`roundtrip-spike-transcripts.txt`](roundtrip-spike-transcripts.txt). Scripts: [`roundtrip-spike-lib.sh`](roundtrip-spike-lib.sh) + `roundtrip-spike-{host-npm,host-pypi,host-pypi-cache,host-gemcargo,docker-npm,docker-npm-minexcl,docker-pypi,hr-w23}.sh`.

---

## 1. Step 0 — container runtime on THIS machine

```
$ docker info >/dev/null 2>&1; echo DOCKER_RC=$?
DOCKER_RC=0
$ docker version --format '{{.Server.Version}} storage={{.Driver}}'   # via info
Server 29.1.3, Storage Driver: overlayfs (io.containerd.snapshotter.v1)
$ command -v podman; echo RC=$?
RC=127   (podman absent — irrelevant, docker works)
```

Both spike images pulled cleanly and are the lanes used below:

```
$ timeout 300 docker pull node:24-slim   -> ok (transcripts /tmp/rt-pull-node.log)
$ timeout 300 docker pull python:3.12-slim -> ok
```

**Docker is present, so the plan's "docker-absent ⇒ host-mode-only" fallback is not the operative branch here** — but its fail-closed rule is confirmed structurally by the host lanes: unprivileged installers **cannot write** `/etc/profile.d` or `/usr/local/bin` on this box (EACCES shown in every host lane), yet those paths are **unhashable by an unprivileged manifest** (`/etc/shadow` EACCES, `/var/spool/cron/crontabs` `drwx-wx--T`, `ls` RC=2). Worse, this machine grants **passwordless sudo** (`sudo -n true` RC=0) to the desktop user that would run `border roundtrip` — so a postinstall script running in host mode is privilege-reachable to root surfaces that the host-mode manifest cannot observe. Per plan W2.0: **cannot-verify ⇒ exit 2, never clean**. That is the correct product semantic for host mode here regardless of which specific write happens to be blocked.

## 2. Manifest model (spike lib, `roundtrip-spike-lib.sh`)

- `rt_snapshot OUT [--exclude P ...] -- [root[:h] ...]` → lines `F|L|D \t path \t mode \t sha256|'-'`. Content hash + mode only — **no mtime/atime/ctime/inode**, so overlayfs copy-up (which changes atime/inode on first write) cannot pollute diffs by construction.
- `rt_diff before after` → join-based `ADDED(n)/REMOVED(n)/MODIFIED(n)` keyed on (type,path); exit 0 iff identical.
- `rt_ctr_snapshot CONTAINER OUT ...` → same pipeline executed via `docker exec <ctr> sh -c` (POSIX sh, works on debian-slim images).
- Path-only roots (`/tmp` without `:h`) because hashing host `/tmp` is infeasible:

```
20000 readable /tmp files hashed in 10.61s -> 512923 files extrapolate: 272s (~4.5 min/pass)
```

- Fixtures: planted packages (never real registries — puppeteer too heavy per prior research) that write **5 targets**: `$HOME/.config/rt-<eco>-plant/rc-say.sh`, `/tmp/rt-<eco>-plant-tmp`, `/var/tmp/rt-<eco>-plant-vartmp`, `/etc/profile.d/rt-<eco>-plant.sh`, `/usr/local/bin/rt-<eco>-plant` — 3 writable by any user, 2 root-only. Uninstall-side hooks: none (compliant package), so the acceptance diff should be exactly the planted tree.

## 3. Host lanes (throwaway HOME + disposable install root)

All host lanes share this shape (`bash roundtrip-spike-host-npm.sh`, full command lines in transcripts): `mktemp -d` scratch → `HOME=$SCRATCH/home` (plus pinned `XDG_CONFIG_HOME`) → manifest → install → manifest → uninstall → manifest → diff.

### 3.1 npm (`npm install --prefix $SCR/prefix --cache $SCR/prefix/.npmcache`)

Postinstall output (host, unprivileged):

```
PLANTED /tmp/rt-host-npm.Qv2xTI/home/.config/rt-npm-plant/rc-say.sh
PLANTED /tmp/rt-npm-plant-tmp
PLANTED /var/tmp/rt-npm-plant-vartmp
PLANT-DENIED /etc/profile.d/rt-npm-plant.sh EACCES
PLANT-DENIED /usr/local/bin/rt-npm-plant EACCES
```

Acceptance diff (baseline → after uninstall), observed roots {HOME, /tmp path-only, /var/tmp, /etc/profile.d, /usr/local/bin}:

```
ADDED(6)
A	D/tmp/rt-host-npm.Qv2xTI/home/.config
A	D/tmp/rt-host-npm.Qv2xTI/home/.config/rt-npm-plant
A	F/tmp/rt-host-npm.Qv2xTI/home/.config/rt-npm-plant/rc-say.sh
A	F/tmp/rt-host-npm.Qv2xTI/home/.npm/_logs/2026-09-10T07_41_39_508Z-debug-0.log
A	F/tmp/rt-npm-plant-tmp
A	F/var/tmp/rt-npm-plant-vartmp
REMOVED(0)
MODIFIED(0)
```

- Planted tree **EXACT** (3/3 writable-surface plants; no false negatives; 2 root targets correctly invisible to an unprivileged writer *and* the manifest — the cannot-verify case).
- **Tool-noise line #4 is npm itself**: writes `$HOME/.npm/_logs/*.log` inside the throwaway HOME even with `--cache` relocated. Pass-to-pass control (`obs-final` 639861 → `obs-final2` 639862 entries, 28 s apart) shows the same: exactly +1 npm debug log. So host-mode acceptance must **exclude `$HOME/.npm/_logs`** (or the diff is never empty for any npm install).
- Uninstall reversal of the install root: `npm uninstall` REMOVED(4) (package tree) but **MODIFIED(3)** — it rewrites `package.json`/`package-lock.json`/`.package-lock.json` inside the prefix. Harmless in a disposable prefix; would be residue-facts in a real one.
- Default-cache control (HOME override only): survivors `~/.npm/_cacache{content-v2,index-v5}` + 4534 B → cache relocation mandatory.

### 3.2 pypi (`python3 -m venv` + cold `pip install` sdist, `PIP_CACHE_DIR` relocated)

Setup.py runs at build time and plants. Install (network to public PyPI for build-isolation setuptools — allowed):

```
Successfully built rt-pypi-plant
Successfully installed rt-pypi-plant-0.0.1
```

Acceptance diff:

```
=== ACCEPTANCE DIFF obs-baseline -> obs-final ===
ADDED(6)
A	D/tmp/rt-host-pypi.izb6pn/home/.config
A	D/tmp/rt-host-pypi.izb6pn/home/.config/rt-pypi-plant
A	F/tmp/rt-host-pypi.izb6pn/home/.config/rt-pypi-plant/rc-say.sh
A	F/tmp/rt-pypi-plant-tmp
A	F/var/tmp/rt-pypi-plant-vartmp
REMOVED(2490)
```

(the 6th ADDED is foreign: `/tmp/border-gitleaks-ignore-TLwaY5` created by the **concurrent worker** mid-window; all 2490 REMOVED are foreign churn — `/tmp/abathur-bundle-o7BxXq/**`, `/tmp/abathur-self-*/** deleted by that worker inside our 2.7-min install window). Then `pip uninstall -y` → `Successfully uninstalled`, zero plant-side REMOVED/MODIFIED.

- Plants captured **EXACTLY** — but this is the spike's **headline host-mode finding**: on a shared desktop `/tmp`, a path-level manifest produced **2491 noise lines from one concurrent process** in under 3 minutes. A "clean" host verdict would require a hand-tuned exclusion list per machine; the noise is adversarial-proof by accident, not by design.
- `files.pythonhosted.org` intermittently truncated downloads (0 B / 818 kB) — lanes use `--resume-retries 5`.
- Default-cache control (`roundtrip-spike-host-pypi-cache.sh`, XDG dirs pinned into throwaway HOME): after clean uninstall, `~/.cache/pip` survives with **1020358 bytes** (first attempt showed a false 0 because this box exports `XDG_CACHE_HOME=/home/lab/.cache` globally — HOME override alone does not relocate pip's cache):

```
--- HOME2 survivors after clean uninstall (default cache policy):
~/.cache
~/.cache/pip
HOME2 bytes after uninstall: 1020358
```

### 3.3 rubygems (`gem install -i $SCR/gems` = GEM_HOME)

Plants fire from `setup.py`-equivalent inline block in the gemspec build (lesson: `gem build` evaluates the gemspec with `Gem::Specification` as receiver — a top-level `def` is invisible: `undefined method 'plant' for class Gem::Specification`; inline `begin/rescue` per write). Acceptance `g-base(615566) → g-final(615571)`:

```
ADDED(5)
A	D/tmp/rt-host-gc.qm5oJa/ghome/.config
A	D/tmp/rt-host-gc.qm5oJa/ghome/.config/rt-gem-plant
A	F/tmp/rt-host-gc.qm5oJa/ghome/.config/rt-gem-plant/rc-say.sh
A	F/tmp/rt-gem-plant-tmp
A	F/var/tmp/rt-gem-plant-vartmp
REMOVED(0)
MODIFIED(0)
```

`PLANT-DENIED /etc/profile.d/rt-gem-plant.sh Permission denied @ rb_sysopen`, ditto `/usr/local/bin`. Uninstall reversal exact: `gems-tree-entries-after-uninstall=0`.

### 3.4 cargo (`cargo install --path . --root $SCR/cargoroot`, `CARGO_HOME` disposable)

`build.rs` plants during install. Acceptance `c-base(615568) → c-final(615573)`: `ADDED(5)` — same five writable-surface entries, `REMOVED(0) MODIFIED(0)`. `cargoroot-entries-after-uninstall=0` (`cargo uninstall` exact). Same two EACCES plant-denials.

**Host-lane summary:** every host lane captured the planted **user-writable** tree exactly (npm 3/3, pypi 3/3, gem 3/3, cargo 3/3, zero false negatives), each with a documented tool-noise exclusion (npm `_logs`+`_cacache`, pip cache, and shared-`/tmp` churn that is **unbounded**); none can observe or contain the two root surfaces.

## 4. Docker lanes (full-FS roundtrip)

### 4.1 npm on `node:24-slim` (`roundtrip-spike-docker-npm.sh`, `npm install -g` as root)

**C0 noise floor / copy-up check** — two back-to-back full-root manifests (`/`, sha256 everywhere; exclusions `/proc /sys /dev` only), nothing running:

```
c0a entries=7212 elapsed=2s     c0b entries=7212 elapsed=2s
--- C0 diff (c0a -> c0b):  ADDED(0) REMOVED(0) MODIFIED(0)   C0_RC=0
```

**Zero noise. overlayfs copy-up does NOT pollute diffs** — because the manifest records content-hash+mode only; a copy-up that merely moves an unchanged file to the upper layer produces byte-identical lines. (First C0 attempt was dirty solely because the scanner itself did `mktemp -d` under `/tmp` — fixed to `/dev/shm`; that was spike-tooling noise, not an overlayfs artifact.)

Install as root writes the **root-only surfaces** the host lane could never see:

```
PLANTED /etc/profile.d/rt-npm-plant.sh
PLANTED /usr/local/bin/rt-npm-plant
c1 entries=7212 -> c2 entries=7783 -> c3 entries=7783   (1-2s per pass)
```

Naive diff (virtual-FS exclusions only) `c1→c3`: `ADDED(571)`, of which ~560 are tool noise — `/root/.npm/_cacache/**`, `/root/.npm/_logs/*.log`, `/root/.npm/_update-notifier-last-checked`, and the V8 **`/tmp/node-compile-cache/v24.21.0-x64-…/**`** tree (node 24 compile cache — new surface, invisible to npm's own config):

```
ADDED(571)
A	D/root/.npm/_cacache
A	D/root/.npm/_cacache/content-v2
...
```

With the identified exclusion set applied (`roundtrip-spike-docker-npm-minexcl.sh`; `MINEXCL = /proc /sys /dev /root/.npm /tmp/node-compile-cache /etc/hostname /etc/resolv.conf /etc/hosts`) and **`/tmp` + `/var/tmp` + `/etc` + `/usr/local` left fully observable**, acceptance `m1(7209) → m3(7216)` after `npm uninstall -g`:

```
PLANTED_LINES=5
ADDED(7)
A	D/root/.config
A	D/root/.config/rt-npm-plant
A	F/etc/profile.d/rt-npm-plant.sh
A	F/root/.config/rt-npm-plant/rc-say.sh
A	F/tmp/rt-npm-plant-tmp
A	F/usr/local/bin/rt-npm-plant
A	F/var/tmp/rt-npm-plant-vartmp
REMOVED(0)
MODIFIED(0)
MINEXCL_RC=0
```

**Planted tree EXACTLY — 5 files + 2 dirs, all 5 plants (incl. both root surfaces), no false negatives, zero noise.** Full roundtrip incl. container boot ≈ 35 s.

### 4.2 pypi on `python:3.12-slim` (`roundtrip-spike-docker-pypi.sh`, `pip install` sdist as root)

- C0 control: `c0a 5572 → c0b 5572, ADDED(0) REMOVED(0) MODIFIED(0)`, 1 s/pass — again zero copy-up noise.
- `Successfully built/installed rt-pypi-plant-0.0.1` inside the container (build-isolation fetch over container NAT).
- Naive diff `c1→c3`: `ADDED(521)` — dominated by `/root/.cache/pip/{http-v2,wheels,selfcheck}`.
- NEXCL round (exclude `/root/.cache /tmp /var/tmp /etc/{hostname,resolv.conf,hosts}`), `c1n(6042) → c3n(6046)`:

```
ADDED(4)
A	D/root/.config/rt-pypi-plant
A	F/etc/profile.d/rt-pypi-plant.sh
A	F/root/.config/rt-pypi-plant/rc-say.sh
A	F/usr/local/bin/rt-pypi-plant
REMOVED(0)
MODIFIED(0)
```

Planted root surfaces **exactly**; pip leaves zero residue beyond its cache (relocatable via `PIP_CACHE_DIR` into `/root/.cache` → one exclusion covers it).

### 4.3 Docker noise-exclusion set required for a zero-noise diff (measured, not guessed)

| exclusion | why (observed) |
|---|---|
| `/proc /sys /dev` | virtual FS, unreadable/volatile by definition |
| `/etc/hostname /etc/resolv.conf /etc/hosts` | docker bind-mounts them; timestamps/inode vary per start (content stable, but excluded to keep C0 strictly zero across container reuse) |
| `/root/.npm` (npm lane) | `_cacache` + `_logs` + `_update-notifier-last-checked` ≈ 555 noise entries per install |
| `/tmp/node-compile-cache` (node 24) | V8 compile cache, ~30 entries, survives `npm cache clean` |
| `/root/.cache` (pip lane) | pip http+wheel+selfcheck cache, ~515 entries |
| `/var/log`, `/var/lib/apt/lists`, `/root/.bash_history` | appeared in the broader NEXCL set; harmless to exclude, none were load-bearing for the planted tree |

Everything else — `/etc`, `/usr/local`, `/tmp`, `/var/tmp`, `$HOME/.config` — **stays observable at 1–2 s per full-root pass**. Notably host lanes need the *same* `~/.npm`/`~/.cache` exclusions, so these are product-level exclusion lists for 0.4.0, not host-mode apologies.

## 5. Per-ecosystem verdict table

| ecosystem | host primitive (throwaway) | observed uninstall reversal (host) | root surfaces (/etc, /usr/local, systemd, cron) | verdict for 0.4.0 `border roundtrip` |
|---|---|---|---|---|
| **npm** | `--prefix` + HOME + relocate `--cache`; **must** exclude `$HOME/.npm/_logs` | 3/3 user plants caught; uninstall REWRITES lockfiles (MODIFIED(3)) | unobservable in host mode (EACCES on write, EACCES on `/etc/shadow`-class reads); **docker lane: 5/5 exact, ADDED(7)/R0/M0** | **docker required** for full-FS; host-mode = cannot-verify (exit 2), usable only for user-surface residue facts |
| **pypi** | venv + `PIP_CACHE_DIR` (+ pin `XDG_CACHE_HOME` — this box sets it globally) | clean: site-packages removed exactly; 1 MB default cache survives unless relocated | same wall; docker lane ADDED(4)/R0/M0 exact | **docker required** (same semantics); venv host lane is already the W2.3 delivery lane for user-surface checks |
| **rubygems** | `-i $GEM_HOME` + HOME | exact (`gems-tree-entries-after-uninstall=0`) | same wall; not container-prototyped this spike (same debian-base class as npm image; expected identical shape) | **docker required**; host sufficiency proven only for user surfaces |
| **cargo** | `--root` + `CARGO_HOME` | exact (`cargoroot-entries-after-uninstall=0`) | same wall; not container-prototyped | **docker required** (host proven for user surfaces only) |

Primitive choice: **per-run throwaway container** (`docker run -d node:24-slim sleep …` + `docker exec` snapshot pipeline) — boot+two manifests+install+uninstall+diff ≈ 35 s/leg; overlayfs needs no special handling beyond content-hash-only manifests. Host throwaway-HOME remains a legitimate **fast lane** for rc-delta/PATH/user-config residue (W2.1 surfaces) provided the tool-noise exclusions above ship with it and its /etc-family results are reported `cannot-verify`, never clean.

## 6. W2.3 preview — hr setup_env byte-reversibility, Linux venv (`roundtrip-spike-hr-w23.sh`)

`pip install aihr` **works Linux-side** (aihr is published; venv install clean: `HOME survivors: 0` with relocated cache; entry points include `hr`). The reversibility demo could **not** be completed as scripted: `hr setup` on this box aborts *before* writing the rc block — `installing plugins: opencode-hr-agent@0.2.2 opencode-fastdraw@1.1.1` → `npm rejected the global install (directory not writable). Fix at user level — set a user npm prefix` → `SETUP_RC=1`, and the pristine `.bashrc` sha stayed `6f81b105…` unchanged; `hr setup --uninstall` doesn't exist on the published version (`No such option`, RC=2 — the `--uninstall` flow lives in `hr-setup-env.py.reference`, not in shipped aihr). So the verdict line `VERDICT: BYTE-IDENTICAL` is **vacuously true** (setup failed safe, touching nothing). Honest one-paragraph answer: **BEGIN/END byte-reversibility is mechanically plausible on Linux** (reference impl writes one delimited `case ":$PATH:"` block to `$HOME` rc candidates and removes exactly that block) **but currently NOT demonstrable via the published aihr CLI in a venv** — two gaps to close before W2.3 claims it: (a) `hr setup` must reach the rc-write step with a user-scoped npm prefix (`npm config set prefix`, which itself mutates `$HOME/.npmrc` = residue the roundtrip must classify), and (b) the uninstall-side flag must be exposed by the shipped CLI. No rabbit hole entered; stopped at the gap.

## 7. Failure modes / caveats

- Container lanes ran as root with no network policy — residue *inside* the throwaway container dies with `docker rm -f` (trap-verified in every script); the product must still decide image pinning + egress posture, out of scope here.
- Host `/tmp` path-manifest took 23 s/pass even without hashing and produced 2491 foreign lines under concurrent load — a real product on a desktop box **cannot** promise host-mode "clean" on `/tmp`.
- npm's V8 compile-cache (`/tmp/node-compile-cache`) is node-22+/24-specific; re-measure on version bumps (exclusion, not a plant).
- spike fixtures plant only 5 canonical surfaces; systemd units/cron jobs would be additional `/etc` family paths — same observability class as `/etc/profile.d` (container: yes, host: cannot-verify).

## Cleanup receipt

```
$ rm -rf /tmp/rt-* ; docker ps -a --format '{{.Names}}' | grep -c '^rt-' || true
0
$ ls /tmp/rt-*-plant-* /var/tmp/rt-*-plant-* /etc/profile.d/rt-*-plant.sh /usr/local/bin/rt-*-plant 2>&1 | head -2
ls: cannot access ...: No such file or directory
```

Written files (all new, allowed names only): `ROUNDTRIP-SPIKE.md`, `roundtrip-spike-transcripts.txt`, `roundtrip-spike-lib.sh`, `roundtrip-spike-host-npm.sh`, `roundtrip-spike-host-pypi.sh`, `roundtrip-spike-host-pypi-cache.sh`, `roundtrip-spike-host-gemcargo.sh`, `roundtrip-spike-docker-npm.sh`, `roundtrip-spike-docker-npm-minexcl.sh`, `roundtrip-spike-docker-pypi.sh`, `roundtrip-spike-hr-w23.sh` — under `.omo/evidence/residue-spike/`.
