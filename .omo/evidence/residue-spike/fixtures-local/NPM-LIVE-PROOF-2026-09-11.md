# W2.4b local-lane live proof — npm plant lane (honest replacement for the disproven wheel demo)

Date: 2026-09-11 (fix round, host docker 29.1.3, images `node:24-slim` / `python:3.12-slim`
pre-pulled; border CLI = `node dist/index.js` built at fix-round HEAD 1208dc5 + working tree).
Cited by: VERIFIER-REPORT-W24B-SHADOW.json (blockers[0] resolution) and this fix round's DONECLAIM.

## 1. Manual ground truth FIRST (no border) — `docker run --rm node:24-slim`

Raw capture: manual-ground-truth-node24.21.0-npm11.19.0.txt (run twice, identical survivor state).

```
== versions == v24.21.0 / npm 11.19.0
> rt-plant-npm@1.0.0 postinstall
> sh postinstall.sh
added 1 package in 494ms
npm warn install-scripts 1 package has install scripts not yet covered by allowScripts: ...
== AFTER INSTALL ==
-rwxr-xr-x 1 root root 31 ... /usr/local/bin/rt-plant-orphan
/etc/profile:35:export RT_W24B_PLANT_MARKER=1
node_modules: corepack  npm  rt-plant-npm
== uninstall -g ==  removed 1 package in 292ms
== AFTER UNINSTALL: GROUND-TRUTH SURVIVOR STATE ==
/usr/local/bin/rt-plant-orphan : STILL PRESENT, executable (prints "rt-plant-orphan")
/etc/profile marker            : STILL PRESENT (line 35)
node_modules/rt-plant-npm      : REMOVED (npm tracked)
```

Survivors after `npm uninstall -g`: EXACTLY { /usr/local/bin/rt-plant-orphan (ADDED),
/etc/profile modified in place (MODIFIED) }. npm only tracks its own dirs — as doctrine says.
Footnote: npm 11 printed an install-scripts warning yet EXECUTED the postinstall anyway
(`added 1 package`, both writes landed); no `--allow-scripts` flag was needed.

## 2. border roundtrip on the SAME bytes — `rt-plant-npm-1.0.0.tgz`
sha256 70435f93c270d93c087c34a3c32fdf666101cbf691b32d17c56d8f2b58d540cb

```
roundtrip: source local:/tmp/rt-w24b/dist/rt-plant-npm-1.0.0.tgz artifact sha256 70435f93...
HIGH roundtrip-residue-file [roundtrip] /usr/local/bin/rt-plant-orphan installed file survived uninstall (ADDED in post-uninstall manifest)
CRITICAL roundtrip-modified-persistence [roundtrip] /etc/profile uninstall mutated a persistence surface (rc/systemd/cron/PATH) — content differs pre-install vs post-uninstall
roundtrip: 2 residue row(s); install-delta 6 files
BORDER_RC=1
```

`--json` run: verdict FAIL, source/artifactSha256 stamped, findings = the same 2 rows.

**rows == ground-truth survivors: EXACT MATCH (2/2, no extras, no misses).**

## 3. Benign controls (live, same CLI)

- rt-clean-npm-1.0.0.tgz sha256 0a95b713b40e41b3a4e44479663dc8ae5c8beb8066e76571d64942e44b73f3b5
  ⇒ `0 residue row(s); install-delta 3 files` rc0 PASS
- rt_benign_local-1.0.0-py3-none-any.whl sha256 01e73f38679ea44bb9ad02153fa620fc6c8e75fbe8416112cdda068dfd9b43d6
  ⇒ `0 residue row(s); install-delta 9 files` rc0 PASS (installability + benign-clean + exact-bytes identity)

## 4. Wheel-lane inertness confirmation (my own run, complements the verifier's 4)

- rt_plant_wheel-0.0.1-py3-none-any.whl sha256 ef86383a06e703487cafb2e68fa8509d004cfa2b4607eacd4e1d89aefb6fb486
  (zip carries rt_plant_wheel-0.0.1.data/data/.config/{evil.txt,systemd/user/evil.service} —
  the exact shape the previous DONECLAIM falsely claimed HIGH)
  ⇒ `roundtrip: 0 residue row(s); install-delta 14 files` rc0 PASS — pip 25.0.1 recorded AND
  pruned every planted path: the LOCAL wheel lane is residue-INERT, confirming
  VERIFIER-REPORT-W24B-SHADOW probes.G4_planted_live (pip 24.0 + 25.0.1, four runs).
