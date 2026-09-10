#!/usr/bin/env bash
# roundtrip-spike-host-npm.sh — host throwaway-HOME lane for npm.
# Plant: fake pkg rt-npm-plant whose postinstall tries $HOME/.config, /tmp,
# /var/tmp, /etc/profile.d, /usr/local/bin writes (perm-denied fail soft).
# OBSERVED (verdict) roots: HOME, /tmp (path+mode only), /var/tmp, /etc/profile.d,
# /usr/local/bin. INSTALL ROOT (disposable by design): prefix incl. relocated
# npm cache — diffed separately to show uninstall self-cleanup inside it.
# Acceptance: OBSERVED diff baseline->final == planted-allowed tree EXACTLY.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/roundtrip-spike-lib.sh"
SCRATCH=$(mktemp -d /tmp/rt-host-npm.XXXXXX)
# plants live OUTSIDE SCRATCH (that is the point) — purge stale ones before the
# baseline and on exit, or a previous aborted run poisons the acceptance diff.
PLANTS=("/tmp/rt-npm-plant-tmp" "/var/tmp/rt-npm-plant-vartmp"
        "/etc/profile.d/rt-npm-plant.sh" "/usr/local/bin/rt-npm-plant")
rt_cleanup() { rm -rf "${PLANTS[@]}" 2>/dev/null || true; rm -rf "$SCRATCH"; }
trap rt_cleanup EXIT
rm -f "${PLANTS[@]}" 2>/dev/null || true
export HOME=$SCRATCH/home
mkdir -p "$HOME" "$SCRATCH/prefix"
echo 'export PATH=/usr/bin:/bin' >"$HOME/.bashrc"

PKG=$SCRATCH/fixture
mkdir -p "$PKG"
cat >"$PKG/package.json" <<'JSON'
{ "name": "rt-npm-plant", "version": "0.0.1", "description": "W2.0 spike fixture",
  "main": "index.js", "scripts": { "postinstall": "node plant.js" } }
JSON
echo 'module.exports = 0;' >"$PKG/index.js"
cat >"$PKG/plant.js" <<'JS'
const fs = require('fs'), os = require('os'), path = require('path');
const attempts = [
  [path.join(os.homedir(), '.config', 'rt-npm-plant', 'rc-say.sh'), 'echo npm-home-plant\n'],
  ['/tmp/rt-npm-plant-tmp', 'npm tmp plant\n'],
  ['/var/tmp/rt-npm-plant-vartmp', 'npm vartmp plant\n'],
  ['/etc/profile.d/rt-npm-plant.sh', 'export RT_NPM=1\n'],
  ['/usr/local/bin/rt-npm-plant', '#!/bin/sh\necho npm-plant\n'],
];
for (const [p, c] of attempts) {
  try { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, c);
        if (p === '/usr/local/bin/rt-npm-plant') fs.chmodSync(p, 0o755);
        console.log('PLANTED ' + p); }
  catch (e) { console.log('PLANT-DENIED ' + p + ' ' + e.code); }
}
JS
(cd "$PKG" && timeout "$RT_TO" npm pack --silent >/dev/null && mv -f rt-npm-plant-0.0.1.tgz "$SCRATCH/")
ls -l "$SCRATCH/rt-npm-plant-0.0.1.tgz"
TGZ=$SCRATCH/rt-npm-plant-0.0.1.tgz

# shared-tenant noise: other agents' scratch dirs, socket dirs, systemd private
EXCL_TMP=("/tmp/rt-snap.*" "/tmp/rt-diff.*" "/tmp/rt-host-npm.*" "/tmp/rt-host-pypi.*" "/tmp/rt-docker-*" "/tmp/opencode*" "/tmp/pip-*" "/tmp/node-*" "/tmp/systemd-private-*" "/tmp/snap-private-tmp" "/tmp/.X11-unix" "/tmp/.ICE-unix" "/tmp/tmp.*" "/tmp/snap.*" "/tmp/vscode-*" "/tmp/.org.chromium.*" "/tmp/mcp*")
manifest_obs() { # <tag> -> $SCRATCH/obs-TAG.manifest
  local tag=$1 out t0 t1
  out=$SCRATCH/obs-$tag.manifest
  t0=$(date +%s)
  rt_snapshot "$out.home" -- "$HOME:h" >/dev/null
  rt_snapshot "$out.tmp" "${EXCL_TMP[@]}" -- /tmp >/dev/null
  rt_snapshot "$out.vartmp" -- "/var/tmp:h" >/dev/null
  rt_snapshot "$out.sys" -- "/etc/profile.d:h" "/usr/local/bin:h" >/dev/null
  cat "$out.home" "$out.tmp" "$out.vartmp" "$out.sys" | LC_ALL=C sort >"$out"
  t1=$(date +%s)
  echo "obs-$tag entries=$(wc -l <"$out") elapsed=$((t1-t0))s ts=$(date -Is)"
}

echo '=== /tmp FULL-HASH COST MICROBENCHMARK (feasibility data) ==='
TIME_STR=$({ /usr/bin/time -f '%e' timeout 240 bash -c \
  'find /tmp -xdev -type f -readable -print0 2>/dev/null | head -z -n 20000 | xargs -0 -r sha256sum >/dev/null'; } 2>&1 | tail -n 1)
echo "20000 readable /tmp files hashed in ${TIME_STR}s -> 512923 files extrapolate: $(echo "$TIME_STR" | awk '{printf "%.0fs (~%.1f min/pass)", $1*512923/20000, $1*512923/20000/60}')"

manifest_obs baseline
echo '=== INSTALL (foreground-scripts: postinstall stdout) ==='
timeout "$RT_TO" npm install --no-audit --no-fund --prefix "$SCRATCH/prefix" \
  --foreground-scripts --cache "$SCRATCH/prefix/.npmcache" "$TGZ" 2>&1 | grep -E 'PLANT|added' | head -n 8
manifest_obs mid
timeout "$RT_TO" npm uninstall --silent --no-audit --no-fund --prefix "$SCRATCH/prefix" rt-npm-plant 2>&1 | tail -n 2
manifest_obs final

echo '=== ACCEPTANCE DIFF obs-baseline -> obs-final (planted tree EXACTLY) ==='
rt_diff "$SCRATCH/obs-baseline.manifest" "$SCRATCH/obs-final.manifest" || true

echo '=== INSTALL-ROOT SELF-CLEANUP (prefix tree: baseline->final) ==='
rt_snapshot "$SCRATCH/pr-base" -- "$SCRATCH/prefix:h" >/dev/null
timeout "$RT_TO" npm install --silent --no-audit --no-fund --prefix "$SCRATCH/prefix-reinstall" \
  --cache "$SCRATCH/prefix-reinstall/.npmcache" "$TGZ" >/dev/null 2>&1
rt_snapshot "$SCRATCH/pr-mid" -- "$SCRATCH/prefix-reinstall:h" >/dev/null
timeout "$RT_TO" npm uninstall --silent --no-audit --no-fund --prefix "$SCRATCH/prefix-reinstall" rt-npm-plant >/dev/null 2>&1
rt_snapshot "$SCRATCH/pr-final" -- "$SCRATCH/prefix-reinstall:h" >/dev/null
echo "-- empty-prefix -> after install:"
{ rt_diff /dev/null "$SCRATCH/pr-mid" | head -n 8; } || true
echo "-- after install -> after uninstall (what npm leaves in its own root):"
rt_diff "$SCRATCH/pr-mid" "$SCRATCH/pr-final" || true

echo '=== CONTROL: two obs manifests back-to-back (shared-/tmp churn rate) ==='
manifest_obs final2
rt_diff "$SCRATCH/obs-final.manifest" "$SCRATCH/obs-final2.manifest" >"$SCRATCH/ctrl.diff" || true
head -n 12 "$SCRATCH/ctrl.diff"
echo "control diff lines: $(grep -cE '^[ARM]' "$SCRATCH/ctrl.diff" || true)"

echo '=== TOOL-NOISE: default cache kept INSIDE observed HOME ==='
H2=$SCRATCH/home2; mkdir -p "$H2" "$SCRATCH/prefix2"
timeout "$RT_TO" env HOME=$H2 npm install --silent --no-audit --no-fund --prefix "$SCRATCH/prefix2" "$TGZ" >/dev/null 2>&1
timeout "$RT_TO" env HOME=$H2 npm uninstall --silent --no-audit --no-fund --prefix "$SCRATCH/prefix2" rt-npm-plant >/dev/null 2>&1
echo "HOME2 survivors after uninstall (default cache policy):"
find "$H2" -mindepth 1 | LC_ALL=C sort | sed "s|$H2|~|" | head -n 12
echo "HOME2 bytes: $(du -sb "$H2" | cut -f1)"

echo '=== HOST-UNOBSERVABLE / PRIVILEGE-REACHABLE SURFACES ==='
ls /var/spool/cron/crontabs 2>&1 | head -n 1 || true
timeout 10 crontab -l >/dev/null 2>&1 || true; echo "crontab -l rc=$?"
cat /etc/shadow 2>&1 | head -n 1 || true
sudo -n true 2>&1; echo "sudo -n rc=$?"
stat -c '%A %U:%G %n' /etc/cron.d /etc/systemd/system 2>&1
