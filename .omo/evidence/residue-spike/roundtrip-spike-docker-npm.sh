#!/usr/bin/env bash
# roundtrip-spike-docker-npm.sh — docker full-FS lane for npm.
# Throwaway container (node:24-slim), npm install -g as root: plants land in
# /etc/profile.d + /usr/local/bin (host lane could not even write them).
# Manifest = container '/' (sha256). C0 control = two back-to-back manifests
# with NOTHING running -> measures overlayfs copy-up / daemon-activity noise
# and defines the exclusion set needed for a zero-noise diff.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/roundtrip-spike-lib.sh"
SCRATCH=$(mktemp -d /tmp/rt-docker-npm.XXXXXX)
CTR=rt-d-npm
trap 'docker rm -f $CTR >/dev/null 2>&1 || true; rm -rf "$SCRATCH"' EXIT

SRC=$SCRATCH/rt-npm-plant-0.0.1; mkdir -p "$SRC"
cat >"$SRC/package.json" <<'JSON'
{ "name": "rt-npm-plant", "version": "0.0.1", "description": "W2.0 spike fixture",
  "scripts": { "postinstall": "node plant.js" }, "license": "MIT" }
JSON
cat >"$SRC/plant.js" <<'JS'
const fs = require("fs"), os = require("os"), path = require("path");
function plant(p, c) {
  try { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, c); console.log("PLANTED " + p); }
  catch (e) { console.log("PLANT-DENIED " + p + " " + e.code); }
}
plant(path.join(os.homedir(), ".config", "rt-npm-plant", "rc-say.sh"), "echo npm-home-plant\n");
plant("/tmp/rt-npm-plant-tmp", "npm tmp plant\n");
plant("/var/tmp/rt-npm-plant-vartmp", "npm vartmp plant\n");
plant("/etc/profile.d/rt-npm-plant.sh", "export RT_NPM=1\n");
plant("/usr/local/bin/rt-npm-plant", "#!/bin/sh\necho npm-plant\n");
JS
(cd "$SRC" && timeout "$RT_TO" npm pack --silent --pack-destination "$SCRATCH" >/dev/null)
TGZ=$SCRATCH/rt-npm-plant-0.0.1.tgz
test -f "$TGZ"

docker rm -f $CTR >/dev/null 2>&1 || true
timeout 120 docker run -d --name $CTR node:24-slim sleep 3600 >/dev/null
timeout 60 docker cp "$TGZ" $CTR:/root/rt-npm-plant.tgz

VEXCL=("/proc" "/sys" "/dev")
ctr_obs() { # ctr_obs <tag> <extra-excl...>
  local tag=$1; shift
  local t0=$(date +%s)
  rt_ctr_snapshot $CTR "$SCRATCH/$tag.manifest" "$@" -- "/:h"
  echo "$tag entries=$(wc -l <"$SCRATCH/$tag.manifest") elapsed=$(( $(date +%s)-t0 ))s ts=$(date -Is)"
}

echo '=== C0 CONTROL: back-to-back manifests, NOTHING running (noise floor + copy-up check) ==='
ctr_obs c0a "${VEXCL[@]}"
ctr_obs c0b "${VEXCL[@]}"
echo '--- C0 diff (c0a -> c0b):'
set +e; { rt_diff "$SCRATCH/c0a.manifest" "$SCRATCH/c0b.manifest"; echo "C0_RC=$?"; } | head -n 15; set -e

ctr_obs c1 "${VEXCL[@]}"
echo '=== INSTALL (npm -g as root; full plant success incl /etc + /usr/local expected) ==='
timeout 300 docker exec $CTR npm install -g --foreground-scripts --no-audit --no-fund /root/rt-npm-plant.tgz 2>&1 | grep -E 'PLANT|added' | head -n 8
ctr_obs c2 "${VEXCL[@]}"
echo '--- C1 -> C2 install delta counts:'
rt_diff "$SCRATCH/c1.manifest" "$SCRATCH/c2.manifest" | grep -cE '^A\s' | sed 's/^/ADDED=/' || true
rt_diff "$SCRATCH/c1.manifest" "$SCRATCH/c2.manifest" | grep -cE '^R\s' | sed 's/^/REMOVED=/' || true
rt_diff "$SCRATCH/c1.manifest" "$SCRATCH/c2.manifest" | grep -E '^A\s/(etc|usr|var|root)' | head -n 8 || true
timeout 300 docker exec $CTR npm uninstall -g rt-npm-plant 2>&1 | tail -n 1
ctr_obs c3 "${VEXCL[@]}"
echo '=== ACCEPTANCE DIFF c1 -> c3 (zero exclusions beyond virtual FS) ==='
set +e; { rt_diff "$SCRATCH/c1.manifest" "$SCRATCH/c3.manifest"; echo "ACCEPT_RC=$?"; } | head -n 30; set -e
echo '--- planted-target grep in c3 diff:'
{ rt_diff "$SCRATCH/c1.manifest" "$SCRATCH/c3.manifest" | grep -E 'rt-npm-plant|\.npm|profile\.d' | head -n 12; } || true

echo '=== NOISE-ZEROING EXCLUSION SET: second cycle with tool-noise excluded ==='
timeout 60 docker exec $CTR sh -c 'rm -f /root/.config/rt-npm-plant/rc-say.sh /tmp/rt-npm-plant-tmp /var/tmp/rt-npm-plant-vartmp /etc/profile.d/rt-npm-plant.sh /usr/local/bin/rt-npm-plant; rmdir /root/.config/rt-npm-plant /root/.config 2>/dev/null; true'
NEXCL=("${VEXCL[@]}" "/root/.npm" "/var/lib/apt/lists" "/var/log" "/tmp" "/var/tmp" "/etc/hostname" "/etc/resolv.conf" "/etc/hosts" "/root/.bash_history")
ctr_obs c1n "${NEXCL[@]}"
timeout 300 docker exec $CTR npm install -g --foreground-scripts --no-audit --no-fund /root/rt-npm-plant.tgz >/dev/null 2>&1 || true
timeout 300 docker exec $CTR npm uninstall -g rt-npm-plant >/dev/null 2>&1 || true
ctr_obs c3n "${NEXCL[@]}"
echo '--- diff with NEXCL (planted /etc + /usr/local + /root/.config must show; npm cache hidden by design):'
{ rt_diff "$SCRATCH/c1n.manifest" "$SCRATCH/c3n.manifest" | head -n 14; } || true
