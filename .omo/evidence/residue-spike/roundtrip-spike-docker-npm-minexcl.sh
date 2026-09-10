#!/usr/bin/env bash
# roundtrip-spike-docker-npm-minexcl.sh — pin the MINIMUM docker exclusion set:
# only virtual FS + the two identified tool-noise paths. /tmp and /var/tmp stay
# OBSERVABLE; success = planted tree only, zero noise lines.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/roundtrip-spike-lib.sh"
SCRATCH=$(mktemp -d /tmp/rt-docker-npm-min.XXXXXX)
CTR=rt-d-npm-min
trap 'docker rm -f $CTR >/dev/null 2>&1 || true; rm -rf "$SCRATCH"' EXIT

timeout 120 docker run -d --name $CTR node:24-slim sleep 600 >/dev/null

# reuse the exact plant tgz source by regenerating (identical bytes not needed)
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
timeout 60 docker cp "$SCRATCH/rt-npm-plant-0.0.1.tgz" $CTR:/root/p.tgz

MINEXCL=("/proc" "/sys" "/dev" "/root/.npm" "/tmp/node-compile-cache" "/etc/hostname" "/etc/resolv.conf" "/etc/hosts")
ctr_obs() { # ctr_obs <tag>
  local tag=$1 t0=$(date +%s)
  rt_ctr_snapshot $CTR "$SCRATCH/$tag.manifest" "${MINEXCL[@]}" -- "/:h" >/dev/null
  echo "$tag entries=$(wc -l <"$SCRATCH/$tag.manifest") elapsed=$(( $(date +%s)-t0 ))s"
}
ctr_obs m1
timeout 300 docker exec $CTR npm install -g --foreground-scripts --no-audit --no-fund /root/p.tgz 2>&1 | grep -cE 'PLANTED' | sed 's/^/PLANTED_LINES=/'
ctr_obs m2
timeout 300 docker exec $CTR npm uninstall -g rt-npm-plant >/dev/null 2>&1
ctr_obs m3
echo '=== ACCEPTANCE m1 -> m3 (minimum exclusions; /tmp,/var/tmp,/etc,/usr/local observable) ==='
set +e; { rt_diff "$SCRATCH/m1.manifest" "$SCRATCH/m3.manifest"; echo "ACCEPT_RC=$?"; } | head -n 16; set -e
