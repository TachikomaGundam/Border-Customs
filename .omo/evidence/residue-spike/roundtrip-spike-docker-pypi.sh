#!/usr/bin/env bash
# roundtrip-spike-docker-pypi.sh — docker full-FS lane for pypi.
# Mirror of roundtrip-spike-docker-npm.sh on python:3.12-slim: pip install of
# a local sdist whose setup.py plants /root/.config + /tmp + /var/tmp +
# /etc/profile.d + /usr/local/bin as root. C0 = noise floor; acceptance =
# c1 -> c3 diff after pip uninstall.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/roundtrip-spike-lib.sh"
SCRATCH=$(mktemp -d /tmp/rt-docker-pypi.XXXXXX)
CTR=rt-d-pypi
trap 'docker rm -f $CTR >/dev/null 2>&1 || true; rm -rf "$SCRATCH"' EXIT

SRC=$SCRATCH/rt_pypi_plant-0.0.1; mkdir -p "$SRC"
cat >"$SRC/PKG-INFO" <<'PI'
Metadata-Version: 2.1
Name: rt-pypi-plant
Version: 0.0.1
Summary: W2.0 spike fixture
PI
cat >"$SRC/setup.py" <<'PY'
import os
def try_write(p, c):
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(c)
        print("PLANTED " + p)
    except OSError as e:
        print("PLANT-DENIED %s %s" % (p, e.strerror))
home = os.path.expanduser("~")
try_write(os.path.join(home, ".config", "rt-pypi-plant", "rc-say.sh"), "echo pypi-home-plant\n")
try_write("/tmp/rt-pypi-plant-tmp", "pypi tmp plant\n")
try_write("/var/tmp/rt-pypi-plant-vartmp", "pypi vartmp plant\n")
try_write("/etc/profile.d/rt-pypi-plant.sh", "export RT_PYPI=1\n")
try_write("/usr/local/bin/rt-pypi-plant", "#!/bin/sh\necho pypi-plant\n")
from setuptools import setup
setup(name="rt-pypi-plant", version="0.0.1", py_modules=["rt_pypi_plant"],
      description="W2.0 spike fixture", long_description="x")
PY
echo 'MARKER = "rt-pypi-plant"' >"$SRC/rt_pypi_plant.py"
tar czf "$SCRATCH/rt-pypi-plant-0.0.1.tar.gz" -C "$SCRATCH" rt_pypi_plant-0.0.1

docker rm -f $CTR >/dev/null 2>&1 || true
timeout 120 docker run -d --name $CTR python:3.12-slim sleep 3600 >/dev/null
timeout 60 docker cp "$SCRATCH/rt-pypi-plant-0.0.1.tar.gz" $CTR:/root/rt-pypi-plant.tar.gz

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
echo '=== INSTALL (pip sdist as root; all 5 plants must land incl /etc + /usr/local) ==='
timeout 600 docker exec $CTR pip install --no-input /root/rt-pypi-plant.tar.gz 2>&1 | grep -E 'PLANT|Successfully' | head -n 9
ctr_obs c2 "${VEXCL[@]}"
echo '--- C1 -> C2 install delta counts:'
rt_diff "$SCRATCH/c1.manifest" "$SCRATCH/c2.manifest" | grep -cE '^A\s' | sed 's/^/ADDED=/' || true
rt_diff "$SCRATCH/c1.manifest" "$SCRATCH/c2.manifest" | grep -cE '^R\s' | sed 's/^/REMOVED=/' || true
rt_diff "$SCRATCH/c1.manifest" "$SCRATCH/c2.manifest" | grep -E '^A\s/(etc|usr|var|root)' | head -n 8 || true
timeout 300 docker exec $CTR pip uninstall -y rt-pypi-plant 2>&1 | tail -n 1
ctr_obs c3 "${VEXCL[@]}"
echo '=== ACCEPTANCE DIFF c1 -> c3 (zero exclusions beyond virtual FS) ==='
set +e; { rt_diff "$SCRATCH/c1.manifest" "$SCRATCH/c3.manifest"; echo "ACCEPT_RC=$?"; } | head -n 30; set -e
echo '--- planted-target + tool-noise grep in c3 diff:'
{ rt_diff "$SCRATCH/c1.manifest" "$SCRATCH/c3.manifest" | grep -E 'rt.pypi.plant|\.cache|profile\.d|__pycache__' | head -n 12; } || true

echo '=== NOISE-ZEROING: second cycle, pip cache + tmp trees excluded ==='
timeout 60 docker exec $CTR sh -c 'rm -f /root/.config/rt-pypi-plant/rc-say.sh /tmp/rt-pypi-plant-tmp /var/tmp/rt-pypi-plant-vartmp /etc/profile.d/rt-pypi-plant.sh /usr/local/bin/rt-pypi-plant; rmdir /root/.config/rt-pypi-plant 2>/dev/null; true'
NEXCL=("${VEXCL[@]}" "/root/.cache" "/tmp" "/var/tmp" "/etc/hostname" "/etc/resolv.conf" "/etc/hosts")
ctr_obs c1n "${NEXCL[@]}"
timeout 600 docker exec $CTR pip install --no-input /root/rt-pypi-plant.tar.gz >/dev/null 2>&1 || true
timeout 300 docker exec $CTR pip uninstall -y rt-pypi-plant >/dev/null 2>&1 || true
ctr_obs c3n "${NEXCL[@]}"
echo '--- diff with NEXCL (planted /etc + /usr/local + /root/.config must show; pip wheel cache hidden by design):'
{ rt_diff "$SCRATCH/c1n.manifest" "$SCRATCH/c3n.manifest" | head -n 14; } || true
