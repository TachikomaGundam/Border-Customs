#!/usr/bin/env bash
# roundtrip-spike-host-pypi.sh — host lane for pypi via throwaway venv.
# Plant: sdist rt-pypi-plant whose setup.py writes $HOME/.config, /tmp,
# /var/tmp, /etc/profile.d, /usr/local/bin AT BUILD TIME (the T3 shape pip
# gates care about). venv + relocated PIP_CACHE_DIR = disposable install root;
# OBSERVED roots = HOME, /tmp, /var/tmp, /etc/profile.d, /usr/local/bin.
# Default-cache control run measures what pip leaves inside observed HOME.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
source "$HERE/roundtrip-spike-lib.sh"
SCRATCH=$(mktemp -d /tmp/rt-host-pypi.XXXXXX)
PLANTS=("/tmp/rt-pypi-plant-tmp" "/var/tmp/rt-pypi-plant-vartmp"
        "/etc/profile.d/rt-pypi-plant.sh" "/usr/local/bin/rt-pypi-plant")
rt_cleanup() { rm -rf "${PLANTS[@]}" 2>/dev/null || true; rm -rf "$SCRATCH"; }
trap rt_cleanup EXIT
rm -f "${PLANTS[@]}" 2>/dev/null || true
export HOME=$SCRATCH/home
mkdir -p "$HOME"
echo 'export PATH=/usr/bin:/bin' >"$HOME/.bashrc"

SRC=$SCRATCH/rt_pypi_plant-0.0.1
mkdir -p "$SRC"
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
ls -l "$SCRATCH/rt-pypi-plant-0.0.1.tar.gz"

EXCL_TMP=("/tmp/rt-snap.*" "/tmp/rt-diff.*" "/tmp/rt-host-*" "/tmp/rt-docker-*" "/tmp/opencode*" "/tmp/pip-*" "/tmp/node-*" "/tmp/systemd-private-*" "/tmp/snap-private-tmp" "/tmp/.X11-unix" "/tmp/.ICE-unix" "/tmp/tmp.*" "/tmp/snap.*" "/tmp/vscode-*" "/tmp/.org.chromium.*" "/tmp/mcp*")
manifest_obs() {
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

# venv is infra (disposable), created BEFORE baseline so its bytes are not
# attributed to the package. Single COLD measured install: cache relocated,
# no warmup — a warmed built-wheel cache would skip re-running setup.py and
# fake the plant-time writes out of the diff (false negative).
timeout "$RT_TO" python3 -m venv "$SCRATCH/venv"
VP=$SCRATCH/venv/bin/pip

manifest_obs baseline
echo '=== INSTALL (sdist build executes setup.py plant writes) ==='
{ timeout 300 env PIP_CACHE_DIR=$SCRATCH/venv/.pipcache "$VP" install --no-input \
    "$SCRATCH/rt-pypi-plant-0.0.1.tar.gz" 2>&1 | grep -E 'PLANT|Successfully' | head -n 8; } || echo PIP-INSTALL-FAILED
manifest_obs mid
timeout "$RT_TO" "$VP" uninstall -y rt-pypi-plant 2>&1 | tail -n 2
manifest_obs final

echo '=== ACCEPTANCE DIFF obs-baseline -> obs-final ==='
rt_diff "$SCRATCH/obs-baseline.manifest" "$SCRATCH/obs-final.manifest" || true

echo '=== CONTROL: back-to-back manifests (shared /tmp churn over ~30s) ==='
manifest_obs final2
{ rt_diff "$SCRATCH/obs-final.manifest" "$SCRATCH/obs-final2.manifest" | head -n 10; } || true

echo '=== TOOL-NOISE: default cache (no PIP_CACHE_DIR) inside observed HOME ==='
H2=$SCRATCH/home2; mkdir -p "$H2"
timeout "$RT_TO" python3 -m venv "$SCRATCH/venv2"
{ timeout 300 env HOME=$H2 "$SCRATCH/venv2/bin/pip" install --no-input \
    "$SCRATCH/rt-pypi-plant-0.0.1.tar.gz" >/dev/null 2>&1; } || true
rm -f "${PLANTS[@]}" 2>/dev/null || true   # venv2 leg's plants: keep verdict diff clean
timeout "$RT_TO" env HOME=$H2 "$SCRATCH/venv2/bin/pip" uninstall -y rt-pypi-plant >/dev/null 2>&1 || true
echo "HOME2 survivors after uninstall (default cache policy):"
find "$H2" -mindepth 1 -maxdepth 3 | LC_ALL=C sort | sed "s|$H2|~|" | head -n 14
echo "HOME2 bytes: $(du -sb "$H2" | cut -f1)"
echo "venv2 leftover after uninstall: $(find "$SCRATCH/venv2" -path '*rt*pypi*' | wc -l) entries matching rt_pypi/rt-pypi"
