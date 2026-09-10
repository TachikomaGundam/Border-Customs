#!/usr/bin/env bash
# roundtrip-spike-host-pypi-cache.sh — focused control replacing the flaky
# venv2 leg in roundtrip-spike-host-pypi.sh: with pip's DEFAULT cache policy,
# how much survives in the observed HOME after a clean pip uninstall?
set -euo pipefail
SCRATCH=$(mktemp -d /tmp/rt-pypicache.XXXXXX)
rm -f /tmp/rt-pypi-plant-tmp /var/tmp/rt-pypi-plant-vartmp 2>/dev/null || true
trap 'rm -f /tmp/rt-pypi-plant-tmp /var/tmp/rt-pypi-plant-vartmp /etc/profile.d/rt-pypi-plant.sh /usr/local/bin/rt-pypi-plant 2>/dev/null || true; rm -rf "$SCRATCH"' EXIT

SRC=$SCRATCH/rt_pypi_plant-0.0.1; mkdir -p "$SRC"
printf 'Metadata-Version: 2.1\nName: rt-pypi-plant\nVersion: 0.0.1\nSummary: x\n' >"$SRC/PKG-INFO"
cat >"$SRC/setup.py" <<'PY'
import os
def try_write(p, c):
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(c); print("PLANTED " + p)
    except OSError as e:
        print("PLANT-DENIED %s %s" % (p, e.strerror))
try_write("/tmp/rt-pypi-plant-tmp", "pypi tmp plant\n")
try_write("/var/tmp/rt-pypi-plant-vartmp", "pypi vartmp plant\n")
from setuptools import setup
setup(name="rt-pypi-plant", version="0.0.1", py_modules=["rt_pypi_plant"], description="x", long_description="x")
PY
echo 'MARKER = "x"' >"$SRC/rt_pypi_plant.py"
tar czf "$SCRATCH/p.tar.gz" -C "$SCRATCH" rt_pypi_plant-0.0.1
timeout 300 python3 -m venv "$SCRATCH/v"
H2=$SCRATCH/home2; mkdir -p "$H2"
# XDG_CACHE_HOME is set GLOBAL on this box — HOME override alone does not
# relocate pip's cache; pin XDG dirs into the throwaway HOME explicitly.
pip_retry() { # files.pythonhosted.org intermittently truncates on this box
  local n=0
  until timeout 600 env XDG_CACHE_HOME=$H2/.cache XDG_CONFIG_HOME=$H2/.config HOME=$H2 "$SCRATCH/v/bin/pip" "$@" >>"$SCRATCH/install.log" 2>&1; do
    n=$((n+1)); [ $n -ge 3 ] && return 1; sleep 5
  done
}
pip_retry install --no-input --resume-retries 5 "$SCRATCH/p.tar.gz" || echo "INSTALL_RC=$?"
grep -cE 'Successfully installed' "$SCRATCH/install.log" | sed 's/^/Successfully_installed_lines=/'
timeout 300 env XDG_CACHE_HOME=$H2/.cache XDG_CONFIG_HOME=$H2/.config HOME=$H2 "$SCRATCH/v/bin/pip" uninstall -y rt-pypi-plant >"$SCRATCH/uninstall.log" 2>&1 || echo "UNINSTALL_RC=$?"
grep -cE 'Successfully uninstalled' "$SCRATCH/uninstall.log" | sed 's/^/Successfully_uninstalled_lines=/'
echo '--- HOME2 survivors after clean uninstall (default cache policy):'
find "$H2" -mindepth 1 -maxdepth 2 | LC_ALL=C sort | sed "s|$H2|~|" | head -n 8
echo "HOME2 bytes after uninstall: $(du -sb "$H2" | cut -f1)"
