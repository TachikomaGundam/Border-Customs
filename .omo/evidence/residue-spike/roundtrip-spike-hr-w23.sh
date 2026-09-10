#!/usr/bin/env bash
# roundtrip-spike-hr-w23.sh — W2.3 preview: is hr setup_env BEGIN/END rc-block
# writing byte-reversible Linux-side? Throwaway HOME + venv + `pip install
# aihr` (published on PyPI, verified HTTP 200 pre-spike). rc file is the only
# mutated surface; byte comparison via sha256. No rabbit holes: if the CLI
# surface differs from `hr setup`, capture help text and stop.
set -euo pipefail
SCRATCH=$(mktemp -d /tmp/rt-hr-w23.XXXXXX)
trap 'rm -rf "$SCRATCH"' EXIT
export HOME=$SCRATCH/home; mkdir -p "$HOME"
export XDG_CACHE_HOME=$HOME/.cache XDG_CONFIG_HOME=$HOME/.config
echo '# pristine bashrc
export PATH=/usr/bin:/bin
' >"$HOME/.bashrc"
sha() { sha256sum "$HOME/.bashrc" | cut -d' ' -f1; }
B0=$(sha)
echo "rc sha before: $B0"
timeout 300 python3 -m venv "$SCRATCH/v"
N=0
until timeout 900 env PIP_CACHE_DIR=$SCRATCH/pipcache "$SCRATCH/v/bin/pip" install --no-input --resume-retries 5 aihr >"$SCRATCH/hr-install.log" 2>&1; do
  N=$((N+1)); [ $N -ge 3 ] && break; sleep 5
done
tail -n 2 "$SCRATCH/hr-install.log"
ls "$HOME"/.cache 2>/dev/null | sed 's/^/HOME-survivor: /' || echo "HOME survivors: $(find "$HOME" -mindepth 1 -maxdepth 1 -not -name .bashrc | wc -l) (excluding .bashrc)"
echo '--- entry points provided by aihr:'
ls "$SCRATCH/v/bin" | grep -ivE '^(pip|python|activate)' | sed 's/^/bin: /' || true
CLI=$SCRATCH/v/bin/hr
if [ -x "$CLI" ]; then
  echo '--- hr --help (top):'
  timeout 60 "$CLI" --help 2>&1 | head -n 12 || true
  echo '--- attempt: hr setup'
  timeout 120 "$CLI" setup </dev/null 2>&1 | head -n 12 || echo "SETUP_RC=$?"
  B1=$(sha); echo "rc sha after setup:    $B1"
  grep -n 'BEGIN aihr' "$HOME/.bashrc" | head -n 2 || true
  echo '--- attempt: hr setup --uninstall'
  timeout 120 "$CLI" setup --uninstall </dev/null 2>&1 | head -n 8 || echo "UNINSTALL_RC=$?"
  B2=$(sha); echo "rc sha after uninstall: $B2"
  if [ "$B0" = "$B2" ]; then echo "VERDICT: BYTE-IDENTICAL (reversibility PASS on this box)"; else echo "VERDICT: NOT byte-identical"; diff <(printf '%s' "$B0") <(printf '%s' "$B2") || true; wc -c "$HOME/.bashrc"; fi
else
  echo "GAP: no hr executable in venv/bin — record CLI-surface gap, do not dig"
  ls "$SCRATCH/v/bin" | head -n 20
fi
