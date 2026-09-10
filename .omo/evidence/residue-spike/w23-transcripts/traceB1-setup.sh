#!/usr/bin/env bash
# W2.3 trace B — FULL published chain: pip install aihr → `python3 -m hr setup`
# in a fresh HOME. Empirical test of the user's PATH claim on the REAL wheel
# (no repo files involved; wheel bytes are PyPI-published aihr 0.2.2).
set -u
export HOME=/root
export PATH=/opt/node-v22.20.0-linux-x64/bin:$PATH
PS4='+ '
printf '# seeded pristine bashrc\nexport PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n' >"$HOME/.bashrc"
printf '# seeded pristine profile\n' >"$HOME/.profile"
echo "===== PHASE 0: baseline ====="
echo "PATH: $PATH"; echo "python: $(python3 --version 2>&1)"
sha256sum "$HOME/.bashrc" "$HOME/.profile" | tee /tmp/b.rc
tree_hash() { find /root /etc/profile.d /etc/paths.d -type f 2>/dev/null | LC_ALL=C sort | xargs -r sha256sum; }
tree_hash >/tmp/b.base

echo "===== PHASE 1: pip install aihr (published wheel — install-time behaviour) ====="
timeout 220 pip install --no-input -i https://mirrors.aliyun.com/pypi/simple/ aihr 2>&1 | tail -3
echo "pip rc=$?"
python3 -c "import hr; print('installed hr.__version__ =', hr.__version__)"
echo "--- pip INSTALL-TIME mutation check (wheel must write nothing outside site-packages) ---"
sha256sum -c /tmp/b.rc 2>/dev/null && echo "RC: UNTOUCHED by pip install" || echo "RC MUTATED BY PIP"
tree_hash >/tmp/b.afterpip
diff <(grep -vE "site-packages|dist-info|/root/.cache/pip" /tmp/b.base) <(grep -vE "site-packages|dist-info|/root/.cache/pip" /tmp/b.afterpip) && echo "PIP: ZERO user-surface mutation (rc/PATH/config clean)"

echo "===== PHASE 2: python3 -m hr setup --help (what removal verbs does the wheel expose?) ====="
timeout 60 python3 -m hr setup --help 2>&1 | sed -n '1,25p'
echo "grep --uninstall in option list:"; timeout 60 python3 -m hr setup --help 2>&1 | grep -ci uninstall || echo "0 (no uninstall option exists in wheel CLI)"

echo "===== PHASE 3: python3 -m hr setup (drives npm install -g + opencode-hr install) ====="
timeout 220 python3 -m hr setup 2>&1 | tail -15
echo "hr-setup rc=$?"

echo "===== PHASE 4: post-setup observation ====="
echo "--- rc/PATH after hr setup: did the PATH story materialise on Linux? ---"
sha256sum -c /tmp/b.rc 2>/dev/null && echo "RC: BYTE-UNCHANGED after hr setup (wheel writes NO rc)" || echo "RC MUTATED"
echo "PATH still: $PATH"
echo "--- what hr setup actually persisted ---"
find /root/.config -type f 2>/dev/null | LC_ALL=C sort | xargs -r sha256sum
cat /root/.config/opencode/opencode.json 2>/dev/null
which opencode-hr
tree_hash >/tmp/b.aftersetup
echo "--- USER-SURFACE delta base vs after-setup (excluding npm/pip internal stores) ---"
diff <(grep -vE "\.npm/|site-packages|dist-info|\.cache/pip|node_modules|/usr/local/bin|\.local/lib" /tmp/b.base) <(grep -vE "\.npm/|site-packages|dist-info|\.cache/pip|node_modules|/usr/local/bin|\.local/lib" /tmp/b.aftersetup)

