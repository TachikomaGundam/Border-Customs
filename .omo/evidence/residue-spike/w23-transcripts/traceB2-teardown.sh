set -u
export HOME=/root
export PATH=/opt/node-v22.20.0-linux-x64/bin:$PATH
tree_hash() { find /root /etc/profile.d /etc/paths.d -type f 2>/dev/null | LC_ALL=C sort | xargs -r sha256sum; }
tree_hash >/tmp/b.aftersetup
echo "--- USER-SURFACE delta base vs after-setup (excluding npm/pip internal stores) ---"
diff <(grep -vE "\.npm/|site-packages|dist-info|\.cache/pip|node_modules|/usr/local/bin|\.local/lib" /tmp/b.base) <(grep -vE "\.npm/|site-packages|dist-info|\.cache/pip|node_modules|/usr/local/bin|\.local/lib" /tmp/b.aftersetup)

echo "===== PHASE 5: wheel-side removal attempt (expect: NO such verb) ====="
timeout 60 python3 -m hr setup --uninstall 2>&1 | tail -3
echo "wheel-uninstall rc=$? (nonzero + usage error = founding gap: wheel owns install, ships no inverse)"

echo "===== PHASE 6: manual chain teardown (npm-managed + registrar uninstall) ====="
timeout 120 opencode-hr uninstall 2>&1 | tail -4
timeout 220 npm uninstall -g opencode-hr-agent opencode-fastdraw 2>&1 | tail -1
timeout 120 pip uninstall -y aihr 2>&1 | tail -1 | head -c 200; echo
echo "===== PHASE 7: final residue over FULL user surface ====="
tree_hash >/tmp/b.final
diff <(grep -vE "\.npm/|site-packages|dist-info|\.cache/pip|node_modules|/usr/local/bin|\.local/lib" /tmp/b.base) <(grep -vE "\.npm/|site-packages|dist-info|\.cache/pip|node_modules|/usr/local/bin|\.local/lib" /tmp/b.final) && echo "FULLCHAIN: NO RESIDUE" || echo "FULLCHAIN: RESIDUE PRESENT (files above)"
sha256sum "$HOME/.bashrc" "$HOME/.profile"
echo "===== TRACE B DONE ====="
