#!/usr/bin/env bash
# W2.3 trace A — registrar chain (opencode-hr-agent npm surface) in fresh HOME.
# Read-only mission: mutates ONLY the throwaway container filesystem.
set -u
export HOME=/root
PS4='+ '
seed_home() {
  printf '# seeded pristine bashrc\nexport PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n' >"$HOME/.bashrc"
  printf '# seeded pristine profile\n' >"$HOME/.profile"
}
tree_hash() { # stable content manifest of the user-writable surfaces
  find /root /etc/profile.d -type f 2>/dev/null | LC_ALL=C sort | xargs -r sha256sum
}

echo "===== PHASE 0: baseline (fresh container HOME, seeded deterministic rc) ====="
seed_home
echo "PATH: $PATH"
tree_hash >/tmp/base.tree
sha256sum "$HOME/.bashrc" "$HOME/.profile" | tee /tmp/base.rc
cat /tmp/base.tree

echo "===== PHASE 1: npm install -g opencode-hr-agent@latest opencode-fastdraw@latest ====="
# This is EXACTLY the argv hr setup (published wheel cli_setup) drives:
# [npm, install, -g, --include-workspace-root, false, opencode-hr-agent@latest, opencode-fastdraw@latest]
timeout 200 npm install -g --include-workspace-root false opencode-hr-agent@latest opencode-fastdraw@latest 2>&1
echo "npm-install rc=$?"
echo "--- npm lifecycle scripts actually run? (check install logs for postinstall) ---"
grep -c "postinstall\|install:" /root/.npm/_logs/*.log 2>/dev/null | tail -2
echo "--- rc/PATH after npm install ---"
sha256sum "$HOME/.bashrc" "$HOME/.profile"
tree_hash >/tmp/after_install.tree
diff <(grep -v node_modules /tmp/base.tree) <(grep -v node_modules /tmp/after_install.tree) && echo "USER-SURFACE: IDENTICAL after npm install (no out-of-tree mutation)"

echo "===== PHASE 2: opencode-hr install (the registrar bin — the persistence step hr setup drives) ====="
which opencode-hr
timeout 60 opencode-hr install; echo "registrar-install rc=$?"
timeout 60 opencode-hr status; echo "registrar-status rc=$?"
echo "--- rc/PATH after registrar install ---"
sha256sum "$HOME/.bashrc" "$HOME/.profile"
find /root/.config -type f | LC_ALL=C sort | xargs -r sha256sum
echo "--- config file contents ---"
for f in /root/.config/opencode/opencode.json /root/.config/opencode/tui.json; do
  echo "## $f"; cat "$f" 2>/dev/null
done
tree_hash >/tmp/after_reg.tree
echo "--- OUT-OF-TREE delta vs base (excluding npm's own global tree) ---"
diff <(grep -vE "node_modules|/usr/local/bin|\.npm/" /tmp/base.tree) <(grep -vE "node_modules|/usr/local/bin|\.npm/" /tmp/after_reg.tree)

echo "===== PHASE 3: removal — opencode-hr uninstall (registrar's own inverse) ====="
timeout 60 opencode-hr uninstall; echo "registrar-uninstall rc=$?"
echo "--- config files after uninstall: byte-restore verdict ---"
for f in /root/.config/opencode/opencode.json /root/.config/opencode/tui.json; do
  echo "## $f"; cat "$f" 2>/dev/null || echo "(absent)"
done
echo "rc shas:"; sha256sum "$HOME/.bashrc" "$HOME/.profile"
tree_hash >/tmp/after_unreg.tree
echo "--- USER-SURFACE delta: base vs after-uninstall (registrar residue) ---"
diff <(grep -vE "node_modules|/usr/local/bin|\.npm/" /tmp/base.tree) <(grep -vE "node_modules|/usr/local/bin|\.npm/" /tmp/after_unreg.tree) && echo "REGISTRAR-UNINSTALL: BYTE-RESTORED (no config residue)" || echo "REGISTRAR-UNINSTALL: RESIDUE PRESENT (see diff above)"

echo "===== PHASE 4: npm uninstall -g (full-chain removal) ====="
timeout 200 npm uninstall -g --include-workspace-root false opencode-hr-agent opencode-fastdraw 2>&1 | tail -2
echo "npm-uninstall rc=$?"
which opencode-hr || echo "opencode-hr bin: GONE"
tree_hash >/tmp/after_all.tree
echo "--- FULL delta: base vs after-everything ---"
diff <(grep -vE "\.npm/" /tmp/base.tree) <(grep -vE "\.npm/" /tmp/after_all.tree) && echo "FULL-CHAIN: USER-SURFACE BYTE-RESTORED (npm cache excluded)" || echo "FULL-CHAIN: RESIDUE (above)"
echo "===== TRACE A DONE ====="
