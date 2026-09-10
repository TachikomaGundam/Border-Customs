#!/usr/bin/env bash
# W2.3 trace A2 — pre-existing user config surface: does the registrar's
# install/uninstall pair byte-restore a NON-FRESH HOME?
set -u
export HOME=/root
CFG=/root/.config/opencode/opencode.json
TUI=/root/.config/opencode/tui.json
rm -rf /root/.config/opencode
mkdir -p /root/.config/opencode
# user file: 4-space indent, unrelated keys, a foreign plugin entry, comments absent (strict JSON)
cat >"$CFG" <<'EOF'
{
    "$schema": "https://opencode.ai/config.json",
    "model": "anthropic/claude-x",
    "plugin": ["acme-user-plugin@1.0.0"]
}
EOF
cp "$CFG" /tmp/cfg.orig
printf '{\n    "theme": "dracula"\n}\n' >"$TUI"; cp "$TUI" /tmp/tui.orig
echo "===== baseline shas ====="
sha256sum "$CFG" "$TUI"
timeout 200 npm install -g --include-workspace-root false opencode-hr-agent@latest >/dev/null 2>&1; echo "npm-install rc=$?"
echo "===== opencode-hr install ====="
timeout 60 opencode-hr install; echo "install rc=$?"
echo "===== opencode-hr uninstall ====="
timeout 60 opencode-hr uninstall; echo "uninstall rc=$?"
echo "===== byte comparison vs original ====="
sha256sum "$CFG" "$TUI"
if cmp -s "$CFG" /tmp/cfg.orig; then echo "CFG: BYTE-RESTORED"; else echo "CFG: MODIFIED — diff:"; diff /tmp/cfg.orig "$CFG"; fi
if cmp -s "$TUI" /tmp/tui.orig; then echo "TUI: BYTE-RESTORED"; else echo "TUI: MODIFIED — diff:"; diff /tmp/tui.orig "$TUI"; fi
echo "===== semantics check: foreign entry survived? ====="
grep -c "acme-user-plugin" "$CFG"; grep -c '"theme"' "$TUI"
timeout 200 npm uninstall -g opencode-hr-agent >/dev/null 2>&1; echo "cleanup npm rc=$?"
echo "===== TRACE A2 DONE ====="
