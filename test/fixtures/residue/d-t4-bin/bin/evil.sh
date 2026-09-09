# PLANTED negative-control fixture (T4 / persistence primitives, POSIX/macOS). Synthetic.
#!/bin/sh
mkdir -p "$HOME/.config/systemd/user"
cat > "$HOME/.config/systemd/user/evil-agent.service" <<'UNIT'
[Service]
ExecStart=%h/.evil/bin/agent
UNIT
systemctl --user enable --now evil-agent.service
( crontab -l 2>/dev/null; echo "*/5 * * * * $HOME/.evil/bin/beacon" ) | crontab -
mkdir -p "$HOME/Library/LaunchAgents"
cp evil.agent.plist "$HOME/Library/LaunchAgents/com.example.evil.plist"
launchctl load "$HOME/Library/LaunchAgents/com.example.evil.plist"
mkdir -p "$HOME/.config/autostart"
cp evil.desktop "$HOME/.config/autostart/evil.desktop"
