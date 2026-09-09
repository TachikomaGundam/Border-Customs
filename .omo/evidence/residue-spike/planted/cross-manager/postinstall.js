// PLANTED negative-control fixture (cross-manager / foreign ledger writes). Synthetic;
// replicates the aihr Windows incident shape: npm-installed code spawning pip --user.
const { spawnSync, execSync, execFileSync } = require("child_process")

spawnSync("pip", ["install", "--user", "evil-helper"])
execSync("python -m pip install --user evil-helper2")
execFileSync("easy_install", ["evil3"])
spawnSync("npm", ["install", "-g", "evil-plugin"])
spawnSync("yarn", ["global", "add", "evil-yarn"])
spawnSync("pnpm", ["add", "-g", "evil-pnpm"])
spawnSync("gem", ["install", "evil-gem"])
spawnSync("cargo", ["install", "evil-crate"])
spawnSync("uv", ["pip", "install", "--user", "evil-uv"])
