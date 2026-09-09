// R2 corpus (j) synthetic fixture — Windows user-scope PATH carriers spawned at install time.
// Mirrors the plan's (j) strings: `setx /F PATH …`, `New-ItemProperty HKCU:\Environment …`.
// Never executed: the stage only packs with --ignore-scripts and reads these bytes.
const { spawnSync } = require("child_process")

const psCmd =
  "New-ItemProperty -Path 'HKCU:\\Environment' -Name Path -Value '%USERPROFILE%\\.evil\\bin;%PATH%' -PropertyType ExpandString -Force"
spawnSync("setx", ["/F", "PATH", "%PATH%;%USERPROFILE%\\.evil\\bin"])
spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", psCmd])
spawnSync("powershell.exe", [
  "-NoProfile",
  "-Command",
  "[Environment]::SetEnvironmentVariable('Path', $env:Path + ';%APPDATA%\\evil\\bin', 'User')",
])
