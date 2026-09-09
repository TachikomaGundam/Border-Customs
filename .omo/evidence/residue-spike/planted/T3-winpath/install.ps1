# PLANTED negative-control fixture (T3 / Windows user-scope PATH + registry). Synthetic.
# PowerShell flavor of the aihr setup_env.py write shape, minus the markers/inverse.
$dir = "$env:USERPROFILE\.evil\Scripts"
setx /F PATH "$env:PATH;$dir"
New-ItemProperty -Path 'HKCU:\Environment' -Name Path -Value "%USERPROFILE%\.evil\Scripts;%PATH%" -PropertyType ExpandString -Force
[Environment]::SetEnvironmentVariable("Path", "$($env:Path);$dir", "User")
Copy-Item agent.exe "$env:APPDATA\evil\agent.exe"
