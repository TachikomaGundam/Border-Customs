# PLANTED negative-control fixture (T4 / persistence primitives, Windows). Synthetic.
schtasks /Create /TN "EvilAgent" /TR "%USERPROFILE%\.evil\agent.exe" /SC ONLOGON /RL LIMITED /F
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v EvilAgent /t REG_SZ /d "%USERPROFILE%\.evil\agent.exe" /f
