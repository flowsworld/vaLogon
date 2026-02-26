# Gemeinsame Umgebungsvariablen
[Environment]::SetEnvironmentVariable("LOGONSERVER", $env:LOGONSERVER, "User")
# setx LOGONSERVER "%LOGONSERVER%"
# Software-Verteilung (Muster)
# Start-Process msiexec.exe -ArgumentList "/i app.msi /qn"
# .\installer.exe
