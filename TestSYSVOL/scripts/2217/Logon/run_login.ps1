# Dummy: PowerShell ruft VBS und BAT auf
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
& ".\login.vbs"
& ".\map_drives.bat"
Start-Process -FilePath "cscript.exe" -ArgumentList "//nologo .\helper.vbs" -Wait
