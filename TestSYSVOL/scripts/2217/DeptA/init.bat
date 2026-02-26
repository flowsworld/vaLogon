@echo off
REM Abteilung A - Laufwerke und Inventar
net use M: \\dept-a-server\data
REM WMI/Inventar (typische Muster)
REM systeminfo
call ..\Logon\map_drives.bat
wscript.exe "..\Logon\helper.vbs"
