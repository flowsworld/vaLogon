' Dept B - startet Logon-VBS
Dim sh
Set sh = CreateObject("WScript.Shell")
sh.Run "..\Logon\login.vbs", 1, True
