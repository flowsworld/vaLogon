' GPO 2236 DeptB - ruft Logon über relativen Pfad auf
Dim sh
Set sh = CreateObject("WScript.Shell")
sh.Run "..\Logon\login.vbs", 1, True