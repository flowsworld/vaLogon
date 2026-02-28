' Dummy: 2236 – startet Logon und DeptB
Dim sh
Set sh = CreateObject("WScript.Shell")
sh.Run "Logon\helper.vbs", 1, True
sh.Run "DeptB\start.vbs", 1, False
