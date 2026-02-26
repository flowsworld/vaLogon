' GPO 2217 Logon - vollständig: Mapper, Drucker, Helper
Option Explicit
Dim shell, wsh
Set shell = CreateObject("WScript.Shell")
Set wsh = CreateObject("WScript.Shell")
shell.Run "map_drives.bat", 1, True
shell.Run "set_printers.cmd", 1, True
shell.Run "helper.vbs", 1, True
Sub LogMessage(msg)
    ' Dummy
End Sub
