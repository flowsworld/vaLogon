' GPO 2236 Logon - schlankes Logon (nur Laufwerke, ein Drucker)
Option Explicit
Dim sh
Set sh = CreateObject("WScript.Shell")
sh.Run "map_drives.bat", 1, True
sh.Run "set_printers.cmd", 1, True
' Kein Helper-Aufruf in 2236