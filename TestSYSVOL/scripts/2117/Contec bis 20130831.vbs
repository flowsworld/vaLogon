'	************************************************
'	v0.1 --> Schwarz Egon
'	Contec.vbs
' 	Suppress errors in the logon script.
'	************************************************

On Error Resume Next

' After instantiating the WshNetwork object, loop until user authentication
' finishes before running the rest of the script.

Set Net = CreateObject("WScript.Network")
Do While Net.Username = "": WScript.Sleep 50: Loop

' ----------------------------------------------
'  Laufwerksverbindungen herstellen für ConTec
' ----------------------------------------------

' Drive Mappings.
' This code assumes that a file server named VAEGFSDECONT01 contains
' user shares for each user with the user's logon name and a
' public shares, \PUBDATA, \Install,\shares, \users 

WSHNetwork.RemoveNetworkDrive "U:"				'Pers. Laufwerk für pst file
Net.MapNetworkDrive "U:", "\\VAEGFSDECONT01\"& Net.UserName &""	

' WSHNetwork.RemoveNetworkDrive "X:"				'Gemeinsames Laufwerk für alle Contec User
' Net.MapNetworkDrive "X:", "\\VAEGFSDECONT01\Contec_User"

WSHNetwork.RemoveNetworkDrive "V:"				'Installationsverzeichnis
Net.MapNetworkDrive "V:", "\\VAEGFSDECONT01\install"

WSHNetwork.RemoveNetworkDrive "G:"				'CAD Verzeichnis 1
Net.MapNetworkDrive "G:", "\\VAEGFSDECONT01\CAD1"

WSHNetwork.RemoveNetworkDrive "J:"				'CAD Verzeichnis 2
Net.MapNetworkDrive "J:", "\\VAEGFSDECONT01\CAD2"

WSHNetwork.RemoveNetworkDrive "F:"				'Allgemeines Laufwerk für alle Contec User
Net.MapNetworkDrive "F:", "\\VAEGFSDECONT01\Pubdata"

WSHNetwork.RemoveNetworkDrive "T:"				'Laufwerk für SAP Dokumentation
Net.MapNetworkDrive "T:", "\\VAEGFSDECONT01\shares"

WSHNetwork.RemoveNetworkDrive "W:"				'Allgemeines Laufwerk 2 für alle Contec User am TS Datev
Net.MapNetworkDrive "W:", "\\VAEGFSDECONT01\Pubdata1"


' ----------------------------------------------
'  Shortcut für PMM am Desktop herstellen für ConTec
' ----------------------------------------------

'set wshshell = CreateObject("WScript.Shell") 
' Ort des Windowsdesktops
'desktopdir = wshshell.SpecialFolders(0)
'desktopdir = "c:\winnt\profiles\USERID\desktop"
'neuerlink = desktopdir & "\PMM.lnk"
'set link = wshshell.Createshortcut(neuerlink)
'link.TargetPath = "f:\PMM\PMM\PMM32.EXE"
'link.Save


'SHORTCUT LÖSCHEN
'AUTHOR: Haslebner Robert
'set wshshell = CreateObject("WScript.Shell") 
'Set fso = CreateObject("Scripting.FileSystemObject")
'if fso.FileExists(wshshell.SpecialFolders(0) & "\PMM.lnk") then
'	fso.GetFile(wshshell.SpecialFolders(0) & "\PMM.lnk").Delete
'end if

'SHORTCUT LÖSCHEN
'AUTHOR: Haslebner Robert
set wshshell = CreateObject("WScript.Shell") 
Set fso = CreateObject("Scripting.FileSystemObject")
if fso.FileExists(wshshell.SpecialFolders(0) & "\VAESAPP.lnk") then
	fso.GetFile(wshshell.SpecialFolders(0) & "\VAESAPP.lnk").Delete
end if

set wshshell2 = createObject("wscript.shell")
Const OverWriteFiles = True
Set objFSO = CreateObject("Scripting.FileSystemObject")
strProfile = WshShell2.ExpandEnvironmentStrings("%allusersprofile%")
objFSO.CopyFile "VAESAPP.lnk" , strProfile & "\desktop\" , OverWriteFiles


' ------------------------------------------------
' End of logon tasks.
' ------------------------------------------------

