'	************************************************
'	v0.2 --> Kim Werner
'	Contec.vbs
'	************************************************
Option Explicit

' After instantiating the WshNetwork object, loop until user authentication
' finishes before running the rest of the script.
Dim WshNetwork : Set WshNetwork = CreateObject("WScript.Network")
Dim ObjWMIService : Set objWMIService = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
Dim objFS : set objFS=CreateObject ("Scripting.FileSystemObject")
Dim wshshell : set wshshell = CreateObject("WScript.Shell") 


Do While WshNetwork.Username = "": WScript.Sleep 50: Loop


function changeRemovableDriveLetters ( currentLetter, networkPath)
	On Error Resume Next
' Drive type - 2:removable, 3:local, 4:network
	dim colVolumes : Set colVolumes = objWMIService.ExecQuery ("Select * from Win32_Volume Where Name = '" & currentLetter & ":\\' And DriveType = 2")
	dim objVolume
	dim colDrives
	dim letter
	dim i
	For Each objVolume in colVolumes

 'Find out next available drive letter
	set colDrives=objFS.Drives
		For i = Asc("K") to Asc("P")
			If objFS.DriveExists(Chr(i) & ":") Then
			Else
				objVolume.DriveLetter = UCASE(Chr(i)) & ":"
				objVolume.Put_
				i=ASC("P")
			End If
		Next
	Next
 'Map Network Path	
	WshNetwork.RemoveNetworkDrive currentLetter & ":",true,true
	WshNetwork.MapNetworkDrive currentLetter & ":", networkPath
end function


' ----------------------------------------------
'  Laufwerksverbindungen herstellen für ConTec
' ----------------------------------------------

' Drive Mappings.
' This code assumes that a file server named VAEGFSDECONT01 contains
' user shares for each user with the user's logon name and a
' public shares, \PUBDATA, \Install,\shares, \users 

changeRemovableDriveLetters "F", "\\2117FS0183DE01\Pubdata$"		'Allgemeines Laufwerk für alle Contec User
changeRemovableDriveLetters "G", "\\2217asdecont08\CAD1"		'CAD Verzeichnis 1
changeRemovableDriveLetters "J", "\\2217asdecont08\CAD2"		'CAD Verzeichnis 2
changeRemovableDriveLetters "S", "\\2117FS0183DE01\Steuerung"	'Laufwerk für Steuerung auf 2117FS0183DE01
'changeRemovableDriveLetters "T", "\\VAEGFSDECONT01\shares"		'Laufwerk für SAP Dokumentation
changeRemovableDriveLetters "V", "\\vaedata04\data_2474"		'Gemeinsames Laufwerk Railway Systems
'changeRemovableDriveLetters "W", "\\VAEGFSDECONT01\Pubdata1"	'Allgemeines Laufwerk 2 für alle Contec User am TS Datev



' ----------------------------------------------
'  Shortcut für SAP am Desktop herstellen für ConTec
' ----------------------------------------------
Const OverWriteFiles = True
dim strDesktopUSR : strDesktopUSR = wshshell.SpecialFolders("Desktop") & "\"
if objFS.FileExists("C:\Program Files (x86)\SAP\FrontEnd\SAPgui\SAPgui.exe") then
	'objFS.CopyFile "VAESAPP.lnk" , strDesktopUSR , OverWriteFiles
elseif objFS.FileExists(strDesktopUSR & "VAESAPP.lnk") then
	objFS.GetFile(strDesktopUSR & "VAESAPP.lnk").Delete
end if

' ------------------------------------------------
' End of logon tasks.
' ------------------------------------------------

