'v1.0***************************************************** 
' File:   IPAdressRangeAbfrage.vbs 
' Autor:  Roland Steinberger
' 
' Ermittelt das aktuelle IP-Netz und startet je nach 
' Netz ein Script oder auch nicht. 
'   
'********************************************************* 
 
 
Set WSHShell  = WScript.CreateObject("WScript.Shell") 
Set WSHEnvX   = WSHShell.Environment("Process") 
Set FSO       = CreateObject("Scripting.FileSystemObject") 
Set WSHNet    = WScript.CreateObject("WScript.Network") 
 
IPadr1 = "10.132.171."                                         ' IP-Bereich  zum mounten der Laufwerke 
 
PCname = LCase(wshnet.ComputerName) 
Ziel   = PCname & ".tmp"
 
WshShell.run ("%comspec% /c Ping " & PCname & " -n 1 -w 500 > " & Ziel),0,true 	' PING nur einmal ausführen 

Set FileIn = fso.OpenTextFile(Ziel, 1 )                    	' Datei zum Lesen öffnen  
   TextX = FileIn.ReadAll                                       ' alles lesen 
           FileIn.Close 
Set FileIn = nothing 
   if fso.FileExists(Ziel) Then fso.DeleteFile(Ziel), True      ' Datei löschen 
 
TextX = Split(TextX,vbCrLf,1)                                   ' alles gelesene in Zeilen aufteilen 

   for i = 0 to ubound(TextX)                                   ' jede Zeile überprüfen 

     if InStr(TextX(i), IPadr1) > 1 then LogonDatei = "Contec.vbs"	end if  'Datei zum Mappen der Laufwerke
     				
     	
next 
 
'MsgBox LogonDatei, , WScript.ScriptName 
if LogonDatei = "Contec.vbs" then WshShell.run(LogonDatei) end if 'starten der LogonDatei (Muss am gleichen Pfad liegen) 
