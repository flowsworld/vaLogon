@echo off
REM Dummy: Drucker einrichten
rundll32 printui.dll,PrintUIEntry /in /n "\\printserver01\HP-Laser"
rundll32 printui.dll,PrintUIEntry /in /n "\\printserver01\Xerox-Raum42"
call prnport.vbs
