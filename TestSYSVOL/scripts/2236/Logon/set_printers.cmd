@echo off
REM GPO 2236: Nur Standard-Drucker
rundll32 printui.dll,PrintUIEntry /in /n "\\printserver02\DefaultPrinter"
REM Kein prnport.vbs in 2236