@echo off
REM Zentraler Logon - ruft VBS und PS1
call login.vbs
call run_login.ps1
start "" wscript.exe "helper.vbs"
