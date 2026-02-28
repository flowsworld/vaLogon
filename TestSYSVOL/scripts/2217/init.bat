@echo off
REM Dummy: 2217 – ruft Logon und Common auf
call Logon\map_drives.bat
call Logon\set_printers.cmd
call Common\security_check.ps1
