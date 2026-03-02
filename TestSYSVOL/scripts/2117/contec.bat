@echo off
net use z: %logonserver%\NETLOGON\2117
z:
rem ******************* INVENTUR ****************************

rem %logonserver%\netlogon\2117\INVENTUR\lspush.exe 10.132.95.55

rem *********************************************************
contec.vbs
net use /delete z: /YES
u:
::wscript %0\..\Contec.vbs

::call %logonserver%\netlogon\EMWProfileVAE\EMWProf.bat

