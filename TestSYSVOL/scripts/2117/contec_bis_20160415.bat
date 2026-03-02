net use z: %logonserver%\NETLOGON\2117
z:
rem ******************* INVENTUR ****************************

net use R: \\SST-SV-FIL\Scanner /delete
net use Q: \\SST-SV-FIL\Dokumente /delete
net use V: \\SST-SV-FIL\Copy /delete



rem %logonserver%\netlogon\2117\INVENTUR\lspush.exe 10.132.95.55

rem *********************************************************
contec.vbs
net use /delete z: /YES
u:
::wscript %0\..\Contec.vbs

::call %logonserver%\netlogon\EMWProfileVAE\EMWProf.bat

