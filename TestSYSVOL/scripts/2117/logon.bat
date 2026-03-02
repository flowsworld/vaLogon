rem if exist "%OS%" =="Windows_NT" goto NTLOGON
rem Goto ende
rem :NTLOGON
if exist v: net use v: /d
net use v: \\VAEDC03\install /persistent:NO
rem if exist u: net use u: /d 
rem net use u: \\VAEDC03\%username% /persistent:NO
rem -------------------------------------------------------------------------------
rem  Setzen Laufwerk X für alle VAE AG users in Wien
rem -------------------------------------------------------------------------------
if exist x: net use x: /d
net use x: \\VAEDC03\W-VAEAGUSERS /persistent:NO
if exist w: net use w: /d
net use w: \\VAEDC03\pubdata /persistent:NO
if exist t: net use t: /d
net use t: \\vaedc03\shares
if exist s: net use s: /d
net use s: \\wien-w2kws18\dokuscan
rem -------------------------------------------------------------------------------
rem  Setzen der Zeit auf den Desktop PC´s wird bei Windows 2000 über Kerberor
rem -------------------------------------------------------------------------------
net time \\VAEDC03 /set /yes
rem -------------------------------------------------------------------------------
REM Autoinstall verschiedener Produkte

rem -------------------------------------------------------------------------------
rem 	ÖBB Fahrplan
rem -------------------------------------------------------------------------------
rem	Altes Icon vom Desktop löschen
rem -------------------------------------------------------------------------------
del  "%UserProfile%\Desktop\ÖBB*.lnk" 
rem -------------------------------------------------------------------------------
rem	Neues Icon am Desktop anlegen
rem -------------------------------------------------------------------------------
copy V:\oebb.S02\BBSOMM~1.lnk "%UserProfile%\Desktop" 
copy V:\oebb.S02\hafas_cc.dll c:\winnt\system"
copy V:\oebb.S02\ctl3d.dll c:\winnt\system"


rem -------------------------------------------------------------------------------
rem  Kopieren Herold auf den Desktop 
rem -------------------------------------------------------------------------------
copy V:\otb\TELEFO~1.lnk "%UserProfile%\desktop"
rem -------------------------------------------------------------------------------
rem  Kopieren Viewer auf den Desktop 
rem -------------------------------------------------------------------------------
copy V:\IRVANVIEW\IRVANVIEW.lnk "%UserProfile%\desktop"
rem -------------------------------------------------------------------------------
rem  Kopieren Cobra Adressdatenbank auf den Desktop 
rem -------------------------------------------------------------------------------
copy W:\Cobra\Programm\winplus.lnk "%UserProfile%\desktop"
rem -------------------------------------------------------------------------------
rem Kopieren Masterliste auf den Desktop  am 24.9.2002 eingetragen
rem -------------------------------------------------------------------------------
copy "%logonserver%"\netlogon\Masterlist.LNK "%UserProfile%\Desktop"
copy "%logonserver%"\netlogon\"Masterlist GmbH Neu.LNK" "%UserProfile%\Desktop"


