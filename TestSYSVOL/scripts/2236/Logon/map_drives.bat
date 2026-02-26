@echo off
REM GPO 2236: Weniger Laufwerke (z.B. Außendienst)
net use H: \\fileserver02\home
net use P: \\fileserver02\projects
REM Kein B: Backup in 2236