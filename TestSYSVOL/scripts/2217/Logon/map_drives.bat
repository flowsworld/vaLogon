@echo off
REM Dummy: Net Use Mappings
net use H: \\fileserver01\users
net use P: \\fileserver01\public
net use S: \\dc01\share
if exist "\\backup02\backup" net use B: \\backup02\backup
