# Dummy: Inventarisierung (Get-CimInstance, systeminfo)
Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Name, Domain
Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption
# systeminfo wird oft in BAT verwendet
