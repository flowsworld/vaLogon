# GPO 2236 DeptA: Andere CIM-Klassen
Get-CimInstance -ClassName Win32_BIOS | Select-Object SerialNumber, Manufacturer
# systeminfo
# Get-CimInstance Win32_LogicalDisk