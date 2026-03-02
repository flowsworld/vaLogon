# Test-SYSVOL (Dummy)

Dieses Verzeichnis simuliert eine typische SYSVOL\scripts-Struktur mit **Dummy-Dateien** zum Testen der vaLogon-Skripte. Keine echten Server oder ausführbaren Aktionen – nur Inhalt, der die gleichen Muster wie in Produktion auslöst.

## Struktur

```
TestSYSVOL/
  scripts/
    2117/        – GPO „Legacy“ (ältere KIX/VBS/BAT-Varianten, historische Konfiguration)
    2217/        – GPO „Büro“ (vollständige Logon-Kette, mehrere Shares/Drucker, prnport.vbs, banner.ps1)
    2236/        – GPO „Schlank“ (weniger Laufwerke/Drucker, andere Server, optional.vbs)
    <GPO-ID>/    – Muster für weitere GPO-IDs
      Logon/     – zentrale Logon-Skripte (VBS, BAT, CMD, PS1, KIX)
      DeptA/     – Abteilung A (Init, Inventar)
      DeptB/     – Abteilung B (Start-VBS → Logon)
      Common/    – Konfiguration, Umgebung, Software-Verteilung, Sicherheit
```

Die GPO-Ordner **2117**, **2217** und **2236** enthalten bewusst **unterschiedliche** Testdateien (andere Server, andere Aufrufketten, teils andere Dateien), damit Duplikat-, Kategorisierungs- und Flow-Analysen echte Varianz sehen.

In **allen** Unterordnern (Logon, Common, DeptA, DeptB) liegen zusätzlich **Dummy-Dateien**, die vom Script-Flowchart **nicht** als Skripte geparst werden: `.txt`, `.ini`, `.xml`, `.log`, `.bak`, `.py`, `.exe`, `.dll` (leere Platzhalter). So kann getestet werden, dass nur VBS/BAT/CMD/PS1/PSM1/KIX in den Aufrufgraphen einfließen.

Im **Stammordner** `scripts/` und in den **Top-Ordnern** `2217/` und `2236/` liegen weitere Dummies: sowohl **relevante** Typen (PS1, BAT, VBS, KIX) mit **Verlinkungen** in darunter liegende Skripte (z. B. `bootstrap.ps1` → `2217\Logon\run_login.ps1`, `2217\startup.ps1` → `.\Logon\user_logon.bat`), als auch **irrelevante** (z. B. `readme.txt`, `config.ini`, `data.xml`, `install.log`, `placeholder.exe`/`.dll`). So lassen sich Aufrufketten über Ordner-Ebenen und die Filterung nach Dateityp prüfen.
Im **Stammordner** `scripts/` und in den **Top-Ordnern** `2117/`, `2217/` und `2236/` liegen weitere Dummies: sowohl **relevante** Typen (PS1, BAT, VBS, KIX) mit **Verlinkungen** in darunter liegende Skripte (z. B. `entry.vbs`, `launcher.bat`, `startup.ps1` → Logon-Skripte in `.\Logon`), als auch **irrelevante** (z. B. `readme.txt`, `config.ini`, `data.xml`, `install.log`, `placeholder.exe`/`.dll`). So lassen sich Aufrufketten über Ordner-Ebenen und die Filterung nach Dateityp prüfen.

Im Wurzelordner `TestSYSVOL/` liegen zusätzlich Hilfsdateien wie eine Excel-Datei (`EbenenVisual.xlsx`) und ein Beispiel-Screenshot, die die Ebenen- und GPO-Struktur visuell dokumentieren.

| Bereich   | 2217 (Büro) | 2236 (Schlank) |
|-----------|--------------|-----------------|
| Logon     | map_drives, set_printers, helper.vbs, prnport.vbs; user_logon ruft login.vbs + run_login.ps1 + helper.vbs | Nur map_drives, set_printers; user_logon nur login.vbs; optional.vbs (verwaist) |
| Laufwerke | fileserver01, dc01, backup02 (H,P,S,B) | fileserver02 (H,P) |
| Drucker   | printserver01 (HP-Laser, Xerox), prnport.vbs | printserver02 (DefaultPrinter) |
| Common    | config (fileserver01, dc01, intranet, IPs), env (SetEnvironmentVariable), install (msi/exe), security_check, **banner.ps1** | config (fileserver02, vpn, andere IPs), env (nur setx), install (nur exe), security_check |
| DeptA     | net use M: dept-a-server, ruft map_drives + helper | net use N: dept-b-server, kein Logon-Aufruf |
| DeptB     | start.vbs → `..\Logon\login.vbs` | start.vbs → `..\Logon\login.vbs` (gleicher Pfad, anderes GPO) |

## Enthaltene Muster (für Skript-Tests)

| Skript | Zweck |
|--------|--------|
| **Export-ScriptFlowchart** | VBS/BAT/CMD/PS1/KIX rufen sich gegenseitig auf; Pfade wie `helper.vbs`, `..\Logon\login.vbs`. |
| **Analyze-LoginScriptCategories** | `net use`, `printui.dll`, `Get-CimInstance`/`Win32_`, `[Environment]::SetEnvironmentVariable`, `setx`, `Start-Process`/`msi`, `ExecutionPolicy`. |
| **Analyze-SysvolHostReachability** | UNC (`\\fileserver01\...`), URLs (`https://intranet...`), IPs in `config.txt`; Subnet-Scan wenn Hosts auflösbar. |
| **Analyze-SysvolScripts** | Alle Dateitypen, Sicherheits-/Dependency-/Nutzungs-/Duplikat-/Codequalitäts-Muster. |

## Verwendung

Alle Skripte mit `-ScriptsPath` auf den **scripts**-Ordner zeigen:

```powershell
# Absoluter Pfad (empfohlen)
$testPath = (Resolve-Path .\TestSYSVOL\scripts).Path

# Skript-Flowchart
.\Export-ScriptFlowchart.ps1 -ScriptsPath $testPath -OutputPath .\TestScriptFlow.html

# Kategorien
.\Analyze-LoginScriptCategories.ps1 -ScriptsPath $testPath -OutputPath .\TestCategories.html

# Host-Erreichbarkeit (pingt echte Hosts nur, wenn Netz erreichbar; sonst nur Extraktion)
.\Analyze-SysvolHostReachability.ps1 -ScriptsPath $testPath -OutputPath .\TestHostReach.html
```

Unter macOS/Linux: `TestSYSVOL/scripts` liegt im Repo; unter Windows kann der gleiche Pfad oder ein UNC wie `\\server\SYSVOL\domain\scripts` verwendet werden.
