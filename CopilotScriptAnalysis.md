# Skript-Analyse für Microsoft 365 Copilot

Dieser Report listet alle erfassten Logon-/Skriptdateien mit Kategorie, Nutzung, Kritikalität, Abhängigkeiten und empfohlener GPO-Migration. Zur Auswertung in Word oder Teams öffnen und mit Copilot z.B. fragen: "Analysiere diese Skripte auf Kritikalität" oder "Welche GPO-Einstellungen ersetzen diese Logon-Skripte?".

| Relativer Pfad | Typ | Kategorie | Nutzung | Risiko | Abhängigkeiten | GPO-Empfehlung |
|---------------|-----|-----------|---------|--------|----------------|----------------|
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/bootstrap.ps1 | .ps1 | Unbekannt | — | — | Aufrufer: — \| Aufgerufen: — | Manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/entry.vbs | .vbs | Unbekannt | — | — | Aufrufer: — \| Aufgerufen: — | Manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/launcher.bat | .bat | Unbekannt | — | — | Aufrufer: — \| Aufgerufen: — | Manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/run_all.kix | .kix | Unbekannt | — | — | Aufrufer: — \| Aufgerufen: — | Manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2217/entry.vbs | .vbs | Unbekannt | — | — | Aufrufer: — \| Aufgerufen: — | Manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2217/init.bat | .bat | Unbekannt | — | — | Aufrufer: — \| Aufgerufen: — | Manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2217/startup.ps1 | .ps1 | Unbekannt | — | — | Aufrufer: — \| Aufgerufen: — | Manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2217/DeptA/init.bat | .bat | Laufwerks-Mappings | — | — | Aufrufer: — \| Aufgerufen: — | GPO Preferences: Laufwerkszuordnung (Drive Map) |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2217/DeptA/inventory.ps1 | .ps1 | Inventarisierung/Asset | — | — | Aufrufer: — \| Aufgerufen: — | Kein 1:1-GPO-Ersatz; Intune/ConfigMgr oder manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2217/Logon/helper.vbs | .vbs | Software-Verteilung/Updates | — | — | Aufrufer: — \| Aufgerufen: — | GPO Software Installation oder Intune; manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2217/Logon/login.vbs | .vbs | Software-Verteilung/Updates | — | — | Aufrufer: — \| Aufgerufen: — | GPO Software Installation oder Intune; manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2217/Logon/logon.kix | .kix | Unbekannt | — | — | Aufrufer: — \| Aufgerufen: — | Manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2217/Logon/map_drives.bat | .bat | Laufwerks-Mappings | — | — | Aufrufer: — \| Aufgerufen: — | GPO Preferences: Laufwerkszuordnung (Drive Map) |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2217/Logon/prnport.vbs | .vbs | Unbekannt | — | — | Aufrufer: — \| Aufgerufen: — | Manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2217/Logon/run_login.ps1 | .ps1 | Sicherheit/Compliance | — | — | Aufrufer: — \| Aufgerufen: — | GPO: Lokale Richtlinie / Registry (z.B. Legal Notice) |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2217/Logon/set_printers.cmd | .cmd | Drucker-Einrichtung | — | — | Aufrufer: — \| Aufgerufen: — | GPO Preferences: Drucker |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2217/Logon/user_logon.bat | .bat | Unbekannt | — | — | Aufrufer: — \| Aufgerufen: — | Manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2217/Common/banner.ps1 | .ps1 | Sicherheit/Compliance | — | — | Aufrufer: — \| Aufgerufen: — | GPO: Lokale Richtlinie / Registry (z.B. Legal Notice) |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2217/Common/env.ps1 | .ps1 | Software-Verteilung/Updates | — | — | Aufrufer: — \| Aufgerufen: — | GPO Software Installation oder Intune; manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2217/Common/install_app.ps1 | .ps1 | Software-Verteilung/Updates | — | — | Aufrufer: — \| Aufgerufen: — | GPO Software Installation oder Intune; manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2217/Common/security_check.ps1 | .ps1 | Sicherheit/Compliance | — | — | Aufrufer: — \| Aufgerufen: — | GPO: Lokale Richtlinie / Registry (z.B. Legal Notice) |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2217/DeptB/start.vbs | .vbs | Unbekannt | — | — | Aufrufer: — \| Aufgerufen: — | Manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2117/Contec bis 20100730.vbs | .vbs | Laufwerks-Mappings | — | — | Aufrufer: — \| Aufgerufen: — | GPO Preferences: Laufwerkszuordnung (Drive Map) |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2117/Contec bis 20130831.vbs | .vbs | Laufwerks-Mappings | — | — | Aufrufer: — \| Aufgerufen: — | GPO Preferences: Laufwerkszuordnung (Drive Map) |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2117/contec_bis_20160415.bat | .bat | Laufwerks-Mappings | — | — | Aufrufer: — \| Aufgerufen: — | GPO Preferences: Laufwerkszuordnung (Drive Map) |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2117/Contec_bis_20160415.vbs | .vbs | Laufwerks-Mappings | — | — | Aufrufer: — \| Aufgerufen: — | GPO Preferences: Laufwerkszuordnung (Drive Map) |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2117/contec_old.bat | .bat | Unbekannt | — | — | Aufrufer: — \| Aufgerufen: — | Manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2117/contec_sst.bat | .bat | Laufwerks-Mappings | — | — | Aufrufer: — \| Aufgerufen: — | GPO Preferences: Laufwerkszuordnung (Drive Map) |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2117/contec.bat | .bat | Laufwerks-Mappings | — | — | Aufrufer: — \| Aufgerufen: — | GPO Preferences: Laufwerkszuordnung (Drive Map) |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2117/Contec.vbs | .vbs | Laufwerks-Mappings | — | — | Aufrufer: — \| Aufgerufen: — | GPO Preferences: Laufwerkszuordnung (Drive Map) |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2117/Contec.vbs bis 20 Jann 2010.vbs | .vbs | Laufwerks-Mappings | — | — | Aufrufer: — \| Aufgerufen: — | GPO Preferences: Laufwerkszuordnung (Drive Map) |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2117/Copy of contec.bat | .bat | Laufwerks-Mappings | — | — | Aufrufer: — \| Aufgerufen: — | GPO Preferences: Laufwerkszuordnung (Drive Map) |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2117/IPAdressRangeAbfrage.vbs | .vbs | Software-Verteilung/Updates | — | — | Aufrufer: — \| Aufgerufen: — | GPO Software Installation oder Intune; manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2117/logon_neu.bat | .bat | Unbekannt | — | — | Aufrufer: — \| Aufgerufen: — | Manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2117/logon.bat | .bat | Laufwerks-Mappings | — | — | Aufrufer: — \| Aufgerufen: — | GPO Preferences: Laufwerkszuordnung (Drive Map) |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2236/entry.vbs | .vbs | Unbekannt | — | — | Aufrufer: — \| Aufgerufen: — | Manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2236/launcher.bat | .bat | Unbekannt | — | — | Aufrufer: — \| Aufgerufen: — | Manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2236/startup.ps1 | .ps1 | Unbekannt | — | — | Aufrufer: — \| Aufgerufen: — | Manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2236/DeptA/init.bat | .bat | Laufwerks-Mappings | — | — | Aufrufer: — \| Aufgerufen: — | GPO Preferences: Laufwerkszuordnung (Drive Map) |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2236/DeptA/inventory.ps1 | .ps1 | Inventarisierung/Asset | — | — | Aufrufer: — \| Aufgerufen: — | Kein 1:1-GPO-Ersatz; Intune/ConfigMgr oder manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2236/Logon/helper.vbs | .vbs | Unbekannt | — | — | Aufrufer: — \| Aufgerufen: — | Manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2236/Logon/login.vbs | .vbs | Unbekannt | — | — | Aufrufer: — \| Aufgerufen: — | Manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2236/Logon/logon.kix | .kix | Unbekannt | — | — | Aufrufer: — \| Aufgerufen: — | Manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2236/Logon/map_drives.bat | .bat | Laufwerks-Mappings | — | — | Aufrufer: — \| Aufgerufen: — | GPO Preferences: Laufwerkszuordnung (Drive Map) |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2236/Logon/optional.vbs | .vbs | Unbekannt | — | — | Aufrufer: — \| Aufgerufen: — | Manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2236/Logon/run_login.ps1 | .ps1 | Unbekannt | — | — | Aufrufer: — \| Aufgerufen: — | Manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2236/Logon/set_printers.cmd | .cmd | Drucker-Einrichtung | — | — | Aufrufer: — \| Aufgerufen: — | GPO Preferences: Drucker |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2236/Logon/user_logon.bat | .bat | Unbekannt | — | — | Aufrufer: — \| Aufgerufen: — | Manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2236/Common/env.ps1 | .ps1 | Umgebungsvariablen/Pfade | — | — | Aufrufer: — \| Aufgerufen: — | GPO Preferences: Umgebung oder Registry |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2236/Common/install_app.ps1 | .ps1 | Software-Verteilung/Updates | — | — | Aufrufer: — \| Aufgerufen: — | GPO Software Installation oder Intune; manuell prüfen |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2236/Common/security_check.ps1 | .ps1 | Sicherheit/Compliance | — | — | Aufrufer: — \| Aufgerufen: — | GPO: Lokale Richtlinie / Registry (z.B. Legal Notice) |
| /Users/florian/Library/CloudStorage/OneDrive-Gratzl.Me/Development/DiesisMedia/vaLogon/TestSYSVOL/scripts/2236/DeptB/start.vbs | .vbs | Unbekannt | — | — | Aufrufer: — \| Aufgerufen: — | Manuell prüfen |

## Zusammenfassung

- **Unbekannt**: 23 Datei(en)
- **Laufwerks-Mappings**: 14 Datei(en)
- **Software-Verteilung/Updates**: 6 Datei(en)
- **Sicherheit/Compliance**: 4 Datei(en)
- **Drucker-Einrichtung**: 2 Datei(en)
- **Inventarisierung/Asset**: 2 Datei(en)
- **Umgebungsvariablen/Pfade**: 1 Datei(en)

- GPO/AD-referenziert (aktiv): 0
- Verwaist: 0

*Erzeugt mit Export-CopilotAnalysisReport.ps1. Keine KI-APIs – Analyse durch Copilot erfolgt manuell.*

