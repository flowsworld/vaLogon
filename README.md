## SYSVOL Scripts Analyse Tool (PowerShell 7)

Ein PowerShell‑7‑basiertes Enterprise‑Analyse‑Tool für große Active‑Directory‑Umgebungen mit vielen Logon‑Skripten im `SYSVOL\scripts`‑Ordner.  
Der Fokus liegt auf **Security**, **Abhängigkeiten**, **Nutzung**, **Duplikaten** und **Codequalität**, bei rein lesendem Zugriff.

### Features im Überblick

- **Read‑Only Analyse** des kompletten `SYSVOL\scripts`‑Baums
- **Sicherheitsanalyse**
  - SHA256‑Hashes und Signaturstatus für EXE/COM/DLL/MSI
  - Erkennung unerwarteter Dateitypen (`.py`, `.rb`, `.pl`, `.jar`)
  - Regex‑basierte Erkennung von:
    - Klartext‑Credentials in mehreren Sprachen: Englisch, Deutsch, Spanisch, Portugiesisch, Schwedisch, Chinesisch, Italienisch (z. B. `password`/`pwd`, `Passwort`/`Kennwort`, `contraseña`/`clave`, `senha`, `lösenord`, 密码/口令, `parola` sowie typische ConnectionString‑Paare wie User/Password, usuario/contraseña, 用户/密码)
    - Download‑Befehlen (Invoke‑WebRequest / Invoke‑RestMethod / wget / curl / `.DownloadFile(`)
    - Execution‑Policy‑Bypässen
    - Base64‑kodierten EncodedCommands
  - Risiko‑Einstufung **Critical/High/Medium/Low** + Handlungsempfehlungen (inkl. PowerShell‑Beispielkommandos im Dry‑Run‑Stil)
- **Dependency‑Tracking**
  - Erkennung von Skriptaufrufen in PowerShell, VBS, Batch/CMD, KiXtart
  - Aufbau eines Aufrufgraphen (Nodes/Edges), Markierung von Zyklen
  - Ermittlung von Entry‑Points (keine eingehenden Kanten) und Leaf‑Skripten (keine ausgehenden Kanten)
- **Nutzungsanalyse**
  - GPO‑basierte Referenzen (Logon/Logoff/Startup/Shutdown, via `Get-GPOReport -ReportType Xml`)
  - AD‑User/Computer `scriptPath` (ActiveDirectory‑Modul oder ADSI‑Fallback)
  - Zeitstempel‑Heuristik (`LastAccessTime`, `LastWriteTime`, `CreationTime`)
  - Kategorisierung: *Aktiv verwendet*, *Wahrscheinlich aktiv*, *Vermutlich ungenutzt*, *Verwaist*
- **Duplikaterkennung**
  - SHA256‑Hash‑Gruppen (100 % identischer Inhalt)
  - Inhaltsähnlichkeit über normalisierten Inhalt (>~90 %)
  - Einfache Namens‑Gruppierung
  - Vorschläge, welche Kopie behalten werden sollte (größte/typischste bzw. referenzierte Version)
- **Code‑Qualität & Komplexität**
  - Dateigröße, LOC gesamt, Kommentar‑LOC, Kommentar‑Ratio
  - Approx. Cyclomatic Complexity (If/ElseIf/Switch/For/Foreach/While/Do/Catch/Case)
  - Erkennung von Hard‑Coded Credentials, Legacy‑Kommandos (z.B. `net use`) und Error‑Handling
- **Outputs**
  - Interaktives Konsolen‑Menü
  - HTML‑Management‑Report (Executive Summary + Detail‑Sektionen)
  - CSV‑Sammlung für alle Bereiche
  - JSON‑Gesamtdatensatz (inkl. Dependency‑Graph)
  - Optional: Excel‑Export (ImportExcel‑Modul)
- **Robustheit**
  - Checkpoint/Resume über JSON‑Datei
  - Batch‑basierte Parallelisierung mit `ForEach-Object -Parallel`
  - Logging (Transcript + Textlog)
  - Fehlertoleranz bei gesperrten/fehlerhaften Dateien und Encoding‑Problemen

---

### Voraussetzungen

- **PowerShell**: Version **7.0 oder höher** (`pwsh`)
- **Active Directory**
  - Single‑Domain AD
  - Leserechte auf:
    - `\\<domain>\SYSVOL\<domain>\scripts`
    - GPOs (für `Get-GPOReport`)
    - AD‑Benutzer/Computerobjekte (für `scriptPath`)
- **Module**
  - Optional, aber empfohlen: `ActiveDirectory` (für AD‑Abfragen)
  - Optional, empfohlen: `GroupPolicy` (für GPO‑Analyse)
  - Optional: `ImportExcel` (für komfortablen Excel‑Report)
- **Rechte**
  - Das Tool ist **rein lesend**: es nimmt keine Änderungen in SYSVOL, AD oder GPOs vor.
  - Empfohlene Aktionen werden als PowerShell‑Beispiele (Dry‑Run‑Stil) ausgegeben.

---

### Dateien im Projekt

- `Analyze-SysvolScripts.ps1`  
  Hauptskript/Entry‑Point mit:
  - Parametern (`ScriptsPath`, `Resume`, `DryRun`, `ParallelThreads`, `OutputPath`)
  - Modul‑ und Umgebungschecks
  - Checkpoint‑/Resume‑Logik
  - Inventarisierung, Analysen, Exporte, Konsolenmenü

- `Export-ScriptFlowchart.ps1`  
  Eigenständiges Skript für einen **Skript-Flowchart** (VBS, BAT, CMD, PS1, PSM1, KIX) als HTML:
  - Findet alle Skriptdateien unter `ScriptsPath` und löst Aufrufbeziehungen auf (wer ruft wen auf).
  - Erzeugt eine einzelne HTML-Datei (**Skript-Flowchart**) mit **Mermaid**-Flowchart und **Tailwind**-Layout: Darstellung **ein Subgraph pro Ordner**, Ebenen strikt **von links nach rechts**; Knoten werden **nach Dateityp gefärbt** (VBS=blau, BAT/CMD=amber, PS1/PSM1=grün, KiXtart=lila, wie in der Legende). Pro Skript wird der Quellcode in `<pre><code>` ausgegeben; Verweise über Top-Ordner-Grenzen werden gelb/rot hervorgehoben; rekursive Aufrufzyklen werden erkannt und betroffene Knoten mit `[REC]` gekennzeichnet. Die Root-Ansicht (Dateien direkt unter `ScriptsPath`) ist entbehrlich und erscheint weder im Filter noch im Diagramm.
  - Robuste Erkennung von Aufrufen in **BAT/CMD** (inkl. `call`/`start`/`cmd /c`, nackten Skriptnamen wie `contec.vbs`, `wscript`/`cscript` mit Skriptargument sowie KiXtart-Aufrufen wie `kix32.exe logon.txt`), in **VBScript** (direkte String-Literale und dynamische Varianten wie `LogonDatei = "Contec.vbs" … WshShell.Run(LogonDatei)`) und in **KiXtart** (`.kix` sowie ausgewählte `.txt`-Skripte wie `logon.txt`). Die Teststruktur unter `TestSYSVOL/scripts/2117` wird vollständig abgebildet und dient als Referenz für die Erkennungslogik.
  - Für große Umgebungen wird der Graph **pro Top-Ordner** (erstes Verzeichnis-Segment unterhalb von `ScriptsPath`) mit eigenen Checkpoint-Dateien aufgebaut; die Teilgraphen werden anschließend zu einer gemeinsamen HTML-Gesamtansicht aggregiert.
  - Parameter: `-ScriptsPath` (Pflicht), `-OutputPath` (Default: `.\ScriptFlowchart.html`), `-EnableGlobalView` (optional, siehe unten), `-ExcludeFolders` (optionale Liste relativer Ordnerpfade, die inklusive ihrer Unterordner von der Analyse ausgeschlossen werden, z. B. `2217`, `2217/Legacy`, `2236/Test`), `-Encoding` (Fallback für Skriptdateien).

- `Export-ScriptFlowchart-All.ps1`  
  Erweiterter Flowchart-Export für **alle Dateitypen** (nicht nur Skripte):
  - Erstellt Knoten für alle Dateien unter `ScriptsPath` (inkl. z. B. `.exe`, `.dll`, `.lnk`, `.ini`, `.xml`, `.json`, `.txt`).
  - Erkennt Dateiverknüpfungen über Dateinamen in textbasierten Dateien und zeichnet Kanten (inkl. cross-boundary/extern).
  - Kommentarbewusste Erkennung: Verknüpfungen in Kommentaren (`rem`, `::`, `#`, `<# #>`, `'`, `;` je Dateityp) werden separat als Kommentar-Link markiert und können im Viewer ein-/ausgeblendet werden.
  - Exportiert pro Top-Ordner eine eigene Graph-JSON (`ScriptFlowchart-All-<Top>.json`) sowie eine separate Content-JSON (`ScriptFlowchart-All-<Top>-content.json`) und erzeugt eine HTML-Template-Datei (`ScriptFlowchart-All.html`), die beides dynamisch lädt (lazy loading für Dateiinhalt).
  - Viewer mit Guardrails gegen übergroße Mermaid-Diagramme: Bei Erreichen von Limits erfolgt automatische Degradation (Kommentar-Links ausblenden, externe/cross-boundary ausblenden, ggf. Chunking).
  - UI-Funktionen: Top-Ordner-Auswahl, Zoom (100–1000 %), Ausblenden externer/roter Verknüpfungen, Ausblenden von Verknüpfungen aus Kommentaren, Chunking (`Gesamtgraph` / `Pro Unterordner` / `Pro Komponente`) mit Teilgraph-Auswahl, dynamischer Codebereich unter dem Flowchart mit markierten Verknüpfungspunkten (gelb intern, rot extern).
  - Funktioniert im HTTP-Modus optimal mit externen JSON-Dateien; für `file://` kann optional `-EmbedTopFolderData` genutzt werden.
  - Parameter: `-ScriptsPath` (Pflicht), `-OutputPath` (Default: `.\ScriptFlowchart-All.html`), `-ExcludeFolders`, `-IncludeFolders`, `-MaxDepth`, `-StartPath`, `-Hops`, `-EmbedTopFolderData`, `-Encoding`.

- `Analyze-LoginScriptCategories.ps1`  
  Eigenständiges Skript zur **statistischen Kategorie-Analyse** von Anmeldeskripten:
  - Analysiert rekursiv alle Skriptdateien (`.ps1`, `.psm1`, `.bat`, `.cmd`, `.vbs`, `.kix`) unter `ScriptsPath` und ordnet sie anhand von Inhaltsmustern Kategorien zu (Laufwerks-Mappings, Drucker, Inventarisierung/Asset, Sicherheit/Compliance, Software-Verteilung, Umgebungsvariablen/Pfade bzw. Unbekannt).
  - Erzeugt eine HTML-Datei mit **Zusammenfassung** (Anzahl Dateien, durchschnittliche Größe), **Kategorie-Dashboard** (prozentuale Verteilung) und **Dateitabelle** mit primärer Kategorie und Konfidenz-Level (Niedrig/Mittel/Hoch).
  - Parameter: `-ScriptsPath` (Pflicht), `-OutputPath` (Default: `.\LoginScriptCategoriesReport.html`), `-Encoding` (Fallback beim Einlesen).

- `Analyze-SysvolHostReachability.ps1`  
  Eigenständiges Skript zur **Host-Erreichbarkeitsanalyse**:
  - Scannt alle Skript- und Textdateien (`.ps1`, `.psm1`, `.bat`, `.cmd`, `.vbs`, `.kix`, `.txt`) unter `ScriptsPath` und extrahiert Servernamen und IP-Adressen per Regex (UNC-Pfade, URLs, IPv4).
  - Führt pro Host eine Erreichbarkeitsprüfung durch: DNS-Auflösung, Ping (ICMP), TCP-Ports (80, 443, 445, 135, 3389, 5985) parallel, optional WinRM (`Test-WSMan`).
  - **Subnet-Scan (optional):** Pro ermitteltem Host wird das zugehörige Subnetz (Standard: /24) nach pingbaren Endpunkten durchsucht; die Ergebnisse erscheinen im HTML in einer eigenen Tabelle (Quell-Host, Subnetz, Anzahl erreichbar, Liste der IPs). Standardmäßig ist der Subnet-Scan **aus** und wird nur mit `-SubnetScan` aktiviert.
  - Erzeugt ein HTML-Template plus Daten-JSONs: `HostReachability-ALL.json` und je Top-Ordner `HostReachability-<Top>.json`; das HTML lädt die gewählte Top-Ordner-JSON dynamisch nach.
  - Resume/Checkpoint: robuster Resume-Modus über Checkpoint + Artefaktdateien (explizit via `-Resume`, automatisch ohne `-NoAutoResume`), optional persistente Zustände mit `-KeepResumeData`.
  - Parameter: `-ScriptsPath` (Pflicht), `-OutputPath` (Default: `.\HostReachabilityReport.html`), `-Encoding` (Fallback), `-ThrottleLimit` (Parallelität, Default: 8), `-SubnetScan` (Subnetz-Scan aktivieren, Default: aus), `-SubnetPrefixLength` (CIDR, Default: 24), `-Resume`, `-NoAutoResume`, `-CheckpointPath`, `-KeepResumeData`.

- `Analyze-OuScriptGpoCoverage.ps1`  
  Eigenständiges Skript zur **OU-basierten Script/GPO-Abdeckungsanalyse**:
  - Durchsucht eine Start-OU inkl. aller untergeordneten OUs nach User- und Computerobjekten.
  - Ermittelt pro Objekt statisch effektive GPOs (OU-Vererbung + Security-Filter via GPO-Berechtigungen/Token-Gruppen).
  - Analysiert Logon/Logoff/Startup/Shutdown-Skriptreferenzen aus GPOs (`scripts.ini`/`psscripts.ini` + GPO-Report XML) sowie AD-`scriptPath` bei Usern.
  - Unterstützt Skripttypen `.ps1`, `.psm1`, `.bat`, `.cmd`, `.vbs`, `.kix` inkl. Funktionsklassifikation (z. B. Laufwerke, Drucker, Software, Security, Umgebung, Inventar).
  - Erstellt einen interaktiven HTML-Report mit objektindividueller Coverage (`abgedeckt`, `teilweise`, `nicht-abgedeckt`) und konkreten Vorschlägen, welche GPOs ergänzt werden können; optional mit vollständigen Skriptinhalten.
  - Parameter: `-StartOuDn` (Pflicht), `-DomainFqdn` (optional), `-OutputPath`, `-IncludeContent`, `-Resume`, `-CheckpointPath`, `-Encoding`, `-MaxScriptBytes`.

- `Export-CopilotAnalysisReport.ps1`  
  Erzeugt einen **Markdown-Report** zur Auswertung mit **Microsoft 365 Copilot** (Word, Teams):
  - Pro Skript: **Dateiname** (kein Dateipfad), Typ, Kategorie, Nutzung/Kritikalität, Abhängigkeiten, SHA256 und GPO-Migrationsempfehlung.
  - Für lesbare Dateien wird der **echte Dateiinhalt** in den Report aufgenommen; bei nicht lesbaren/binären Dateien werden Metadaten und Recherchehinweise für Copilot ausgegeben.
  - Ausgabe wird aufgeteilt in **Index-Datei + Teilreports pro Top-Ordner**.
  - Erzeugt zusätzlich eine zentrale Prompt-Datei **`Copilot-AnalysisPrompt.md`** (nur wenn nicht vorhanden), auf die aus allen Reports verwiesen wird.
  - Unterstützt **Resume/Checkpoint** für unterbrochene Läufe.
  - Mit `-AnalysisResultsPath` (Pfad zu AnalysisResults): Nutzung, Sicherheitsrisiken und Dependency-Graph aus `analysis_results.json`; ohne: nur Inventar und Kategorien aus Dateiinhalt.
  - Parameter: `-ScriptsPath` (Pflicht), `-OutputPath` (Default: `.\CopilotScriptAnalysis.md`), `-AnalysisResultsPath` (optional), `-Resume` (optional), `-CheckpointPath` (optional).

- `Export-GpoMigrationScripts.ps1`  
  Erzeugt **PowerShell-Skripte** zur GPO-Migration (zum manuellen Prüfen und Ausführen):
  - Pro Top-Ordner eine `.ps1`-Datei mit `New-GPO`, `New-GPLink` und Kommentaren für GPO Preferences (Laufwerkszuordnung, Drucker, Umgebung). Keine automatische GPO-Erstellung.
  - Parameter: `-ScriptsPath` (Pflicht), `-OutputPath` (Default: `.\GpoMigrationScripts`), `-AnalysisResultsPath` (optional), `-GpoNamePrefix` (Default: `Migration_`).

Die Analyseergebnisse werden standardmäßig **unterhalb von** `.\AnalysisResults` abgelegt (anpassbar über `-OutputPath`).

Struktur des Output‑Ordners:

- `logs` – Transcript (`transcript-<RunId>.log`) + Textlog (`analysis-<RunId>.log`)
- `json` – `analysis_results.json`
- `csv` – CSV‑Dateien (`security_findings.csv`, `dependencies.csv`, `usage_analysis.csv`, `duplicates.csv`, `code_quality.csv`)
- `html` – HTML‑Report (`sysvol_analysis_report.html`)
- `excel` – Optionaler Excel‑Report (`sysvol_analysis.xlsx`, wenn ImportExcel vorhanden)

---

### Aufruf & Beispiele

#### Minimaler Standardlauf

```powershell
pwsh.exe -File .\Analyze-SysvolScripts.ps1 `
    -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts'
```

#### Lauf mit mehr Threads und benutzerdefiniertem Output‑Pfad

```powershell
pwsh.exe -File .\Analyze-SysvolScripts.ps1 `
    -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts' `
    -ParallelThreads 16 `
    -OutputPath 'D:\Reports\Sysvol'
```

#### Unterbrochene Analyse fortsetzen (Resume)

```powershell
pwsh.exe -File .\Analyze-SysvolScripts.ps1 `
    -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts' `
    -Resume
```

**Hinweise:**

- Die Checkpoint‑Datei heißt `sysvol_analysis_checkpoint.json` und liegt im aktuellen Working Directory (nicht im Output‑Pfad).
- Beim Resume werden:
  - Bereits inventarisierte Dateien,
  - bereits analysierte Dateien,
  - und abgeschlossene Phasen (Inventory, Usage, Content‑Analyse, Duplikate, Dependency‑Graph, Exporte)
  wiederverwendet.
- Wenn sich der `ScriptsPath` oder die Verzeichnisstruktur stark ändert, ist ein Neustart ohne `-Resume` sinnvoll.

#### Skript-Flowchart (HTML mit Aufrufbeziehungen)

```powershell
pwsh.exe -File .\Export-ScriptFlowchart.ps1 `
    -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts'
```

Optional: `-OutputPath 'D:\Reports\ScriptFlow.html'`, `-Encoding` (Fallback-Encoding für Skriptdateien), `-EnableGlobalView` (Gesamt-Ansicht über alle Top-Ordner aktivieren), `-ExcludeFolders @('2217','2236/Test')` (ein oder mehrere relative Ordnerpfade unterhalb von `ScriptsPath`, die inklusive ihrer Unterordner von der Analyse ausgeschlossen werden).

Das Skript erkennt Aufrufe zwischen **VBS**, **BAT/CMD**, **PowerShell** (PS1/PSM1) und **KiXtart** (KIX). Die HTML-Datei (Überschrift: **Skript-Flowchart**) enthält ein Mermaid-Flowchart (Pfeil = „ruft auf“) mit **einem Kästchen pro Ordner**, Ebenen von links nach rechts; Knoten sind **nach Dateityp gefärbt** (wie in der Legende: VBS blau, BAT/CMD amber, PS1/PSM1 grün, KiXtart lila). Filter nach Top-Ordner und Dateityp; pro Skript der Quellcode mit hervorgehobenen Verlinkungen (gelb = gleicher Top-Ordner, rot = über Grenzen). Per `-ExcludeFolders` können ein oder mehrere Ordner (inklusive ihrer Unterordner) von der Analyse ausgeschlossen werden; Aufrufe in diese Ordner werden im Diagramm in einem separaten Bereich **„Extern (…)"** zusammengefasst dargestellt.  
Knoten, die Teil eines rekursiven Aufrufzyklus sind, werden mit `[REC]` markiert.  
Mit `-EnableGlobalView` kann eine **Gesamt-Ansicht** (alle Top-Ordner) eingeblendet werden – bei sehr großen Umgebungen höherer Ressourcenbedarf.  
Checkpoint/Resume: pro Top-Ordner eine eigene Datei `script_flowchart_checkpoint_<Top>.json` im Arbeitsverzeichnis; nach vollständigem Lauf entfernt.

#### Flowchart für alle Dateitypen (Template + Top-Ordner-JSONs)

```powershell
pwsh.exe -File .\Export-ScriptFlowchart-All.ps1 `
    -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts'
```

Optional: `-OutputPath 'D:\Reports\ScriptFlowchart-All.html'`, `-ExcludeFolders @('2217','2236/Test')`, `-IncludeFolders @('2217','2236/Common')`, `-MaxDepth 3`, `-StartPath '2217\\logon.ps1' -Hops 2`, `-EmbedTopFolderData`, `-Encoding`.

Ausgabe:
- `ScriptFlowchart-All.html` als Viewer/Template
- `ScriptFlowchart-All-<Top>.json` pro Top-Ordner (z. B. `...-2117.json`)
- `ScriptFlowchart-All-<Top>-content.json` pro Top-Ordner (Dateiinhalt für den Codebereich)

Die HTML bietet Top-Ordner-Auswahl, Zoom, optionales Ausblenden externer/roter Verknüpfungen, optionales Ausblenden von Verknüpfungen aus Kommentaren, Chunking-Auswahl für große Graphen sowie einen dynamischen Bereich „Dateien und Inhalt“ unterhalb des Diagramms mit farblicher Markierung der Verknüpfungspunkte.  
Bei sehr großen Top-Ordnern greift ein automatischer Guardrail/Fallback, um Mermaid-Fehler wie „Maximum text size in diagram exceeded“ zu vermeiden.

#### Login-Skript Kategorien (statistische Analyse)

```powershell
pwsh.exe -File .\Analyze-LoginScriptCategories.ps1 `
    -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts'
```

Optional: `-OutputPath 'D:\Reports\LoginScriptCategoriesReport.html'`, `-Encoding` (Fallback-Encoding).

Das Skript kategorisiert alle gefundenen Skripte (PS1, BAT, CMD, VBS, KiXtart) nach Inhalt (z. B. `net use`/New-PSDrive → Laufwerks-Mappings, Add-Printer/printui.dll → Drucker, Get-CimInstance/systeminfo → Inventarisierung). Der HTML-Report enthält eine Zusammenfassung, ein Balken-Dashboard der Kategorien und eine Tabelle mit Datei, primärer Kategorie und Konfidenz.

#### Host-Erreichbarkeit

```powershell
pwsh.exe -File .\Analyze-SysvolHostReachability.ps1 `
    -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts'
```

Optional: `-OutputPath 'D:\Reports\HostReachabilityReport.html'`, `-Encoding`, `-ThrottleLimit` (z. B. 4), `-SubnetScan` (Subnetz-Scan, Standard: aus), `-SubnetPrefixLength` (z. B. 24 für /24), `-Resume`, `-NoAutoResume`, `-CheckpointPath`, `-KeepResumeData`.

Das Skript durchsucht alle Skript- und Textdateien nach Servernamen und IPs (UNC, `http(s)://`, IPv4), entfernt Duplikate und lokale Platzhalter (localhost, 127.0.0.1), und prüft jeden Host: DNS, Ping, TCP-Ports 80/443/445/135/3389/5985 (parallel), WinRM. Wenn **Subnet-Scan** aktiv ist, wird pro Host das zugehörige Subnetz (z. B. /24) ermittelt und nach erreichbaren (pingbaren) IP-Adressen durchsucht.  
Ausgabe ist ein HTML-Template plus JSON-Datasets:
- `HostReachability-ALL.json` (Gesamt)
- `HostReachability-<Top>.json` (pro Top-Ordner)  
Die HTML lädt die Daten je Top-Ordner dynamisch nach.

Resume/Checkpoint:
- Checkpoint-Datei (konfigurierbar über `-CheckpointPath`)
- zusätzliche Artefaktdateien für robustes Fortsetzen (`*.host-results.json`, `*.subnet-data.json`)
- Auto-Resume standardmäßig aktiv (abschaltbar via `-NoAutoResume`), explizites Resume via `-Resume`
- bei erfolgreichem Lauf werden Resume-Dateien standardmäßig gelöscht (behaltbar via `-KeepResumeData`)

#### OU-basierte Script/GPO-Abdeckung

```powershell
pwsh.exe -File .\Analyze-OuScriptGpoCoverage.ps1 `
    -StartOuDn 'OU=StandortA,OU=Benutzer,DC=contoso,DC=local' `
    -OutputPath 'D:\Reports\OuScriptGpoCoverage.html' `
    -IncludeContent
```

Optional: `-DomainFqdn 'contoso.local'`, `-Resume`, `-CheckpointPath '.\ou_script_gpo_coverage_checkpoint.json'`, `-MaxScriptBytes 1048576`.

Das Skript berechnet pro User/Computer in der OU-Hierarchie die statisch effektiven GPOs, korreliert sie mit den tatsächlich referenzierten Skripten (Logon/Logoff/Startup/Shutdown sowie AD-`scriptPath`) und zeigt je Objekt Überschneidungen/Lücken nach Funktionskategorien an.  
Ausgabe:
- `<OutputPath>.html` (interaktiv, inkl. Mermaid-Datenfluss)
- `<OutputPath>.json` (vollständiger Datensatz für Nachanalyse)
- Checkpoint-Datei für Resume (falls aktiviert)

#### Report für Microsoft 365 Copilot

```powershell
pwsh.exe -File .\Export-CopilotAnalysisReport.ps1 `
    -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts'
```

Optional: `-OutputPath '.\CopilotScriptAnalysis.md'`, `-AnalysisResultsPath '.\AnalysisResults'` (wenn die Hauptanalyse bereits gelaufen ist), `-Resume`, `-CheckpointPath`.

Erzeugt:
- eine **Index-Markdown-Datei** (am `-OutputPath`) mit Zusammenfassung und Links,
- **Teilreports pro Top-Ordner** (`<OutputBase>-<TopFolder>.md`),
- eine zentrale Prompt-Datei `Copilot-AnalysisPrompt.md` (einmalig, create-if-missing).

In den Teilreports steht pro Skript der tatsächliche Inhalt (wenn lesbar). Nicht lesbare/binäre Dateien werden über Dateiname/Hash/Metadaten mit Copilot-Recherchehinweis abgedeckt.

Keine KI-APIs im Tool – die Analyse durch Copilot erfolgt manuell durch den Nutzer. Mit `-AnalysisResultsPath` werden Nutzung, Sicherheitsrisiken und Dependency-Graph aus `json/analysis_results.json` übernommen; ohne diesen Parameter nur Inventar und Kategorien.

Resume/Checkpoint:
- Standard-Checkpoint: `<OutputBase>.checkpoint.json` im aktuellen Working Directory
- alternativ über `-CheckpointPath` explizit setzbar
- bei erfolgreichem Lauf wird der Checkpoint automatisch entfernt

#### GPO-Migrations-Skripte

```powershell
pwsh.exe -File .\Export-GpoMigrationScripts.ps1 `
    -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts'
```

Optional: `-OutputPath '.\GpoMigrationScripts'`, `-AnalysisResultsPath '.\AnalysisResults'`, `-GpoNamePrefix 'Migration_'`.

Erzeugt **pro Top-Ordner** eine PowerShell-Datei (`Create-GPO-<Top>.ps1`), die `New-GPO` und `New-GPLink` verwendet sowie Kommentare für GPO Preferences (Laufwerkszuordnung, Drucker, Umgebung) enthält. **Keine automatische GPO-Erstellung** – der Admin prüft die Skripte, ersetzt Platzhalter (z. B. Ziel-OU, Servernamen) und führt sie nach Prüfung aus (z. B. mit `-WhatIf`). Voraussetzung: GroupPolicy-Modul (RSAT), Rechte zum Erstellen/Verknüpfen von GPOs.

---

### Parameter im Detail

- **`-ScriptsPath`** (Required)  
  UNC‑Pfad zum SYSVOL‑Scripts‑Verzeichnis, z.B.  
  `\\contoso.local\SYSVOL\contoso.local\scripts`

- **`-Resume`** (Switch)  
  - Nutzt vorhandenen Checkpoint (`sysvol_analysis_checkpoint.json`) und setzt die Analyse fort.  
  - Wenn kein gültiger Checkpoint existiert, wird ein Vollscan mit neuem Checkpoint gestartet.

- **`-DryRun`** (Switch)  
  - Das Tool arbeitet ohnehin read‑only; `-DryRun` ist für zukünftige Erweiterungen vorgesehen, um konkrete Remediation‑Kommandos ggf. nur mit `-WhatIf` auszuführen.
  - Aktuell beeinflusst der Switch das Verhalten nicht wesentlich, die Empfehlungen werden als Kommentare/Beispiel‑Kommandos ausgegeben.

- **`-ParallelThreads`** (int, Default: 8, 1–64)  
  - ThrottleLimit für `ForEach-Object -Parallel`.  
  - 8–16 Threads sind auf aktuellen Systemen mit SSD und genügend RAM in der Regel ein guter Startwert.

- **`-OutputPath`** (string, Default: `.\AnalysisResults`)  
  - Root‑Ordner für Logs, JSON, CSV, HTML und (optional) Excel.

- **`-Credential`** (`[PSCredential]`, optional)  
  - Optionaler Satz von Anmeldedaten, der für **AD‑Abfragen** (ActiveDirectory‑Modul) und den **ADSI‑Fallback** verwendet wird.  
  - Ermöglicht es, die Nutzungsanalyse mit einem anderen AD‑Konto durchzuführen, ohne eine neue PowerShell‑Session „Als anderer Benutzer ausführen“ zu starten.

- **`-PromptForCredential`** (Switch)  
  - Wenn angegeben und `-Credential` nicht gesetzt ist, fragt das Skript zu Beginn einmalig per `Get-Credential` nach Anmeldedaten.  
  - Praktisch, wenn du die Credentials nicht als Variable/Parameter übergeben möchtest.

---

### Was wird analysiert?

#### Inventarisierung

- Rekursive Auflistung aller Dateien unterhalb von `ScriptsPath` mit:
  - Pfad, Dateiname, Erweiterung, Größe
  - `CreationTimeUtc`, `LastWriteTimeUtc`, `LastAccessTimeUtc`
  - Klassifizierung: Skript (`.ps1`, `.psm1`, `.psd1`, `.vbs`, `.bat`, `.cmd`, `.kix`) vs. Executable (`.exe`, `.com`, `.dll`, `.msi`)

#### Sicherheitsanalyse

- Hashes & Signaturen für Executables
- Mustererkennung in Skripten (s.o.)
- Pro Finding:
  - Dateipfad, Typ, Risiko, Details, SHA256
  - Deutsche Empfehlung + Beispiel‑PowerShell‑Kommando (z.B. Verschieben in Quarantäne mit `-WhatIf`)

#### Dependency‑Tracking

- Analyse typischer Aufrufmuster:
  - PowerShell: `& .\script.ps1`, `. .\script.ps1`, `powershell.exe ... script.ps1`
  - VBS: `WScript.Shell.Run`, `Execute`, `ExecuteGlobal`
  - Batch/CMD: `call`, `start`, `cmd /c`
  - KiXtart: `CALL`, `RUN`, `SHELL`
- Pfad‑Auflösung:
  - Absolute Pfade (UNC/Laufwerk)
  - Relative Pfade relativ zum Skript‑Ordner (soweit eindeutig auflösbar)
- Aufbau eines In‑Memory‑Graphs:
  - Knoten = Skripte
  - Kanten = „ruft Skript X auf“
  - Markierung von Zyklen
  - Entry‑Points und Leaf‑Knoten werden berechnet

#### Nutzungsanalyse

- **GPO‑Referenzen** (wenn `GroupPolicy` vorhanden):
  - `Get-GPO -All` + `Get-GPOReport -ReportType Xml`
  - Extraktion der konfigurierten Skripte für Logon/Logoff/Startup/Shutdown
- **AD‑Attribute**:
  - Mit `ActiveDirectory`‑Modul: `Get-ADUser` / `Get-ADComputer` mit `scriptPath`
  - Ohne Modul: ADSI‑Fallback via `DirectorySearcher`
- **Zeitbasierte Heuristik**:
  - `UsageCategory` je Datei:
    - *Aktiv verwendet* – über GPO/AD referenziert
    - *Wahrscheinlich aktiv* – Änderung/Zugriff in den letzten 6 Monaten
    - *Vermutlich ungenutzt* – >2 Jahre keine Änderung/Zugriff
    - *Verwaist* – keine Referenzen, keine jüngeren Aktivitäten

#### Duplikate

- Hash‑basierte Duplikate (identische SHA256)
- Inhaltsbasierte Duplikate über normalisierte Inhalte (Whitespace/Kommentare entfernt)
- Namensduplikate als einfacher Fallback
- Pro Duplikatgruppe:
  - Gruppe‑ID, Vertreterpfad, alle Pfade, empfohlene zu behaltende Datei

#### Codequalität & Komplexität

- LOC‑Zählung ohne Kommentare
- Kommentar‑Quote in %
- Komplexität über einfache Heuristik (Kontrollstrukturen)
- Flags:
  - `HasErrorHandling`
  - `HasHardcodedCreds`
  - `HasDeprecatedCmds`

---

### Output‑Formate

- **Konsole**
  - Farbige Zusammenfassung:
    - Anzahl Dateien
    - Critical/High/Medium/Low Findings
    - Anzahl verwaister Skripte
  - Interaktives Menü:
    ```text
    [1] Sicherheitsrisiken anzeigen
    [2] Dependency-Graph exportieren (JSON bereits erstellt)
    [3] Unbenutzte/verwaiste Skripte auflisten
    [4] Duplikate anzeigen
    [5] Vollständigen Report-Ordner öffnen
    [Q] Beenden
    ```

- **HTML**
  - `html\sysvol_analysis_report.html`
  - Executive Summary (KPI‑Kacheln, Top‑Risiken, Sofortmaßnahmen‑Teaser)
  - Aufklappbare Sektionen für alle Analysebereiche
  - Kurzinfo zum Dependency‑Graphen (Knoten/Kanten, Entry‑Points/Leafs)

- **CSV**
  - `csv\security_findings.csv`
  - `csv\dependencies.csv`
  - `csv\usage_analysis.csv`
  - `csv\duplicates.csv`
  - `csv\code_quality.csv`

- **JSON**
  - `json\analysis_results.json`  
    Vollständiger Datensatz, geeignet für:
    - eigene Auswertungen (PowerShell, Python, BI‑Tools)
    - Visualisierungen (z.B. D3.js, Mermaid) auf Basis des Dependency‑Graphs

- **Excel** (optional)
  - `excel\sysvol_analysis.xlsx`
  - Ein Worksheet pro Analysebereich (Security, Dependencies, Usage, Duplicates, CodeQuality)
  - Basis für Conditional Formatting und PivotTables (kann in Excel oder Power BI weiterverarbeitet werden)

---

### Checkpoints & Resume im Detail

- Checkpoint‑Datei: `sysvol_analysis_checkpoint.json` im aktuellen Arbeitsverzeichnis
- Enthält u.a.:
  - Inventar (Dateiliste)
  - bereits verarbeitete Dateien
  - Zwischenergebnisse aller Analysen
  - Status pro Phase (`InventoryCompleted`, `UsageAnalysisCompleted`, `ContentAnalysisCompleted`, `DuplicateAnalysisCompleted`, `DependencyGraphCompleted`, `ReportsExported`)
- Schreibvorgänge:
  - nach Abschluss jeder Phase
  - nach jedem Batch in der Inhaltsanalyse
- Empfohlene Praxis:
  - Längere Läufe (19k+ Dateien) vorzugsweise im Screen/Tmux oder als geplanten Task ausführen
  - Bei Abbruch oder Wartungsfenstern: Lauf mit `-Resume` fortsetzen, statt von vorn zu starten

---

### Performance‑Hinweise

- **Threads**:
  - Starte mit `-ParallelThreads 8` oder `16` und skaliere nach oben, wenn CPU/IO es erlauben.
- **Storage**:
  - Eine schnelle Anbindung von SYSVOL (DFS/Netzwerk, Domain Controller) beschleunigt Hash‑ und Inhaltsanalysen deutlich.
- **Filterung**:
  - Aktuell wird der gesamte `ScriptsPath` analysiert. Für Tests empfiehlt sich ein kleiner Ordner mit Beispielskripten.

Beispiel‑Testsetup (lokal):

```powershell
New-Item -ItemType Directory -Path 'C:\TestSysvol\scripts' -Force | Out-Null
# Beispielskripte / Testdateien hinein kopieren

pwsh.exe -File .\Analyze-SysvolScripts.ps1 `
    -ScriptsPath 'C:\TestSysvol\scripts' `
    -ParallelThreads 4
```

---

### Sicherheit & Best Practices

- Das Tool selbst **ändert keine Dateien** in SYSVOL, AD oder GPOs.
- Empfehlungen werden immer als **Beispielkommandos** (mit Kommentaren bzw. `-WhatIf`) ausgegeben.
- Vor dem Löschen/Konsolidieren von Skripten unbedingt:
  - Dependency‑Graph prüfen (wird Skript noch indirekt aufgerufen?)
  - Nutzungsanalyse und Zeitstempel gegen Fachbereiche abstimmen
  - Sicherungs‑/Archivkonzept definieren (z.B. Quarantäne‑Share)

---

### Weiterentwicklung

Mögliche Erweiterungen:

- Detailliertere Risiko‑Scores (gewichtete Punkte‑Systeme)
- Zusätzliche Legacy‑Pattern (z.B. alte COM‑Objektnutzung in VBS)
- Export von Mermaid‑ oder D3‑fertigen Graphen direkt im HTML
- Integration mit Ticket‑Systemen (z.B. Erzeugen von Tickets für kritische Findings)

