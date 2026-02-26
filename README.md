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

- `Export-VbsFlowchart.ps1`  
  Eigenständiges Skript für einen **VBS-Flowchart** als HTML:
  - Findet alle VBS-Dateien unter `ScriptsPath` und löst Aufrufbeziehungen auf (welche VBS ruft welche Dateien auf; welche BAT/CMD/PS1/**KiXtart**-Dateien rufen welche VBS auf).
  - Erzeugt eine einzelne HTML-Datei mit **Mermaid**-Flowchart und **Tailwind**-Layout; pro VBS wird der vollständige Quellcode in `<pre><code>` ausgegeben.
  - Parameter: `-ScriptsPath` (Pflicht), `-OutputPath` (Default: `.\VbsFlowchart.html`), `-Encoding` (Fallback für Skriptdateien).

- `Analyze-LoginScriptCategories.ps1`  
  Eigenständiges Skript zur **statistischen Kategorie-Analyse** von Anmeldeskripten:
  - Analysiert rekursiv alle Skriptdateien (`.ps1`, `.psm1`, `.bat`, `.cmd`, `.vbs`, `.kix`) unter `ScriptsPath` und ordnet sie anhand von Inhaltsmustern Kategorien zu (Laufwerks-Mappings, Drucker, Inventarisierung/Asset, Sicherheit/Compliance, Software-Verteilung, Umgebungsvariablen/Pfade bzw. Unbekannt).
  - Erzeugt eine HTML-Datei mit **Zusammenfassung** (Anzahl Dateien, durchschnittliche Größe), **Kategorie-Dashboard** (prozentuale Verteilung) und **Dateitabelle** mit primärer Kategorie und Konfidenz-Level (Niedrig/Mittel/Hoch).
  - Parameter: `-ScriptsPath` (Pflicht), `-OutputPath` (Default: `.\LoginScriptCategoriesReport.html`), `-Encoding` (Fallback beim Einlesen).

- `Analyze-SysvolHostReachability.ps1`  
  Eigenständiges Skript zur **Host-Erreichbarkeitsanalyse**:
  - Scannt alle Skript- und Textdateien (`.ps1`, `.psm1`, `.bat`, `.cmd`, `.vbs`, `.kix`, `.txt`) unter `ScriptsPath` und extrahiert Servernamen und IP-Adressen per Regex (UNC-Pfade, URLs, IPv4).
  - Führt pro Host eine Erreichbarkeitsprüfung durch: DNS-Auflösung, Ping (ICMP), TCP-Ports (80, 443, 445, 135, 3389, 5985) parallel, optional WinRM (`Test-WSMan`).
  - **Subnet-Scan (optional):** Pro ermitteltem Host wird das zugehörige Subnetz (Standard: /24) nach pingbaren Endpunkten durchsucht; die Ergebnisse erscheinen im HTML in einer eigenen Tabelle (Quell-Host, Subnetz, Anzahl erreichbar, Liste der IPs).
  - Erzeugt eine HTML-Datei mit **Zusammenfassung**, **Erreichbarkeit pro Host** (farbige Indikatoren) und ggf. **Subnet-Scan** (pingbare IPs pro Subnetz).
  - Parameter: `-ScriptsPath` (Pflicht), `-OutputPath` (Default: `.\HostReachabilityReport.html`), `-Encoding` (Fallback), `-ThrottleLimit` (Parallelität, Default: 8), `-SubnetScan` (Subnetz-Scan aktivieren, Default: an), `-SubnetPrefixLength` (CIDR, Default: 24).

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

#### VBS-Flowchart (HTML mit Aufrufbeziehungen)

```powershell
pwsh.exe -File .\Export-VbsFlowchart.ps1 `
    -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts'
```

Optional: `-OutputPath 'D:\Reports\VbsFlow.html'`, `-Encoding` (Fallback-Encoding für Skriptdateien).

Das Skript erkennt Aufrufe aus **VBS** (z. B. `WScript.Shell.Run`, `Execute`), **BAT/CMD** (`call`, `start`, `cmd /c`), **PowerShell** (`& .\*.vbs`, `Start-Process` usw.) und **KiXtart** (`CALL`, `RUN`, `SHELL`). Die HTML-Datei enthält ein Mermaid-Flowchart (Pfeil = „ruft auf“) und pro VBS-Datei den vollständigen Quellcode in `<pre><code>`.

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

Optional: `-OutputPath 'D:\Reports\HostReachabilityReport.html'`, `-Encoding`, `-ThrottleLimit` (z. B. 4), `-SubnetScan` (Subnetz-Scan, Standard: an), `-SubnetPrefixLength` (z. B. 24 für /24).

Das Skript durchsucht alle Skript- und Textdateien nach Servernamen und IPs (UNC, `http(s)://`, IPv4), entfernt Duplikate und lokale Platzhalter (localhost, 127.0.0.1), und prüft jeden Host: DNS, Ping, TCP-Ports 80/443/445/135/3389/5985 (parallel), WinRM. Wenn **Subnet-Scan** aktiv ist, wird pro Host das zugehörige Subnetz (z. B. /24) ermittelt und nach erreichbaren (pingbaren) IP-Adressen durchsucht. Der HTML-Report enthält eine Zusammenfassung, eine Tabelle mit grünen/roten Badges pro Host (DNS, Ping, Ports, WinRM) und bei aktiviertem Subnet-Scan eine weitere Tabelle „Subnet-Scan (pingbare Endpunkte)“ mit Quell-Host, Subnetz, Anzahl erreichbarer IPs und Liste der IPs.

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

