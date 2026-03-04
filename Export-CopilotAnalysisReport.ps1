<#
.SYNOPSIS
    Erzeugt einen strukturierten Markdown-Report aller Skripte zur Auswertung mit Microsoft 365 Copilot.

.DESCRIPTION
    Erstellt eine Markdown-Datei (.md) mit pro Skript: Pfad, Typ, Kategorie, Nutzung/Kritikalität,
    Abhängigkeiten und empfohlene GPO-Migration. Die Datei kann in Word oder Teams geöffnet und
    mit M365 Copilot analysiert werden (z.B. "Analysiere diese Skripte auf Kritikalität" oder
    "Welche GPO-Einstellungen ersetzen diese Logon-Skripte?").
    Keine Nutzung von KI-APIs – die Analyse durch Copilot erfolgt manuell durch den Nutzer.

.PARAMETER ScriptsPath
    Stammverzeichnis der Skripte (z.B. \\domain\SYSVOL\domain\scripts). Pflicht.

.PARAMETER OutputPath
    Pfad der zu erzeugenden Markdown-Datei (Default: .\CopilotScriptAnalysis.md).

.PARAMETER AnalysisResultsPath
    Optional: Pfad zum Ordner der Hauptanalyse (AnalysisResults). Wenn gesetzt, werden
    json/analysis_results.json (Inventar, Nutzung, Sicherheit, Dependency-Graph) eingelesen
    und im Report genutzt. Ohne diesen Parameter: nur Datei-Inventar und Kategorien (keine
    Nutzung/Sicherheit/Abhängigkeiten).

.EXAMPLE
    .\Export-CopilotAnalysisReport.ps1 -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts'

.EXAMPLE
    .\Export-CopilotAnalysisReport.ps1 -ScriptsPath '\\contoso.local\SYSVOL\scripts' -AnalysisResultsPath '.\AnalysisResults' -OutputPath '.\CopilotReport.md'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScriptsPath,

    [string]$OutputPath = ".\CopilotScriptAnalysis.md",

    [string]$AnalysisResultsPath = '',

    [switch]$Resume,

    [string]$CheckpointPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScriptExtensions = @('.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.kix')
$script:CheckpointVersion = 1
$script:RootTrimmed = ''

function Get-CategoryPatterns {
    $opts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    return [ordered]@{
        'Laufwerks-Mappings'           = @(
            [regex]::new('net\s+use', $opts),
            [regex]::new('New-PSDrive', $opts),
            [regex]::new('MapNetworkDrive', $opts),
            [regex]::new('WScript\.Network', $opts)
        )
        'Drucker-Einrichtung'          = @(
            [regex]::new('Add-Printer', $opts),
            [regex]::new('printui\.dll', $opts),
            [regex]::new('SetDefaultPrinter', $opts)
        )
        'Inventarisierung/Asset'       = @(
            [regex]::new('Get-CimInstance', $opts),
            [regex]::new('Get-WmiObject', $opts),
            [regex]::new('Win32_', $opts)
        )
        'Sicherheit/Compliance'        = @(
            [regex]::new('ExecutionPolicy', $opts),
            [regex]::new('LegalNotice', $opts)
        )
        'Software-Verteilung/Updates'  = @(
            [regex]::new('\.msi\b', $opts),
            [regex]::new('msiexec', $opts),
            [regex]::new('Start-Process', $opts),
            [regex]::new('Shell\.Run', $opts)
        )
        'Umgebungsvariablen/Pfade'     = @(
            [regex]::new('setx', $opts),
            [regex]::new('\[Environment\]::SetEnvironmentVariable', $opts)
        )
    }
}

function Get-FileCategoryResult {
    param([string]$Content, [hashtable]$CategoryPatterns)
    $scores = [ordered]@{}
    foreach ($cat in $CategoryPatterns.Keys) {
        $count = 0
        foreach ($re in $CategoryPatterns[$cat]) {
            $count += $re.Matches($Content).Count
        }
        if ($count -gt 0) { $scores[$cat] = $count }
    }
    $primary = 'Unbekannt'
    if ($scores.Count -gt 0) {
        $primary = ($scores.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 1).Key
    }
    return $primary
}

function Get-GpoRecommendation {
    param([string]$Category)
    switch ($Category) {
        'Laufwerks-Mappings'           { return 'GPO Preferences: Laufwerkszuordnung (Drive Map)' }
        'Drucker-Einrichtung'          { return 'GPO Preferences: Drucker' }
        'Umgebungsvariablen/Pfade'     { return 'GPO Preferences: Umgebung oder Registry' }
        'Sicherheit/Compliance'        { return 'GPO: Lokale Richtlinie / Registry (z.B. Legal Notice)' }
        'Software-Verteilung/Updates'  { return 'GPO Software Installation oder Intune; manuell prüfen' }
        'Inventarisierung/Asset'       { return 'Kein 1:1-GPO-Ersatz; Intune/ConfigMgr oder manuell prüfen' }
        default                        { return 'Manuell prüfen' }
    }
}

function Get-RelativePath {
    param([string]$FullPath)
    if ([string]::IsNullOrWhiteSpace($FullPath)) { return '' }
    if ([string]::IsNullOrWhiteSpace($script:RootTrimmed)) { return $FullPath.TrimStart('\', '/') }
    if ($FullPath.StartsWith($script:RootTrimmed, [StringComparison]::OrdinalIgnoreCase)) {
        return $FullPath.Substring($script:RootTrimmed.Length).TrimStart('\', '/')
    }
    return $FullPath
}

function Get-SafeFileHash {
    param([string]$Path)
    try {
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    }
    catch {
        return ''
    }
}

function Convert-ToDisplayName {
    param([string]$FullPath)
    if ([string]::IsNullOrWhiteSpace($FullPath)) { return '' }
    return [System.IO.Path]::GetFileName($FullPath)
}

function Test-IsLikelyText {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return $true }
    $probeLen = [Math]::Min($Bytes.Length, 4096)
    $nullByteCount = 0
    for ($i = 0; $i -lt $probeLen; $i++) {
        if ($Bytes[$i] -eq 0) { $nullByteCount++ }
    }
    if ($nullByteCount -gt 0) { return $false }
    return $true
}

function Get-ReadableFileContent {
    param([string]$Path)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        if (-not (Test-IsLikelyText -Bytes $bytes)) {
            return [pscustomobject]@{
                IsReadable = $false
                Content    = ''
                Reason     = 'Datei wirkt binär (Null-Bytes erkannt)'
            }
        }

        $encodings = @(
            [System.Text.Encoding]::UTF8,
            [System.Text.Encoding]::Unicode,
            [System.Text.Encoding]::BigEndianUnicode,
            [System.Text.Encoding]::ASCII
        )
        foreach ($enc in $encodings) {
            try {
                $text = $enc.GetString($bytes)
                if ($null -ne $text) {
                    return [pscustomobject]@{
                        IsReadable = $true
                        Content    = $text
                        Reason     = ''
                    }
                }
            } catch {}
        }

        return [pscustomobject]@{
            IsReadable = $false
            Content    = ''
            Reason     = 'Textkodierung konnte nicht sicher gelesen werden'
        }
    }
    catch {
        return [pscustomobject]@{
            IsReadable = $false
            Content    = ''
            Reason     = $_.Exception.Message
        }
    }
}

function Read-Checkpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CheckpointFile
    )
    if (-not (Test-Path -LiteralPath $CheckpointFile)) { return $null }
    try {
        $json = Get-Content -LiteralPath $CheckpointFile -Raw -ErrorAction Stop
        $data = $json | ConvertFrom-Json -ErrorAction Stop
        if (-not $data.Version -or -not $data.ScriptsPath -or -not $data.OutputPath) { return $null }
        return $data
    }
    catch {
        Write-Warning "Fehler beim Lesen des Checkpoints: $($_.Exception.Message)"
        return $null
    }
}

function Write-Checkpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$State,
        [Parameter(Mandatory = $true)]
        [string]$CheckpointFile
    )
    try {
        $State | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $CheckpointFile -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        Write-Warning "Fehler beim Schreiben des Checkpoints: $($_.Exception.Message)"
    }
}

function New-CopilotReportState {
    param(
        [string]$ScriptsPathValue,
        [string]$OutputPathValue
    )
    return [ordered]@{
        Version        = $script:CheckpointVersion
        ScriptsPath    = $ScriptsPathValue
        OutputPath     = $OutputPathValue
        TimestampUtc   = (Get-Date).ToUniversalTime()
        Inventory      = @()
        Rows           = @()
        ProcessedPaths = @()
        WrittenTopFolders = @()
        PartFiles      = @{}
        Phases         = @{
            InventoryCompleted = $false
            AnalysisCompleted  = $false
            PartsWritten       = $false
            IndexWritten       = $false
        }
        Errors         = @()
    }
}

function Convert-ToHashtable {
    param([object]$InputObject)
    $result = @{}
    if ($null -eq $InputObject) { return $result }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($k in $InputObject.Keys) {
            $result[[string]$k] = [string]$InputObject[$k]
        }
        return $result
    }
    foreach ($p in $InputObject.PSObject.Properties) {
        if ($p.Name -in @('Keys', 'Values', 'Count', 'IsReadOnly', 'IsFixedSize', 'SyncRoot', 'IsSynchronized')) {
            continue
        }
        $result[$p.Name] = [string]$p.Value
    }
    return $result
}

function Get-TopFolderFromFullPath {
    param([string]$FullPath)
    $rel = Get-RelativePath -FullPath $FullPath
    if ([string]::IsNullOrWhiteSpace($rel)) { return '(Root)' }
    if ($rel -eq $FullPath) { return '(Extern)' }
    if ($rel -notmatch '[\\/]') { return '(Root)' }
    $seg = ($rel -split '[\\/]')[0]
    if ([string]::IsNullOrWhiteSpace($seg)) { return '(Root)' }
    return $seg
}

function Get-SafeKey {
    param([string]$Value)
    $safe = $Value -replace '[^A-Za-z0-9_-]', '_'
    if ([string]::IsNullOrWhiteSpace($safe)) { return 'ROOT' }
    return $safe
}

function New-CentralCopilotPromptMarkdown {
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("# Zentraler Copilot-Prompt für Legacy-Logon-Skripte")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Nutze diese Analyseanweisung **unverändert** für alle zugehörigen Copilot-Reports, damit Ergebnisse vergleichbar bleiben.")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("## Ziel")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Analysiere die bereitgestellten Skripte, um eine belastbare Entscheidungsgrundlage für die Ablösung veralteter Logon-Skript-Lösungen zu erstellen.")
    [void]$sb.AppendLine("Migrationsstrategie: zuerst GPO-first, danach Intune-native. Keine Bastellösungen, keine Rücksicht auf absolute Legacy-Sonderfälle.")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("## Arbeitsauftrag")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("1. **Funktionsanalyse je Skript**")
    [void]$sb.AppendLine("   - Was macht das Skript tatsächlich (technisch/fachlich)?")
    [void]$sb.AppendLine("   - Welche Trigger, Inputs, Abhängigkeiten, Seiteneffekte und Zielsysteme gibt es?")
    [void]$sb.AppendLine("2. **Nutzwert und Relevanz**")
    [void]$sb.AppendLine("   - Ist das Skript heute noch notwendig, redundant, veraltet oder verwaist?")
    [void]$sb.AppendLine("   - Gibt es Überschneidungen mit anderen Skripten?")
    [void]$sb.AppendLine("3. **Risiko- und Qualitätsbewertung**")
    [void]$sb.AppendLine("   - Sicherheitsrisiken, Stabilitätsrisiken, Wartbarkeit, Nachvollziehbarkeit.")
    [void]$sb.AppendLine("   - Für nicht lesbare Dateien: Bewertung auf Basis Dateiname, Dateityp, Hash, Kontext und typischer Einsatzmuster.")
    [void]$sb.AppendLine("4. **Modernisierungsoptionen ohne Legacy-Kompromisse**")
    [void]$sb.AppendLine("   - Kurzfristig: sauberer Ersatz mit GPO-Mechanismen.")
    [void]$sb.AppendLine("   - Mittelfristig: Intune-native Zielarchitektur.")
    [void]$sb.AppendLine("   - Nenne explizit, was ersatzlos entfallen sollte.")
    [void]$sb.AppendLine("5. **Entscheidungsvorlage**")
    [void]$sb.AppendLine("   - Liefere konkrete Priorisierung mit Aufwand, Risiko, Business-Impact und empfohlener Reihenfolge.")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("## Ausgabeformat (verbindlich)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("### A) Strukturierte Tabelle je Skript")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("| Skript | Zweck heute | Status (Behalten/Ersetzen/Entfernen) | Risiko | GPO-Alternative (kurzfristig) | Intune-Alternative (zielbild) | Aufwand (S/M/L) | Priorität (1-3) |")
    [void]$sb.AppendLine("|--------|-------------|--------------------------------------|--------|-------------------------------|-------------------------------|-----------------|-----------------|")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("### B) Strukturierte Kerndaten (JSON-ähnlich)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine('```json')
    [void]$sb.AppendLine('{')
    [void]$sb.AppendLine('  "scripts": [')
    [void]$sb.AppendLine('    {')
    [void]$sb.AppendLine('      "name": "example.ps1",')
    [void]$sb.AppendLine('      "currentPurpose": "...",')
    [void]$sb.AppendLine('      "decision": "replace",')
    [void]$sb.AppendLine('      "riskLevel": "high",')
    [void]$sb.AppendLine('      "gpoTarget": "...",')
    [void]$sb.AppendLine('      "intuneTarget": "...",')
    [void]$sb.AppendLine('      "effort": "M",')
    [void]$sb.AppendLine('      "priority": 1,')
    [void]$sb.AppendLine('      "notes": "..."')
    [void]$sb.AppendLine('    }')
    [void]$sb.AppendLine('  ],')
    [void]$sb.AppendLine('  "programLevelRecommendations": [')
    [void]$sb.AppendLine('    "..."')
    [void]$sb.AppendLine('  ]')
    [void]$sb.AppendLine('}')
    [void]$sb.AppendLine('```')
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("### C) Management Summary")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("- Wichtigste Risiken (Top 5)")
    [void]$sb.AppendLine("- Quick Wins (sofort umsetzbar)")
    [void]$sb.AppendLine("- Zielbild in 3 Migrationswellen: Stabilisierung (GPO) -> Konsolidierung -> Intune-native Endstate")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("## Bewertungsprinzipien")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("- Bevorzuge Standards und supportbare Plattform-Features.")
    [void]$sb.AppendLine("- Keine temporären Bastellösungen als Dauerlösung empfehlen.")
    [void]$sb.AppendLine("- Legacy-only Sonderfälle dürfen kein Design-Treiber sein.")
    [void]$sb.AppendLine("- Unsicherheiten explizit markieren und Verifikationsschritte nennen.")
    return $sb.ToString()
}

function Initialize-CentralPromptFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PromptPath
    )
    if (Test-Path -LiteralPath $PromptPath) {
        Write-Host "Zentrale Prompt-Datei vorhanden, wird nicht überschrieben: $PromptPath" -ForegroundColor Yellow
        return $false
    }
    $content = New-CentralCopilotPromptMarkdown
    $content | Set-Content -LiteralPath $PromptPath -Encoding UTF8
    Write-Host "Zentrale Prompt-Datei geschrieben: $PromptPath" -ForegroundColor Green
    return $true
}

function New-TopFolderReportMarkdown {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Rows,
        [Parameter(Mandatory = $true)]
        [string]$TopFolder,
        [Parameter(Mandatory = $true)]
        [string]$PromptLink
    )
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("# Skript-Analyse für Microsoft 365 Copilot")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Top-Ordner: **$TopFolder**")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("## Copilot-Analyseanweisung")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Verwende den zentralen Prompt für eine standardisierte Bewertung: [$PromptLink]($PromptLink)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("| Datei | Typ | Kategorie | Nutzung | Risiko | SHA256 | Abhängigkeiten | GPO-Empfehlung |")
    [void]$sb.AppendLine("|-------|-----|-----------|---------|--------|--------|----------------|----------------|")
    foreach ($r in ($Rows | Sort-Object -Property FileName)) {
        $name = [string]$r.FileName -replace '\|', '\|' -replace '\r?\n', ' '
        $deps = [string]$r.Dependencies -replace '\|', '\|' -replace '\r?\n', ' '
        $gpo = [string]$r.GpoRecommendation -replace '\|', '\|' -replace '\r?\n', ' '
        $hashCol = if ($r.Hash) { $r.Hash } else { '—' }
        [void]$sb.AppendLine("| $name | $($r.Type) | $($r.Category) | $($r.Usage) | $($r.Risk) | $hashCol | $deps | $gpo |")
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("## Dateiinhalte für Copilot")
    [void]$sb.AppendLine("")
    foreach ($r in ($Rows | Sort-Object -Property FileName)) {
        [void]$sb.AppendLine("### $($r.FileName)")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("- Typ: $($r.Type)")
        [void]$sb.AppendLine("- Kategorie: $($r.Category)")
        [void]$sb.AppendLine("- Nutzung: $($r.Usage)")
        [void]$sb.AppendLine("- Risiko: $($r.Risk)")
        [void]$sb.AppendLine("- SHA256: $(if ($r.Hash) { $r.Hash } else { '—' })")
        [void]$sb.AppendLine("- Abhängigkeiten: $($r.Dependencies)")
        [void]$sb.AppendLine("")
        if ([bool]$r.IsReadable) {
            [void]$sb.AppendLine('```text')
            [void]$sb.AppendLine([string]$r.Content)
            [void]$sb.AppendLine('```')
        }
        else {
            [void]$sb.AppendLine("> Dateiinhalt nicht direkt lesbar.")
            if ($r.ReadError) {
                [void]$sb.AppendLine("> Grund: $($r.ReadError)")
            }
            [void]$sb.AppendLine("> Copilot-Recherchehinweis:")
            [void]$sb.AppendLine("> Prüfe Dateiname, Dateityp, SHA256-Hash und bekannte Indikatoren (Signatur/Produktname/typische Nutzung), um Zweck und Risiko einzuordnen.")
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine('```text')
            [void]$sb.AppendLine("Dateiname: $($r.FileName)")
            [void]$sb.AppendLine("Dateityp: $($r.Type)")
            [void]$sb.AppendLine("SHA256: $(if ($r.Hash) { $r.Hash } else { '—' })")
            [void]$sb.AppendLine('```')
        }
        [void]$sb.AppendLine("")
    }
    return $sb.ToString()
}

function New-IndexMarkdown {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Rows,
        [Parameter(Mandatory = $true)]
        [hashtable]$PartFiles,
        [Parameter(Mandatory = $true)]
        [string]$PromptLink
    )
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("# Skript-Analyse für Microsoft 365 Copilot")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine('Dieser Index enthält die Zusammenfassung und verlinkt auf Teilreports pro Top-Ordner.')
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("## Copilot-Analyseanweisung")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Nutze für alle Auswertungen denselben zentralen Prompt: [$PromptLink]($PromptLink)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("## Teilreports")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("| Top-Ordner | Dateien | Report |")
    [void]$sb.AppendLine("|------------|---------|--------|")
    foreach ($top in ($PartFiles.Keys | Sort-Object)) {
        $count = (@($Rows | Where-Object { [string]$_.TopFolder -eq $top })).Count
        $file = [string]$PartFiles[$top]
        [void]$sb.AppendLine("| $top | $count | [$file]($file) |")
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("## Zusammenfassung")
    [void]$sb.AppendLine("")
    $byCat = $Rows | Group-Object -Property Category | Sort-Object -Property Count -Descending
    foreach ($g in $byCat) {
        [void]$sb.AppendLine("- **$($g.Name)**: $($g.Count) Datei(en)")
    }
    $activeCount = ($Rows | Where-Object { $_.Usage -eq 'Aktiv verwendet' } | Measure-Object).Count
    $orphanCount = ($Rows | Where-Object { $_.Usage -eq 'Verwaist' } | Measure-Object).Count
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("- GPO/AD-referenziert (aktiv): $activeCount")
    [void]$sb.AppendLine("- Verwaist: $orphanCount")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("*Erzeugt mit Export-CopilotAnalysisReport.ps1. Keine KI-APIs – Analyse durch Copilot erfolgt manuell.*")
    return $sb.ToString()
}

# Pfade auflösen
$rootResolved = Resolve-Path -Path $ScriptsPath -ErrorAction Stop
$rootPath = $rootResolved.ProviderPath
$script:RootTrimmed = $rootPath.TrimEnd('\', '/')

$outResolved = $OutputPath
if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
    $outResolved = Join-Path -Path (Get-Location) -ChildPath $OutputPath
}
try {
    $outResolved = [System.IO.Path]::GetFullPath($outResolved)
} catch {}
$outDir = [System.IO.Path]::GetDirectoryName($outResolved)
if (-not [string]::IsNullOrEmpty($outDir) -and -not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

$baseName = [System.IO.Path]::GetFileNameWithoutExtension($outResolved)
if ([string]::IsNullOrWhiteSpace($baseName)) { $baseName = 'CopilotScriptAnalysis' }
$promptFileName = 'Copilot-AnalysisPrompt.md'
$promptResolved = Join-Path -Path $outDir -ChildPath $promptFileName
$checkpointResolved = $CheckpointPath
if ([string]::IsNullOrWhiteSpace($checkpointResolved)) {
    $checkpointResolved = Join-Path -Path (Get-Location) -ChildPath ("{0}.checkpoint.json" -f $baseName)
}
elseif (-not [System.IO.Path]::IsPathRooted($checkpointResolved)) {
    $checkpointResolved = Join-Path -Path (Get-Location) -ChildPath $checkpointResolved
}
try {
    $checkpointResolved = [System.IO.Path]::GetFullPath($checkpointResolved)
} catch {}

[void](Initialize-CentralPromptFile -PromptPath $promptResolved)

# Analyse-Hilfsdaten laden (Nutzung, Risiko, Abhängigkeiten)
$inventory = @()
$securityMaxRiskByPath = @{}
$edges = @()

if (-not [string]::IsNullOrWhiteSpace($AnalysisResultsPath)) {
    $jsonPath = Join-Path -Path $AnalysisResultsPath -ChildPath 'json'
    $analysisFile = Join-Path -Path $jsonPath -ChildPath 'analysis_results.json'
    if (Test-Path -LiteralPath $analysisFile) {
        try {
            $json = Get-Content -LiteralPath $analysisFile -Raw -Encoding UTF8
            $analysisState = $json | ConvertFrom-Json
            $inv = @($analysisState.Inventory ?? @()) | Where-Object {
                $_.Extension -in $script:ScriptExtensions -or $_.IsScript -eq $true
            }
            foreach ($i in $inv) {
                $fp = [string]$i.FullPath
                $inventory += [pscustomobject]@{
                    FullPath      = $fp
                    Name          = $i.Name
                    Extension     = if ($i.Extension) { $i.Extension } else { [System.IO.Path]::GetExtension($fp) }
                    UsageCategory = if ($i.UsageCategory) { $i.UsageCategory } else { '—' }
                    UsageSources  = if ($i.UsageSources) { $i.UsageSources } else { '' }
                }
            }
            foreach ($s in @($analysisState.SecurityFindings ?? @())) {
                $fp = [string]$s.FilePath
                if (-not $fp) { continue }
                $risk = [string]$s.RiskLevel
                if (-not $securityMaxRiskByPath[$fp] -or ($risk -eq 'Critical') -or ($risk -eq 'High' -and $securityMaxRiskByPath[$fp] -ne 'Critical')) {
                    $securityMaxRiskByPath[$fp] = $risk
                }
            }
            if ($analysisState.DependencyGraph -and $analysisState.DependencyGraph.Edges) {
                $edges = @($analysisState.DependencyGraph.Edges)
            }
        }
        catch {
            Write-Warning "Konnte analysis_results.json nicht lesen: $($_.Exception.Message). Fallback: nur Inventar."
        }
    }
}

# Resume-Status initialisieren/laden
$state = $null
$checkpoint = $null
if ($Resume) {
    $checkpoint = Read-Checkpoint -CheckpointFile $checkpointResolved
    if ($checkpoint -and $checkpoint.Version -eq $script:CheckpointVersion -and $checkpoint.ScriptsPath -eq $rootPath -and $checkpoint.OutputPath -eq $outResolved) {
        Write-Host "Checkpoint gefunden, setze fort: $checkpointResolved" -ForegroundColor Yellow
        $partFiles = Convert-ToHashtable -InputObject $checkpoint.PartFiles
        $state = [ordered]@{
            Version           = $script:CheckpointVersion
            ScriptsPath       = [string]$checkpoint.ScriptsPath
            OutputPath        = [string]$checkpoint.OutputPath
            TimestampUtc      = $checkpoint.TimestampUtc
            Inventory         = @($checkpoint.Inventory)
            Rows              = @($checkpoint.Rows)
            ProcessedPaths    = @($checkpoint.ProcessedPaths)
            WrittenTopFolders = @($checkpoint.WrittenTopFolders)
            PartFiles         = $partFiles
            Phases            = $checkpoint.Phases
            Errors            = @($checkpoint.Errors)
        }
    }
    elseif ($checkpoint) {
        Write-Warning "Checkpoint ignoriert (Version, ScriptsPath oder OutputPath passt nicht)."
    }
}
if (-not $state) {
    $state = New-CopilotReportState -ScriptsPathValue $rootPath -OutputPathValue $outResolved
    Write-Host "Kein passender Checkpoint gefunden. Starte neuen Lauf." -ForegroundColor Gray
}

# Inventarphase
if (-not $state.Phases.InventoryCompleted -or @($state.Inventory).Count -eq 0) {
    if ($inventory.Count -eq 0) {
        $files = Get-ChildItem -LiteralPath $rootPath -Recurse -File -ErrorAction Stop |
            Where-Object { $_.Extension -in $script:ScriptExtensions }
        foreach ($f in $files) {
            $inventory += [pscustomobject]@{
                FullPath      = $f.FullName
                Name          = $f.Name
                Extension     = $f.Extension
                UsageCategory = '—'
                UsageSources  = ''
            }
        }
    }
    $state.Inventory = @($inventory)
    $state.Phases.InventoryCompleted = $true
    Write-Checkpoint -State $state -CheckpointFile $checkpointResolved
}
else {
    $inventory = @($state.Inventory)
}

$patterns = Get-CategoryPatterns
$rows = [System.Collections.ArrayList]::new()
foreach ($r in @($state.Rows)) { [void]$rows.Add($r) }
$processed = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
foreach ($p in @($state.ProcessedPaths)) {
    if ($p) { [void]$processed.Add([string]$p) }
}
foreach ($r in @($rows)) {
    if ($r.FullPath) { [void]$processed.Add([string]$r.FullPath) }
}

# Analysephase
if (-not $state.Phases.AnalysisCompleted) {
    $totalInv = [Math]::Max(1, @($inventory).Count)
    $idx = 0
    foreach ($inv in $inventory) {
        $idx++
        $fullPath = [string]$inv.FullPath
        if ([string]::IsNullOrWhiteSpace($fullPath)) { continue }
        if ($processed.Contains($fullPath)) { continue }
        Write-Progress -Activity 'Erstelle Copilot-Analyse' -Status ([System.IO.Path]::GetFileName($fullPath)) -PercentComplete ([math]::Min(100, [int](100 * $idx / $totalInv)))

        $displayName = Convert-ToDisplayName -FullPath $fullPath
        $ext = if ($inv.Extension) { [string]$inv.Extension } else { [System.IO.Path]::GetExtension($fullPath) }
        $usage = if ($inv.UsageCategory) { [string]$inv.UsageCategory } else { '—' }
        $risk = $securityMaxRiskByPath[$fullPath]
        if (-not $risk) { $risk = '—' }
        $hash = ''
        $content = ''
        $isReadable = $false
        $readError = ''

        if (Test-Path -LiteralPath $fullPath) {
            $hash = Get-SafeFileHash -Path $fullPath
            $contentInfo = Get-ReadableFileContent -Path $fullPath
            $content = if ($contentInfo.IsReadable) { [string]$contentInfo.Content } else { '' }
            $isReadable = [bool]$contentInfo.IsReadable
            $readError = [string]$contentInfo.Reason
        }
        else {
            $readError = 'Datei nicht gefunden'
        }

        $category = Get-FileCategoryResult -Content $content -CategoryPatterns $patterns
        $gpoRec = Get-GpoRecommendation -Category $category

        $inEdges = @($edges | Where-Object { [string]$_.TargetPath -eq $fullPath })
        $outEdges = @($edges | Where-Object { [string]$_.SourcePath -eq $fullPath })
        $callers = ($inEdges | ForEach-Object { Convert-ToDisplayName -FullPath ([string]$_.SourcePath) } | Where-Object { $_ }) -join '; '
        $callees = ($outEdges | ForEach-Object { Convert-ToDisplayName -FullPath ([string]$_.TargetPath) } | Where-Object { $_ }) -join '; '
        if (-not $callers) { $callers = '—' }
        if (-not $callees) { $callees = '—' }
        $deps = "Aufrufer: $callers | Aufgerufen: $callees"

        [void]$rows.Add([pscustomobject]@{
            FullPath           = $fullPath
            TopFolder          = Get-TopFolderFromFullPath -FullPath $fullPath
            FileName           = $displayName
            Type               = $ext
            Category           = $category
            Usage              = $usage
            Risk               = $risk
            Hash               = $hash
            Dependencies       = $deps
            GpoRecommendation  = $gpoRec
            IsReadable         = $isReadable
            Content            = $content
            ReadError          = $readError
        })

        [void]$processed.Add($fullPath)
        if (($processed.Count % 20) -eq 0) {
            $state.Rows = @($rows)
            $state.ProcessedPaths = @($processed)
            Write-Checkpoint -State $state -CheckpointFile $checkpointResolved
        }
    }
    Write-Progress -Activity 'Erstelle Copilot-Analyse' -Completed
    $state.Rows = @($rows)
    $state.ProcessedPaths = @($processed)
    $state.Phases.AnalysisCompleted = $true
    Write-Checkpoint -State $state -CheckpointFile $checkpointResolved
}
else {
    Write-Host ("Resume: Analyse bereits vollständig ({0} Dateien)." -f @($state.Rows).Count) -ForegroundColor Yellow
    $rows = [System.Collections.ArrayList]::new()
    foreach ($r in @($state.Rows)) { [void]$rows.Add($r) }
}

# Teilreports pro Top-Ordner schreiben
if (-not $state.Phases.PartsWritten) {
    $writtenSet = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($w in @($state.WrittenTopFolders)) { if ($w) { [void]$writtenSet.Add([string]$w) } }
    $partFiles = Convert-ToHashtable -InputObject $state.PartFiles
    $grouped = @($rows | Group-Object -Property TopFolder | Sort-Object -Property Name)
    foreach ($g in $grouped) {
        $top = [string]$g.Name
        if ($writtenSet.Contains($top)) { continue }
        $safe = Get-SafeKey -Value $top
        $partFileName = "{0}-{1}.md" -f $baseName, $safe
        $partPath = Join-Path -Path $outDir -ChildPath $partFileName
        $partContent = New-TopFolderReportMarkdown -Rows @($g.Group) -TopFolder $top -PromptLink $promptFileName
        $partContent | Set-Content -LiteralPath $partPath -Encoding UTF8
        $partFiles[$top] = $partFileName
        [void]$writtenSet.Add($top)
        Write-Host ("Teilreport geschrieben: {0}" -f $partFileName) -ForegroundColor Green
        $state.PartFiles = $partFiles
        $state.WrittenTopFolders = @($writtenSet)
        Write-Checkpoint -State $state -CheckpointFile $checkpointResolved
    }
    $state.PartFiles = $partFiles
    $state.WrittenTopFolders = @($writtenSet)
    $state.Phases.PartsWritten = $true
    Write-Checkpoint -State $state -CheckpointFile $checkpointResolved
}

# Index schreiben
$index = New-IndexMarkdown -Rows @($rows) -PartFiles (Convert-ToHashtable -InputObject $state.PartFiles) -PromptLink $promptFileName
$index | Set-Content -LiteralPath $outResolved -Encoding UTF8
$state.Phases.IndexWritten = $true
Write-Checkpoint -State $state -CheckpointFile $checkpointResolved

if (Test-Path -LiteralPath $checkpointResolved) {
    Remove-Item -LiteralPath $checkpointResolved -Force -ErrorAction SilentlyContinue
    Write-Host "Checkpoint gelöscht (Lauf vollständig)." -ForegroundColor Green
}
Write-Host "Copilot-Report Index geschrieben: $outResolved" -ForegroundColor Green
