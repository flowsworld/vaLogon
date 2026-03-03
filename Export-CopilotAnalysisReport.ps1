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

    [string]$AnalysisResultsPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScriptExtensions = @('.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.kix')
$rootTrimmed = $ScriptsPath.TrimEnd('\', '/')

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
    if ([string]::IsNullOrWhiteSpace($rootTrimmed)) { return $FullPath.TrimStart('\', '/') }
    if ($FullPath.StartsWith($rootTrimmed, [StringComparison]::OrdinalIgnoreCase)) {
        return $FullPath.Substring($rootTrimmed.Length).TrimStart('\', '/')
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

# Skript-Liste ermitteln
$inventory = @()
$usageByPath = @{}
$securityMaxRiskByPath = @{}
$edges = @()

if (-not [string]::IsNullOrWhiteSpace($AnalysisResultsPath)) {
    $jsonPath = Join-Path -Path $AnalysisResultsPath -ChildPath 'json'
    $analysisFile = Join-Path -Path $jsonPath -ChildPath 'analysis_results.json'
    if (Test-Path -LiteralPath $analysisFile) {
        try {
            $json = Get-Content -LiteralPath $analysisFile -Raw -Encoding UTF8
            $state = $json | ConvertFrom-Json
            $inv = @($state.Inventory ?? @()) | Where-Object {
                $_.Extension -in $script:ScriptExtensions -or $_.IsScript -eq $true
            }
            foreach ($i in $inv) {
                $fp = [string]$i.FullPath
                $inventory += [pscustomobject]@{
                    FullPath   = $fp
                    Name       = $i.Name
                    Extension  = if ($i.Extension) { $i.Extension } else { [System.IO.Path]::GetExtension($fp) }
                    UsageCategory = if ($i.UsageCategory) { $i.UsageCategory } else { '—' }
                    UsageSources  = if ($i.UsageSources) { $i.UsageSources } else { '' }
                }
                if ($i.UsageCategory) { $usageByPath[$fp] = $i.UsageCategory }
            }
            $sec = @($state.SecurityFindings ?? @())
            foreach ($s in $sec) {
                $fp = [string]$s.FilePath
                if (-not $fp) { continue }
                $risk = [string]$s.RiskLevel
                if (-not $securityMaxRiskByPath[$fp] -or ($risk -eq 'Critical') -or ($risk -eq 'High' -and $securityMaxRiskByPath[$fp] -ne 'Critical')) {
                    $securityMaxRiskByPath[$fp] = $risk
                }
            }
            $graph = $state.DependencyGraph
            if ($graph -and $graph.Edges) {
                $edges = @($graph.Edges)
            }
        }
        catch {
            Write-Warning "Konnte analysis_results.json nicht lesen: $($_.Exception.Message). Fallback: nur Inventar."
        }
    }
}

if ($inventory.Count -eq 0) {
    $files = Get-ChildItem -LiteralPath $ScriptsPath -Recurse -File -ErrorAction Stop |
        Where-Object { $_.Extension -in $script:ScriptExtensions }
    foreach ($f in $files) {
        $inventory += [pscustomobject]@{
            FullPath       = $f.FullName
            Name           = $f.Name
            Extension      = $f.Extension
            UsageCategory  = '—'
            UsageSources   = ''
        }
    }
}

$patterns = Get-CategoryPatterns
$rows = [System.Collections.ArrayList]::new()

foreach ($inv in $inventory) {
    $fullPath = [string]$inv.FullPath
    $displayName = Convert-ToDisplayName -FullPath $fullPath
    $ext = $inv.Extension
    $usage = $inv.UsageCategory
    $risk = $securityMaxRiskByPath[$fullPath]
    if (-not $risk) { $risk = '—' }
    $hash = Get-SafeFileHash -Path $fullPath

    $contentInfo = Get-ReadableFileContent -Path $fullPath
    $content = if ($contentInfo.IsReadable) { [string]$contentInfo.Content } else { '' }
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
        FileName       = $displayName
        Type           = $ext
        Category       = $category
        Usage          = $usage
        Risk           = $risk
        Hash           = $hash
        Dependencies   = $deps
        GpoRecommendation = $gpoRec
        IsReadable     = $contentInfo.IsReadable
        Content        = $content
        ReadError      = $contentInfo.Reason
    })
}

# Markdown ausgeben
$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine("# Skript-Analyse für Microsoft 365 Copilot")
[void]$sb.AppendLine("")
[void]$sb.AppendLine('Dieser Report listet alle erfassten Logon-/Skriptdateien mit Kategorie, Nutzung, Kritikalität, Abhängigkeiten, Hash und empfohlener GPO-Migration. Der tatsächliche Dateiinhalt wird pro Datei eingebettet (sofern lesbar). Für nicht lesbare Dateien werden Recherchehinweise aus Metadaten bereitgestellt. Zur Auswertung in Word oder Teams öffnen und mit Copilot z.B. fragen: "Analysiere diese Skripte auf Kritikalität" oder "Welche GPO-Einstellungen ersetzen diese Logon-Skripte?".')
[void]$sb.AppendLine("")
[void]$sb.AppendLine("| Datei | Typ | Kategorie | Nutzung | Risiko | SHA256 | Abhängigkeiten | GPO-Empfehlung |")
[void]$sb.AppendLine("|-------|-----|-----------|---------|--------|--------|----------------|----------------|")

foreach ($r in $rows) {
    $name = $r.FileName -replace '\|', '\|' -replace '\r?\n', ' '
    $deps = $r.Dependencies -replace '\|', '\|' -replace '\r?\n', ' '
    $gpo = $r.GpoRecommendation -replace '\|', '\|' -replace '\r?\n', ' '
    $hashCol = if ($r.Hash) { $r.Hash } else { '—' }
    [void]$sb.AppendLine("| $name | $($r.Type) | $($r.Category) | $($r.Usage) | $($r.Risk) | $hashCol | $deps | $gpo |")
}

[void]$sb.AppendLine("")
[void]$sb.AppendLine("## Dateiinhalte für Copilot")
[void]$sb.AppendLine("")
foreach ($r in ($rows | Sort-Object -Property FileName)) {
    [void]$sb.AppendLine("### $($r.FileName)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("- Typ: $($r.Type)")
    [void]$sb.AppendLine("- Kategorie: $($r.Category)")
    [void]$sb.AppendLine("- Nutzung: $($r.Usage)")
    [void]$sb.AppendLine("- Risiko: $($r.Risk)")
    [void]$sb.AppendLine("- SHA256: $(if ($r.Hash) { $r.Hash } else { '—' })")
    [void]$sb.AppendLine("- Abhängigkeiten: $($r.Dependencies)")
    [void]$sb.AppendLine("")
    if ($r.IsReadable) {
        [void]$sb.AppendLine('```text')
        [void]$sb.AppendLine($r.Content)
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

[void]$sb.AppendLine("")
[void]$sb.AppendLine("## Zusammenfassung")
[void]$sb.AppendLine("")
$byCat = $rows | Group-Object -Property Category | Sort-Object -Property Count -Descending
foreach ($g in $byCat) {
    [void]$sb.AppendLine("- **$($g.Name)**: $($g.Count) Datei(en)")
}
$activeCount = ($rows | Where-Object { $_.Usage -eq 'Aktiv verwendet' } | Measure-Object).Count
$orphanCount = ($rows | Where-Object { $_.Usage -eq 'Verwaist' } | Measure-Object).Count
[void]$sb.AppendLine("")
[void]$sb.AppendLine("- GPO/AD-referenziert (aktiv): $activeCount")
[void]$sb.AppendLine("- Verwaist: $orphanCount")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("*Erzeugt mit Export-CopilotAnalysisReport.ps1. Keine KI-APIs – Analyse durch Copilot erfolgt manuell.*")

$outResolved = $OutputPath
if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
    $outResolved = Join-Path -Path (Get-Location) -ChildPath $OutputPath
}
$outDir = [System.IO.Path]::GetDirectoryName($outResolved)
if (-not [string]::IsNullOrEmpty($outDir) -and -not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
$sb.ToString() | Set-Content -LiteralPath $outResolved -Encoding UTF8
Write-Host "Copilot-Report geschrieben: $outResolved" -ForegroundColor Green
