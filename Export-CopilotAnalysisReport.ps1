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
    $relPath = Get-RelativePath -FullPath $fullPath
    $ext = $inv.Extension
    $usage = $inv.UsageCategory
    $risk = $securityMaxRiskByPath[$fullPath]
    if (-not $risk) { $risk = '—' }

    $content = $null
    try {
        $content = Get-Content -LiteralPath $fullPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {}
    $category = Get-FileCategoryResult -Content ($content ?? '') -CategoryPatterns $patterns
    $gpoRec = Get-GpoRecommendation -Category $category

    $inEdges = @($edges | Where-Object { [string]$_.TargetPath -eq $fullPath })
    $outEdges = @($edges | Where-Object { [string]$_.SourcePath -eq $fullPath })
    $callers = ($inEdges | ForEach-Object { Get-RelativePath -FullPath $_.SourcePath } | Where-Object { $_ }) -join '; '
    $callees = ($outEdges | ForEach-Object { Get-RelativePath -FullPath $_.TargetPath } | Where-Object { $_ }) -join '; '
    if (-not $callers) { $callers = '—' }
    if (-not $callees) { $callees = '—' }
    $deps = "Aufrufer: $callers | Aufgerufen: $callees"

    [void]$rows.Add([pscustomobject]@{
        RelativePath   = $relPath
        Type           = $ext
        Category       = $category
        Usage          = $usage
        Risk           = $risk
        Dependencies   = $deps
        GpoRecommendation = $gpoRec
    })
}

# Markdown ausgeben
$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine("# Skript-Analyse für Microsoft 365 Copilot")
[void]$sb.AppendLine("")
[void]$sb.AppendLine('Dieser Report listet alle erfassten Logon-/Skriptdateien mit Kategorie, Nutzung, Kritikalität, Abhängigkeiten und empfohlener GPO-Migration. Zur Auswertung in Word oder Teams öffnen und mit Copilot z.B. fragen: "Analysiere diese Skripte auf Kritikalität" oder "Welche GPO-Einstellungen ersetzen diese Logon-Skripte?".')
[void]$sb.AppendLine("")
[void]$sb.AppendLine("| Relativer Pfad | Typ | Kategorie | Nutzung | Risiko | Abhängigkeiten | GPO-Empfehlung |")
[void]$sb.AppendLine("|---------------|-----|-----------|---------|--------|----------------|----------------|")

foreach ($r in $rows) {
    $rel = $r.RelativePath -replace '\|', '\|' -replace '\r?\n', ' '
    $deps = $r.Dependencies -replace '\|', '\|' -replace '\r?\n', ' '
    $gpo = $r.GpoRecommendation -replace '\|', '\|' -replace '\r?\n', ' '
    [void]$sb.AppendLine("| $rel | $($r.Type) | $($r.Category) | $($r.Usage) | $($r.Risk) | $deps | $gpo |")
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
