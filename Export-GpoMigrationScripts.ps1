<#
.SYNOPSIS
    Erzeugt PowerShell-Skripte zur GPO-Migration pro Top-Ordner (zum manuellen Prüfen und Ausführen).

.DESCRIPTION
    Erstellt pro Top-Ordner (erstes Verzeichnis unter ScriptsPath) eine .ps1-Datei, die
    New-GPO und New-GPLink verwendet sowie Anweisungen/Kommentare für GPO Preferences
    (Laufwerkszuordnung, Drucker, Umgebung) enthält. Keine automatische GPO-Erstellung –
    der Admin prüft die Skripte, ersetzt Platzhalter und führt sie aus (z.B. mit -WhatIf).

.PARAMETER ScriptsPath
    Stammverzeichnis der Skripte (z.B. \\domain\SYSVOL\domain\scripts). Pflicht.

.PARAMETER OutputPath
    Ordner für die generierten .ps1-Dateien (Default: .\GpoMigrationScripts).

.PARAMETER AnalysisResultsPath
    Optional: Pfad zum Analyse-Ergebnisordner. Wenn gesetzt, wird json/analysis_results.json
    für Inventar genutzt; Kategorien werden aus Dateiinhalt ermittelt.

.PARAMETER GpoNamePrefix
    Präfix für den GPO-Namen (Default: Migration_).

.EXAMPLE
    .\Export-GpoMigrationScripts.ps1 -ScriptsPath '\\contoso.local\SYSVOL\scripts'

.EXAMPLE
    .\Export-GpoMigrationScripts.ps1 -ScriptsPath '\\contoso.local\SYSVOL\scripts' -OutputPath '.\GPO-Skripte' -GpoNamePrefix 'LogonErsetzung_'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScriptsPath,

    [string]$OutputPath = ".\GpoMigrationScripts",

    [string]$AnalysisResultsPath = '',

    [string]$GpoNamePrefix = 'Migration_'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScriptExtensions = @('.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.kix')
$rootTrimmed = $ScriptsPath.TrimEnd('\', '/')

function Get-CategoryPatterns {
    $opts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    return [ordered]@{
        'Laufwerks-Mappings'           = @([regex]::new('net\s+use', $opts), [regex]::new('New-PSDrive', $opts), [regex]::new('MapNetworkDrive', $opts), [regex]::new('WScript\.Network', $opts))
        'Drucker-Einrichtung'          = @([regex]::new('Add-Printer', $opts), [regex]::new('printui\.dll', $opts), [regex]::new('SetDefaultPrinter', $opts))
        'Inventarisierung/Asset'       = @([regex]::new('Get-CimInstance', $opts), [regex]::new('Win32_', $opts))
        'Sicherheit/Compliance'        = @([regex]::new('ExecutionPolicy', $opts), [regex]::new('LegalNotice', $opts))
        'Software-Verteilung/Updates'  = @([regex]::new('\.msi\b', $opts), [regex]::new('msiexec', $opts), [regex]::new('Shell\.Run', $opts))
        'Umgebungsvariablen/Pfade'      = @([regex]::new('setx', $opts), [regex]::new('\[Environment\]::SetEnvironmentVariable', $opts))
    }
}

function Get-FileCategoryResult {
    param([string]$Content, [hashtable]$CategoryPatterns)
    $scores = [ordered]@{}
    foreach ($cat in $CategoryPatterns.Keys) {
        $count = 0
        foreach ($re in $CategoryPatterns[$cat]) { $count += $re.Matches($Content).Count }
        if ($count -gt 0) { $scores[$cat] = $count }
    }
    if ($scores.Count -gt 0) {
        return ($scores.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 1).Key
    }
    return 'Unbekannt'
}

# Skripte nach Top-Ordner gruppieren
$inventory = @()
if (-not [string]::IsNullOrWhiteSpace($AnalysisResultsPath)) {
    $analysisFile = Join-Path -Path $AnalysisResultsPath -ChildPath 'json\analysis_results.json'
    if (Test-Path -LiteralPath $analysisFile) {
        try {
            $state = Get-Content -LiteralPath $analysisFile -Raw -Encoding UTF8 | ConvertFrom-Json
            $inv = @($state.Inventory ?? @()) | Where-Object { $_.Extension -in $script:ScriptExtensions -or $_.IsScript -eq $true }
            foreach ($i in $inv) {
                $inventory += [pscustomobject]@{ FullPath = [string]$i.FullPath; Name = $i.Name; Extension = $i.Extension }
            }
        } catch {
            Write-Warning "analysis_results.json nicht lesbar: $($_.Exception.Message)"
        }
    }
}
if ($inventory.Count -eq 0) {
    Get-ChildItem -LiteralPath $ScriptsPath -Recurse -File -ErrorAction Stop |
        Where-Object { $_.Extension -in $script:ScriptExtensions } |
        ForEach-Object { $inventory += [pscustomobject]@{ FullPath = $_.FullName; Name = $_.Name; Extension = $_.Extension } }
}

# Top-Ordner = erstes Segment des relativen Pfads
$byTop = @{}
foreach ($item in $inventory) {
    $full = [string]$item.FullPath
    if (-not $full.StartsWith($rootTrimmed, [StringComparison]::OrdinalIgnoreCase)) { continue }
    $rel = $full.Substring($rootTrimmed.Length).TrimStart('\', '/')
    $segments = $rel -split '[\\/]'
    $top = if ($segments.Length -gt 1) { $segments[0] } else { '(Root)' }
    if (-not $byTop[$top]) { $byTop[$top] = [System.Collections.ArrayList]::new() }
    [void]$byTop[$top].Add($item)
}

$patterns = Get-CategoryPatterns
$outResolved = $OutputPath
if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
    $outResolved = Join-Path -Path (Get-Location) -ChildPath $OutputPath
}
if (-not (Test-Path -LiteralPath $outResolved)) {
    New-Item -ItemType Directory -Path $outResolved -Force | Out-Null
}

foreach ($top in $byTop.Keys) {
    $safeName = $top -replace '[^A-Za-z0-9_-]', '_'
    $gpoName = $GpoNamePrefix + $safeName
    $scriptPath = Join-Path -Path $outResolved -ChildPath "Create-GPO-$safeName.ps1"

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("# Generiert von Export-GpoMigrationScripts.ps1 – bitte manuell prüfen, Platzhalter ersetzen, ggf. mit -WhatIf testen.")
    [void]$sb.AppendLine("# Ersetzt Logon-Skript-Funktionalität für Top-Ordner: $top")
    [void]$sb.AppendLine("# Voraussetzung: GroupPolicy-Modul (z.B. RSAT), Rechte zum Erstellen/Verknüpfen von GPOs.")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Requires -Modules GroupPolicy")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("`$GpoName = '$gpoName'")
    [void]$sb.AppendLine("`$TargetOU = 'OU=Platzhalter,DC=contoso,DC=com'  # Ziel-OU für GPO-Link anpassen")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("# GPO anlegen (ausführen nur nach Prüfung)")
    [void]$sb.AppendLine("`$gpo = New-GPO -Name `$GpoName -Comment 'Migration von Logon-Skripten (Top-Ordner $top)'")
    [void]$sb.AppendLine("if (`$gpo) {")
    [void]$sb.AppendLine("    New-GPLink -Guid `$gpo.Id -Target `$TargetOU -Order 1")
    [void]$sb.AppendLine("}")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("# --- GPO Preferences (in GPMC konfigurieren oder per XML/weitere Cmdlets) ---")
    [void]$sb.AppendLine("# Laufwerkszuordnung: User Configuration > Preferences > Windows Settings > Drive Maps")
    [void]$sb.AppendLine("#   Platzhalter z.B.: \\SERVER\Share, Laufwerksbuchstabe H:")
    [void]$sb.AppendLine("# Drucker: User Configuration > Preferences > Control Panel Settings > Printers")
    [void]$sb.AppendLine("#   Platzhalter: Drucker-UNC oder -Name")
    [void]$sb.AppendLine("# Umgebungsvariablen: User Configuration > Preferences > Windows Settings > Environment")
    [void]$sb.AppendLine("")

    $items = @($byTop[$top])
    $categoriesInTop = @($items | ForEach-Object {
        $c = $null
        try {
            $content = Get-Content -LiteralPath $_.FullPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
            $c = Get-FileCategoryResult -Content ($content ?? '') -CategoryPatterns $patterns
        } catch {}
        $c
    } | Where-Object { $_ -and $_ -ne 'Unbekannt' } | Sort-Object -Unique)

    if ($categoriesInTop.Count -gt 0) {
        [void]$sb.AppendLine("# In diesem Top-Ordner erkannte Kategorien (Skripte als Vorlage): $($categoriesInTop -join ', ')")
        [void]$sb.AppendLine("# Zuordnung: Laufwerks-Mappings -> Drive Maps; Drucker-Einrichtung -> Printers; Umgebungsvariablen -> Environment; Sicherheit/Compliance -> ggf. Registry.")
    }
    [void]$sb.AppendLine("")

    $content = $sb.ToString()
    $content | Set-Content -LiteralPath $scriptPath -Encoding UTF8
    Write-Host "GPO-Skript geschrieben: $scriptPath" -ForegroundColor Green
}

Write-Host "Fertig. $($byTop.Count) Skript(e) in $outResolved. Bitte Platzhalter anpassen und nach Prüfung ausführen." -ForegroundColor Cyan
