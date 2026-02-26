<#
.SYNOPSIS
    Statistische Analyse von Anmeldeskripten im SYSVOL\scripts-Pfad nach Kategorien.

.DESCRIPTION
    Analysiert alle Skriptdateien (.ps1, .psm1, .bat, .cmd, .vbs, .kix) rekursiv im angegebenen
    Verzeichnis, ordnet sie anhand von Inhaltsmustern Kategorien zu (Laufwerks-Mappings,
    Drucker, Inventarisierung, Sicherheit/Compliance, Software-Verteilung, Umgebungsvariablen
    bzw. Unbekannt) und erzeugt einen HTML-Report mit Zusammenfassung, Kategorie-Dashboard
    und Dateitabelle inkl. Konfidenz-Level. Alle dynamischen Inhalte werden HTML-escaped (XSS-Schutz).

.PARAMETER ScriptsPath
    Stammverzeichnis (z.B. \\domain\SYSVOL\domain\scripts). Muss existieren.

.PARAMETER OutputPath
    Pfad der zu erzeugenden HTML-Datei (Default: .\LoginScriptCategoriesReport.html).

.PARAMETER Encoding
    Fallback-Encoding beim Lesen von Skriptdateien (Default: UTF8).

.EXAMPLE
    .\Analyze-LoginScriptCategories.ps1 -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts'

.EXAMPLE
    .\Analyze-LoginScriptCategories.ps1 -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts' -OutputPath 'D:\Reports\Categories.html'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScriptsPath,

    [string]$OutputPath = ".\LoginScriptCategoriesReport.html",

    [System.Text.Encoding]$Encoding = [System.Text.Encoding]::UTF8
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScriptExtensions = @('.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.kix')

function Get-FileContentSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [System.Text.Encoding]$FallbackEncoding = $Encoding
    )
    try {
        $content = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop
        return $content
    }
    catch {
        try {
            $content = Get-Content -LiteralPath $Path -Raw -Encoding $FallbackEncoding -ErrorAction Stop
            return $content
        }
        catch {
            Write-Warning "Konnte Datei nicht lesen: $Path - $($_.Exception.Message)"
            return $null
        }
    }
}

function Get-ScriptFileInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootPath
    )
    $files = Get-ChildItem -LiteralPath $RootPath -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in $script:ScriptExtensions }
    return @($files)
}

function Get-CategoryPatterns {
    # Liefert Hashtable: Kategorie -> @(Regex-Patterns). Alle case-insensitive.
    $opts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    return [ordered]@{
        'Laufwerks-Mappings'          = @(
            [regex]::new('net\s+use', $opts),
            [regex]::new('New-PSDrive', $opts),
            [regex]::new('MapNetworkDrive', $opts)
        )
        'Drucker-Einrichtung'         = @(
            [regex]::new('Add-Printer', $opts),
            [regex]::new('AddWindowsPrinterConnection', $opts),
            [regex]::new('printui\.dll', $opts)
        )
        'Inventarisierung/Asset'      = @(
            [regex]::new('Get-CimInstance', $opts),
            [regex]::new('Get-WmiObject', $opts),
            [regex]::new('systeminfo', $opts),
            [regex]::new('Win32_', $opts)
        )
        'Sicherheit/Compliance'        = @(
            [regex]::new('ExecutionPolicy', $opts),
            [regex]::new('LegalNotice', $opts),
            [regex]::new('Antivirus', $opts),
            [regex]::new('reg.*(Banner|Legal)', $opts)
        )
        'Software-Verteilung/Updates' = @(
            [regex]::new('\.msi\b', $opts),
            [regex]::new('msiexec', $opts),
            [regex]::new('Start-Process', $opts),
            [regex]::new('\.exe\b', $opts)
        )
        'Umgebungsvariablen/Pfade'    = @(
            [regex]::new('setx', $opts),
            [regex]::new('\[Environment\]::SetEnvironmentVariable', $opts)
        )
    }
}

function Get-FileCategoryResult {
    [CmdletBinding()]
    param(
        [string]$Content,
        [hashtable]$CategoryPatterns
    )
    $scores = [ordered]@{}
    foreach ($cat in $CategoryPatterns.Keys) {
        $count = 0
        foreach ($re in $CategoryPatterns[$cat]) {
            $matches = $re.Matches($Content)
            $count += $matches.Count
        }
        if ($count -gt 0) {
            $scores[$cat] = $count
        }
    }
    $primary = 'Unbekannt'
    $confidenceLevel = '—'
    $allCategories = @()
    if ($scores.Count -gt 0) {
        $allCategories = @($scores.Keys)
        $primary = ($scores.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 1).Key
        $primaryHits = $scores[$primary]
        if ($primaryHits -ge 5) { $confidenceLevel = 'Hoch' }
        elseif ($primaryHits -ge 2) { $confidenceLevel = 'Mittel' }
        else { $confidenceLevel = 'Niedrig' }
    }
    return [pscustomobject]@{
        PrimaryCategory = $primary
        AllCategories    = $allCategories
        Confidence       = $confidenceLevel
        HitCount         = if ($primary -ne 'Unbekannt') { $scores[$primary] } else { 0 }
    }
}

function Export-CategoriesReportToHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Results,
        [Parameter(Mandatory = $true)]
        [string]$OutputFilePath
    )
    $totalFiles = $Results.Count
    $readable = @($Results | Where-Object { $_.Unreadable -ne $true })
    $unreadableCount = $totalFiles - $readable.Count
    $totalBytes = ($readable | Measure-Object -Property Size -Sum).Sum
    $avgBytes = if ($readable.Count -gt 0) { [math]::Round($totalBytes / $readable.Count) } else { 0 }
    $avgKb = [math]::Round($avgBytes / 1024, 2)

    $byPrimary = $Results | Group-Object -Property PrimaryCategory | Sort-Object -Property Count -Descending
    $pct = @{}
    foreach ($g in $byPrimary) {
        $pct[$g.Name] = if ($totalFiles -gt 0) { [math]::Round(100.0 * $g.Count / $totalFiles, 1) } else { 0 }
    }

    $summaryHtml = @"
    <section class="mb-8 bg-white rounded-xl shadow p-4">
      <h2 class="text-lg font-semibold text-gray-800 mb-3">Zusammenfassung</h2>
      <ul class="text-gray-700 space-y-1">
        <li><strong>Dateien gesamt:</strong> $totalFiles</li>
        <li><strong>Durchschnittliche Größe:</strong> $avgKb KB</li>
$(if ($unreadableCount -gt 0) { "        <li class=\"text-amber-700\"><strong>Nicht lesbar:</strong> $unreadableCount</li>" })
      </ul>
    </section>
"@

    $bars = ($byPrimary | ForEach-Object {
        $name = [System.Net.WebUtility]::HtmlEncode($_.Name)
        $cnt = $_.Count
        $p = $pct[$_.Name]
        $color = switch -Regex ($_.Name) {
            'Laufwerks' { 'bg-blue-500' }
            'Drucker' { 'bg-amber-500' }
            'Inventar' { 'bg-green-500' }
            'Sicherheit' { 'bg-red-500' }
            'Software' { 'bg-purple-500' }
            'Umgebung' { 'bg-cyan-500' }
            default { 'bg-gray-500' }
        }
        "      <div class=\"mb-2\"><div class=\"flex justify-between text-sm mb-0.5\"><span>$name</span><span>$p % ($cnt)</span></div><div class=\"w-full bg-gray-200 rounded h-4\"><div class=\"$color h-4 rounded\" style=\"width:$p%\" title=\"$name\"></div></div></div>"
    }) -join "`n"

    $dashboardHtml = @"
    <section class="mb-8 bg-white rounded-xl shadow p-4">
      <h2 class="text-lg font-semibold text-gray-800 mb-3">Kategorien (primär)</h2>
      <div class="max-w-2xl">
$bars
      </div>
    </section>
"@

    $rows = [System.Text.StringBuilder]::new()
    foreach ($r in ($Results | Sort-Object -Property FullName)) {
        $relPath = $r.RelativePath
        $fileName = $r.FileName
        $prim = $r.PrimaryCategory
        $conf = $r.Confidence
        $allCat = ($r.AllCategories -join ', ')
        $relPathEnc = [System.Net.WebUtility]::HtmlEncode($relPath)
        if ($r.Unreadable) { $relPathEnc = $relPathEnc + ' <span class="text-amber-600 text-sm">(nicht lesbar)</span>' }
        $fileNameEnc = [System.Net.WebUtility]::HtmlEncode($fileName)
        $primEnc = [System.Net.WebUtility]::HtmlEncode($prim)
        $confEnc = [System.Net.WebUtility]::HtmlEncode($conf)
        $allCatEnc = [System.Net.WebUtility]::HtmlEncode($allCat)
        [void]$rows.AppendLine("        <tr><td class=\"font-mono text-sm\">$fileNameEnc</td><td class=\"font-mono text-sm text-gray-600\">$relPathEnc</td><td>$primEnc</td><td>$confEnc</td><td class=\"text-sm text-gray-600\">$allCatEnc</td></tr>")
    }

    $tableHtml = $rows.ToString()

    $html = @"
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <title>Login-Skript Kategorien – SYSVOL</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 text-gray-900 min-h-screen">
  <div class="max-w-7xl mx-auto px-4 py-8">
    <header class="mb-8">
      <h1 class="text-3xl font-bold text-gray-900">Login-Skript Kategorien</h1>
      <p class="mt-2 text-gray-600">Statistische Analyse der Anmeldeskripte nach Inhaltskategorien.</p>
    </header>
$summaryHtml
$dashboardHtml
    <section class="mb-8 bg-white rounded-xl shadow p-4 overflow-x-auto">
      <h2 class="text-lg font-semibold text-gray-800 mb-3">Alle Dateien</h2>
      <table class="w-full text-left border-collapse">
        <thead>
          <tr class="border-b border-gray-300">
            <th class="py-2 pr-4">Dateiname</th>
            <th class="py-2 pr-4">Pfad</th>
            <th class="py-2 pr-4">Primäre Kategorie</th>
            <th class="py-2 pr-4">Konfidenz</th>
            <th class="py-2 pr-4">Alle Kategorien</th>
          </tr>
        </thead>
        <tbody>
$tableHtml
        </tbody>
      </table>
    </section>
  </div>
</body>
</html>
"@
    try {
        $html | Set-Content -Path $OutputFilePath -Encoding UTF8
        Write-Host "HTML geschrieben: $OutputFilePath" -ForegroundColor Green
    }
    catch {
        Write-Error "Fehler beim Schreiben der HTML-Datei: $($_.Exception.Message)"
    }
}

# Main
if (-not (Test-Path -LiteralPath $ScriptsPath -PathType Container)) {
    Write-Error "Pfad existiert nicht oder ist kein Verzeichnis: $ScriptsPath"
}
$rootResolved = Resolve-Path -Path $ScriptsPath -ErrorAction Stop
$rootPath = $rootResolved.Path

Write-Host "Scanne $rootPath ..." -ForegroundColor Cyan
$files = Get-ScriptFileInventory -RootPath $rootPath
Write-Host "Gefunden: $($files.Count) Skriptdateien." -ForegroundColor Cyan

$patterns = Get-CategoryPatterns
$results = [System.Collections.ArrayList]::new()
foreach ($f in $files) {
    $content = Get-FileContentSafe -Path $f.FullName
    $relativePath = $f.FullName.Substring($rootPath.TrimEnd('\', '/').Length).TrimStart('\', '/')
    if ($null -eq $content) {
        [void]$results.Add([pscustomobject]@{
            FullName       = $f.FullName
            RelativePath   = $relativePath
            FileName       = $f.Name
            Size           = $f.Length
            PrimaryCategory = 'Unbekannt'
            AllCategories  = @()
            Confidence     = '—'
            Unreadable     = $true
        })
    }
    else {
        $catResult = Get-FileCategoryResult -Content $content -CategoryPatterns $patterns
        [void]$results.Add([pscustomobject]@{
            FullName        = $f.FullName
            RelativePath    = $relativePath
            FileName        = $f.Name
            Size            = $f.Length
            PrimaryCategory = $catResult.PrimaryCategory
            AllCategories   = $catResult.AllCategories
            Confidence      = $catResult.Confidence
            Unreadable      = $false
        })
    }
}

$outResolved = $OutputPath
if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
    $outResolved = Join-Path -Path (Get-Location) -ChildPath $OutputPath
}
$outDir = [System.IO.Path]::GetDirectoryName($outResolved)
if (-not [string]::IsNullOrEmpty($outDir) -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
Export-CategoriesReportToHtml -Results $results -OutputFilePath $outResolved
