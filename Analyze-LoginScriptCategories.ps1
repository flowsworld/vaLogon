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
$script:CheckpointFileName = 'login_script_categories_checkpoint.json'
$script:CheckpointPath = Join-Path -Path (Get-Location) -ChildPath $script:CheckpointFileName

function Read-Checkpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CheckpointPath
    )
    if (-not (Test-Path -LiteralPath $CheckpointPath)) {
        return $null
    }
    try {
        $json = Get-Content -LiteralPath $CheckpointPath -Raw -ErrorAction Stop
        $data = $json | ConvertFrom-Json -ErrorAction Stop
        if (-not $data.Version -or -not $data.ScriptsPath) { return $null }
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
        [string]$CheckpointPath
    )
    try {
        $State | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $CheckpointPath -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        Write-Warning "Fehler beim Schreiben des Checkpoints: $($_.Exception.Message)"
    }
}

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
    # Enthält Muster für PowerShell, BAT/CMD, VBS und KiXtart.
    $opts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    return [ordered]@{
        'Laufwerks-Mappings'          = @(
            [regex]::new('net\s+use', $opts),
            [regex]::new('New-PSDrive', $opts),
            [regex]::new('MapNetworkDrive', $opts),
            [regex]::new('RemoveNetworkDrive', $opts),
            [regex]::new('WScript\.Network', $opts)
        )
        'Drucker-Einrichtung'         = @(
            [regex]::new('Add-Printer', $opts),
            [regex]::new('AddWindowsPrinterConnection', $opts),
            [regex]::new('AddPrinterConnection', $opts),
            [regex]::new('SetDefaultPrinter', $opts),
            [regex]::new('printui\.dll', $opts),
            [regex]::new('rundll32.*printui', $opts)
        )
        'Inventarisierung/Asset'      = @(
            [regex]::new('Get-CimInstance', $opts),
            [regex]::new('Get-WmiObject', $opts),
            [regex]::new('systeminfo', $opts),
            [regex]::new('Win32_', $opts),
            [regex]::new('winmgmts:', $opts),
            [regex]::new('GetObject\s*\(.*wmi', $opts)
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
            [regex]::new('\.exe\b', $opts),
            [regex]::new('Shell\.Run', $opts),
            [regex]::new('WshShell\.Run', $opts),
            [regex]::new('\.Exec\s*\(', $opts)
        )
        'Umgebungsvariablen/Pfade'    = @(
            [regex]::new('setx', $opts),
            [regex]::new('\[Environment\]::SetEnvironmentVariable', $opts),
            [regex]::new('WshShell\.Environment', $opts),
            [regex]::new('ExpandEnvironmentStrings', $opts)
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
    # Top-Ordner = erstes Segment des relativen Pfads
    $topFoldersList = @($Results | ForEach-Object {
        $seg = ($_.RelativePath -split '[\\/]')[0]
        if ([string]::IsNullOrWhiteSpace($seg)) { '(Root)' } else { $seg }
    } | Sort-Object -Unique)
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
    <section id="summary-section" class="mb-8 bg-white rounded-xl shadow p-4">
      <h2 class="text-lg font-semibold text-gray-800 mb-3">Zusammenfassung</h2>
      <ul class="text-gray-700 space-y-1">
        <li><strong>Dateien gesamt:</strong> <span id="summary-total">$totalFiles</span></li>
        <li><strong>Durchschnittliche Größe:</strong> <span id="summary-avgkb">$avgKb</span> KB</li>
        <li id="summary-unreadable-li"$(if ($unreadableCount -eq 0) { ' style="display:none"' } else { '' }) class="text-amber-700"><strong>Nicht lesbar:</strong> <span id="summary-unreadable">$unreadableCount</span></li>
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
        "      <div class=`"mb-2`" data-category=`"$([System.Net.WebUtility]::HtmlEncode($_.Name))`"><div class=`"flex justify-between text-sm mb-0.5`"><span>$name</span><span class=`"dashboard-count`">$p % ($cnt)</span></div><div class=`"w-full bg-gray-200 rounded h-4`"><div class=`"$color h-4 rounded dashboard-bar`" style=`"width:$p%`" title=`"$name`"></div></div></div>"
    }) -join "`n"

    $dashboardHtml = @"
    <section class="mb-8 bg-white rounded-xl shadow p-4">
      <h2 class="text-lg font-semibold text-gray-800 mb-3">Kategorien (primär)</h2>
      <div id="dashboard-bars" class="max-w-2xl">
$bars
      </div>
    </section>
"@

    $rows = [System.Text.StringBuilder]::new()
    foreach ($r in ($Results | Sort-Object -Property FullName)) {
        $relPath = $r.RelativePath
        $topFolder = ($relPath -split '[\\/]')[0]
        if ([string]::IsNullOrWhiteSpace($topFolder)) { $topFolder = '(Root)' }
        $topFolderEnc = [System.Net.WebUtility]::HtmlEncode($topFolder)
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
        [void]$rows.AppendLine("        <tr data-topfolder=`"$topFolderEnc`"><td class=`"font-mono text-sm`">$fileNameEnc</td><td class=`"font-mono text-sm text-gray-600`">$relPathEnc</td><td>$primEnc</td><td>$confEnc</td><td class=`"text-sm text-gray-600`">$allCatEnc</td></tr>")
    }

    $tableHtml = $rows.ToString()

    $reportResults = @($Results | Sort-Object -Property FullName | ForEach-Object {
        $top = ($_.RelativePath -split '[\\/]')[0]
        if ([string]::IsNullOrWhiteSpace($top)) { $top = '(Root)' }
        [ordered]@{
            relativePath   = $_.RelativePath
            topFolder      = $top
            fileName       = $_.FileName
            size           = [long]$_.Size
            unreadable     = [bool]$_.Unreadable
            primaryCategory= $_.PrimaryCategory
            confidence     = $_.Confidence
            allCategories  = @($_.AllCategories)
        }
    })
    $reportDataJson = @{
        topFolders = @($topFoldersList)
        results    = $reportResults
    } | ConvertTo-Json -Depth 4 -Compress
    $reportDataJsonEscaped = $reportDataJson -replace '</', '\u003c/'   # Verhindert </script> im HTML

    $dropdownOptions = ($topFoldersList | ForEach-Object {
        $enc = [System.Net.WebUtility]::HtmlEncode($_)
        "        <option value=`"$enc`">$enc</option>"
    }) -join "`n"
    $filterBlock = @"
    <div class="mb-6 flex items-center gap-3">
      <label for="filter-topfolder" class="text-sm font-medium text-gray-700">Filter: Top-Ordner</label>
      <select id="filter-topfolder" class="rounded border border-gray-300 px-3 py-1.5 text-gray-900 focus:ring-2 focus:ring-blue-500">
        <option value="">Gesamt</option>
$dropdownOptions
      </select>
    </div>
"@

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
    $filterBlock
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
        <tbody id="files-tbody">
$tableHtml
        </tbody>
      </table>
    </section>
  </div>
  <script type="application/json" id="reportData">$reportDataJsonEscaped</script>
  <script>
(function() {
  var dataEl = document.getElementById('reportData');
  if (!dataEl) return;
  var raw = dataEl.textContent;
  var reportData = JSON.parse(raw);
  var results = reportData.results || [];
  var select = document.getElementById('filter-topfolder');
  var tbody = document.getElementById('files-tbody');
  var summaryTotal = document.getElementById('summary-total');
  var summaryAvgkb = document.getElementById('summary-avgkb');
  var summaryUnreadable = document.getElementById('summary-unreadable');
  var summaryUnreadableLi = document.getElementById('summary-unreadable-li');
  var dashboardBars = document.getElementById('dashboard-bars');
  var categoryColors = { 'Laufwerks': 'bg-blue-500', 'Drucker': 'bg-amber-500', 'Inventar': 'bg-green-500', 'Sicherheit': 'bg-red-500', 'Software': 'bg-purple-500', 'Umgebung': 'bg-cyan-500' };
  function getColor(name) { for (var k in categoryColors) if (name && name.indexOf(k) !== -1) return categoryColors[k]; return 'bg-gray-500'; }
  function applyFilter(value) {
    var filtered = value === '' ? results : results.filter(function(r) { return r.topFolder === value; });
    var rows = tbody ? tbody.querySelectorAll('tr') : [];
    for (var i = 0; i < rows.length; i++) {
      var tf = rows[i].getAttribute('data-topfolder');
      var show = value === '' || tf === value;
      rows[i].style.display = show ? '' : 'none';
    }
    var total = filtered.length;
    var readable = filtered.filter(function(r) { return !r.unreadable; });
    var unreadableCount = total - readable.length;
    var sumSize = readable.reduce(function(s, r) { return s + (r.size || 0); }, 0);
    var avgKb = total > 0 ? (sumSize / readable.length / 1024).toFixed(2) : 0;
    if (readable.length === 0) avgKb = 0;
    if (summaryTotal) summaryTotal.textContent = total;
    if (summaryAvgkb) summaryAvgkb.textContent = avgKb;
    if (summaryUnreadable) summaryUnreadable.textContent = unreadableCount;
    if (summaryUnreadableLi) { summaryUnreadableLi.style.display = unreadableCount > 0 ? '' : 'none'; }
    var byCat = {};
    filtered.forEach(function(r) { var p = r.primaryCategory || 'Unbekannt'; byCat[p] = (byCat[p] || 0) + 1; });
    var order = Object.keys(byCat).sort(function(a,b) { return (byCat[b]||0) - (byCat[a]||0); });
    if (dashboardBars) {
      var html = '';
      order.forEach(function(name) {
        var cnt = byCat[name];
        var pct = total > 0 ? (100 * cnt / total).toFixed(1) : 0;
        var color = getColor(name);
        html += '<div class="mb-2" data-category="' + name.replace(/"/g,'&quot;') + '"><div class="flex justify-between text-sm mb-0.5"><span>' + name.replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</span><span class="dashboard-count">' + pct + ' % (' + cnt + ')</span></div><div class="w-full bg-gray-200 rounded h-4"><div class="' + color + ' h-4 rounded dashboard-bar" style="width:' + pct + '%" title="' + name.replace(/"/g,'&quot;') + '"></div></div></div>';
      });
      dashboardBars.innerHTML = html;
    }
  }
  if (select) select.addEventListener('change', function() { applyFilter(select.value); });
  applyFilter(select ? select.value : '');
})();
  </script>
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
# Provider-Qualifier (z.B. 'Microsoft.PowerShell.Core\FileSystem::') entfernen,
# damit $rootPath zum Format von $fi.FullName passt.
$rootPath = $rootResolved.ProviderPath

function New-LoginCategoriesState {
    param([string]$ScriptsPathValue)
    return [ordered]@{
        Version     = 1
        ScriptsPath = $ScriptsPathValue
        TimestampUtc= (Get-Date).ToUniversalTime()
        Inventory   = @()
        ProcessedFiles = @()
        Results     = @()
        Phases      = @{
            InventoryCompleted      = $false
            CategorizationCompleted = $false
            ReportExported          = $false
        }
        Errors      = @()
    }
}

$state = New-LoginCategoriesState -ScriptsPathValue $rootPath
$checkpoint = Read-Checkpoint -CheckpointPath $script:CheckpointPath
if ($checkpoint -and $checkpoint.ScriptsPath -eq $rootPath -and $checkpoint.Version -eq 1) {
    Write-Host "Checkpoint gefunden, setze fort: $script:CheckpointFileName" -ForegroundColor Yellow
    $state = [ordered]@{
        Version        = 1
        ScriptsPath    = $checkpoint.ScriptsPath
        TimestampUtc   = $checkpoint.TimestampUtc
        Inventory      = @($checkpoint.Inventory)
        ProcessedFiles = @($checkpoint.ProcessedFiles)
        Results        = @($checkpoint.Results)
        Phases         = $checkpoint.Phases
        Errors         = @($checkpoint.Errors)
    }
}
elseif ($checkpoint) {
    Write-Warning "Checkpoint ignoriert (ScriptsPath oder Version passt nicht)."
}
else {
    Write-Host "Kein Checkpoint gefunden. Starte neuen Lauf." -ForegroundColor Gray
}

Write-Host "Scanne $rootPath ..." -ForegroundColor Cyan
if (-not $state.Phases.InventoryCompleted -or -not $state.Inventory -or $state.Inventory.Count -eq 0) {
    $files = Get-ScriptFileInventory -RootPath $rootPath
    $state.Inventory = @($files | ForEach-Object {
        [pscustomobject]@{ FullName = $_.FullName; Name = $_.Name; Length = $_.Length }
    })
    $state.Phases.InventoryCompleted = $true
    Write-Checkpoint -State $state -CheckpointPath $script:CheckpointPath
}
else {
    $files = @($state.Inventory | ForEach-Object { Get-Item -LiteralPath $_.FullName -ErrorAction SilentlyContinue } | Where-Object { $_ })
}
Write-Host "Gefunden: $($state.Inventory.Count) Skriptdateien." -ForegroundColor Cyan

$patterns = Get-CategoryPatterns
$results = [System.Collections.ArrayList]::new()
foreach ($r in @($state.Results)) { [void]$results.Add($r) }
$processedSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($p in @($state.ProcessedFiles)) { [void]$processedSet.Add([string]$p) }

$totalFiles = [math]::Max(1, $state.Inventory.Count)
$doneCount = $processedSet.Count
$remainingCount = [math]::Max(0, $state.Inventory.Count - $doneCount)
if ($doneCount -gt 0) {
    Write-Host "Resume: bereits kategorisiert: $doneCount, verbleibend: $remainingCount" -ForegroundColor Yellow
}
$batch = 0

try {
    foreach ($fi in $state.Inventory) {
        $full = [string]$fi.FullName
        if ($processedSet.Contains($full)) {
            continue
        }
        $batch++
        Write-Progress -Activity 'Kategorisiere Skripte' -Status $fi.Name -PercentComplete ([math]::Min(100, [int](100 * $doneCount / $totalFiles)))

        $content = Get-FileContentSafe -Path $full
        # Relativen Pfad sicher ermitteln: Substring wirft, wenn $full kürzer als Root oder $full nicht unter Root liegt.
        $rootTrimmed = $rootPath.TrimEnd('\', '/')
        if ([string]::IsNullOrEmpty($full)) {
            $relativePath = $fi.Name ?? ''
        } elseif ([string]::IsNullOrEmpty($rootTrimmed)) {
            $relativePath = $full.TrimStart('\', '/')
        } elseif ($full.Length -lt $rootTrimmed.Length) {
            $relativePath = $fi.Name ?? $full
        } elseif ($full.StartsWith($rootTrimmed, [StringComparison]::OrdinalIgnoreCase)) {
            $relativePath = $full.Substring($rootTrimmed.Length).TrimStart('\', '/')
        } else {
            $relativePath = $fi.Name ?? $full
        }
        if ($null -eq $content) {
            $res = [pscustomobject]@{
                FullName        = $full
                RelativePath    = $relativePath
                FileName        = $fi.Name
                Size            = $fi.Length
                PrimaryCategory = 'Unbekannt'
                AllCategories   = @()
                Confidence      = '—'
                Unreadable      = $true
            }
        }
        else {
            $catResult = Get-FileCategoryResult -Content $content -CategoryPatterns $patterns
            $res = [pscustomobject]@{
                FullName        = $full
                RelativePath    = $relativePath
                FileName        = $fi.Name
                Size            = $fi.Length
                PrimaryCategory = $catResult.PrimaryCategory
                AllCategories   = $catResult.AllCategories
                Confidence      = $catResult.Confidence
                Unreadable      = $false
            }
        }

        [void]$results.Add($res)
        [void]$processedSet.Add($full)
        $state.ProcessedFiles = @($processedSet)
        $state.Results = @($results)
        $doneCount++

        if ($batch -ge 100) {
            $batch = 0
            Write-Checkpoint -State $state -CheckpointPath $script:CheckpointPath
        }
    }
    $state.Phases.CategorizationCompleted = $true
    Write-Checkpoint -State $state -CheckpointPath $script:CheckpointPath
}
catch {
    $state.Errors += [pscustomobject]@{ TimestampUtc = (Get-Date).ToUniversalTime(); Message = $_.Exception.Message }
    Write-Checkpoint -State $state -CheckpointPath $script:CheckpointPath
    throw
}
finally {
    Write-Progress -Activity 'Kategorisiere Skripte' -Completed
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
$state.Phases.ReportExported = $true
Write-Checkpoint -State $state -CheckpointPath $script:CheckpointPath

if ($state.Phases.InventoryCompleted -and $state.Phases.CategorizationCompleted -and $state.Phases.ReportExported) {
    Remove-Item -LiteralPath $script:CheckpointPath -Force -ErrorAction SilentlyContinue
    Write-Host "Checkpoint gelöscht (Lauf vollständig): $script:CheckpointFileName" -ForegroundColor Green
}
