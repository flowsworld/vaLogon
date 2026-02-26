<#
.SYNOPSIS
    Erstellt eine HTML-Datei mit Flowchart aller VBS-Dateien und ihrer Aufrufbeziehungen (inkl. Aufrufer: BAT, CMD, PS1, KiXtart).

.DESCRIPTION
    Findet alle VBS-Dateien unter dem angegebenen Stammpfad (z.B. SYSVOL\scripts), löst Aufrufbeziehungen auf
    (welche VBS ruft welche Dateien auf; welche BAT/CMD/PS1/KiXtart-Dateien rufen welche VBS auf) und erzeugt
    eine einzelne HTML-Datei mit Mermaid-Flowchart und Quellcode aller Skripte (VBS, BAT, CMD, PS1, KiXtart, …); Aufrufe/Verlinkungen im Code werden hervorgehoben. Alle dynamischen Inhalte werden HTML-escaped (XSS-Sanitisierung), damit keine Ausführung eingeschleusten Codes möglich ist.

.PARAMETER ScriptsPath
    Stammverzeichnis (z.B. \\domain\SYSVOL\domain\scripts).

.PARAMETER OutputPath
    Pfad der zu erzeugenden HTML-Datei (Default: .\VbsFlowchart.html).

.PARAMETER Encoding
    Fallback-Encoding beim Lesen von Skriptdateien (Default: UTF8).

.EXAMPLE
    .\Export-VbsFlowchart.ps1 -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts'

.EXAMPLE
    .\Export-VbsFlowchart.ps1 -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts' -OutputPath 'D:\Reports\VbsFlow.html'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScriptsPath,

    [string]$OutputPath = ".\VbsFlowchart.html",

    [System.Text.Encoding]$Encoding = [System.Text.Encoding]::UTF8
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:MaxFileBytes = 1MB
$script:VbsExtensions = @('.vbs')
$script:CallerExtensions = @('.bat', '.cmd', '.ps1', '.psm1', '.kix')
$script:CheckpointFileName = 'vbs_flowchart_checkpoint.json'
$script:CheckpointPath = Join-Path -Path (Get-Location) -ChildPath $script:CheckpointFileName

function Read-Checkpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CheckpointPath
    )
    if (-not (Test-Path -LiteralPath $CheckpointPath)) { return $null }
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
        $State | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $CheckpointPath -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        Write-Warning "Fehler beim Schreiben des Checkpoints: $($_.Exception.Message)"
    }
}

function New-VbsFlowState {
    param([string]$ScriptsPathValue)
    return [ordered]@{
        Version     = 1
        ScriptsPath = $ScriptsPathValue
        TimestampUtc= (Get-Date).ToUniversalTime()
        VbsFiles    = @()
        CallerFiles = @()
        Nodes       = @()
        Edges       = @()
        ProcessedVbs    = @()
        ProcessedCallers= @()
        Phases      = @{
            InventoryCompleted   = $false
            ParseVbsCompleted    = $false
            ParseCallersCompleted= $false
            ContentLoadCompleted = $false
            HtmlExported         = $false
        }
        Errors      = @()
    }
}

function Get-FileContentSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [int]$MaxBytes = $script:MaxFileBytes,
        [System.Text.Encoding]$FallbackEncoding = $Encoding
    )
    try {
        $fileInfo = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($fileInfo.Length -gt $MaxBytes) {
            $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            try {
                $bufferSize = [Math]::Min($MaxBytes, $fileInfo.Length)
                $buffer = New-Object byte[] $bufferSize
                [void]$fs.Read($buffer, 0, $bufferSize)
                return $FallbackEncoding.GetString($buffer)
            }
            finally { $fs.Close() }
        }
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

function Test-ContentReferencesVbs {
    param([string]$Content)
    if (-not $Content) { return $false }
    $vbsRefPattern = '(?i)(\.vbs\b|WScript\.Shell\.Run|Execute\s*\(|ExecuteGlobal\s*\(|call\s+.+\.vbs|&\s*["''].*\.vbs|CALL\s+|RUN\s+|SHELL\s+)'
    return $Content -match $vbsRefPattern
}

function Get-AllRelevantFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootPath
    )
    $allFiles = @()
    try {
        $files = Get-ChildItem -Path $RootPath -Recurse -File -ErrorAction Stop
    }
    catch {
        Write-Error "Fehler beim Scannen von $RootPath : $($_.Exception.Message)"
        return @(), @()
    }
    $vbsFiles = @()
    $callerCandidates = @()
    foreach ($f in $files) {
        $ext = $f.Extension.ToLowerInvariant()
        if ($ext -eq '.vbs') {
            $vbsFiles += $f
        }
        elseif ($script:CallerExtensions -contains $ext) {
            $callerCandidates += $f
        }
    }
    $callerFiles = @()
    $total = $callerCandidates.Count
    $i = 0
    foreach ($c in $callerCandidates) {
        $i++
        Write-Progress -Activity 'Scanne Aufrufer-Kandidaten' -Status $c.Name -PercentComplete ([math]::Min(100, [int](100 * $i / $total)))
        $content = Get-FileContentSafe -Path $c.FullName
        if (Test-ContentReferencesVbs -Content $content) {
            $callerFiles += $c
        }
    }
    Write-Progress -Activity 'Scanne Aufrufer-Kandidaten' -Completed
    return $vbsFiles, $callerFiles
}

function Resolve-TargetPath {
    param(
        [string]$RawTarget,
        [string]$SourceDirectory
    )
    if (-not $RawTarget) { return $null }
    $raw = $RawTarget.Trim().Trim('"', "'")
    if ($raw -like '\\*' -or $raw -match '^[A-Za-z]:\\') {
        if (Test-Path -LiteralPath $raw -ErrorAction SilentlyContinue) {
            return (Resolve-Path -LiteralPath $raw -ErrorAction SilentlyContinue).Path
        }
        return $raw
    }
    $candidate = Join-Path -Path $SourceDirectory -ChildPath $raw
    $resolved = Resolve-Path -Path $candidate -ErrorAction SilentlyContinue
    if ($resolved) { return $resolved.Path }
    foreach ($ext in @('', '.vbs', '.bat', '.cmd', '.ps1')) {
        $withExt = $candidate + $ext
        $r = Resolve-Path -Path $withExt -ErrorAction SilentlyContinue
        if ($r) { return $r.Path }
    }
    return $null
}

function Get-VbsCallsFromContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content,
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,
        [Parameter(Mandatory = $true)]
        [string]$SourceDirectory
    )
    $edges = @()
    if (-not $Content) { return $edges }
    $vbsRegexes = @(
        'WScript\.Shell\.Run\s*\(\s*["''](.+?)["'']',
        '(?i)CreateObject\s*\(\s*["'']WScript\.Shell["'']\)\.Run\s*\(\s*["''](.+?)["'']',
        '(?i)\bExecute(?:Global)?\s*\(\s*["''](.+?)["'']',
        '(?i)\bExecute(?:Global)?\s+["''](.+?\.vbs)["'']'
    )
    foreach ($rx in $vbsRegexes) {
        $matches = [regex]::Matches($content, $rx)
        foreach ($m in $matches) {
            $rawTarget = $m.Groups[1].Value
            if (-not $rawTarget) { continue }
            $resolved = Resolve-TargetPath -RawTarget $rawTarget -SourceDirectory $SourceDirectory
            if ($resolved) {
                $edges += [pscustomobject]@{
                    SourcePath = $SourcePath
                    TargetPath = $resolved
                    RawCall    = $m.Value
                }
            }
        }
    }
    return $edges
}

function Get-CallersOfVbs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content,
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,
        [Parameter(Mandatory = $true)]
        [string]$SourceDirectory,
        [Parameter(Mandatory = $true)]
        [string]$Extension
    )
    $edges = @()
    if (-not $Content) { return $edges }
    $dir = $SourceDirectory
    if ($Extension -in '.bat', '.cmd') {
        $lines = $Content -split "`n"
        foreach ($l in $lines) {
            $t = $l.Trim()
            if ($t -match '^(?i)\s*(call|start|cmd\s+/c)\s+(.+)$') {
                $cmd = $matches[2].Trim()
                $targetToken = ($cmd -split '\s+')[0]
                $rawTarget = $targetToken.Trim('"', "'")
                $resolved = Resolve-TargetPath -RawTarget $rawTarget -SourceDirectory $dir
                if ($resolved -and [System.IO.Path]::GetExtension($resolved) -eq '.vbs') {
                    $edges += [pscustomobject]@{
                        SourcePath = $SourcePath
                        TargetPath = $resolved
                        RawCall    = $t
                    }
                }
            }
        }
    }
    elseif ($Extension -in '.ps1', '.psm1') {
        $psRegexes = @(
            '(?i)&\s*["'']?(.+?\.vbs)["'']?',
            '(?i)\.\s*["'']?(.+?\.vbs)["'']?',
            '(?i)Start-Process\s+["'']?(.+?\.vbs)["'']?',
            '(?i)Invoke-Expression\s+.*["'']?(.+?\.vbs)["'']?',
            '(?i)powershell\.exe.+["'']?(.+?\.vbs)["'']?'
        )
        foreach ($rx in $psRegexes) {
            $matches = [regex]::Matches($content, $rx)
            foreach ($m in $matches) {
                $rawTarget = $m.Groups[1].Value
                if (-not $rawTarget) { continue }
                $resolved = Resolve-TargetPath -RawTarget $rawTarget -SourceDirectory $dir
                if ($resolved) {
                    $edges += [pscustomobject]@{
                        SourcePath = $SourcePath
                        TargetPath = $resolved
                        RawCall    = $m.Value
                    }
                }
            }
        }
    }
    elseif ($Extension -eq '.kix') {
        $lines = $Content -split "`n"
        foreach ($l in $lines) {
            $t = $l.Trim()
            if ($t -match '^(?i)\s*(CALL|RUN|SHELL)\s+(.+)$') {
                $rest = $matches[2].Trim()
                $rawTarget = ($rest -split '\s+')[0].Trim('"', "'")
                $resolved = Resolve-TargetPath -RawTarget $rawTarget -SourceDirectory $dir
                if ($resolved -and [System.IO.Path]::GetExtension($resolved) -eq '.vbs') {
                    $edges += [pscustomobject]@{
                        SourcePath = $SourcePath
                        TargetPath = $resolved
                        RawCall    = $t
                    }
                }
            }
        }
    }
    return $edges
}

function Build-FlowGraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.IO.FileInfo[]]$VbsFiles,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.IO.FileInfo[]]$CallerFiles,
        [Parameter(Mandatory = $true)]
        [string]$RootPath,
        [hashtable]$State,
        [string]$CheckpointPath
    )
    $nodes = @{}
    $edges = @()
    $processedVbs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $processedCallers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    if ($State) {
        foreach ($p in @($State.ProcessedVbs)) { if ($p) { [void]$processedVbs.Add([string]$p) } }
        foreach ($p in @($State.ProcessedCallers)) { if ($p) { [void]$processedCallers.Add([string]$p) } }

        foreach ($n in @($State.Nodes)) {
            if (-not $n.FullPath) { continue }
            $nodes[[string]$n.FullPath] = [pscustomobject]@{
                Id          = $n.Id
                FullPath    = $n.FullPath
                DisplayName = $n.DisplayName
                Type        = $n.Type
                Content     = $n.Content
            }
        }
        foreach ($e in @($State.Edges)) {
            if ($e.SourcePath -and $e.TargetPath) {
                $edges += [pscustomobject]@{
                    SourcePath = $e.SourcePath
                    TargetPath = $e.TargetPath
                    RawCall    = $e.RawCall
                }
            }
        }
    }

    $seenEdges = @{}
    foreach ($e in $edges) {
        $key = "$($e.SourcePath)->$($e.TargetPath)"
        $seenEdges[$key] = $true
    }
    $getNodeId = {
        param([string]$Path)
        $id = $Path -replace '[\\/:.\s\[\]]', '_'
        $id = $id -replace '_+', '_'
        $hashBytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Path))[0..7]
        $id = 'n' + (($hashBytes | ForEach-Object { $_.ToString('x2') }) -join '')
        return $id
    }
    $ensureNode = {
        param([hashtable]$NodeDict, [string]$FullPath, [string]$Type, [string]$Content)
        if ($NodeDict.ContainsKey($FullPath)) { return $NodeDict[$FullPath] }
        $name = [System.IO.Path]::GetFileName($FullPath)
        $ext = [System.IO.Path]::GetExtension($FullPath).ToLowerInvariant()
        if (-not $Type) {
            $Type = switch ($ext) {
                '.vbs' { 'VBS' }
                '.bat' { 'BAT' }
                '.cmd' { 'CMD' }
                '.ps1' { 'PS1' }
                '.psm1' { 'PSM1' }
                '.kix' { 'KIX' }
                default { '' }
            }
        }
        $id = & $getNodeId $FullPath
        $node = [pscustomobject]@{
            Id          = $id
            FullPath    = $FullPath
            DisplayName = $name
            Type        = $Type
            Content     = $Content
        }
        $NodeDict[$FullPath] = $node
        return $node
    }

    $totalV = [math]::Max(1, $VbsFiles.Count)
    $idx = 0
    foreach ($v in $VbsFiles) {
        $idx++
        Write-Progress -Activity 'Graph aufbauen' -Status "VBS initialisieren: $($v.Name)" -PercentComplete ([math]::Min(100, [int](100 * $idx / $totalV)))
        if (-not $nodes.ContainsKey($v.FullName) -or -not $nodes[$v.FullName].Content) {
            $content = Get-FileContentSafe -Path $v.FullName
            if ($nodes.ContainsKey($v.FullName)) {
                $nodes[$v.FullName].Content = $content
            }
            else {
                $null = & $ensureNode $nodes $v.FullName 'VBS' $content
            }
        }
    }

    foreach ($c in $CallerFiles) {
        $type = switch ($c.Extension.ToLowerInvariant()) {
            '.bat' { 'BAT' }
            '.cmd' { 'CMD' }
            '.ps1' { 'PS1' }
            '.psm1' { 'PSM1' }
            '.kix' { 'KIX' }
            default { 'OTHER' }
        }
        $null = & $ensureNode $nodes $c.FullName $type $null
    }

    $persist = {
        param([string]$PhaseName)
        if (-not $State -or -not $CheckpointPath) { return }
        $State.Nodes = @($nodes.Values)
        $State.Edges = @($edges)
        $State.ProcessedVbs = @($processedVbs)
        $State.ProcessedCallers = @($processedCallers)
        if ($PhaseName) { $State.Phases.$PhaseName = $true }
        Write-Checkpoint -State $State -CheckpointPath $CheckpointPath
    }

    if (-not ($State -and $State.Phases.ParseVbsCompleted)) {
        $idx = 0
        $batch = 0
        foreach ($v in $VbsFiles) {
            $idx++
            Write-Progress -Activity 'Graph aufbauen' -Status "VBS-Aufrufe parsen: $($v.Name)" -PercentComplete ([math]::Min(100, [int](100 * $idx / $totalV)))
            if ($processedVbs.Contains($v.FullName)) { continue }
            $content = $nodes[$v.FullName].Content
            if (-not $content) { $content = Get-FileContentSafe -Path $v.FullName }
            $dir = $v.DirectoryName
            $outEdges = Get-VbsCallsFromContent -Content $content -SourcePath $v.FullName -SourceDirectory $dir
            foreach ($e in $outEdges) {
                $key = "$($e.SourcePath)->$($e.TargetPath)"
                if ($seenEdges[$key]) { continue }
                $seenEdges[$key] = $true
                $targetNode = & $ensureNode $nodes $e.TargetPath $null $null
                if ($targetNode -and -not $targetNode.Content -and [System.IO.Path]::GetExtension($e.TargetPath) -eq '.vbs') {
                    $targetNode.Content = Get-FileContentSafe -Path $e.TargetPath
                }
                $edges += $e
            }
            [void]$processedVbs.Add($v.FullName)
            $batch++
            if ($batch -ge 50) { $batch = 0; & $persist $null }
        }
        & $persist 'ParseVbsCompleted'
    }

    $totalC = [math]::Max(1, $CallerFiles.Count)
    if (-not ($State -and $State.Phases.ParseCallersCompleted)) {
        $idxC = 0
        $batch = 0
        foreach ($c in $CallerFiles) {
            $idxC++
            Write-Progress -Activity 'Graph aufbauen' -Status "Aufrufer parsen: $($c.Name)" -PercentComplete ([math]::Min(100, [int](100 * $idxC / $totalC)))
            if ($processedCallers.Contains($c.FullName)) { continue }
            $content = Get-FileContentSafe -Path $c.FullName
            $dir = $c.DirectoryName
            $outEdges = Get-CallersOfVbs -Content $content -SourcePath $c.FullName -SourceDirectory $dir -Extension $c.Extension.ToLowerInvariant()
            foreach ($e in $outEdges) {
                $key = "$($e.SourcePath)->$($e.TargetPath)"
                if ($seenEdges[$key]) { continue }
                $seenEdges[$key] = $true
                $null = & $ensureNode $nodes $e.TargetPath $null $null
                $edges += $e
            }
            [void]$processedCallers.Add($c.FullName)
            $batch++
            if ($batch -ge 50) { $batch = 0; & $persist $null }
        }
        & $persist 'ParseCallersCompleted'
    }

    $nodeList = @($nodes.Values)
    if (-not ($State -and $State.Phases.ContentLoadCompleted)) {
        $totalN = [math]::Max(1, $nodeList.Count)
        $idxN = 0
        $batch = 0
        foreach ($n in $nodeList) {
            $idxN++
            Write-Progress -Activity 'Graph aufbauen' -Status "Inhalte laden: $($n.DisplayName)" -PercentComplete ([math]::Min(100, [int](100 * $idxN / $totalN)))
            if (-not $n.Content -and $n.FullPath -and (Test-Path -LiteralPath $n.FullPath -ErrorAction SilentlyContinue)) {
                $n.Content = Get-FileContentSafe -Path $n.FullPath
                $batch++
                if ($batch -ge 100) { $batch = 0; & $persist $null }
            }
        }
        & $persist 'ContentLoadCompleted'
    }
    Write-Progress -Activity 'Graph aufbauen' -Completed
    # Pro Knoten: Liste der im Code vorkommenden Aufruf-Snippets (für Hervorhebung)
    foreach ($n in $nodeList) {
        $calls = @($edges | Where-Object { $_.SourcePath -eq $n.FullPath } | ForEach-Object { $_.RawCall } | Where-Object { $_ })
        $n | Add-Member -NotePropertyName 'OutgoingRawCalls' -NotePropertyValue $calls -Force
    }
    return [pscustomobject]@{
        Nodes     = $nodeList
        Edges     = $edges
        GetNodeId = $getNodeId
    }
}

function Get-MermaidFlowchart {
    param(
        [pscustomobject]$Graph
    )
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("flowchart LR")
    [void]$sb.AppendLine("  direction TB")
    $idByPath = @{}
    foreach ($n in $Graph.Nodes) {
        $idByPath[$n.FullPath] = $n.Id
    }
    foreach ($n in $Graph.Nodes) {
        $typeLabel = switch ($n.Type) { 'VBS' { 'VBS' } 'BAT' { 'BAT' } 'CMD' { 'CMD' } 'PS1' { 'PS1' } 'PSM1' { 'PSM1' } 'KIX' { 'KIX' } default { '' } }
        $nodeLabel = if ($typeLabel) { "$($n.DisplayName) ($typeLabel)" } else { $n.DisplayName }
        $nodeLabel = $nodeLabel -replace '"', '\"' -replace '\[', '\[' -replace '\]', '\]'
        [void]$sb.AppendLine("  $($n.Id)[`"$nodeLabel`"]")
    }
    foreach ($e in $Graph.Edges) {
        $sid = $idByPath[$e.SourcePath]
        $tid = $idByPath[$e.TargetPath]
        if ($sid -and $tid) {
            [void]$sb.AppendLine("  $sid --> $tid")
        }
    }
    foreach ($n in $Graph.Nodes) {
        [void]$sb.AppendLine("  click $($n.Id) href `"#code-$($n.Id)`"")
    }
    return $sb.ToString()
}

function Get-CodeWithHighlightedLinks {
    param(
        [string]$Content,
        [string[]]$LinkSnippets
    )
    if (-not $Content) { return '' }
    # Alles escapen, damit im Browser keine Ausführung (XSS) möglich ist.
    $escaped = [System.Net.WebUtility]::HtmlEncode($Content)
    $snippets = @($LinkSnippets | Where-Object { $_ } | Sort-Object -Property Length -Descending)
    foreach ($snip in $snippets) {
        $snipEscaped = [System.Net.WebUtility]::HtmlEncode($snip)
        if ($snipEscaped.Length -gt 0 -and $escaped.IndexOf($snipEscaped, [StringComparison]::Ordinal) -ge 0) {
            # Nur eigenes Markup; Snippet bleibt escaped.
            $highlight = "<span class=`"bg-amber-300 text-amber-950 rounded px-0.5 font-semibold`" title=`"Aufruf/Verlinkung`">" + $snipEscaped + "</span>"
            $escaped = $escaped.Replace($snipEscaped, $highlight)
        }
    }
    return $escaped
}

function Get-HtmlSafeMermaid {
    param([string]$MermaidCode)
    if (-not $MermaidCode) { return '' }
    # Mermaid-Code wird in ein <div> eingefügt und vom Browser als HTML geparst.
    # Vollständig HTML-escapen, damit keine eingeschleusten Tags (z. B. <script>, <img onerror>) ausgeführt werden.
    return [System.Net.WebUtility]::HtmlEncode($MermaidCode)
}

function Export-VbsFlowchartToHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Graph,
        [Parameter(Mandatory = $true)]
        [string]$OutputFilePath
    )
    $mermaidCode = Get-MermaidFlowchart -Graph $Graph
    $mermaidCodeSafe = Get-HtmlSafeMermaid -MermaidCode $mermaidCode
    $codeSections = [System.Text.StringBuilder]::new()
    foreach ($n in $Graph.Nodes) {
        # ID für Anker/Attribut: nur sichere Zeichen, keine Injektion in id="..."
        $safeId = $n.Id -replace '[^A-Za-z0-9_-]', '_'
        $anchorId = "code-" + $safeId
        $displayName = [System.Net.WebUtility]::HtmlEncode($n.DisplayName)
        $fullPath = [System.Net.WebUtility]::HtmlEncode($n.FullPath)
        $typeLabel = switch ($n.Type) { 'VBS' { 'VBS' } 'BAT' { 'BAT' } 'CMD' { 'CMD' } 'PS1' { 'PS1' } 'PSM1' { 'PSM1' } 'KIX' { 'KIX' } default { 'Skript' } }
        $linkSnippets = @($n.OutgoingRawCalls ?? @())
        $codeWithHighlights = Get-CodeWithHighlightedLinks -Content $n.Content -LinkSnippets $linkSnippets
        if (-not $n.Content) {
            $codeWithHighlights = [System.Net.WebUtility]::HtmlEncode("# Datei nicht lesbar oder leer: $($n.FullPath)")
        }
        [void]$codeSections.AppendLine(@"
    <section id="$anchorId" class="mb-8 scroll-mt-8">
      <h2 class="text-xl font-semibold text-gray-800 mb-2">
        <a href="#$anchorId" class="text-blue-600 hover:underline">$displayName</a>
        <span class="ml-2 text-sm font-normal text-gray-500">($typeLabel)</span>
      </h2>
      <p class="text-sm text-gray-500 mb-2 font-mono">$fullPath</p>
$(if ($linkSnippets.Count -gt 0) { "      <p class=`"text-xs text-amber-700 mb-1`">Gelb markiert: Aufruf/Verlinkung zu anderen Dateien</p>" })
      <pre class="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto text-sm"><code>$codeWithHighlights</code></pre>
    </section>
"@)
    }
    $html = @"
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <title>VBS Flowchart – Aufrufbeziehungen</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
</head>
<body class="bg-gray-50 text-gray-900 min-h-screen">
  <div class="max-w-7xl mx-auto px-4 py-8">
    <header class="mb-8">
      <h1 class="text-3xl font-bold text-gray-900">VBS Flowchart</h1>
      <p class="mt-2 text-gray-600">Aufrufbeziehungen: Pfeil = „ruft auf“ (von Aufrufer zu aufgerufener Datei).</p>
      <div class="mt-2 flex flex-wrap gap-2">
        <span class="px-2 py-1 rounded bg-blue-100 text-blue-800 text-sm">VBS</span>
        <span class="px-2 py-1 rounded bg-amber-100 text-amber-800 text-sm">BAT/CMD</span>
        <span class="px-2 py-1 rounded bg-green-100 text-green-800 text-sm">PS1/PSM1</span>
        <span class="px-2 py-1 rounded bg-purple-100 text-purple-800 text-sm">KiXtart</span>
      </div>
    </header>

    <section class="mb-8 bg-white rounded-xl shadow p-4 overflow-x-auto">
      <h2 class="text-lg font-semibold text-gray-800 mb-3">Flowchart</h2>
      <div class="mermaid" id="flowchart">
$mermaidCodeSafe
      </div>
    </section>

    <h2 class="text-2xl font-bold text-gray-900 mt-12 mb-4">Quellcode (alle Skripte)</h2>
    <p class="text-gray-600 mb-4">Alle aufrufenden und aufgerufenen Dateien (VBS, BAT, CMD, PS1, KiXtart). Gelb markiert: Zeilen/Snippets, die eine andere Datei aufrufen.</p>
$($codeSections.ToString())
  </div>
  <script>
    mermaid.initialize({ startOnLoad: true, flowchart: { useMaxWidth: true, htmlLabels: true } });
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
$rootResolved = Resolve-Path -Path $ScriptsPath -ErrorAction Stop
$rootPath = $rootResolved.Path

$state = New-VbsFlowState -ScriptsPathValue $rootPath
$checkpoint = Read-Checkpoint -CheckpointPath $script:CheckpointPath
if ($checkpoint -and $checkpoint.ScriptsPath -eq $rootPath -and $checkpoint.Version -eq 1) {
    Write-Host "Checkpoint gefunden, setze fort: $script:CheckpointFileName" -ForegroundColor Yellow
    $state = [ordered]@{
        Version          = 1
        ScriptsPath      = $checkpoint.ScriptsPath
        TimestampUtc     = $checkpoint.TimestampUtc
        VbsFiles         = @($checkpoint.VbsFiles)
        CallerFiles      = @($checkpoint.CallerFiles)
        Nodes            = @($checkpoint.Nodes)
        Edges            = @($checkpoint.Edges)
        ProcessedVbs     = @($checkpoint.ProcessedVbs)
        ProcessedCallers = @($checkpoint.ProcessedCallers)
        Phases           = $checkpoint.Phases
        Errors           = @($checkpoint.Errors)
    }
}
elseif ($checkpoint) {
    Write-Warning "Checkpoint ignoriert (ScriptsPath oder Version passt nicht)."
}
else {
    Write-Host "Kein Checkpoint gefunden. Starte neuen Lauf." -ForegroundColor Gray
}

Write-Host "Scanne $rootPath ..." -ForegroundColor Cyan
if (-not $state.Phases.InventoryCompleted -or -not $state.VbsFiles -or -not $state.CallerFiles) {
    $vbsFiles, $callerFiles = Get-AllRelevantFiles -RootPath $rootPath
    $state.VbsFiles = @($vbsFiles | ForEach-Object { $_.FullName })
    $state.CallerFiles = @($callerFiles | ForEach-Object { $_.FullName })
    $state.Phases.InventoryCompleted = $true
    Write-Checkpoint -State $state -CheckpointPath $script:CheckpointPath
}
else {
    $vbsFiles = @($state.VbsFiles | ForEach-Object { Get-Item -LiteralPath $_ -ErrorAction SilentlyContinue } | Where-Object { $_ })
    $callerFiles = @($state.CallerFiles | ForEach-Object { Get-Item -LiteralPath $_ -ErrorAction SilentlyContinue } | Where-Object { $_ })
}
Write-Host "Gefunden: $($vbsFiles.Count) VBS-Dateien, $($callerFiles.Count) Aufrufer (BAT/CMD/PS1/KIX)." -ForegroundColor Cyan
if ($state.ProcessedVbs.Count -gt 0 -or $state.ProcessedCallers.Count -gt 0) {
    Write-Host ("Resume: VBS verarbeitet: {0}/{1}; Aufrufer verarbeitet: {2}/{3}" -f $state.ProcessedVbs.Count, $vbsFiles.Count, $state.ProcessedCallers.Count, $callerFiles.Count) -ForegroundColor Yellow
}
if ($vbsFiles.Count -eq 0 -and $callerFiles.Count -eq 0) {
    Write-Warning "Keine VBS-Dateien oder Aufrufer gefunden. Leere HTML wird trotzdem erzeugt."
}

$graph = Build-FlowGraph -VbsFiles $vbsFiles -CallerFiles $callerFiles -RootPath $rootPath -State $state -CheckpointPath $script:CheckpointPath
$outResolved = $OutputPath
if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
    $outResolved = Join-Path -Path (Get-Location) -ChildPath $OutputPath
}
$outDir = [System.IO.Path]::GetDirectoryName($outResolved)
if (-not [string]::IsNullOrEmpty($outDir) -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
Export-VbsFlowchartToHtml -Graph $graph -OutputFilePath $outResolved
$state.Phases.HtmlExported = $true
Write-Checkpoint -State $state -CheckpointPath $script:CheckpointPath

if ($state.Phases.InventoryCompleted -and $state.Phases.ParseVbsCompleted -and $state.Phases.ParseCallersCompleted -and $state.Phases.ContentLoadCompleted -and $state.Phases.HtmlExported) {
    Remove-Item -LiteralPath $script:CheckpointPath -Force -ErrorAction SilentlyContinue
    Write-Host "Checkpoint gelöscht (Lauf vollständig): $script:CheckpointFileName" -ForegroundColor Green
}
