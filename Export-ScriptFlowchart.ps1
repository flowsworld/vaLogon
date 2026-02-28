<#
.SYNOPSIS
    Erstellt eine HTML-Datei mit Flowchart aller Skriptdateien (VBS, BAT, CMD, PS1, PSM1, KIX) und ihrer Aufrufbeziehungen.

.DESCRIPTION
    Findet alle Skriptdateien unter dem angegebenen Stammpfad (z.B. SYSVOL\scripts), löst Aufrufbeziehungen auf
    (wer ruft wen auf) und erzeugt eine einzelne HTML-Datei mit Mermaid-Flowchart und Quellcode aller Skripte;
    Aufrufe/Verlinkungen im Code werden hervorgehoben; Verweise über Top-Ordner-Grenzen werden rot markiert.
    Alle dynamischen Inhalte werden HTML-escaped (XSS-Sanitisierung).

.PARAMETER ScriptsPath
    Stammverzeichnis (z.B. \\domain\SYSVOL\domain\scripts).

.PARAMETER OutputPath
    Pfad der zu erzeugenden HTML-Datei (Default: .\ScriptFlowchart.html).

.PARAMETER Encoding
    Fallback-Encoding beim Lesen von Skriptdateien (Default: UTF8).

.EXAMPLE
    .\Export-ScriptFlowchart.ps1 -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts'

.EXAMPLE
    .\Export-ScriptFlowchart.ps1 -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts' -OutputPath 'D:\Reports\ScriptFlow.html'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScriptsPath,

    [string]$OutputPath = ".\ScriptFlowchart.html",

    [switch]$EnableGlobalView,

    [System.Text.Encoding]$Encoding = [System.Text.Encoding]::UTF8
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:MaxFileBytes = 1MB
$script:VbsExtensions = @('.vbs')
$script:CallerExtensions = @('.bat', '.cmd', '.ps1', '.psm1', '.kix')
$script:AllScriptExtensions = @('.vbs', '.bat', '.cmd', '.ps1', '.psm1', '.kix')

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
    param(
        [string]$ScriptsPathValue,
        [string]$TopFolder
    )
    return [ordered]@{
        Version      = 1
        ScriptsPath  = $ScriptsPathValue
        TopFolder    = $TopFolder
        TimestampUtc = (Get-Date).ToUniversalTime()
        VbsFiles     = @()
        CallerFiles  = @()
        Nodes        = @()
        Edges        = @()
        ProcessedVbs     = @()
        ProcessedCallers = @()
        Phases       = @{
            InventoryCompleted    = $false
            ParseVbsCompleted     = $false
            ParseCallersCompleted = $false
            ContentLoadCompleted  = $false
            HtmlExported          = $false
        }
        Errors       = @()
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

function Test-ContentReferencesScript {
    param([string]$Content)
    if (-not $Content) { return $false }
    $scriptRefPattern = '(?i)(\.(?:vbs|bat|cmd|ps1|psm1|kix)\b|WScript\.Shell\.Run|Execute\s*\(|ExecuteGlobal\s*\(|CALL\s+|RUN\s+|SHELL\s+|&\s*["'']|Start-Process\s+)'
    return $Content -match $scriptRefPattern
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
        if (Test-ContentReferencesScript -Content $content) {
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
    foreach ($ext in @('', '.vbs', '.bat', '.cmd', '.ps1', '.psm1', '.kix')) {
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
            if ($resolved -and [System.IO.Path]::GetExtension($resolved) -in $script:AllScriptExtensions) {
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
                if ($resolved -and [System.IO.Path]::GetExtension($resolved) -in $script:AllScriptExtensions) {
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
            '(?i)&\s*["'']?(.+?\.(?:vbs|bat|cmd|ps1|psm1|kix))["'']?',
            '(?i)\.\s*["'']?(.+?\.(?:vbs|bat|cmd|ps1|psm1|kix))["'']?',
            '(?i)Start-Process\s+["'']?(.+?\.(?:vbs|bat|cmd|ps1|psm1|kix))["'']?',
            '(?i)Invoke-Expression\s+.*["'']?(.+?\.(?:vbs|bat|cmd|ps1|psm1|kix))["'']?',
            '(?i)powershell\.exe.+["'']?(.+?\.(?:vbs|bat|cmd|ps1|psm1|kix))["'']?',
            '(?i)&\s*["'']?([^"''\s]+)["'']?',
            '(?i)\.\s*["'']?([^"''\s]+)["'']?',
            '(?i)Start-Process\s+["'']?([^"''\s]+)["'']?'
        )
        foreach ($rx in $psRegexes) {
            $matchList = [regex]::Matches($content, $rx)
            foreach ($m in $matchList) {
                $rawTarget = $m.Groups[1].Value
                if (-not $rawTarget) { continue }
                $resolved = Resolve-TargetPath -RawTarget $rawTarget -SourceDirectory $dir
                if ($resolved -and [System.IO.Path]::GetExtension($resolved) -in $script:AllScriptExtensions) {
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
                if ($resolved -and [System.IO.Path]::GetExtension($resolved) -in $script:AllScriptExtensions) {
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

function Get-RecursiveInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [pscustomobject[]]$Nodes,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [pscustomobject[]]$Edges
    )
    $nodePaths = @($Nodes | ForEach-Object { $_.FullPath } | Where-Object { $_ })
    if ($nodePaths.Count -eq 0 -or $Edges.Count -eq 0) {
        return [pscustomobject]@{
            RecursiveNodes = @{}
            RecursiveEdges = @{}
        }
    }
    $indexByNode = @{}
    $lowlink = @{}
    $onStack = @{}
    $stack = New-Object System.Collections.Stack
    $adj = @{}
    foreach ($e in $Edges) {
        if (-not $e.SourcePath -or -not $e.TargetPath) { continue }
        if (-not $adj.ContainsKey($e.SourcePath)) {
            $adj[$e.SourcePath] = New-Object System.Collections.Generic.List[string]
        }
        $adj[$e.SourcePath].Add([string]$e.TargetPath)
    }
    $components = New-Object System.Collections.Generic.List[object]
    $index = 0
    $strongConnect = {
        param([string]$v)
        $indexByNode[$v] = $index
        $lowlink[$v] = $index
        $index++
        $stack.Push($v)
        $onStack[$v] = $true
        $neighbors = $null
        if ($adj.ContainsKey($v)) {
            $neighbors = $adj[$v]
        }
        if ($neighbors) {
            foreach ($w in $neighbors) {
                if (-not $indexByNode.ContainsKey($w)) {
                    & $strongConnect $w
                    $lowlink[$v] = [Math]::Min($lowlink[$v], $lowlink[$w])
                }
                elseif ($onStack[$w]) {
                    $lowlink[$v] = [Math]::Min($lowlink[$v], $indexByNode[$w])
                }
            }
        }
        if ($lowlink[$v] -eq $indexByNode[$v]) {
            $component = @()
            while ($true) {
                $w = $stack.Pop()
                $onStack[$w] = $false
                $component += $w
                if ($w -eq $v) { break }
            }
            if ($component.Count -gt 0) {
                [void]$components.Add($component)
            }
        }
    }
    foreach ($v in $nodePaths) {
        if (-not $indexByNode.ContainsKey($v)) {
            & $strongConnect $v
        }
    }
    $recursiveNodes = @{}
    foreach ($comp in $components) {
        if ($comp.Count -gt 1) {
            foreach ($p in $comp) {
                $recursiveNodes[$p] = $true
            }
        }
        elseif ($comp.Count -eq 1) {
            $p = $comp[0]
            foreach ($e in $Edges) {
                if ($e.SourcePath -and $e.TargetPath -and $e.SourcePath -eq $p -and $e.TargetPath -eq $p) {
                    $recursiveNodes[$p] = $true
                    break
                }
            }
        }
    }
    $recursiveEdges = @{}
    foreach ($e in $Edges) {
        if (-not $e.SourcePath -or -not $e.TargetPath) { continue }
        if ($recursiveNodes.ContainsKey($e.SourcePath) -and $recursiveNodes.ContainsKey($e.TargetPath)) {
            $key = "$($e.SourcePath)->$($e.TargetPath)"
            $recursiveEdges[$key] = $true
        }
    }
    return [pscustomobject]@{
        RecursiveNodes = $recursiveNodes
        RecursiveEdges = $recursiveEdges
    }
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
                    SourcePath     = $e.SourcePath
                    TargetPath     = $e.TargetPath
                    RawCall        = $e.RawCall
                    IsCrossBoundary = $false
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
            # In einigen Umgebungen schlagen Funktionsaufrufe mit leerem String für -Content fehl.
            # Leere Dateien überspringen wir deshalb an dieser Stelle.
            if ([string]::IsNullOrEmpty($content)) {
                [void]$processedVbs.Add($v.FullName)
                $batch++
                if ($batch -ge 50) { $batch = 0; & $persist $null }
                continue
            }
            $dir = $v.DirectoryName
            $outEdges = Get-VbsCallsFromContent -Content $content -SourcePath $v.FullName -SourceDirectory $dir
            foreach ($e in $outEdges) {
                $key = "$($e.SourcePath)->$($e.TargetPath)"
                if ($seenEdges[$key]) { continue }
                $seenEdges[$key] = $true
                $targetNode = & $ensureNode $nodes $e.TargetPath $null $null
                if ($targetNode -and -not $targetNode.Content -and [System.IO.Path]::GetExtension($e.TargetPath) -in $script:AllScriptExtensions) {
                    $targetNode.Content = Get-FileContentSafe -Path $e.TargetPath
                }
                $e2 = [pscustomobject]@{ SourcePath = $e.SourcePath; TargetPath = $e.TargetPath; RawCall = $e.RawCall; IsCrossBoundary = $false }
                $edges += $e2
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
            if ([string]::IsNullOrEmpty($content)) {
                [void]$processedCallers.Add($c.FullName)
                $batch++
                if ($batch -ge 50) { $batch = 0; & $persist $null }
                continue
            }
            $dir = $c.DirectoryName
            $outEdges = Get-CallersOfVbs -Content $content -SourcePath $c.FullName -SourceDirectory $dir -Extension $c.Extension.ToLowerInvariant()
            foreach ($e in $outEdges) {
                $key = "$($e.SourcePath)->$($e.TargetPath)"
                if ($seenEdges[$key]) { continue }
                $seenEdges[$key] = $true
                $null = & $ensureNode $nodes $e.TargetPath $null $null
                $e2 = [pscustomobject]@{ SourcePath = $e.SourcePath; TargetPath = $e.TargetPath; RawCall = $e.RawCall; IsCrossBoundary = $false }
                $edges += $e2
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
    $rootTrimmed = $RootPath.TrimEnd('\', '/')
    foreach ($e in $edges) {
        $srcTop = Get-NodeTopFolder -FullPath $e.SourcePath -RootPath $RootPath
        $tgtTop = Get-NodeTopFolder -FullPath $e.TargetPath -RootPath $RootPath
        $targetUnderRoot = $e.TargetPath -and $e.TargetPath.StartsWith($rootTrimmed, [StringComparison]::OrdinalIgnoreCase)
        $e.IsCrossBoundary = (-not $targetUnderRoot) -or ($srcTop -ne $tgtTop)
    }
    $recInfo = Get-RecursiveInfo -Nodes $nodeList -Edges $edges
    $recursiveNodes = $recInfo.RecursiveNodes
    $recursiveEdges = $recInfo.RecursiveEdges
    foreach ($n in $nodeList) {
        $isRec = $false
        if ($n.FullPath -and $recursiveNodes.ContainsKey($n.FullPath)) {
            $isRec = $true
        }
        $n | Add-Member -NotePropertyName 'IsRecursive' -NotePropertyValue $isRec -Force
    }
    foreach ($e in $edges) {
        $key = "$($e.SourcePath)->$($e.TargetPath)"
        $isRec = $false
        if ($e.SourcePath -and $e.TargetPath -and $recursiveEdges.ContainsKey($key)) {
            $isRec = $true
        }
        $e | Add-Member -NotePropertyName 'IsRecursive' -NotePropertyValue $isRec -Force
    }
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
    $typeStyle = @{ VBS = 'fill:#dbeafe,stroke:#1e40af'; BAT = 'fill:#fef3c7,stroke:#92400e'; CMD = 'fill:#fef3c7,stroke:#92400e'; PS1 = 'fill:#dcfce7,stroke:#166534'; PSM1 = 'fill:#dcfce7,stroke:#166534'; KIX = 'fill:#f3e8ff,stroke:#6b21a8' }
    foreach ($n in $Graph.Nodes) {
        $s = $typeStyle[$n.Type]
        if ($s) { [void]$sb.AppendLine("  style $($n.Id) $s") }
    }
    $edgeIndex = 0
    foreach ($e in $Graph.Edges) {
        $sid = $idByPath[$e.SourcePath]
        $tid = $idByPath[$e.TargetPath]
        if ($sid -and $tid) {
            [void]$sb.AppendLine("  $sid --> $tid")
            $edgeIndex++
        }
    }
    foreach ($n in $Graph.Nodes) {
        [void]$sb.AppendLine("  click $($n.Id) href `"#code-$($n.Id)`"")
    }
    $idx = 0
    foreach ($e in $Graph.Edges) {
        $sid = $idByPath[$e.SourcePath]
        $tid = $idByPath[$e.TargetPath]
        if ($sid -and $tid -and $e.IsCrossBoundary) {
            [void]$sb.AppendLine("  linkStyle $idx stroke:red,stroke-width:2px")
        }
        if ($sid -and $tid) { $idx++ }
    }
    return $sb.ToString()
}

function Get-NodeTopFolder {
    param([string]$FullPath, [string]$RootPath)
    $rootTrimmed = $RootPath.TrimEnd('\', '/')
    $rel = $FullPath
    if ($rel.StartsWith($rootTrimmed, [StringComparison]::OrdinalIgnoreCase)) {
        $rel = $rel.Substring($rootTrimmed.Length).TrimStart('\', '/')
    }
    # Dateien direkt unter Root (ein Segment, kein Unterordner) → (Root)
    if ([string]::IsNullOrWhiteSpace($rel) -or $rel -notmatch '[\\/]') { return '(Root)' }
    $seg = ($rel -split '[\\/]')[0]
    if ([string]::IsNullOrWhiteSpace($seg)) { return '(Root)' }
    return $seg
}

function Get-CodeWithHighlightedLinks {
    param(
        [string]$Content,
        [string[]]$SameFolderSnippets = @(),
        [string[]]$CrossBoundarySnippets = @()
    )
    if (-not $Content) { return '' }
    $escaped = [System.Net.WebUtility]::HtmlEncode($Content)
    $cross = @($CrossBoundarySnippets | Where-Object { $_ } | Sort-Object -Property Length -Descending)
    $same = @($SameFolderSnippets | Where-Object { $_ } | Sort-Object -Property Length -Descending)
    foreach ($snip in $cross) {
        $snipEscaped = [System.Net.WebUtility]::HtmlEncode($snip)
        if ($snipEscaped.Length -gt 0 -and $escaped.IndexOf($snipEscaped, [StringComparison]::Ordinal) -ge 0) {
            $highlight = "<span class=`"bg-red-200 text-red-900 rounded px-0.5 font-semibold`" title=`"Verweis in anderen Top-Ordner / nach außen`">" + $snipEscaped + "</span>"
            $escaped = $escaped.Replace($snipEscaped, $highlight)
        }
    }
    foreach ($snip in $same) {
        $snipEscaped = [System.Net.WebUtility]::HtmlEncode($snip)
        if ($snipEscaped.Length -gt 0 -and $escaped.IndexOf($snipEscaped, [StringComparison]::Ordinal) -ge 0) {
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

function Export-ScriptFlowchartToHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Graph,
        [Parameter(Mandatory = $true)]
        [string]$OutputFilePath,
        [Parameter(Mandatory = $true)]
        [string]$RootPath,
        [switch]$EnableGlobalView
    )
    $rootTrimmed = $RootPath.TrimEnd('\', '/')
    $nodesWithTop = @($Graph.Nodes | ForEach-Object {
        $top = Get-NodeTopFolder -FullPath $_.FullPath -RootPath $RootPath
        [pscustomobject]@{ Node = $_; TopFolder = $top }
    })
    $topFoldersList = @($nodesWithTop | ForEach-Object { $_.TopFolder } | Sort-Object -Unique)

    $reportNodes = @($nodesWithTop | ForEach-Object {
        $node = $_.Node
        $top  = $_.TopFolder
        $full = $node.FullPath
        $isExternal = $false
        $relative = $full
        $folderDepth = 0
        $parentFolder = ''
        $folderLabel  = '(Root)'
        if ($full) {
            if ($full.StartsWith($rootTrimmed, [StringComparison]::OrdinalIgnoreCase)) {
                $relative = $full.Substring($rootTrimmed.Length).TrimStart('\', '/')
                $segments = $relative -split '[\\/]'
                if ($segments.Length -gt 1) {
                    # Verzeichnis-Tiefe relativ zu RootPath (Anzahl Verzeichnisse)
                    $folderDepth = $segments.Length - 1
                    $parentFolder = $segments[0..($segments.Length - 2)] -join '/'
                    $folderLabel = $segments[$segments.Length - 2]
                }
                else {
                    $folderDepth = 0
                    $parentFolder = ''
                    $folderLabel = 'scripts'
                }
            }
            else {
                # Ziel außerhalb von ScriptsPath
                $isExternal = $true
            }
        }
        [ordered]@{
            id           = $node.Id
            fullPath     = $full
            displayName  = $node.DisplayName
            type         = $node.Type
            topFolder    = $top
            relativePath = $relative
            folderDepth  = $folderDepth
            parentFolder = $parentFolder
            folderLabel  = $folderLabel
            isExternal   = $isExternal
            isRecursive  = [bool]$node.IsRecursive
        }
    })
    $reportEdges = @($Graph.Edges | ForEach-Object {
        [ordered]@{
            sourcePath      = $_.SourcePath
            targetPath      = $_.TargetPath
            isCrossBoundary = [bool]$_.IsCrossBoundary
            isRecursive     = [bool]$_.IsRecursive
        }
    })
    $reportData = @{ nodes = $reportNodes; edges = $reportEdges } | ConvertTo-Json -Depth 3 -Compress
    $reportDataEscaped = $reportData -replace '</', '\u003c/'

    $mermaidGesamtSafe = ''
    if ($EnableGlobalView) {
        $mermaidGesamt = Get-MermaidFlowchart -Graph $Graph
        $mermaidGesamtSafe = Get-HtmlSafeMermaid -MermaidCode $mermaidGesamt
    }
    $flowchartContainerHtml = @"
    <div class="flowchart-container">
      <div id="mermaid-target" class="mermaid">$mermaidGesamtSafe</div>
    </div>
"@

    $dropdownTopOptions = ($topFoldersList | Where-Object { $_ -ne '(Root)' } | ForEach-Object {
        $enc = [System.Net.WebUtility]::HtmlEncode($_)
        "        <option value=`"$enc`">$enc</option>"
    }) -join "`n"
    $gesamtOptionLine = if ($EnableGlobalView) { '          <option value="">Gesamt</option>' } else { '' }
    $dropdownTypeOptions = (@('', 'VBS', 'BAT', 'CMD', 'PS1', 'PSM1', 'KIX') | ForEach-Object {
        $label = if ($_ -eq '') { 'Gesamt' } else { $_ }
        $val = [System.Net.WebUtility]::HtmlEncode($_)
        "        <option value=`"$val`">$label</option>"
    }) -join "`n"
    $filterBlock = @"
    <div class="mb-6 flex flex-wrap items-center gap-4">
      <div class="flex items-center gap-2">
        <label for="filter-topfolder" class="text-sm font-medium text-gray-700">Filter: Top-Ordner</label>
        <select id="filter-topfolder" class="rounded border border-gray-300 px-3 py-1.5 text-gray-900 focus:ring-2 focus:ring-blue-500">
$gesamtOptionLine
$dropdownTopOptions
        </select>
      </div>
      <div class="flex items-center gap-2">
        <label for="filter-type" class="text-sm font-medium text-gray-700">Filter: Dateityp</label>
        <select id="filter-type" class="rounded border border-gray-300 px-3 py-1.5 text-gray-900 focus:ring-2 focus:ring-blue-500">
$dropdownTypeOptions
        </select>
      </div>
    </div>
"@

    $graphEdges = @($Graph.Edges)
    $codeSections = [System.Text.StringBuilder]::new()
    foreach ($nw in $nodesWithTop) {
        $n = $nw.Node
        $topFolder = $nw.TopFolder
        $topFolderEnc = [System.Net.WebUtility]::HtmlEncode($topFolder)
        $safeId = $n.Id -replace '[^A-Za-z0-9_-]', '_'
        $anchorId = "code-" + $safeId
        $displayName = [System.Net.WebUtility]::HtmlEncode($n.DisplayName)
        $fullPath = [System.Net.WebUtility]::HtmlEncode($n.FullPath)
        $typeLabel = switch ($n.Type) { 'VBS' { 'VBS' } 'BAT' { 'BAT' } 'CMD' { 'CMD' } 'PS1' { 'PS1' } 'PSM1' { 'PSM1' } 'KIX' { 'KIX' } default { 'Skript' } }
        $outgoing = @($graphEdges | Where-Object { $_.SourcePath -eq $n.FullPath })
        $sameSnippets = @($outgoing | Where-Object { -not $_.IsCrossBoundary } | ForEach-Object { $_.RawCall } | Where-Object { $_ })
        $crossSnippets = @($outgoing | Where-Object { $_.IsCrossBoundary } | ForEach-Object { $_.RawCall } | Where-Object { $_ })
        $codeWithHighlights = Get-CodeWithHighlightedLinks -Content $n.Content -SameFolderSnippets $sameSnippets -CrossBoundarySnippets $crossSnippets
        if (-not $n.Content) {
            $codeWithHighlights = [System.Net.WebUtility]::HtmlEncode("# Datei nicht lesbar oder leer: $($n.FullPath)")
        }
        $hasLinks = ($sameSnippets.Count + $crossSnippets.Count) -gt 0
        $legendText = if ($crossSnippets.Count -gt 0) { "Gelb: Aufruf im gleichen Top-Ordner. Rot: Verweis in anderen Top-Ordner / nach außen." } else { "Gelb markiert: Aufruf/Verlinkung zu anderen Dateien" }
        [void]$codeSections.AppendLine(@"
    <section id="$anchorId" class="mb-8 scroll-mt-8" data-topfolder="$topFolderEnc" data-type="$typeLabel">
      <h2 class="text-xl font-semibold text-gray-800 mb-2">
        <a href="#$anchorId" class="text-blue-600 hover:underline">$displayName</a>
        <span class="ml-2 text-sm font-normal text-gray-500">($typeLabel)</span>
      </h2>
      <p class="text-sm text-gray-500 mb-2 font-mono">$fullPath</p>
$(if ($hasLinks) { "      <p class=`"text-xs text-amber-700 mb-1`">$legendText</p>" })
      <pre class="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto text-sm"><code>$codeWithHighlights</code></pre>
    </section>
"@)
    }
$filterScript = @"
(function() {
  var selectTop = document.getElementById('filter-topfolder');
  var selectType = document.getElementById('filter-type');
  var mermaidTarget = document.getElementById('mermaid-target');
  var sections = document.querySelectorAll('section[data-topfolder]');
  var dataEl = document.getElementById('reportData');
  var reportData = (dataEl && dataEl.textContent) ? JSON.parse(dataEl.textContent) : { nodes: [], edges: [] };
  var nodes = reportData.nodes || [];
  var edges = reportData.edges || [];
  var renderId = 0;
  function escapeMermaidLabel(s) {
    if (!s) return '';
    return String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\[/g, '\\[').replace(/\]/g, '\\]');
  }
  function buildMermaidCode(filteredNodes, filteredEdges, topVal) {
    if (!filteredNodes || filteredNodes.length === 0) {
      return '';
    }
    // Root-Ansicht entbehrlich: Knoten mit Top-Ordner (Root) aus Diagramm ausblenden
    filteredNodes = filteredNodes.filter(function(n) { return n.topFolder !== '(Root)'; });
    if (filteredNodes.length === 0) {
      return '';
    }
    var pathSet = {};
    var idByPath = {};
    var nodeById = {};
    filteredNodes.forEach(function(n) {
      pathSet[n.fullPath] = true;
      idByPath[n.fullPath] = n.id;
      nodeById[n.id] = n;
    });
    filteredEdges = (filteredEdges || []).filter(function(e) {
      return pathSet[e.sourcePath] && pathSet[e.targetPath];
    });
    var lines = ['flowchart LR'];

    // Knoten nach Ordner (parentFolder) und externen Zielen gruppieren – ein Subgraph pro Ordner
    var folderMap = {};   // parentFolder -> [nodeId]
    var externalIds = [];
    filteredNodes.forEach(function(n) {
      if (n.isExternal) {
        externalIds.push(n.id);
        return;
      }
      var key = (n.parentFolder != null && n.parentFolder !== undefined) ? String(n.parentFolder) : '';
      if (!folderMap[key]) folderMap[key] = [];
      folderMap[key].push(n.id);
    });

    function folderDepth(path) {
      if (!path || path === '') return 0;
      return (path.match(/[/\\]/g) || []).length + 1;
    }
    var folderKeys = Object.keys(folderMap).sort(function(a, b) {
      var da = folderDepth(a), db = folderDepth(b);
      if (da !== db) return da - db;
      return (a || '').localeCompare(b || '');
    });

    // Nach Tiefe gruppieren: jede Tiefe = eine Spalte (links nach rechts), Ordner gleicher Ebene untereinander
    var byDepth = {};
    folderKeys.forEach(function(parentFolder) {
      var d = folderDepth(parentFolder);
      if (!byDepth[d]) byDepth[d] = [];
      byDepth[d].push(parentFolder);
    });
    var depthOrder = Object.keys(byDepth).map(Number).sort(function(a, b) { return a - b; });

    // Pro Ordner einen Anker (erster Knoten); Reihenfolge = Tiefe, dann Pfad
    var anchorsByDepth = {};
    depthOrder.forEach(function(d) { anchorsByDepth[d] = []; });

    depthOrder.forEach(function(d) {
      var folderList = byDepth[d];
      lines.push('  subgraph col_d' + d + ' [" "]');
      folderList.forEach(function(parentFolder) {
        var sgId = (parentFolder === '') ? 'root' : ('folder_' + parentFolder.replace(/[/\\]/g, '_').replace(/[^A-Za-z0-9_]/g, '_'));
        var label = 'scripts';
        var nodeIds = folderMap[parentFolder];
        if (nodeIds.length && nodeById[nodeIds[0]] && nodeById[nodeIds[0]].folderLabel != null) {
          label = nodeById[nodeIds[0]].folderLabel;
        } else if (parentFolder !== '') {
          var parts = parentFolder.split(/[/\\]/);
          label = parts[parts.length - 1] || parentFolder;
        }
        if (nodeIds.length > 0) {
          anchorsByDepth[d].push(nodeIds[0]);
        }
        lines.push('    subgraph ' + sgId + ' ["' + escapeMermaidLabel(label) + '"]');
        nodeIds.forEach(function(nodeId) {
          var n = nodeById[nodeId];
          if (!n) return;
          var typeLabel = n.type || '';
          var lbl = typeLabel ? n.displayName + ' (' + typeLabel + ')' : n.displayName;
          if (n.isRecursive) {
            lbl += ' [REC]';
          }
          lines.push('      ' + n.id + '["' + escapeMermaidLabel(lbl) + '"]');
        });
        lines.push('    end');
      });
      lines.push('  end');
    });

    // Externe Ziele in eigene Spalte
    if (externalIds.length > 0) {
      lines.push('  subgraph external ["Extern"]');
      externalIds.forEach(function(nodeId) {
        var n = nodeById[nodeId];
        if (!n) return;
        var typeLabel = n.type || '';
        var lbl = typeLabel ? n.displayName + ' (' + typeLabel + ')' : n.displayName;
        if (n.isRecursive) {
          lbl += ' [REC]';
        }
        lines.push('    ' + n.id + '["' + escapeMermaidLabel(lbl) + '"]');
      });
      lines.push('  end');
    }

    // Knotenfaerbung gemaess Legende: VBS=blau, BAT/CMD=amber, PS1/PSM1=gruen, KIX=lila
    var typeStyle = { VBS: 'fill:#dbeafe,stroke:#1e40af', BAT: 'fill:#fef3c7,stroke:#92400e', CMD: 'fill:#fef3c7,stroke:#92400e', PS1: 'fill:#dcfce7,stroke:#166534', PSM1: 'fill:#dcfce7,stroke:#166534', KIX: 'fill:#f3e8ff,stroke:#6b21a8' };
    filteredNodes.forEach(function(n) {
      var s = typeStyle[n.type];
      if (s) {
        lines.push('  style ' + n.id + ' ' + s);
      }
    });

    // Layout-Kanten: VERPFLICHTEND links nach rechts pro Ebene
    // - Gleiche Ebene: ~~~ (gleicher Rank) zwischen Ankern derselben Tiefe -> Ordner untereinander
    // - Naechste Ebene: --> von letztem Anker der Tiefe zum ersten der naechsten -> naechste Spalte rechts
    var layoutEdgeCount = 0;
    for (var di = 0; di < depthOrder.length; di++) {
      var anchors = anchorsByDepth[depthOrder[di]] || [];
      for (var ai = 0; ai < anchors.length - 1; ai++) {
        lines.push('  ' + anchors[ai] + ' ~~~ ' + anchors[ai + 1]);
        layoutEdgeCount++;
      }
      if (di < depthOrder.length - 1) {
        var nextAnchors = anchorsByDepth[depthOrder[di + 1]] || [];
        if (anchors.length > 0 && nextAnchors.length > 0) {
          lines.push('  ' + anchors[anchors.length - 1] + ' --> ' + nextAnchors[0]);
          layoutEdgeCount++;
        }
      }
    }

    var edgeIndex = 0;
    var crossBoundaryIndices = [];
    filteredEdges.forEach(function(e) {
      var sid = idByPath[e.sourcePath];
      var tid = idByPath[e.targetPath];
      if (sid && tid) {
        lines.push('  ' + sid + ' --> ' + tid);
        if (e.isCrossBoundary) crossBoundaryIndices.push(layoutEdgeCount + edgeIndex);
        edgeIndex++;
      }
    });
    filteredNodes.forEach(function(n) {
      lines.push('  click ' + n.id + ' href "#code-' + n.id.replace(/[^A-Za-z0-9_-]/g, '_') + '"');
    });
    for (var li = 0; li < layoutEdgeCount; li++) {
      lines.push('  linkStyle ' + li + ' stroke:none,stroke-width:0');
    }
    crossBoundaryIndices.forEach(function(idx) {
      lines.push('  linkStyle ' + idx + ' stroke:red,stroke-width:2px');
    });
    return lines.join('\n');
  }
  function renderMermaid(code) {
    if (!mermaidTarget || typeof mermaid === 'undefined') return;
    if (!code || !code.trim()) { mermaidTarget.innerHTML = ''; return; }
    var id = 'mermaid-render-' + (++renderId);
    mermaid.render(id, code).then(function(result) {
      mermaidTarget.innerHTML = result.svg || '';
      if (result.bindFunctions) result.bindFunctions(mermaidTarget);
    }).catch(function(err) {
      mermaidTarget.textContent = 'Diagramm-Fehler: ' + (err.message || String(err));
    });
  }
  function applyFilter() {
    var topVal = selectTop ? selectTop.value : '';
    var typeVal = selectType ? selectType.value : '';
    var filteredNodes = nodes.filter(function(n) {
      var topOk = topVal === '' || n.topFolder === topVal;
      var typeOk = typeVal === '' || n.type === typeVal;
      return topOk && typeOk;
    });
    var pathSet = {};
    filteredNodes.forEach(function(n) { pathSet[n.fullPath] = true; });
    var filteredEdges = edges.filter(function(e) {
      return pathSet[e.sourcePath] && pathSet[e.targetPath];
    });
    var code = buildMermaidCode(filteredNodes, filteredEdges, topVal);
    renderMermaid(code);
    sections.forEach(function(sec) {
      var tf = sec.getAttribute('data-topfolder') || '';
      var typ = sec.getAttribute('data-type') || '';
      var topOk = topVal === '' || tf === topVal;
      var typeOk = typeVal === '' || typ === typeVal;
      sec.style.display = (topOk && typeOk) ? '' : 'none';
    });
  }
  if (selectTop) selectTop.addEventListener('change', applyFilter);
  if (selectType) selectType.addEventListener('change', applyFilter);
  applyFilter();
})();
"@
    $html = @"
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <title>Skript-Flowchart – Aufrufbeziehungen</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
</head>
<body class="bg-gray-50 text-gray-900 min-h-screen">
  <div class="max-w-7xl mx-auto px-4 py-8">
    <header class="mb-8">
      <h1 class="text-3xl font-bold text-gray-900">Skript-Flowchart</h1>
      <p class="mt-2 text-gray-600">Aufrufbeziehungen: Pfeil = „ruft auf“ (von Aufrufer zu aufgerufener Datei). Knoten mit [REC] im Namen gehören zu rekursiven Aufrufzyklen.</p>
      <div class="mt-2 flex flex-wrap gap-2">
        <span class="px-2 py-1 rounded bg-blue-100 text-blue-800 text-sm">VBS</span>
        <span class="px-2 py-1 rounded bg-amber-100 text-amber-800 text-sm">BAT/CMD</span>
        <span class="px-2 py-1 rounded bg-green-100 text-green-800 text-sm">PS1/PSM1</span>
        <span class="px-2 py-1 rounded bg-purple-100 text-purple-800 text-sm">KiXtart</span>
      </div>
    </header>
    $filterBlock
    <section class="mb-8 bg-white rounded-xl shadow p-4 overflow-x-auto">
      <h2 class="text-lg font-semibold text-gray-800 mb-3">Flowchart</h2>
$flowchartContainerHtml
    </section>

    <h2 class="text-2xl font-bold text-gray-900 mt-12 mb-4">Quellcode (alle Skripte)</h2>
    <p class="text-gray-600 mb-4">Alle aufrufenden und aufgerufenen Dateien (VBS, BAT, CMD, PS1, KiXtart). Knoten mit [REC] im Namen gehören zu rekursiven Aufrufzyklen. Gelb: Aufruf im gleichen Top-Ordner. Rot: Verweis in anderen Top-Ordner oder nach außen. Rote Pfeile im Diagramm = gleiche Bedeutung.</p>
$($codeSections.ToString())
  <script type="application/json" id='reportData'>$reportDataEscaped</script>
  </div>
  <script>
    mermaid.initialize({ startOnLoad: false, flowchart: { useMaxWidth: true, htmlLabels: true } });
  </script>
  <script>
$filterScript
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
# Provider-Qualifier (z.B. 'Microsoft.PowerShell.Core\FileSystem::') entfernen,
# damit $rootPath zum Format von $v.FullName / $c.FullName passt.
$rootPath = $rootResolved.ProviderPath

Write-Host "Scanne $rootPath ..." -ForegroundColor Cyan
$vbsFiles, $callerFiles = Get-AllRelevantFiles -RootPath $rootPath

if ($vbsFiles.Count -eq 0 -and $callerFiles.Count -eq 0) {
    Write-Warning "Keine VBS-Dateien oder Aufrufer gefunden. Leere HTML wird trotzdem erzeugt."
}

# Dateien nach Top-Ordner gruppieren
$groups = @{}
foreach ($v in $vbsFiles) {
    $top = Get-NodeTopFolder -FullPath $v.FullName -RootPath $rootPath
    if (-not $groups.ContainsKey($top)) {
        $groups[$top] = [ordered]@{ VbsFiles = @(); CallerFiles = @() }
    }
    $groups[$top].VbsFiles += $v
}
foreach ($c in $callerFiles) {
    $top = Get-NodeTopFolder -FullPath $c.FullName -RootPath $rootPath
    if (-not $groups.ContainsKey($top)) {
        $groups[$top] = [ordered]@{ VbsFiles = @(); CallerFiles = @() }
    }
    $groups[$top].CallerFiles += $c
}

Write-Host ("Gefunden: {0} VBS-Dateien, {1} Aufrufer (BAT/CMD/PS1/KIX) in {2} Top-Ordner(n)." -f $vbsFiles.Count, $callerFiles.Count, $groups.Keys.Count) -ForegroundColor Cyan

# Aggregierte Ergebnisstrukturen
$allNodesByPath = @{}
$allEdges = @()
$allEdgeKeys = @{}
$checkpointPaths = @()

foreach ($top in ($groups.Keys | Sort-Object)) {
    $group = $groups[$top]
    $topVbsFiles = $group.VbsFiles
    $topCallerFiles = $group.CallerFiles

    Write-Host ("Verarbeite Top-Ordner '{0}' (VBS: {1}, Aufrufer: {2}) ..." -f $top, $topVbsFiles.Count, $topCallerFiles.Count) -ForegroundColor Cyan

    if ($topVbsFiles.Count -eq 0 -and $topCallerFiles.Count -eq 0) {
        Write-Warning "Top-Ordner '$top' hat keine VBS-Dateien oder Aufrufer. Überspringe Graphaufbau."
        continue
    }

    $topSafe = $top -replace '[^A-Za-z0-9_\-]', '_'
    if ([string]::IsNullOrWhiteSpace($topSafe)) { $topSafe = 'Root' }
    $checkpointFileName = "script_flowchart_checkpoint_$topSafe.json"
    $checkpointPath = Join-Path -Path (Get-Location) -ChildPath $checkpointFileName
    $checkpointPaths += $checkpointPath

    $state = $null
    $checkpoint = Read-Checkpoint -CheckpointPath $checkpointPath
    if ($checkpoint -and $checkpoint.ScriptsPath -eq $rootPath -and $checkpoint.Version -eq 1 -and $checkpoint.TopFolder -eq $top) {
        Write-Host "Checkpoint für Top-Ordner '$top' gefunden, setze fort: $checkpointFileName" -ForegroundColor Yellow
        $state = [ordered]@{
            Version          = 1
            ScriptsPath      = $checkpoint.ScriptsPath
            TopFolder        = $checkpoint.TopFolder
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
        Write-Warning "Checkpoint für Top-Ordner '$top' ignoriert (ScriptsPath, Version oder TopFolder passt nicht)."
    }

    if (-not $state) {
        $state = New-VbsFlowState -ScriptsPathValue $rootPath -TopFolder $top
    }

    if (-not $state.Phases.InventoryCompleted -or -not $state.VbsFiles -or -not $state.CallerFiles) {
        $state.VbsFiles = @($topVbsFiles | ForEach-Object { $_.FullName })
        $state.CallerFiles = @($topCallerFiles | ForEach-Object { $_.FullName })
        $state.Phases.InventoryCompleted = $true
        Write-Checkpoint -State $state -CheckpointPath $checkpointPath
    }
    else {
        $topVbsFiles = @($state.VbsFiles | ForEach-Object { Get-Item -LiteralPath $_ -ErrorAction SilentlyContinue } | Where-Object { $_ })
        $topCallerFiles = @($state.CallerFiles | ForEach-Object { Get-Item -LiteralPath $_ -ErrorAction SilentlyContinue } | Where-Object { $_ })
    }

    if ($state.ProcessedVbs.Count -gt 0 -or $state.ProcessedCallers.Count -gt 0) {
        Write-Host ("Resume für Top-Ordner '{0}': VBS verarbeitet: {1}/{2}; Aufrufer verarbeitet: {3}/{4}" -f $top, $state.ProcessedVbs.Count, $topVbsFiles.Count, $state.ProcessedCallers.Count, $topCallerFiles.Count) -ForegroundColor Yellow
    }

    $graphPart = Build-FlowGraph -VbsFiles $topVbsFiles -CallerFiles $topCallerFiles -RootPath $rootPath -State $state -CheckpointPath $checkpointPath

    foreach ($n in $graphPart.Nodes) {
        if (-not $n.FullPath) { continue }
        if (-not $allNodesByPath.ContainsKey($n.FullPath)) {
            $allNodesByPath[$n.FullPath] = $n
        }
    }

    foreach ($e in $graphPart.Edges) {
        if (-not $e.SourcePath -or -not $e.TargetPath) { continue }
        $edgeKey = "$($e.SourcePath)->$($e.TargetPath)"
        if (-not $allEdgeKeys.ContainsKey($edgeKey)) {
            $allEdgeKeys[$edgeKey] = $true
            $allEdges += $e
        }
    }
}

$combinedNodes = @($allNodesByPath.Values)

if ($combinedNodes.Count -gt 0 -and $allEdges.Count -gt 0) {
    $recInfoCombined = Get-RecursiveInfo -Nodes $combinedNodes -Edges $allEdges
    $recursiveNodesCombined = $recInfoCombined.RecursiveNodes
    $recursiveEdgesCombined = $recInfoCombined.RecursiveEdges

    foreach ($n in $combinedNodes) {
        $isRec = $false
        if ($n.FullPath -and $recursiveNodesCombined.ContainsKey($n.FullPath)) {
            $isRec = $true
        }
        $n | Add-Member -NotePropertyName 'IsRecursive' -NotePropertyValue $isRec -Force
    }

    foreach ($e in $allEdges) {
        $key = "$($e.SourcePath)->$($e.TargetPath)"
        $isRec = $false
        if ($e.SourcePath -and $e.TargetPath -and $recursiveEdgesCombined.ContainsKey($key)) {
            $isRec = $true
        }
        $e | Add-Member -NotePropertyName 'IsRecursive' -NotePropertyValue $isRec -Force
    }
}

$combinedGraph = [pscustomobject]@{
    Nodes     = $combinedNodes
    Edges     = $allEdges
    GetNodeId = $null
}

$outResolved = $OutputPath
if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
    $outResolved = Join-Path -Path (Get-Location) -ChildPath $OutputPath
}
$outDir = [System.IO.Path]::GetDirectoryName($outResolved)
if (-not [string]::IsNullOrEmpty($outDir) -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

Export-ScriptFlowchartToHtml -Graph $combinedGraph -OutputFilePath $outResolved -RootPath $rootPath -EnableGlobalView:$EnableGlobalView

foreach ($cp in ($checkpointPaths | Sort-Object -Unique)) {
    if (Test-Path -LiteralPath $cp) {
        Remove-Item -LiteralPath $cp -Force -ErrorAction SilentlyContinue
    }
}
