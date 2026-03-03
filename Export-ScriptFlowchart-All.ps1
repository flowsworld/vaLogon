<#
.SYNOPSIS
    Erstellt eine HTML-Datei mit einem Mermaid-Flowchart aller Dateien
    unterhalb eines Skript-Stammpfads und aller gefundenen Dateiverknüpfungen.

.DESCRIPTION
    - Durchsucht ein Skript-Stammverzeichnis (z.B. \\domain\SYSVOL\domain\scripts)
      rekursiv nach Dateien.
    - Jede gefundene Datei (inkl. .exe, .dll, .lnk usw.) wird als Knoten im
      Mermaid-Flowchart dargestellt.
    - In textbasierten Dateien (Skripte, INI, TXT, XML, JSON, …) werden
      Vorkommen von Dateinamen erkannt (z.B. "login.vbs", "setup.exe",
      "VAESAPP.lnk") und als Verknüpfung von aufrufender Datei zu Ziel-Datei
      modelliert.
    - Wird ein Dateiname gefunden, zu dem es unterhalb des ScriptsPath eine
      passende Datei gibt, entsteht eine Kante im Flowchart.
      Existiert keine passende Datei, wird ein externer Ziel-Knoten erzeugt.
    - Es wird ausschließlich nach Dateinamen (inkl. Erweiterung) gesucht,
      unabhängig davon, ob der Aufruf über wscript, kix32, Copy-Operationen
      oder Konfigurationswerte erfolgt.
    - Das Flowchart ist nach Ordner-Tiefe von links (Root/oberste Ebene)
      nach rechts (tiefere Ordner) gruppiert. Zusätzlich gibt es einen
      Filter nach Top-Ordner (erstes Unterverzeichnis unterhalb von ScriptsPath).
    - Es gibt KEINEN Dateityp-Filter im UI – alle Dateien bleiben sichtbar.

.PARAMETER ScriptsPath
    Stammverzeichnis (z.B. \\domain\SYSVOL\domain\scripts).

.PARAMETER OutputPath
    Pfad der zu erzeugenden HTML-Datei (Default: .\ScriptFlowchart-All.html).

.PARAMETER ExcludeFolders
    Liste relativer Ordnerpfade unterhalb von ScriptsPath, die inklusive
    ihrer Unterordner bei der Analyse ignoriert werden sollen
    (z. B. 2217, 2217/Legacy, 2236/Test).

.PARAMETER Encoding
    Fallback-Encoding beim Lesen textbasierter Dateien (Default: UTF8).

.EXAMPLE
    .\Export-ScriptFlowchart-All.ps1 -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts'

.EXAMPLE
    .\Export-ScriptFlowchart-All.ps1 -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts' -OutputPath 'D:\Reports\ScriptFlow-All.html'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScriptsPath,

    [string]$OutputPath = ".\ScriptFlowchart-All.html",

    [string[]]$ExcludeFolders,

    [System.Text.Encoding]$Encoding = [System.Text.Encoding]::UTF8
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:MaxFileBytes = 1MB

# Dateiendungen, die typischerweise Text enthalten und sinnvoll nach Verknüpfungen durchsucht werden können.
$script:TextLikeExtensions = @(
    '.vbs','.bat','.cmd','.ps1','.psm1','.kix',
    '.txt','.log','.ini','.cfg','.config','.xml',
    '.json','.csv','.url','.md'
)

# Dateiendungen, nach denen im Text explizit gesucht wird, um Verknüpfungen zu erkennen.
$script:LinkExtensionsPattern = 'vbs|bat|cmd|ps1|psm1|kix|exe|dll|msi|lnk|url|txt|log|ini|cfg|config|xml|json|csv'
$script:BackupSuffixTokens = @(
    '.old', '.bak', '.tmp', '.alt',
    '.orig', '.save', '.sav', '.backup', '.copy', '.prev',
    '_old', '_bak', '_tmp', '_alt',
    '_orig', '_save', '_sav', '_backup', '_copy', '_prev',
    '-old', '-bak', '-tmp', '-alt',
    '-orig', '-save', '-sav', '-backup', '-copy', '-prev',
    '~'
)

function Get-EffectiveExtensionInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fileName = [System.IO.Path]::GetFileName($Path)
    if ([string]::IsNullOrWhiteSpace($fileName)) {
        return [pscustomobject]@{
            OriginalExtension  = ''
            EffectiveExtension = ''
            NormalizedName     = ''
        }
    }

    $normalizedName = $fileName.ToLowerInvariant()
    $changed = $true
    while ($changed -and $normalizedName.Length -gt 0) {
        $changed = $false
        foreach ($token in $script:BackupSuffixTokens) {
            if ([string]::IsNullOrWhiteSpace($token)) { continue }
            if ($normalizedName.EndsWith($token, [StringComparison]::OrdinalIgnoreCase)) {
                $normalizedName = $normalizedName.Substring(0, $normalizedName.Length - $token.Length)
                $changed = $true
                break
            }
        }
    }

    $originalExt = [System.IO.Path]::GetExtension($fileName).ToLowerInvariant()
    $effectiveExt = [System.IO.Path]::GetExtension($normalizedName).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($effectiveExt)) {
        $effectiveExt = $originalExt
    }

    return [pscustomobject]@{
        OriginalExtension  = $originalExt
        EffectiveExtension = $effectiveExt
        NormalizedName     = $normalizedName
    }
}

function Test-IsLikelyBinaryByHeader {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [byte[]]$Bytes
    )

    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return $false }

    $probeLen = [Math]::Min($Bytes.Length, 4096)
    for ($i = 0; $i -lt $probeLen; $i++) {
        if ($Bytes[$i] -eq 0) { return $true }
    }

    $signatures = @(
        ([byte[]](0x4D,0x5A)),                                  # MZ / PE
        ([byte[]](0x50,0x4B,0x03,0x04)),                        # ZIP
        ([byte[]](0x50,0x4B,0x05,0x06)),                        # ZIP (empty archive)
        ([byte[]](0x50,0x4B,0x07,0x08)),                        # ZIP (spanned)
        ([byte[]](0x25,0x50,0x44,0x46)),                        # PDF
        ([byte[]](0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1)),    # OLE Compound
        ([byte[]](0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A)),    # PNG
        ([byte[]](0x47,0x49,0x46,0x38)),                        # GIF
        ([byte[]](0xFF,0xD8,0xFF)),                             # JPEG
        ([byte[]](0x1F,0x8B)),                                  # GZIP
        ([byte[]](0x37,0x7A,0xBC,0xAF,0x27,0x1C)),              # 7z
        ([byte[]](0x52,0x61,0x72,0x21,0x1A,0x07)),              # RAR
        ([byte[]](0x7F,0x45,0x4C,0x46))                         # ELF
    )

    foreach ($sig in $signatures) {
        if ($Bytes.Length -lt $sig.Length) { continue }
        $match = $true
        for ($j = 0; $j -lt $sig.Length; $j++) {
            if ($Bytes[$j] -ne $sig[$j]) {
                $match = $false
                break
            }
        }
        if ($match) { return $true }
    }

    return $false
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

        if ($fileInfo.Length -gt 0) {
            $probeFs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            try {
                $probeSize = [int][Math]::Min([int64]8192, $fileInfo.Length)
                $probe = New-Object byte[] $probeSize
                [void]$probeFs.Read($probe, 0, $probeSize)
                if (Test-IsLikelyBinaryByHeader -Bytes $probe) {
                    return $null
                }
            }
            finally { $probeFs.Close() }
        }

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

function Get-SanitizedContentForJson {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Content
    )
    if ($null -eq $Content) { return $null }
    # Entfernt problematische Steuerzeichen; HTML-Sanitizing passiert zusätzlich im Browser-Renderer.
    $sanitized = $Content -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ''
    return $sanitized
}

function Get-PowerShellCommentStartInfo {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Line
    )
    if ($null -eq $Line -or $Line.Length -eq 0) { return $null }

    $inSingle = $false
    $inDouble = $false
    $escapeInDouble = $false
    $len = $Line.Length

    for ($i = 0; $i -lt $len; $i++) {
        $ch = $Line[$i]

        if ($inSingle) {
            if ($ch -eq "'") {
                # In PowerShell wird ein einzelnes Apostroph in Single-Quoted Strings durch '' escaped.
                if ($i + 1 -lt $len -and $Line[$i + 1] -eq "'") {
                    $i++
                    continue
                }
                $inSingle = $false
            }
            continue
        }

        if ($inDouble) {
            if ($escapeInDouble) {
                $escapeInDouble = $false
                continue
            }
            if ($ch -eq '`') {
                $escapeInDouble = $true
                continue
            }
            if ($ch -eq '"') {
                $inDouble = $false
            }
            continue
        }

        if ($ch -eq "'") {
            $inSingle = $true
            continue
        }
        if ($ch -eq '"') {
            $inDouble = $true
            continue
        }

        if ($ch -eq '<' -and $i + 1 -lt $len -and $Line[$i + 1] -eq '#') {
            return [pscustomobject]@{
                Kind  = 'Block'
                Index = $i
            }
        }
        if ($ch -eq '#') {
            return [pscustomobject]@{
                Kind  = 'Line'
                Index = $i
            }
        }
    }

    return $null
}

function Get-CommentInfoForLine {
    [CmdletBinding()]
    param(
        [string]$Line,
        [string]$Extension,
        [bool]$InPsBlockComment
    )
    $result = [ordered]@{
        IsCommentLine    = $false
        CommentStart     = -1
        InPsBlockComment = $InPsBlockComment
    }
    if ($null -eq $Line) { return [pscustomobject]$result }

    $ext = if ($null -ne $Extension) { [string]$Extension } else { '' }
    $ext = $ext.ToLowerInvariant()
    $trimmed = $Line.TrimStart()
    $leadingWs = $Line.Length - $trimmed.Length

    if ($ext -in @('.ps1', '.psm1')) {
        if ($result.InPsBlockComment) {
            $result.IsCommentLine = $true
            $result.CommentStart = 0
            $psBlockEnd = '#' + '>'
            $endIdx = $Line.IndexOf($psBlockEnd)
            if ($endIdx -ge 0) {
                $result.InPsBlockComment = $false
            }
            return [pscustomobject]$result
        }
        $psBlockEnd = '#' + '>'
        $commentStartInfo = Get-PowerShellCommentStartInfo -Line $Line
        if ($null -ne $commentStartInfo) {
            $commentStartIdx = [int]$commentStartInfo.Index
            $result.CommentStart = $commentStartIdx
            $result.IsCommentLine = $true
            if ([string]$commentStartInfo.Kind -eq 'Block') {
                $endIdxSame = $Line.IndexOf($psBlockEnd, $commentStartIdx + 2)
                if ($endIdxSame -lt 0) {
                    $result.InPsBlockComment = $true
                }
            }
            return [pscustomobject]$result
        }
        return [pscustomobject]$result
    }

    switch ($ext) {
        { $_ -in @('.bat', '.cmd') } {
            if ($trimmed -match '^(?i)(rem\b|::)') {
                $result.IsCommentLine = $true
                $result.CommentStart = $leadingWs
            }
        }
        '.vbs' {
            if ($trimmed -match "^(?i)rem\b") {
                $result.IsCommentLine = $true
                $result.CommentStart = $leadingWs
            }
            else {
                $apos = $Line.IndexOf("'")
                if ($apos -ge 0) {
                    $result.IsCommentLine = $true
                    $result.CommentStart = $apos
                }
            }
        }
        '.kix' {
            if ($trimmed.StartsWith(';')) {
                $result.IsCommentLine = $true
                $result.CommentStart = $leadingWs
            }
        }
        { $_ -in @('.ini', '.cfg', '.config', '.url') } {
            if ($trimmed.StartsWith(';') -or $trimmed.StartsWith('#')) {
                $result.IsCommentLine = $true
                $result.CommentStart = $leadingWs
            }
        }
    }

    return [pscustomobject]$result
}

function Get-NormalizedExcludeFolders {
    param(
        [string[]]$Folders
    )
    if (-not $Folders) { return @() }
    $normalized = @(
        $Folders |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object {
                $p = $_.Trim()
                $p = $p -replace '\\', '/'
                $p = $p.Trim('/')
                $p
            } |
            Where-Object { $_ } |
            Sort-Object -Unique
    )
    return $normalized
}

function Test-IsExcludedPath {
    param(
        [string]$FullPath,
        [string]$RootPath,
        [string[]]$ExcludePrefixes
    )
    if (-not $ExcludePrefixes -or @($ExcludePrefixes).Count -eq 0) { return $false }
    $rootTrimmed = $RootPath.TrimEnd('\', '/')
    $rel = $FullPath
    if ($rel.StartsWith($rootTrimmed, [StringComparison]::OrdinalIgnoreCase)) {
        $rel = $rel.Substring($rootTrimmed.Length).TrimStart('\', '/')
    }
    $relNorm = $rel -replace '\\', '/'
    foreach ($p in $ExcludePrefixes) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        if ($relNorm.Equals($p, [StringComparison]::OrdinalIgnoreCase) -or
            $relNorm.StartsWith($p + '/', [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Get-RelativePath {
    param(
        [string]$FullPath,
        [string]$RootPath
    )
    $rootTrimmed = $RootPath.TrimEnd('\', '/')
    if ($FullPath.StartsWith($rootTrimmed, [StringComparison]::OrdinalIgnoreCase)) {
        return $FullPath.Substring($rootTrimmed.Length).TrimStart('\', '/')
    }
    return $FullPath
}

function Get-TopFolderFromRelative {
    param([string]$RelativePath)
    if ([string]::IsNullOrWhiteSpace($RelativePath) -or $RelativePath -notmatch '[\\/]') {
        return '(Root)'
    }
    $seg = ($RelativePath -split '[\\/]')[0]
    if ([string]::IsNullOrWhiteSpace($seg)) { return '(Root)' }
    return $seg
}

function New-Node {
    param(
        [hashtable]$NodesByPath,
        [System.Collections.Generic.List[object]]$NodeList,
        [hashtable]$NameIndex,
        [string]$FullPath,
        [string]$RootPath,
        [bool]$IsExternal,
        [ref]$NextId
    )
    if ($NodesByPath.ContainsKey($FullPath)) {
        return $NodesByPath[$FullPath]
    }

    $id = "n$($NextId.Value)"
    $NextId.Value++

    $displayName = [System.IO.Path]::GetFileName($FullPath)
    if (-not $displayName) { $displayName = $FullPath }
    $extInfo = Get-EffectiveExtensionInfo -Path $FullPath
    $extOriginal = [string]$extInfo.OriginalExtension
    $ext = [string]$extInfo.EffectiveExtension

    $type = switch ($ext) {
        '.vbs'   { 'VBS' }
        '.bat'   { 'BAT' }
        '.cmd'   { 'CMD' }
        '.ps1'   { 'PS1' }
        '.psm1'  { 'PSM1' }
        '.kix'   { 'KIX' }
        '.exe'   { 'EXE' }
        '.dll'   { 'DLL' }
        '.msi'   { 'MSI' }
        '.lnk'   { 'LNK' }
        '.url'   { 'URL' }
        '.txt'   { 'TXT' }
        '.log'   { 'LOG' }
        '.ini'   { 'INI' }
        '.cfg'   { 'CFG' }
        '.config'{ 'CONFIG' }
        '.xml'   { 'XML' }
        '.json'  { 'JSON' }
        '.csv'   { 'CSV' }
        default  { 'FILE' }
    }

    if ($IsExternal) {
        $relativePath = $FullPath
        $topFolder = '[Extern]'
        $folderDepth = 0
    }
    else {
        $relativePath = Get-RelativePath -FullPath $FullPath -RootPath $RootPath
        $topFolder = Get-TopFolderFromRelative -RelativePath $relativePath
        $segments = $relativePath -split '[\\/]'
        if ($segments.Length -gt 1) {
            $folderDepth = $segments.Length - 1
        }
        else {
            $folderDepth = 0
        }
    }

    $node = [pscustomobject]@{
        Id           = $id
        FullPath     = $FullPath
        DisplayName  = $displayName
        Extension    = $extOriginal
        EffectiveExtension = $ext
        Type         = $type
        TopFolder    = $topFolder
        RelativePath = $relativePath
        FolderDepth  = $folderDepth
        IsExternal   = $IsExternal
        Content      = $null
    }

    $NodesByPath[$FullPath] = $node
    $NodeList.Add($node) | Out-Null

    if (-not $IsExternal -and $displayName) {
        $key = $displayName.ToLowerInvariant()
        if (-not $NameIndex.ContainsKey($key)) {
            $NameIndex[$key] = New-Object System.Collections.Generic.List[object]
        }
        $NameIndex[$key].Add($node) | Out-Null
    }

    return $node
}

function Get-LinksFromContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content,
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,
        [Parameter(Mandatory = $true)]
        [string]$Extension,
        [Parameter(Mandatory = $true)]
        [hashtable]$NameIndex,
        [hashtable]$ExternalNodesByLabel,
        [hashtable]$NodesByPath,
        [System.Collections.Generic.List[object]]$NodeList,
        [string]$RootPath,
        [ref]$NextId
    )

    $edges = New-Object System.Collections.Generic.List[object]
    if (-not $Content) { return $edges }

    # Einfache Heuristik: jedes Vorkommen eines Dateinamens mit bekannter Erweiterung
    # (z.B. login.vbs, setup.exe, VAESAPP.lnk) wird als Verknüpfung interpretiert.
    $pattern = "(?i)([A-Za-z0-9_\-\.]+\.(?:$($script:LinkExtensionsPattern)))"
    $allMatches = [regex]::Matches($Content, $pattern)
    if ($allMatches.Count -eq 0) { return $edges }

    $labelFlags = @{}
    $lineMatches = [regex]::Matches($Content, '(?m)^.*(?:\r?\n|$)')
    $inPsBlockComment = $false

    foreach ($lm in $lineMatches) {
        $line = $lm.Value
        if ($null -eq $line) { continue }
        $commentInfo = Get-CommentInfoForLine -Line $line -Extension $Extension -InPsBlockComment:$inPsBlockComment
        $inPsBlockComment = [bool]$commentInfo.InPsBlockComment
        $lineCommentStart = [int]$commentInfo.CommentStart
        $lineIsComment = [bool]$commentInfo.IsCommentLine

        $lineMatchesLinks = [regex]::Matches($line, $pattern)
        foreach ($m in $lineMatchesLinks) {
            $label = $m.Groups[1].Value
            if (-not $label) { continue }
            if (-not $labelFlags.ContainsKey($label)) {
                $labelFlags[$label] = [ordered]@{
                    HasComment    = $false
                    HasNonComment = $false
                }
            }
            $isComment = $false
            if ($lineIsComment) {
                if ($lineCommentStart -lt 0 -or $m.Index -ge $lineCommentStart) {
                    $isComment = $true
                }
            }
            if ($isComment) { $labelFlags[$label].HasComment = $true }
            else { $labelFlags[$label].HasNonComment = $true }
        }
    }

    foreach ($label in $labelFlags.Keys) {
        $isCommentLink = -not [bool]$labelFlags[$label].HasNonComment

        $fileName = [System.IO.Path]::GetFileName($label)
        $localTargets = $null
        $key = $fileName.ToLowerInvariant()
        if ($NameIndex.ContainsKey($key)) {
            $localTargets = $NameIndex[$key]
        }

        if ($localTargets -and $localTargets.Count -gt 0) {
            foreach ($targetNode in $localTargets) {
                if ($targetNode.FullPath -eq $SourcePath) { continue }
                $edges.Add([pscustomobject]@{
                    SourcePath = $SourcePath
                    TargetPath = $targetNode.FullPath
                    Label      = $label
                    IsCommentLink = $isCommentLink
                }) | Out-Null
            }
        }
        else {
            # Kein lokales Ziel gefunden -> externer Knoten
            if (-not $ExternalNodesByLabel.ContainsKey($label)) {
                $extNode = New-Node -NodesByPath $NodesByPath -NodeList $NodeList -NameIndex $NameIndex -FullPath $label -RootPath $RootPath -IsExternal:$true -NextId $NextId
                $ExternalNodesByLabel[$label] = $extNode
            }
            $edges.Add([pscustomobject]@{
                SourcePath = $SourcePath
                TargetPath = $ExternalNodesByLabel[$label].FullPath
                Label      = $label
                IsCommentLink = $isCommentLink
            }) | Out-Null
        }
    }

    return $edges
}

function Export-ScriptLinksFlowchartHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[object]]$Nodes,
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[object]]$Edges,
        [Parameter(Mandatory = $true)]
        [string]$OutputFilePath
    )

    $topFolders = @(
        $Nodes |
            Where-Object { -not $_.IsExternal } |
            Select-Object -ExpandProperty TopFolder -Unique |
            Sort-Object
    )

    $reportNodes = @(
        $Nodes | ForEach-Object {
            [ordered]@{
                id           = $_.Id
                fullPath     = $_.FullPath
                displayName  = $_.DisplayName
                type         = $_.Type
                topFolder    = $_.TopFolder
                relativePath = $_.RelativePath
                folderDepth  = $_.FolderDepth
                isExternal   = [bool]$_.IsExternal
                content      = $_.Content
            }
        }
    )

    $reportEdges = @(
        $Edges | ForEach-Object {
            [ordered]@{
                sourceId       = $_.SourceId
                targetId       = $_.TargetId
                sourcePath     = $_.SourcePath
                targetPath     = $_.TargetPath
                label          = $_.Label
                isCrossBoundary = [bool]$_.IsCrossBoundary
                isCommentLink  = [bool]$_.IsCommentLink
            }
        }
    )

    $reportData = @{ nodes = $reportNodes; edges = $reportEdges } | ConvertTo-Json -Depth 4 -Compress
    $reportDataEscaped = $reportData -replace '</', '\u003c/'

    $dropdownTopOptions = ($topFolders | ForEach-Object {
        $enc = [System.Net.WebUtility]::HtmlEncode($_)
        "          <option value=`"$enc`">$enc</option>"
    }) -join "`n"

    $html = @"
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <title>Skript- und Dateiverknüpfungen – Flowchart (alle Dateitypen)</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
</head>
<body class="bg-gray-50 text-gray-900 min-h-screen">
  <div class="max-w-7xl mx-auto px-4 py-8">
    <header class="mb-8">
      <h1 class="text-3xl font-bold text-gray-900">Skript- und Dateiverknüpfungen (alle Dateitypen)</h1>
      <p class="mt-2 text-gray-600">
        Jede Datei unterhalb des angegebenen ScriptsPath wird als Knoten dargestellt.
        Jede gefundene Erwähnung eines Dateinamens (z.B. <code>login.vbs</code>, <code>setup.exe</code>, <code>VAESAPP.lnk</code>)
        in textbasierten Dateien wird als Verknüpfung von der aufrufenden Datei zum Ziel interpretiert.
      </p>
      <p class="mt-1 text-gray-600">
        Das Flowchart ist nach Ordner-Tiefe von links nach rechts gruppiert. Externe Ziele (ohne passende Datei im ScriptsPath)
        erscheinen in einer eigenen Spalte "Extern".
      </p>
      <p class="mt-1 text-gray-600 text-sm">
        <span class="font-semibold">Pfeil-Legende:</span>
        Schwarze Pfeile = Aufruf/Verknüpfung innerhalb desselben Top-Ordners;
        rote Pfeile = Verweis in einen anderen Top-Ordner oder nach außen.
      </p>
      <div class="mt-3 flex flex-wrap gap-2 text-sm">
        <span class="px-2 py-1 rounded bg-blue-100 text-blue-800">VBS</span>
        <span class="px-2 py-1 rounded bg-amber-100 text-amber-800">BAT/CMD</span>
        <span class="px-2 py-1 rounded bg-green-100 text-green-800">PS1/PSM1</span>
        <span class="px-2 py-1 rounded bg-purple-100 text-purple-800">KiXtart</span>
        <span class="px-2 py-1 rounded bg-orange-100 text-orange-800">EXE/MSI</span>
        <span class="px-2 py-1 rounded bg-slate-100 text-slate-800">DLL</span>
        <span class="px-2 py-1 rounded bg-cyan-100 text-cyan-800">INI/TXT/CFG/XML/JSON</span>
        <span class="px-2 py-1 rounded bg-gray-100 text-gray-800">Sonstige Dateien</span>
      </div>
    </header>

    <div class="mb-6 flex flex-wrap items-center gap-4">
      <div class="flex items-center gap-2">
        <label for="filter-topfolder" class="text-sm font-medium text-gray-700">Filter: Top-Ordner</label>
        <select id="filter-topfolder" class="rounded border border-gray-300 px-3 py-1.5 text-gray-900 focus:ring-2 focus:ring-blue-500">
          <option value="">Alle Top-Ordner</option>
$dropdownTopOptions
          <option value="[Extern]">[Extern]</option>
        </select>
      </div>
    </div>

    <section class="mb-8 bg-white rounded-xl shadow p-4">
      <div class="flex items-center justify-between mb-3 gap-4">
        <h2 class="text-lg font-semibold text-gray-800">Flowchart</h2>
        <div class="flex items-center gap-2 text-xs text-gray-600">
          <button id="zoom-out" type="button" class="px-2 py-1 rounded border border-gray-300 bg-white hover:bg-gray-100">-</button>
          <input id="zoom-range" type="range" min="100" max="1000" value="100" class="w-40 accent-blue-600">
          <button id="zoom-in" type="button" class="px-2 py-1 rounded border border-gray-300 bg-white hover:bg-gray-100">+</button>
          <span id="zoom-label" class="w-12 text-right">100%</span>
        </div>
      </div>
      <div id="mermaid-wrapper" class="border border-gray-200 rounded-lg overflow-auto max-h-[75vh]">
        <div id="mermaid-target" class="mermaid min-w-[800px] min-h-[400px]"></div>
      </div>
    </section>

    <section class="mb-8 bg-white rounded-xl shadow p-4">
      <h2 class="text-lg font-semibold text-gray-800 mb-3">Dateien und Inhalt</h2>
      <p class="text-sm text-gray-600 mb-3">
        Gelb markiert: interne Verknüpfung. Rot markiert: externe/übergreifende Verknüpfung.
      </p>
      <div id="code-sections" class="space-y-6">
        <p class="text-sm text-gray-500">Bitte einen Top-Ordner auswählen.</p>
      </div>
    </section>
  </div>

  <script type="application/json" id="reportData">$reportDataEscaped</script>

  <script>
    mermaid.initialize({ startOnLoad: false, flowchart: { useMaxWidth: true, htmlLabels: true } });
  </script>

  <script>
  (function() {
    var selectTop = document.getElementById('filter-topfolder');
    var mermaidTarget = document.getElementById('mermaid-target');
    var zoomRange = document.getElementById('zoom-range');
    var zoomOutBtn = document.getElementById('zoom-out');
    var zoomInBtn = document.getElementById('zoom-in');
    var zoomLabel = document.getElementById('zoom-label');
    var dataEl = document.getElementById('reportData');
    var reportData = (dataEl && dataEl.textContent) ? JSON.parse(dataEl.textContent) : { nodes: [], edges: [] };
    var nodes = reportData.nodes || [];
    var edges = reportData.edges || [];
    var renderId = 0;
    var currentZoom = 1.0;

    function escapeMermaidLabel(s) {
      if (!s) return '';
      return String(s)
        .replace(/\\/g, '\\\\')
        .replace(/"/g, '\\"')
        .replace(/\[/g, '\\[')
        .replace(/\]/g, '\\]');
    }

    function buildMermaidCode(filteredNodes, filteredEdges) {
      if (!filteredNodes || filteredNodes.length === 0) {
        return '';
      }

      var lines = ['flowchart LR'];

      var internal = filteredNodes.filter(function(n) { return !n.isExternal; });
      var external = filteredNodes.filter(function(n) { return n.isExternal; });

      // Pro Tiefe und pro echtem Ordnerpfad gruppieren:
      // dadurch bleiben z.B. 2217/Common und 2236/Common getrennte Boxen.
      var byDepthFolder = {};
      internal.forEach(function(n) {
        var d = (typeof n.folderDepth === 'number') ? n.folderDepth : 0;
        var folderPath = '(Root)';
        var folderLabel = '(Root)';
        if (n.relativePath) {
          var segs = String(n.relativePath).split(/[\/\\]/);
          if (segs.length >= 2) {
            // Voller Ordnerpfad relativ zum scripts-Root (ohne Dateiname)
            folderPath = segs.slice(0, segs.length - 1).join('/');
            // Anzeige: letzter Ordnername
            folderLabel = segs[segs.length - 2];
          }
        }
        if (!byDepthFolder[d]) byDepthFolder[d] = {};
        if (!byDepthFolder[d][folderPath]) {
          byDepthFolder[d][folderPath] = { label: folderLabel, nodes: [] };
        }
        byDepthFolder[d][folderPath].nodes.push(n);
      });

      var depthKeys = Object.keys(byDepthFolder).map(Number).sort(function(a, b) { return a - b; });

      // Merkmale pro Tiefe sammeln, damit wir Layout-Kanten setzen können
      var anchorsByDepth = {};
      depthKeys.forEach(function(d) { anchorsByDepth[d] = []; });

      depthKeys.forEach(function(d) {
        var folderMap = byDepthFolder[d] || {};
        var folderPaths = Object.keys(folderMap).sort();
        var depthId = 'depth' + d;

        lines.push('  subgraph ' + depthId + '["Ebene ' + d + '"]');
        folderPaths.forEach(function(folderPath, idx) {
          var folderId = 'd' + d + 'f' + idx;
          var folderInfo = folderMap[folderPath] || { label: '(Root)', nodes: [] };
          var folderNodes = folderInfo.nodes || [];
          lines.push('    subgraph ' + folderId + '["' + escapeMermaidLabel(folderInfo.label) + '"]');
          folderNodes.forEach(function(n, nodeIdx) {
            var lbl = n.displayName || n.fullPath || n.id;
            if (n.type) {
              lbl = lbl + ' (' + n.type + ')';
            }
            lines.push('      ' + n.id + '["' + escapeMermaidLabel(lbl) + '"]');
            // Ein Anker pro Ordnerbox reicht für Layout-Verknüpfungen zwischen Ebenen
            if (nodeIdx === 0) {
              anchorsByDepth[d].push(n.id);
            }
          });
          lines.push('    end');
        });
        lines.push('  end');
      });

      if (external.length > 0) {
        // Externe Ziele in separatem Subgraph "Extern"
        lines.push('  subgraph external["Extern"]');
        external.forEach(function(n) {
          var lbl = n.displayName || n.fullPath || n.id;
          if (n.type) {
            lbl = lbl + ' (' + n.type + ')';
          }
          lines.push('    ' + n.id + '["' + escapeMermaidLabel(lbl) + '"]');
        });
        lines.push('  end');
      }

      // Typ-Farben
      var typeStyle = {
        VBS:   'fill:#dbeafe,stroke:#1e40af',
        BAT:   'fill:#fef3c7,stroke:#92400e',
        CMD:   'fill:#fef3c7,stroke:#92400e',
        PS1:   'fill:#dcfce7,stroke:#166534',
        PSM1:  'fill:#dcfce7,stroke:#166534',
        KIX:   'fill:#f3e8ff,stroke:#6b21a8',
        EXE:   'fill:#ffedd5,stroke:#c05621',
        MSI:   'fill:#ffedd5,stroke:#c05621',
        DLL:   'fill:#e5e7eb,stroke:#374151',
        LNK:   'fill:#e0f2fe,stroke:#0369a1',
        URL:   'fill:#e0f2fe,stroke:#0369a1',
        TXT:   'fill:#cffafe,stroke:#0e7490',
        LOG:   'fill:#cffafe,stroke:#0e7490',
        INI:   'fill:#ccfbf1,stroke:#0f766e',
        CFG:   'fill:#ccfbf1,stroke:#0f766e',
        CONFIG:'fill:#ccfbf1,stroke:#0f766e',
        XML:   'fill:#e0f2fe,stroke:#1d4ed8',
        JSON:  'fill:#e0f2fe,stroke:#1d4ed8',
        CSV:   'fill:#fef9c3,stroke:#854d0e',
        FILE:  'fill:#f3f4f6,stroke:#4b5563'
      };

      filteredNodes.forEach(function(n) {
        var s = typeStyle[n.type] || null;
        if (s) {
          lines.push('  style ' + n.id + ' ' + s);
        }
      });

      // Layout-Kanten: unsichtbare Verbindungen zwischen Tiefen, um links-rechts-Anordnung zu erzwingen
      var layoutEdgeCount = 0;
      for (var i = 0; i < depthKeys.length; i++) {
        var d = depthKeys[i];
        var anchors = anchorsByDepth[d] || [];
        var canUseColumnLayoutEdges = anchors.length > 1;
        if (!canUseColumnLayoutEdges) {
          continue;
        }
        for (var j = 0; j < anchors.length - 1; j++) {
          lines.push('  ' + anchors[j] + ' ~~~ ' + anchors[j + 1]);
          layoutEdgeCount++;
        }
        if (i < depthKeys.length - 1) {
          var nextD = depthKeys[i + 1];
          var nextAnchors = anchorsByDepth[nextD] || [];
          if (nextAnchors.length > 1) {
            lines.push('  ' + anchors[anchors.length - 1] + ' --> ' + nextAnchors[0]);
            layoutEdgeCount++;
          }
        }
      }

      var edgeIndex = 0;
      var crossIndices = [];
      filteredEdges.forEach(function(e) {
        var sid = e.sourceId;
        var tid = e.targetId;
        if (sid && tid) {
          lines.push('  ' + sid + ' --> ' + tid);
          if (e.isCrossBoundary) {
            crossIndices.push(layoutEdgeCount + edgeIndex);
          }
          edgeIndex++;
        }
      });

      // Layout-Kanten unsichtbar machen
      for (var k = 0; k < layoutEdgeCount; k++) {
        lines.push('  linkStyle ' + k + ' stroke:transparent,fill:transparent,color:transparent,stroke-width:0,opacity:0');
      }
      // Cross-Boundary-Kanten rot hervorheben
      crossIndices.forEach(function(idx) {
        lines.push('  linkStyle ' + idx + ' stroke:red,stroke-width:2px');
      });

      return lines.join('\n');
    }

    function applyZoom() {
      var svg = mermaidTarget ? mermaidTarget.querySelector('svg') : null;
      if (!svg) return;
      svg.style.transformOrigin = '0 0';
      svg.style.transform = 'scale(' + currentZoom + ')';
    }

    function renderMermaid(code) {
      if (!mermaidTarget || typeof mermaid === 'undefined') return;
      if (!code || !code.trim()) {
        mermaidTarget.innerHTML = '';
        return;
      }
      var id = 'mermaid-render-' + (++renderId);
      mermaid.render(id, code).then(function(result) {
        mermaidTarget.innerHTML = result.svg || '';
        if (result.bindFunctions) {
          result.bindFunctions(mermaidTarget);
        }
        applyZoom();
      }).catch(function(err) {
        mermaidTarget.textContent = 'Diagramm-Fehler: ' + (err.message || String(err));
      });
    }

    function applyFilter() {
      var topVal = selectTop ? selectTop.value : '';
      var filteredNodes = nodes.filter(function(n) {
        if (topVal === '') return true;
        if (topVal === '[Extern]') return n.isExternal;
        return (!n.isExternal && n.topFolder === topVal);
      });

      var idSet = {};
      filteredNodes.forEach(function(n) { idSet[n.id] = true; });

      var filteredEdges = edges.filter(function(e) {
        return idSet[e.sourceId] && idSet[e.targetId];
      });

      var code = buildMermaidCode(filteredNodes, filteredEdges);
      renderMermaid(code);
    }

    function setZoomFromRange() {
      if (!zoomRange) return;
      var val = parseInt(zoomRange.value, 10);
      if (isNaN(val) || val <= 0) val = 100;
      currentZoom = val / 100;
      if (zoomLabel) {
        zoomLabel.textContent = val + '%';
      }
      applyZoom();
    }

    if (zoomRange) {
      zoomRange.addEventListener('input', setZoomFromRange);
      zoomRange.addEventListener('change', setZoomFromRange);
    }
    if (zoomInBtn) {
      zoomInBtn.addEventListener('click', function() {
        var val = zoomRange ? parseInt(zoomRange.value, 10) || 100 : Math.round(currentZoom * 100);
        val = Math.min(1000, val + 50);
        if (zoomRange) zoomRange.value = String(val);
        setZoomFromRange();
      });
    }
    if (zoomOutBtn) {
      zoomOutBtn.addEventListener('click', function() {
        var val = zoomRange ? parseInt(zoomRange.value, 10) || 100 : Math.round(currentZoom * 100);
        val = Math.max(100, val - 50);
        if (zoomRange) zoomRange.value = String(val);
        setZoomFromRange();
      });
    }

    if (selectTop) {
      selectTop.addEventListener('change', applyFilter);
    }

    applyFilter();
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

function Export-ScriptLinksFlowchartTemplate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$TopFolders,
        [Parameter(Mandatory = $true)]
        [hashtable]$EmbeddedData,
        [Parameter(Mandatory = $true)]
        [string]$OutputFilePath
    )

    $sortedTop = @($TopFolders | Where-Object { $_ } | Sort-Object -Unique)
    $dropdownTopOptions = ($sortedTop | ForEach-Object {
        $enc = [System.Net.WebUtility]::HtmlEncode($_)
        "          <option value=`"$enc`">$enc</option>"
    }) -join "`n"

    $embeddedBlocks = @()
    foreach ($key in $EmbeddedData.Keys) {
        $json = $EmbeddedData[$key]
        if (-not $json) { continue }
        $jsonEscaped = $json -replace '</', '\u003c/'
        $embeddedBlocks += "  <script type=`"application/json`" id=`"data-$key`">$jsonEscaped</script>"
    }
    $embeddedJoined = $embeddedBlocks -join "`n"

    $html = @"
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <title>Skript- und Dateiverknüpfungen – Flowchart (alle Dateitypen)</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
</head>
<body class="bg-gray-50 text-gray-900 min-h-screen">
  <div class="max-w-7xl mx-auto px-4 py-8">
    <header class="mb-8">
      <h1 class="text-3xl font-bold text-gray-900">Skript- und Dateiverknüpfungen (alle Dateitypen)</h1>
      <p class="mt-2 text-gray-600">
        Jede Datei unterhalb des angegebenen ScriptsPath wird als Knoten dargestellt.
        Jede gefundene Erwähnung eines Dateinamens (z.B. <code>login.vbs</code>, <code>setup.exe</code>, <code>VAESAPP.lnk</code>)
        in textbasierten Dateien wird als Verknüpfung von der aufrufenden Datei zum Ziel interpretiert.
      </p>
      <p class="mt-1 text-gray-600">
        Das Flowchart ist nach Ordner-Tiefe von links nach rechts gruppiert. Externe Ziele (ohne passende Datei im ScriptsPath)
        erscheinen in einer eigenen Spalte "Extern".
      </p>
      <div class="mt-3 flex flex-wrap gap-2 text-sm">
        <span class="px-2 py-1 rounded bg-blue-100 text-blue-800">VBS</span>
        <span class="px-2 py-1 rounded bg-amber-100 text-amber-800">BAT/CMD</span>
        <span class="px-2 py-1 rounded bg-green-100 text-green-800">PS1/PSM1</span>
        <span class="px-2 py-1 rounded bg-purple-100 text-purple-800">KiXtart</span>
        <span class="px-2 py-1 rounded bg-orange-100 text-orange-800">EXE/MSI</span>
        <span class="px-2 py-1 rounded bg-slate-100 text-slate-800">DLL</span>
        <span class="px-2 py-1 rounded bg-cyan-100 text-cyan-800">INI/TXT/CFG/XML/JSON</span>
        <span class="px-2 py-1 rounded bg-gray-100 text-gray-800">Sonstige Dateien</span>
      </div>
    </header>

    <div class="mb-6 flex flex-wrap items-center gap-4">
      <div class="flex items-center gap-2">
        <label for="filter-topfolder" class="text-sm font-medium text-gray-700">Top-Ordner</label>
        <select id="filter-topfolder" class="rounded border border-gray-300 px-3 py-1.5 text-gray-900 focus:ring-2 focus:ring-blue-500">
          <option value="">— bitte wählen —</option>
$dropdownTopOptions
        </select>
      </div>
      <label class="flex items-center gap-2 text-sm text-gray-700">
        <input id="toggle-hide-external" type="checkbox" class="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500">
        Externe Verknüpfungen ausblenden
      </label>
      <label class="flex items-center gap-2 text-sm text-gray-700">
        <input id="toggle-hide-comment-links" type="checkbox" class="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500">
        Verknüpfungen aus Kommentaren ausblenden
      </label>
    </div>

    <section class="mb-8 bg-white rounded-xl shadow p-4">
      <div class="flex items-center justify-between mb-3 gap-4">
        <h2 class="text-lg font-semibold text-gray-800">Flowchart</h2>
        <div class="flex items-center gap-2 text-xs text-gray-600">
          <button id="zoom-out" type="button" class="px-2 py-1 rounded border border-gray-300 bg-white hover:bg-gray-100">-</button>
          <input id="zoom-range" type="range" min="100" max="1000" value="100" class="w-40 accent-blue-600">
          <button id="zoom-in" type="button" class="px-2 py-1 rounded border border-gray-300 bg-white hover:bg-gray-100">+</button>
          <span id="zoom-label" class="w-12 text-right">100%</span>
        </div>
      </div>
      <div id="mermaid-wrapper" class="border border-gray-200 rounded-lg overflow-auto max-h-[75vh]">
        <div id="mermaid-target" class="mermaid min-w-[800px] min-h-[400px] flex items-center justify-center text-sm text-gray-500">
          Bitte einen Top-Ordner auswählen.
        </div>
      </div>
    </section>

    <section class="mb-8 bg-white rounded-xl shadow p-4">
      <h2 class="text-lg font-semibold text-gray-800 mb-3">Dateien und Inhalt</h2>
      <p class="text-sm text-gray-600 mb-3">
        Gelb markiert: interne Verknüpfung. Rot markiert: externe/übergreifende Verknüpfung.
      </p>
      <div id="code-sections" class="space-y-6">
        <p class="text-sm text-gray-500">Bitte einen Top-Ordner auswählen.</p>
      </div>
    </section>
  </div>

  $embeddedJoined

  <script>
    mermaid.initialize({ startOnLoad: false, flowchart: { useMaxWidth: true, htmlLabels: true } });
  </script>

  <script>
  (function() {
    var selectTop = document.getElementById('filter-topfolder');
    var mermaidTarget = document.getElementById('mermaid-target');
    var zoomRange = document.getElementById('zoom-range');
    var zoomOutBtn = document.getElementById('zoom-out');
    var zoomInBtn = document.getElementById('zoom-in');
    var zoomLabel = document.getElementById('zoom-label');
    var hideExternalToggle = document.getElementById('toggle-hide-external');
    var hideCommentLinksToggle = document.getElementById('toggle-hide-comment-links');
    var codeSectionsEl = document.getElementById('code-sections');
    var mermaidWrapper = document.getElementById('mermaid-wrapper');
    var renderId = 0;
    var currentZoom = 1.0;
    var currentData = null;
    var currentRenderedNodes = [];
    var currentTopVal = '';

    function escapeMermaidLabel(s) {
      if (!s) return '';
      return String(s)
        .replace(/\\/g, '\\\\')
        .replace(/"/g, '\\"')
        .replace(/\[/g, '\\[')
        .replace(/\]/g, '\\]');
    }

    function escapeHtml(s) {
      if (s == null) return '';
      return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    function highlightContent(content, internalLabels, externalLabels) {
      var escaped = escapeHtml(content || '');
      function apply(list, cssClass, title) {
        (list || []).sort(function(a, b) { return String(b).length - String(a).length; }).forEach(function(lbl) {
          if (!lbl) return;
          var token = escapeHtml(lbl);
          if (!token) return;
          var marked = '<span class="' + cssClass + '" title="' + title + '">' + token + '</span>';
          escaped = escaped.split(token).join(marked);
        });
      }
      apply(externalLabels, 'bg-red-200 text-red-900 rounded px-0.5 font-semibold', 'Externe/übergreifende Verknüpfung');
      apply(internalLabels, 'bg-amber-300 text-amber-950 rounded px-0.5 font-semibold', 'Interne Verknüpfung');
      return escaped;
    }

    function findDiagramNodeElement(nodeId) {
      if (!nodeId || !mermaidTarget) return null;
      var svg = mermaidTarget.querySelector('svg');
      if (!svg) return null;
      var selectors = [
        'g.node[data-id="' + nodeId + '"]',
        'g.node[id="' + nodeId + '"]',
        'g.node[id*="-' + nodeId + '-"]',
        'g.node[id$="-' + nodeId + '"]',
        'g.node[id^="' + nodeId + '-"]'
      ];
      for (var i = 0; i < selectors.length; i++) {
        var el = svg.querySelector(selectors[i]);
        if (el) return el;
      }
      return null;
    }

    function flashNode(nodeEl) {
      if (!nodeEl) return;
      var shape = nodeEl.querySelector('rect, polygon, path, ellipse, circle');
      if (!shape) return;
      var oldStroke = shape.style.stroke || '';
      var oldStrokeWidth = shape.style.strokeWidth || '';
      shape.style.stroke = '#2563eb';
      shape.style.strokeWidth = '4px';
      setTimeout(function() {
        shape.style.stroke = oldStroke;
        shape.style.strokeWidth = oldStrokeWidth;
      }, 1200);
    }

    function scrollToNodeInDiagram(nodeId) {
      var nodeEl = findDiagramNodeElement(nodeId);
      if (!nodeEl || !mermaidWrapper) return;
      mermaidWrapper.scrollIntoView({ behavior: 'smooth', block: 'center' });
      setTimeout(function() {
        var wrapperRect = mermaidWrapper.getBoundingClientRect();
        var nodeRect = nodeEl.getBoundingClientRect();
        var dx = (nodeRect.left - wrapperRect.left) - (mermaidWrapper.clientWidth / 2) + (nodeRect.width / 2);
        var dy = (nodeRect.top - wrapperRect.top) - (mermaidWrapper.clientHeight / 2) + (nodeRect.height / 2);
        mermaidWrapper.scrollBy({ left: dx, top: dy, behavior: 'smooth' });
        flashNode(nodeEl);
      }, 120);
    }

    function renderCodeSections(nodes, edges) {
      if (!codeSectionsEl) return;
      if (!nodes || nodes.length === 0) {
        codeSectionsEl.innerHTML = '<p class="text-sm text-gray-500">Keine Dateien für diese Auswahl.</p>';
        return;
      }

      var bySource = {};
      (edges || []).forEach(function(e) {
        if (!e || !e.sourceId) return;
        if (!bySource[e.sourceId]) bySource[e.sourceId] = [];
        bySource[e.sourceId].push(e);
      });

      var sortedNodes = nodes.slice().sort(function(a, b) {
        var pa = (a.relativePath || a.displayName || '').toLowerCase();
        var pb = (b.relativePath || b.displayName || '').toLowerCase();
        if (pa < pb) return -1;
        if (pa > pb) return 1;
        return 0;
      });

      var html = [];
      sortedNodes.forEach(function(n) {
        var out = bySource[n.id] || [];
        var internal = [];
        var external = [];
        out.forEach(function(e) {
          var lbl = e.label || '';
          if (!lbl) return;
          if (e.isCrossBoundary) external.push(lbl);
          else internal.push(lbl);
        });

        var hasText = (n.content != null && String(n.content).length > 0);
        var codeHtml = '';
        if (hasText) {
          codeHtml = highlightContent(String(n.content), internal, external);
        } else if (n.isExternal) {
          codeHtml = escapeHtml('# Externe Referenz: kein lokaler Dateiinhalt verfügbar: ' + (n.fullPath || n.displayName || n.id));
        } else {
          codeHtml = escapeHtml('# Datei nicht lesbar oder nicht textbasiert: ' + (n.fullPath || n.displayName || n.id));
        }

        html.push(
          '<section id="code-' + escapeHtml(n.id) + '" class="border border-gray-200 rounded-lg p-3 scroll-mt-24">' +
          '<div class="mb-1 flex flex-wrap items-center justify-between gap-2">' +
          '<h3 class="text-sm font-semibold text-gray-800">' + escapeHtml((n.displayName || n.id) + (n.type ? ' (' + n.type + ')' : '')) + '</h3>' +
          '<button type="button" class="jump-to-node inline-flex items-center rounded border border-blue-200 px-2 py-1 text-xs font-medium text-blue-700 hover:bg-blue-50" data-node-id="' + escapeHtml(n.id) + '">Zum Knoten im Flowchart</button>' +
          '</div>' +
          '<p class="text-xs text-gray-500 font-mono mb-2">' + escapeHtml(n.fullPath || '') + '</p>' +
          '<pre class="bg-gray-900 text-gray-100 p-3 rounded overflow-x-auto text-xs"><code>' + codeHtml + '</code></pre>' +
          '</section>'
        );
      });

      codeSectionsEl.innerHTML = html.join('');
    }

    function buildMermaidCode(nodes, edges) {
      if (!nodes || nodes.length === 0) {
        return '';
      }

      var lines = ['flowchart LR'];

      var internal = nodes.filter(function(n) { return !n.isExternal; });
      var external = nodes.filter(function(n) { return n.isExternal; });
      var renderedNodes = internal.concat(external);

      // Pro echtem Ordnerpfad gruppieren (nicht nur nach Ordnername)
      // Dadurch bleiben z.B. 2217/Common und 2236/Common getrennte Boxen.
      var folderMap = {};   // parentFolderPath -> [node]
      internal.forEach(function(n) {
        var parentFolder = '';
        var folderLabel = 'scripts';
        if (n.relativePath) {
          var segs = String(n.relativePath).split(/[\/\\]/);
          if (segs.length > 1) {
            parentFolder = segs.slice(0, segs.length - 1).join('/');
            folderLabel = segs[segs.length - 2] || 'scripts';
          }
        }
        if (!folderMap[parentFolder]) {
          folderMap[parentFolder] = { label: folderLabel, nodes: [] };
        }
        folderMap[parentFolder].nodes.push(n);
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

      // Nach Tiefe gruppieren: jede Tiefe = eine Spalte, Ordner gleicher Ebene untereinander
      var byDepth = {};
      folderKeys.forEach(function(parentFolder) {
        var d = folderDepth(parentFolder);
        if (!byDepth[d]) byDepth[d] = [];
        byDepth[d].push(parentFolder);
      });

      var depthKeys = Object.keys(byDepth).map(Number).sort(function(a, b) { return a - b; });

      // Pro Ordner einen Layout-Anker (erster Knoten)
      var anchorsByDepth = {};
      depthKeys.forEach(function(d) { anchorsByDepth[d] = []; });

      depthKeys.forEach(function(d) {
        var folderList = byDepth[d] || [];
        lines.push('  subgraph col_d' + d + ' [" "]');
        folderList.forEach(function(parentFolder, idx) {
          var info = folderMap[parentFolder] || { label: 'scripts', nodes: [] };
          var folderNodes = info.nodes || [];
          var safePath = (parentFolder || 'root_' + d + '_' + idx).replace(/[/\\]/g, '_').replace(/[^A-Za-z0-9_]/g, '_');
          var folderId = 'folder_' + safePath + '_' + d + '_' + idx;

          lines.push('    subgraph ' + folderId + ' ["' + escapeMermaidLabel(info.label || 'scripts') + '"]');
          folderNodes.forEach(function(n, nodeIdx) {
            var lbl = n.displayName || n.fullPath || n.id;
            if (n.type) {
              lbl = lbl + ' (' + n.type + ')';
            }
            lines.push('      ' + n.id + '["' + escapeMermaidLabel(lbl) + '"]');
            if (nodeIdx === 0) {
              anchorsByDepth[d].push(n.id);
            }
          });
          lines.push('    end');
        });
        lines.push('  end');
      });

      if (external.length > 0) {
        // Externe Ziele in separatem Subgraph "Extern"
        lines.push('  subgraph external["Extern"]');
        external.forEach(function(n) {
          var lbl = n.displayName || n.fullPath || n.id;
          if (n.type) {
            lbl = lbl + ' (' + n.type + ')';
          }
          lines.push('    ' + n.id + '["' + escapeMermaidLabel(lbl) + '"]');
        });
        lines.push('  end');
      }

      // Typ-Farben
      var typeStyle = {
        VBS:   'fill:#dbeafe,stroke:#1e40af',
        BAT:   'fill:#fef3c7,stroke:#92400e',
        CMD:   'fill:#fef3c7,stroke:#92400e',
        PS1:   'fill:#dcfce7,stroke:#166534',
        PSM1:  'fill:#dcfce7,stroke:#166534',
        KIX:   'fill:#f3e8ff,stroke:#6b21a8',
        EXE:   'fill:#ffedd5,stroke:#c05621',
        MSI:   'fill:#ffedd5,stroke:#c05621',
        DLL:   'fill:#e5e7eb,stroke:#374151',
        LNK:   'fill:#e0f2fe,stroke:#0369a1',
        URL:   'fill:#e0f2fe,stroke:#0369a1',
        TXT:   'fill:#cffafe,stroke:#0e7490',
        LOG:   'fill:#cffafe,stroke:#0e7490',
        INI:   'fill:#ccfbf1,stroke:#0f766e',
        CFG:   'fill:#ccfbf1,stroke:#0f766e',
        CONFIG:'fill:#ccfbf1,stroke:#0f766e',
        XML:   'fill:#e0f2fe,stroke:#1d4ed8',
        JSON:  'fill:#e0f2fe,stroke:#1d4ed8',
        CSV:   'fill:#fef9c3,stroke:#854d0e',
        FILE:  'fill:#f3f4f6,stroke:#4b5563'
      };

      renderedNodes.forEach(function(n) {
        var s = typeStyle[n.type] || null;
        if (s) {
          lines.push('  style ' + n.id + ' ' + s);
        }
        lines.push('  click ' + n.id + ' href "#code-' + n.id + '" "Zur Datei springen"');
      });

      // Layout-Kanten: unsichtbare Verbindungen zwischen Tiefen, um links-rechts-Anordnung zu erzwingen
      var layoutEdgeCount = 0;
      for (var i = 0; i < depthKeys.length; i++) {
        var d = depthKeys[i];
        var anchors = anchorsByDepth[d] || [];
        var canUseColumnLayoutEdges = anchors.length > 1;
        if (!canUseColumnLayoutEdges) {
          continue;
        }
        for (var j = 0; j < anchors.length - 1; j++) {
          lines.push('  ' + anchors[j] + ' ~~~ ' + anchors[j + 1]);
          layoutEdgeCount++;
        }
        if (i < depthKeys.length - 1) {
          var nextD = depthKeys[i + 1];
          var nextAnchors = anchorsByDepth[nextD] || [];
          if (nextAnchors.length > 1) {
            lines.push('  ' + anchors[anchors.length - 1] + ' --> ' + nextAnchors[0]);
            layoutEdgeCount++;
          }
        }
      }

      var edgeIndex = 0;
      var crossIndices = [];
      (edges || []).forEach(function(e) {
        var sid = e.sourceId;
        var tid = e.targetId;
        if (sid && tid) {
          lines.push('  ' + sid + ' --> ' + tid);
          if (e.isCrossBoundary) {
            crossIndices.push(layoutEdgeCount + edgeIndex);
          }
          edgeIndex++;
        }
      });

      // Layout-Kanten unsichtbar machen
      for (var k = 0; k < layoutEdgeCount; k++) {
        lines.push('  linkStyle ' + k + ' stroke:transparent,fill:transparent,color:transparent,stroke-width:0,opacity:0');
      }
      // Cross-Boundary-Kanten rot hervorheben
      crossIndices.forEach(function(idx) {
        lines.push('  linkStyle ' + idx + ' stroke:red,stroke-width:2px');
      });

      return lines.join('\n');
    }

    function applyZoom() {
      var svg = mermaidTarget ? mermaidTarget.querySelector('svg') : null;
      if (!svg) return;
      svg.style.transformOrigin = '0 0';
      svg.style.transform = 'scale(' + currentZoom + ')';
    }

    function renderMermaid(code) {
      if (!mermaidTarget || typeof mermaid === 'undefined') return;
      if (!code || !code.trim()) {
        mermaidTarget.innerHTML = '<p class="text-sm text-gray-500">Keine Daten für diesen Top-Ordner.</p>';
        return;
      }
      var id = 'mermaid-render-' + (++renderId);
      mermaid.render(id, code).then(function(result) {
        mermaidTarget.innerHTML = result.svg || '';
        if (result.bindFunctions) {
          result.bindFunctions(mermaidTarget);
        }
        applyZoom();
        (currentRenderedNodes || []).forEach(function(n) {
          var nodeEl = findDiagramNodeElement(n.id);
          if (!nodeEl) return;
          nodeEl.style.cursor = 'pointer';
          nodeEl.addEventListener('click', function() {
            var target = document.getElementById('code-' + n.id);
            if (!target) return;
            target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            if (history && history.replaceState) {
              history.replaceState(null, '', '#code-' + n.id);
            }
          });
        });
      }).catch(function(err) {
        mermaidTarget.textContent = 'Diagramm-Fehler: ' + (err.message || String(err));
      });
    }

    function setZoomFromRange() {
      if (!zoomRange) return;
      var val = parseInt(zoomRange.value, 10);
      if (isNaN(val) || val <= 0) val = 100;
      currentZoom = val / 100;
      if (zoomLabel) {
        zoomLabel.textContent = val + '%';
      }
      applyZoom();
    }

    function getSafeKey(topVal) {
      if (!topVal) return null;
      if (topVal === '[Extern]') return 'EXTERN';
      var safe = topVal.replace(/[^A-Za-z0-9_-]/g, '_');
      if (!safe) safe = 'ROOT';
      return safe;
    }

    function getEmbeddedData(safeKey) {
      if (!safeKey) return null;
      var el = document.getElementById('data-' + safeKey);
      if (!el) return null;
      var txt = el.textContent || el.innerText || '';
      if (!txt) return null;
      try {
        return JSON.parse(txt);
      } catch (e) {
        console.error('Fehler beim Parsen eingebetteter Daten für', safeKey, e);
        return null;
      }
    }

    function renderCurrentData() {
      if (!currentData) {
        mermaidTarget.innerHTML = '<p class="text-sm text-gray-500">Bitte einen Top-Ordner auswählen.</p>';
        if (codeSectionsEl) codeSectionsEl.innerHTML = '<p class="text-sm text-gray-500">Bitte einen Top-Ordner auswählen.</p>';
        return;
      }
      var nodes = (currentData && currentData.nodes) || [];
      var edges = (currentData && currentData.edges) || [];

      if (hideCommentLinksToggle && hideCommentLinksToggle.checked) {
        edges = edges.filter(function(e) { return !e.isCommentLink; });
      }

      // Optional: alle roten Verweise (Cross-Boundary) inkl. deren Fremd-/Externe Knoten ausblenden
      if (hideExternalToggle && hideExternalToggle.checked) {
        if (currentTopVal && currentTopVal !== '[Extern]') {
          nodes = nodes.filter(function(n) {
            return !n.isExternal && n.topFolder === currentTopVal;
          });
        } else {
          nodes = nodes.filter(function(n) { return !n.isExternal; });
        }
        var keepIds = {};
        nodes.forEach(function(n) { keepIds[n.id] = true; });
        edges = edges.filter(function(e) {
          return !e.isCrossBoundary && keepIds[e.sourceId] && keepIds[e.targetId];
        });
      }

      var code = buildMermaidCode(nodes, edges);
      currentRenderedNodes = nodes.slice();
      renderMermaid(code);
      renderCodeSections(nodes, edges);
    }

    function loadAndRender(topVal) {
      currentTopVal = topVal || '';
      var safeKey = getSafeKey(topVal);
      if (!topVal || !safeKey) {
        mermaidTarget.innerHTML = '<p class="text-sm text-gray-500">Bitte einen Top-Ordner auswählen.</p>';
        if (codeSectionsEl) codeSectionsEl.innerHTML = '<p class="text-sm text-gray-500">Bitte einen Top-Ordner auswählen.</p>';
        return;
      }

      // Datei-Modus oder externe Ziele: direkt aus eingebetteten JSON-Daten lesen (funktioniert auch bei file://)
      if (window.location.protocol === 'file:' || topVal === '[Extern]') {
        var data = getEmbeddedData(safeKey);
        if (!data) {
          mermaidTarget.innerHTML = '<p class="text-sm text-red-600">Keine eingebetteten Daten für ' + topVal + ' gefunden.</p>';
          return;
        }
        currentData = data;
        renderCurrentData();
        return;
      }

      // HTTP-Modus: JSON-Dateien dynamisch nachladen
      var jsonFile = 'ScriptFlowchart-All-' + safeKey + '.json';
      if (!jsonFile) {
        mermaidTarget.innerHTML = '<p class="text-sm text-gray-500">Bitte einen Top-Ordner auswählen.</p>';
        return;
      }
      mermaidTarget.textContent = 'Lade Daten für ' + topVal + ' ...';
      fetch(jsonFile, { cache: 'no-store' })
        .then(function(resp) {
          if (!resp.ok) {
            throw new Error('HTTP ' + resp.status + ' beim Laden von ' + jsonFile);
          }
          return resp.json();
        })
        .then(function(data) {
          currentData = data;
          renderCurrentData();
        })
        .catch(function(err) {
          mermaidTarget.textContent = 'Fehler beim Laden der Daten: ' + (err.message || String(err));
        });
    }

    if (zoomRange) {
      zoomRange.addEventListener('input', setZoomFromRange);
      zoomRange.addEventListener('change', setZoomFromRange);
    }
    if (hideExternalToggle) {
      hideExternalToggle.addEventListener('change', function() {
        renderCurrentData();
      });
    }
    if (hideCommentLinksToggle) {
      hideCommentLinksToggle.addEventListener('change', function() {
        renderCurrentData();
      });
    }
    if (codeSectionsEl) {
      codeSectionsEl.addEventListener('click', function(ev) {
        var btn = ev.target && ev.target.closest ? ev.target.closest('.jump-to-node') : null;
        if (!btn) return;
        ev.preventDefault();
        var nodeId = btn.getAttribute('data-node-id');
        if (!nodeId) return;
        scrollToNodeInDiagram(nodeId);
        if (history && history.replaceState) {
          history.replaceState(null, '', '#');
        }
      });
    }
    if (zoomInBtn) {
      zoomInBtn.addEventListener('click', function() {
        var val = zoomRange ? parseInt(zoomRange.value, 10) || 100 : Math.round(currentZoom * 100);
        val = Math.min(1000, val + 50);
        if (zoomRange) zoomRange.value = String(val);
        setZoomFromRange();
      });
    }
    if (zoomOutBtn) {
      zoomOutBtn.addEventListener('click', function() {
        var val = zoomRange ? parseInt(zoomRange.value, 10) || 100 : Math.round(currentZoom * 100);
        val = Math.max(100, val - 50);
        if (zoomRange) zoomRange.value = String(val);
        setZoomFromRange();
      });
    }

    if (selectTop) {
      selectTop.addEventListener('change', function() {
        loadAndRender(selectTop.value);
      });
      // Initial: falls es einen ersten echten Top-Ordner gibt, direkt laden
      if (selectTop.value === '' && selectTop.options.length > 1) {
        selectTop.value = selectTop.options[1].value;
      }
      if (selectTop.value) {
        loadAndRender(selectTop.value);
      }
    } else if (mermaidTarget) {
      mermaidTarget.textContent = 'Kein Top-Ordner-Filter gefunden.';
    }
  })();
  </script>
</body>
</html>
"@

    try {
        $html | Set-Content -Path $OutputFilePath -Encoding UTF8
        Write-Host "HTML geschrieben (Template): $OutputFilePath" -ForegroundColor Green
    }
    catch {
        Write-Error "Fehler beim Schreiben der HTML-Template-Datei: $($_.Exception.Message)"
    }
}

# Main

$rootResolved = Resolve-Path -Path $ScriptsPath -ErrorAction Stop
$rootPath = $rootResolved.ProviderPath

$normalizedExclude = @(Get-NormalizedExcludeFolders -Folders $ExcludeFolders)
if (@($normalizedExclude).Count -gt 0) {
    Write-Host ("Ausschlussordner (inkl. Unterordner) werden ignoriert: {0}" -f ($normalizedExclude -join ', ')) -ForegroundColor Yellow
    foreach ($prefix in $normalizedExclude) {
        $folderPath = Join-Path -Path $rootPath -ChildPath ($prefix -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $folderPath -PathType Container)) {
            Write-Warning "Ausschlussordner '$prefix' wurde unterhalb von '$rootPath' nicht gefunden."
        }
    }
}

Write-Host "Scanne $rootPath (alle Dateien) ..." -ForegroundColor Cyan

try {
    $allFiles = Get-ChildItem -Path $rootPath -Recurse -File -ErrorAction Stop
}
catch {
    Write-Error "Fehler beim Scannen von $rootPath : $($_.Exception.Message)"
    return
}

$nodesByPath = @{}
$nodeList = New-Object System.Collections.Generic.List[object]
$nameIndex = @{}
$externalNodesByLabel = @{}

$nextId = [ref]0

# Zuerst: alle lokalen Dateien als Knoten anlegen
foreach ($f in $allFiles) {
    if (Test-IsExcludedPath -FullPath $f.FullName -RootPath $rootPath -ExcludePrefixes $normalizedExclude) {
        continue
    }
    [void](New-Node -NodesByPath $nodesByPath -NodeList $nodeList -NameIndex $nameIndex -FullPath $f.FullName -RootPath $rootPath -IsExternal:$false -NextId $nextId)
}

Write-Host ("Gefunden: {0} Dateien (nach Ausschlussfilter)." -f $nodeList.Count) -ForegroundColor Cyan

# Danach: textbasierte Dateien nach Verknüpfungen durchsuchen
$edgeListRaw = New-Object System.Collections.Generic.List[object]

$total = [math]::Max(1, @($allFiles).Count)
$i = 0
foreach ($f in $allFiles) {
    $i++
    if (Test-IsExcludedPath -FullPath $f.FullName -RootPath $rootPath -ExcludePrefixes $normalizedExclude) {
        continue
    }
    $extInfo = Get-EffectiveExtensionInfo -Path $f.FullName
    $ext = [string]$extInfo.EffectiveExtension
    if (-not ($script:TextLikeExtensions -contains $ext)) {
        continue
    }
    Write-Progress -Activity 'Analysiere Dateiverknüpfungen' -Status $f.Name -PercentComplete ([math]::Min(100, [int](100 * $i / $total)))

    $content = Get-FileContentSafe -Path $f.FullName
    if ([string]::IsNullOrEmpty($content)) { continue }
    if ($nodesByPath.ContainsKey($f.FullName)) {
        $nodesByPath[$f.FullName].Content = $content
    }

    $edges = Get-LinksFromContent -Content $content -SourcePath $f.FullName -Extension $ext -NameIndex $nameIndex -ExternalNodesByLabel $externalNodesByLabel -NodesByPath $nodesByPath -NodeList $nodeList -RootPath $rootPath -NextId $nextId
    foreach ($e in $edges) {
        $edgeListRaw.Add($e) | Out-Null
    }
}
Write-Progress -Activity 'Analysiere Dateiverknüpfungen' -Completed

# Aus den Roh-Kanten die endgültige Kantenliste mit Knoten-IDs und Cross-Boundary-Flag bauen
$edgesFinal = New-Object System.Collections.Generic.List[object]
$edgeIndexByKey = @{}

foreach ($e in $edgeListRaw) {
    $srcPath = $e.SourcePath
    $tgtPath = $e.TargetPath
    if (-not $srcPath -or -not $tgtPath) { continue }
    if (-not $nodesByPath.ContainsKey($srcPath) -or -not $nodesByPath.ContainsKey($tgtPath)) { continue }

    $srcNode = $nodesByPath[$srcPath]
    $tgtNode = $nodesByPath[$tgtPath]

    $edgeKey = "$($srcNode.Id)->$($tgtNode.Id)"
    $isCross = $false
    if ($tgtNode.IsExternal -or $srcNode.TopFolder -ne $tgtNode.TopFolder) {
        $isCross = $true
    }

    if ($edgeIndexByKey.ContainsKey($edgeKey)) {
        $existing = $edgesFinal[$edgeIndexByKey[$edgeKey]]
        if ($existing.IsCommentLink -and -not [bool]$e.IsCommentLink) {
            $existing.IsCommentLink = $false
            if ($e.Label) { $existing.Label = $e.Label }
        }
        continue
    }

    $edgeObj = [pscustomobject]@{
        SourceId        = $srcNode.Id
        TargetId        = $tgtNode.Id
        SourcePath      = $srcNode.FullPath
        TargetPath      = $tgtNode.FullPath
        Label           = $e.Label
        IsCrossBoundary = $isCross
        IsCommentLink   = [bool]$e.IsCommentLink
    }
    $edgesFinal.Add($edgeObj) | Out-Null
    $edgeIndexByKey[$edgeKey] = $edgesFinal.Count - 1
}

Write-Host ("Verknüpfungen gefunden: {0}" -f $edgesFinal.Count) -ForegroundColor Cyan

# Ausgabe-Datei auflösen/anlegen
$outResolved = $OutputPath
if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
    $outResolved = Join-Path -Path (Get-Location) -ChildPath $OutputPath
}
$outDir = [System.IO.Path]::GetDirectoryName($outResolved)
if (-not [string]::IsNullOrEmpty($outDir) -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

# Top-Ordner ermitteln
$internalTopFolders = @(
    $nodeList |
        Where-Object { -not $_.IsExternal } |
        Select-Object -ExpandProperty TopFolder -Unique |
        Sort-Object
)
$hasExternalNodes = $nodeList | Where-Object { $_.IsExternal } | Select-Object -First 1
$topFoldersForTemplate = @($internalTopFolders)
if ($hasExternalNodes) {
    $topFoldersForTemplate += '[Extern]'
}

# JSON-Dateien pro Top-Ordner erzeugen
$embeddedData = @{}
foreach ($tf in $internalTopFolders) {
    $localNodes = @($nodeList | Where-Object { -not $_.IsExternal -and $_.TopFolder -eq $tf })
    if ($localNodes.Count -eq 0) { continue }

    $pathSet = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $localNodes) {
        if ($n.FullPath) { [void]$pathSet.Add($n.FullPath) }
    }

    $localEdges = @(
        $edgesFinal | Where-Object {
            $pathSet.Contains($_.SourcePath) -or $pathSet.Contains($_.TargetPath)
        }
    )

    foreach ($e in $localEdges) {
        if ($e.SourcePath) { [void]$pathSet.Add($e.SourcePath) }
        if ($e.TargetPath) { [void]$pathSet.Add($e.TargetPath) }
    }

    $nodesForTf = @(
        $nodeList | Where-Object { $pathSet.Contains($_.FullPath) }
    )

    $reportNodesTf = @(
        $nodesForTf | ForEach-Object {
            [ordered]@{
                id           = $_.Id
                fullPath     = $_.FullPath
                displayName  = $_.DisplayName
                type         = $_.Type
                topFolder    = $_.TopFolder
                relativePath = $_.RelativePath
                folderDepth  = $_.FolderDepth
                isExternal   = [bool]$_.IsExternal
                content      = (Get-SanitizedContentForJson -Content $_.Content)
            }
        }
    )

    $reportEdgesTf = @(
        $localEdges | ForEach-Object {
            [ordered]@{
                sourceId       = $_.SourceId
                targetId       = $_.TargetId
                sourcePath     = $_.SourcePath
                targetPath     = $_.TargetPath
                label          = $_.Label
                isCrossBoundary = [bool]$_.IsCrossBoundary
                isCommentLink  = [bool]$_.IsCommentLink
            }
        }
    )

    $obj = @{ nodes = $reportNodesTf; edges = $reportEdgesTf }
    $json = $obj | ConvertTo-Json -Depth 4 -Compress

    $safeTf = $tf -replace '[^A-Za-z0-9_-]', '_'
    if ([string]::IsNullOrWhiteSpace($safeTf)) { $safeTf = 'ROOT' }
    $jsonFileName = "ScriptFlowchart-All-$safeTf.json"
    $jsonPath = Join-Path -Path $outDir -ChildPath $jsonFileName
    $json | Set-Content -Path $jsonPath -Encoding UTF8
    $embeddedData[$safeTf] = $json
    Write-Host ("JSON für Top-Ordner '{0}' geschrieben: {1}" -f $tf, $jsonFileName) -ForegroundColor Green
}

# JSON-Struktur für externe Ziele (nur eingebettet, keine eigene Datei)
if ($hasExternalNodes) {
    $externalNodes = @($nodeList | Where-Object { $_.IsExternal })
    if ($externalNodes.Count -gt 0) {
        $extPathSet = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
        foreach ($n in $externalNodes) {
            if ($n.FullPath) { [void]$extPathSet.Add($n.FullPath) }
        }
        $extEdges = @(
            $edgesFinal | Where-Object {
                $extPathSet.Contains($_.SourcePath) -and $extPathSet.Contains($_.TargetPath)
            }
        )

        $reportNodesExt = @(
            $externalNodes | ForEach-Object {
                [ordered]@{
                    id           = $_.Id
                    fullPath     = $_.FullPath
                    displayName  = $_.DisplayName
                    type         = $_.Type
                    topFolder    = $_.TopFolder
                    relativePath = $_.RelativePath
                    folderDepth  = $_.FolderDepth
                    isExternal   = $true
                    content      = $null
                }
            }
        )
        $reportEdgesExt = @(
            $extEdges | ForEach-Object {
                [ordered]@{
                    sourceId       = $_.SourceId
                    targetId       = $_.TargetId
                    sourcePath     = $_.SourcePath
                    targetPath     = $_.TargetPath
                    label          = $_.Label
                    isCrossBoundary = [bool]$_.IsCrossBoundary
                    isCommentLink  = [bool]$_.IsCommentLink
                }
            }
        )
        $objExt = @{ nodes = $reportNodesExt; edges = $reportEdgesExt }
        $jsonExt = $objExt | ConvertTo-Json -Depth 4 -Compress
        $embeddedData['EXTERN'] = $jsonExt
        Write-Host "Struktur für externe Ziele vorbereitet (nur eingebettet, keine JSON-Datei)." -ForegroundColor Green
    }
}

# HTML-Template schreiben (lädt pro Auswahl die passende JSON-Datei nach)
Export-ScriptLinksFlowchartTemplate -TopFolders $topFoldersForTemplate -EmbeddedData $embeddedData -OutputFilePath $outResolved

