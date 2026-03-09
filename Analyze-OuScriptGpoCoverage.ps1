<#
.SYNOPSIS
    OU-basierte Script/GPO-Abdeckungsanalyse (read-only) fuer AD-Domaenen.

.DESCRIPTION
    Analysiert eine Start-OU inkl. aller untergeordneten OUs. Ermittelt pro User und Computer
    die statisch effektiven GPOs (OU-Vererbung + Security-Filter), sammelt zugeordnete
    Logon/Logoff/Startup/Shutdown-Skripte (inkl. AD scriptPath), klassifiziert deren Funktionen
    und vergleicht sie mit den in effektiven GPOs erkannten Funktionen.

    Ergebnis:
    - Interaktiver HTML-Report
    - JSON-Dataset (fuer Nachvollziehbarkeit)
    - optional Resume/Checkpoint

    Unterstuetzte Skripttypen:
    .ps1, .psm1, .bat, .cmd, .vbs, .kix

    Hinweis:
    - Read-only (keine Aenderungen in AD/GPO/SYSVOL)
    - Statische Modellierung; kein Client-RSoP/GPResult
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$StartOuDn,

    [string]$DomainFqdn = '',

    [string]$OutputPath = ".\OuScriptGpoCoverageReport.html",

    [switch]$IncludeContent,

    [switch]$Resume,

    [string]$CheckpointPath = ".\ou_script_gpo_coverage_checkpoint.json",

    [System.Text.Encoding]$Encoding = [System.Text.Encoding]::UTF8,

    [ValidateRange(10240, 5242880)]
    [int]$MaxScriptBytes = 1048576
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ScriptExtensions = @('.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.kix')

function Resolve-FullPathSafe {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $p = Resolve-Path -LiteralPath $Path -ErrorAction Stop
        return $p.ProviderPath
    }
    catch {
        if ([System.IO.Path]::IsPathRooted($Path)) { return $Path }
        return [System.IO.Path]::GetFullPath((Join-Path -Path (Get-Location) -ChildPath $Path))
    }
}

function Read-CheckpointSafe {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        Write-Warning "Checkpoint unlesbar: $($_.Exception.Message)"
        return $null
    }
}

function Write-CheckpointSafe {
    param(
        [Parameter(Mandatory = $true)][hashtable]$State,
        [Parameter(Mandatory = $true)][string]$Path
    )
    try {
        $State.TimestampUtc = (Get-Date).ToUniversalTime()
        $State | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Path -Encoding UTF8
    }
    catch {
        Write-Warning "Konnte Checkpoint nicht schreiben: $($_.Exception.Message)"
    }
}

function Initialize-RequiredModules {
    $missing = @()
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) { $missing += 'ActiveDirectory' }
    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) { $missing += 'GroupPolicy' }
    if ($missing.Count -gt 0) {
        throw "Fehlende Module: $($missing -join ', '). Bitte RSAT/Module installieren."
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module GroupPolicy -ErrorAction Stop
}

function Get-CategoryPatterns {
    $opts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    return [ordered]@{
        'Laufwerks-Mappings' = @(
            [regex]::new('net\s+use', $opts),
            [regex]::new('New-PSDrive', $opts),
            [regex]::new('MapNetworkDrive', $opts),
            [regex]::new('WScript\.Network', $opts)
        )
        'Drucker-Einrichtung' = @(
            [regex]::new('Add-Printer', $opts),
            [regex]::new('printui\.dll', $opts),
            [regex]::new('AddWindowsPrinterConnection', $opts),
            [regex]::new('SetDefaultPrinter', $opts)
        )
        'Software-Verteilung/Updates' = @(
            [regex]::new('msiexec', $opts),
            [regex]::new('\.msi\b', $opts),
            [regex]::new('Start-Process', $opts),
            [regex]::new('WshShell\.Run', $opts),
            [regex]::new('\.exe\b', $opts)
        )
        'Sicherheit/Compliance' = @(
            [regex]::new('ExecutionPolicy', $opts),
            [regex]::new('BitLocker', $opts),
            [regex]::new('Defender', $opts),
            [regex]::new('LegalNotice', $opts)
        )
        'Umgebungsvariablen/Pfade' = @(
            [regex]::new('setx', $opts),
            [regex]::new('SetEnvironmentVariable', $opts),
            [regex]::new('PATH', $opts)
        )
        'Inventarisierung/Asset' = @(
            [regex]::new('Get-CimInstance', $opts),
            [regex]::new('Get-WmiObject', $opts),
            [regex]::new('Win32_', $opts),
            [regex]::new('systeminfo', $opts)
        )
    }
}

function Get-PrimaryCategoriesFromText {
    param(
        [AllowNull()][string]$Text,
        [hashtable]$Patterns
    )
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $hits = New-Object System.Collections.Generic.List[object]
    foreach ($cat in $Patterns.Keys) {
        $count = 0
        foreach ($rx in $Patterns[$cat]) {
            $count += $rx.Matches($Text).Count
        }
        if ($count -gt 0) {
            $hits.Add([pscustomobject]@{ Category = $cat; Hits = $count }) | Out-Null
        }
    }
    return @($hits | Sort-Object -Property Hits -Descending | Select-Object -ExpandProperty Category)
}

function Get-FileContentSafe {
    param([Parameter(Mandatory = $true)][string]$Path)
    try {
        $fi = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($fi.Length -gt $MaxScriptBytes) {
            $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            try {
                $len = [int][Math]::Min($MaxScriptBytes, $fi.Length)
                $buf = New-Object byte[] $len
                [void]$fs.Read($buf, 0, $len)
                if ($buf -contains 0) { return $null }
                return $Encoding.GetString($buf)
            }
            finally { $fs.Close() }
        }
        $txt = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop
        return $txt
    }
    catch {
        try {
            $txt = Get-Content -LiteralPath $Path -Raw -Encoding $Encoding -ErrorAction Stop
            return $txt
        }
        catch {
            return $null
        }
    }
}

function Get-DomainContext {
    param([string]$DomainFqdnParam)
    if (-not [string]::IsNullOrWhiteSpace($DomainFqdnParam)) {
        $domainObj = Get-ADDomain -Identity $DomainFqdnParam -ErrorAction Stop
    }
    else {
        $domainObj = Get-ADDomain -ErrorAction Stop
    }
    $fqdn = [string]$domainObj.DNSRoot
    return [pscustomobject]@{
        DomainFqdn     = $fqdn
        DomainDn       = [string]$domainObj.DistinguishedName
        ScriptsRoot    = "\\$fqdn\SYSVOL\$fqdn\scripts"
    }
}

function Get-OuSubtree {
    param([Parameter(Mandatory = $true)][string]$StartDn)
    $startOu = Get-ADOrganizationalUnit -Identity $StartDn -ErrorAction Stop
    $all = @(
        Get-ADOrganizationalUnit -LDAPFilter '(objectClass=organizationalUnit)' -SearchBase $StartDn -SearchScope Subtree -Properties DistinguishedName,Name -ErrorAction Stop |
            Select-Object DistinguishedName,Name
    )
    if (-not ($all | Where-Object { $_.DistinguishedName -eq $startOu.DistinguishedName })) {
        $all += [pscustomobject]@{ DistinguishedName = $startOu.DistinguishedName; Name = $startOu.Name }
    }
    return @($all | Sort-Object -Property DistinguishedName -Unique)
}

function Get-ObjectsInOuTree {
    param([Parameter(Mandatory = $true)][string]$StartDn)
    $users = @(
        Get-ADUser -LDAPFilter '(objectCategory=person)' -SearchBase $StartDn -SearchScope Subtree -Properties DistinguishedName,SamAccountName,scriptPath,SID,MemberOf -ErrorAction Stop |
            Select-Object DistinguishedName,SamAccountName,scriptPath,SID,MemberOf
    )
    $computers = @(
        Get-ADComputer -LDAPFilter '(objectCategory=computer)' -SearchBase $StartDn -SearchScope Subtree -Properties DistinguishedName,Name,SID,MemberOf -ErrorAction Stop |
            Select-Object DistinguishedName,Name,SID,MemberOf
    )
    return [pscustomobject]@{ Users = $users; Computers = $computers }
}

function Get-ContainerPathFromDn {
    param([Parameter(Mandatory = $true)][string]$DistinguishedName)
    $parts = $DistinguishedName -split ','
    if ($parts.Count -le 1) { return $DistinguishedName }
    return ($parts[1..($parts.Count - 1)] -join ',')
}

function Get-ContainerChainToDomain {
    param(
        [Parameter(Mandatory = $true)][string]$ContainerDn,
        [Parameter(Mandatory = $true)][string]$DomainDn
    )
    $chain = New-Object System.Collections.Generic.List[string]
    $current = $ContainerDn
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        $chain.Add($current) | Out-Null
        if ($current.Equals($DomainDn, [StringComparison]::OrdinalIgnoreCase)) { break }
        $idx = $current.IndexOf(',')
        if ($idx -lt 0 -or $idx -ge ($current.Length - 1)) { break }
        $current = $current.Substring($idx + 1)
    }
    return @($chain)
}

function Get-GpoPermissionsMap {
    param([Parameter(Mandatory = $true)][array]$Gpos)
    $map = @{}
    foreach ($gpo in $Gpos) {
        $id = [string]$gpo.Id
        if ($map.ContainsKey($id)) { continue }
        $allow = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
        try {
            $perms = Get-GPPermission -Guid $gpo.Id -All -ErrorAction Stop
            foreach ($p in $perms) {
                $permName = [string]$p.Permission
                if ($permName -in @('GpoApply', 'GpoRead', 'GpoEditDeleteModifySecurity', 'GpoEdit', 'GpoCustom')) {
                    if ($permName -eq 'GpoApply') {
                        $n = [string]$p.Trustee.Name
                        if (-not [string]::IsNullOrWhiteSpace($n)) { [void]$allow.Add($n) }
                    }
                }
            }
        }
        catch {
            # ohne Permissiondaten -> spaeter als "unbekannt/zulassen" behandeln
        }
        $map[$id] = [pscustomobject]@{
            AllowedTrustees = @($allow)
            HasData = ($allow.Count -gt 0)
        }
    }
    return $map
}

function Get-TokenForPrincipal {
    param(
        [Parameter(Mandatory = $true)][string]$Dn,
        [Parameter(Mandatory = $true)][string]$PrincipalType, # User|Computer
        [Parameter(Mandatory = $true)][string]$Sid
    )
    $names = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
    $sids = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
    if (-not [string]::IsNullOrWhiteSpace($Sid)) { [void]$sids.Add($Sid) }
    try {
        if ($PrincipalType -eq 'User') {
            $principal = Get-ADUser -Identity $Dn -Properties SamAccountName -ErrorAction Stop
        }
        else {
            $principal = Get-ADComputer -Identity $Dn -Properties SamAccountName -ErrorAction Stop
        }
        if ($principal.SamAccountName) { [void]$names.Add([string]$principal.SamAccountName) }
    }
    catch {}

    try {
        $groups = Get-ADPrincipalGroupMembership -Identity $Dn -ErrorAction Stop
        foreach ($g in $groups) {
            if ($g.Name) { [void]$names.Add([string]$g.Name) }
            if ($g.SamAccountName) { [void]$names.Add([string]$g.SamAccountName) }
            if ($g.SID) { [void]$sids.Add([string]$g.SID.Value) }
        }
    }
    catch {}

    # praktisch fuer die meisten Standardfaelle
    [void]$names.Add('Authenticated Users')

    return [pscustomobject]@{
        Names = @($names)
        Sids  = @($sids)
    }
}

function Test-GpoAppliesToPrincipal {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$PermissionInfo,
        [Parameter(Mandatory = $true)][pscustomobject]$TokenInfo
    )
    if ($null -eq $PermissionInfo -or -not $PermissionInfo.HasData) { return $true }
    foreach ($n in $PermissionInfo.AllowedTrustees) {
        if ($TokenInfo.Names -contains $n) { return $true }
        if ($TokenInfo.Sids -contains $n) { return $true }
    }
    return $false
}

function Get-GpoInheritanceForContainers {
    param([Parameter(Mandatory = $true)][string[]]$ContainerDns)
    $cache = @{}
    foreach ($dn in ($ContainerDns | Sort-Object -Unique)) {
        try {
            $inh = Get-GPInheritance -Target $dn -ErrorAction Stop
            $links = @($inh.InheritedGpoLinks)
            $cache[$dn] = $links
        }
        catch {
            $cache[$dn] = @()
        }
    }
    return $cache
}

function Get-EffectiveGposForPrincipal {
    param(
        [Parameter(Mandatory = $true)][string]$ContainerDn,
        [Parameter(Mandatory = $true)][string]$DomainDn,
        [Parameter(Mandatory = $true)][string]$PrincipalType, # User|Computer
        [Parameter(Mandatory = $true)][pscustomobject]$TokenInfo,
        [Parameter(Mandatory = $true)][hashtable]$InheritanceCache,
        [Parameter(Mandatory = $true)][hashtable]$PermissionMap
    )
    $chain = Get-ContainerChainToDomain -ContainerDn $ContainerDn -DomainDn $DomainDn
    $resolved = New-Object System.Collections.Generic.List[object]
    $seen = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
    foreach ($container in $chain) {
        $links = @()
        if ($InheritanceCache.ContainsKey($container)) { $links = @($InheritanceCache[$container]) }
        foreach ($lnk in $links) {
            if ($null -eq $lnk) { continue }
            $gpoId = [string]$lnk.GpoId
            if ([string]::IsNullOrWhiteSpace($gpoId)) { continue }
            if ($seen.Contains($gpoId)) { continue }
            $seen.Add($gpoId) | Out-Null

            $perm = $null
            if ($PermissionMap.ContainsKey($gpoId)) { $perm = $PermissionMap[$gpoId] }
            $allowed = Test-GpoAppliesToPrincipal -PermissionInfo $perm -TokenInfo $TokenInfo
            if (-not $allowed) { continue }

            $status = [string]$lnk.GpoStatus
            if ($PrincipalType -eq 'User' -and $status -in @('User settings disabled', 'AllSettingsDisabled')) { continue }
            if ($PrincipalType -eq 'Computer' -and $status -in @('Computer settings disabled', 'AllSettingsDisabled')) { continue }

            $resolved.Add([pscustomobject]@{
                GpoId        = $gpoId
                DisplayName  = [string]$lnk.DisplayName
                TargetDn     = $container
                Enforced     = [bool]$lnk.Enforced
                Enabled      = [bool]$lnk.Enabled
                GpoStatus    = $status
                Order        = [int]$lnk.Order
            }) | Out-Null
        }
    }
    return @($resolved)
}

function Get-GpoReportMap {
    param([Parameter(Mandatory = $true)][array]$AllGpos)
    $map = @{}
    foreach ($gpo in $AllGpos) {
        $id = [string]$gpo.Id
        if ($map.ContainsKey($id)) { continue }
        try {
            $xml = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction Stop
            $map[$id] = [string]$xml
        }
        catch {
            $map[$id] = ''
        }
    }
    return $map
}

function Get-GpoScriptRefsFromIni {
    param([Parameter(Mandatory = $true)][string]$IniPath)
    if (-not (Test-Path -LiteralPath $IniPath)) { return @() }
    $lines = @(Get-Content -LiteralPath $IniPath -Encoding UTF8 -ErrorAction SilentlyContinue)
    $refs = New-Object System.Collections.Generic.List[string]
    foreach ($ln in $lines) {
        if ($ln -match '^\s*\d+CmdLine=(.+)$') {
            $cmd = $matches[1].Trim()
            if (-not [string]::IsNullOrWhiteSpace($cmd)) {
                $token = $cmd.Split(' ')[0].Trim('"', "'")
                $refs.Add($token) | Out-Null
            }
        }
    }
    return @($refs)
}

function Resolve-GpoScriptPath {
    param(
        [Parameter(Mandatory = $true)][string]$RawRef,
        [Parameter(Mandatory = $true)][string]$GpoPath,
        [Parameter(Mandatory = $true)][string]$ScriptsRoot,
        [Parameter(Mandatory = $true)][string]$Phase
    )
    if ([string]::IsNullOrWhiteSpace($RawRef)) { return $null }
    $r = $RawRef.Trim('"', "'")
    if ($r -match '^[A-Za-z]:\\' -or $r -like '\\*') { return $r }

    $phaseFolder = if ($Phase -in @('Logon', 'Logoff')) { "User\Scripts\$Phase" } else { "Machine\Scripts\$Phase" }
    $candidateA = Join-Path -Path $GpoPath -ChildPath (Join-Path -Path $phaseFolder -ChildPath $r)
    if (Test-Path -LiteralPath $candidateA) { return (Resolve-FullPathSafe -Path $candidateA) }

    $candidateB = Join-Path -Path $ScriptsRoot -ChildPath $r
    if (Test-Path -LiteralPath $candidateB) { return (Resolve-FullPathSafe -Path $candidateB) }

    return $candidateB
}

function Get-ScriptRefsForGpo {
    param(
        [Parameter(Mandatory = $true)][string]$GpoId,
        [Parameter(Mandatory = $true)][hashtable]$GpoById,
        [Parameter(Mandatory = $true)][hashtable]$GpoReportMap,
        [Parameter(Mandatory = $true)][string]$ScriptsRoot
    )
    if (-not $GpoById.ContainsKey($GpoId)) { return @() }
    $gpo = $GpoById[$GpoId]
    $gpoPath = [string]$gpo.Path
    $refs = New-Object System.Collections.Generic.List[object]

    foreach ($phase in @('Logon', 'Logoff', 'Startup', 'Shutdown')) {
        $iniCandidates = @()
        if ($phase -in @('Logon', 'Logoff')) {
            $iniCandidates += (Join-Path -Path $gpoPath -ChildPath 'User\Scripts\scripts.ini')
            $iniCandidates += (Join-Path -Path $gpoPath -ChildPath 'User\Scripts\psscripts.ini')
        }
        else {
            $iniCandidates += (Join-Path -Path $gpoPath -ChildPath 'Machine\Scripts\scripts.ini')
            $iniCandidates += (Join-Path -Path $gpoPath -ChildPath 'Machine\Scripts\psscripts.ini')
        }
        foreach ($ini in $iniCandidates) {
            $rawRefs = Get-GpoScriptRefsFromIni -IniPath $ini
            foreach ($rr in $rawRefs) {
                $resolved = Resolve-GpoScriptPath -RawRef $rr -GpoPath $gpoPath -ScriptsRoot $ScriptsRoot -Phase $phase
                $refs.Add([pscustomobject]@{
                    GpoId      = $GpoId
                    SourceType = 'GPO'
                    Phase      = $phase
                    RawRef     = $rr
                    ScriptPath = $resolved
                }) | Out-Null
            }
        }
    }

    $xmlText = ''
    if ($GpoReportMap.ContainsKey($GpoId)) { $xmlText = [string]$GpoReportMap[$GpoId] }
    if (-not [string]::IsNullOrWhiteSpace($xmlText)) {
        $scriptMatches = [regex]::Matches($xmlText, '(?i)([A-Za-z0-9_\-\.\\\/]+?\.(?:ps1|psm1|bat|cmd|vbs|kix))')
        foreach ($m in $scriptMatches) {
            $rr = $m.Groups[1].Value
            $phase = 'Unknown'
            $idx = [Math]::Max(0, $m.Index - 80)
            $len = [Math]::Min(160, $xmlText.Length - $idx)
            $ctx = $xmlText.Substring($idx, $len)
            if ($ctx -match '(?i)Logon') { $phase = 'Logon' }
            elseif ($ctx -match '(?i)Logoff') { $phase = 'Logoff' }
            elseif ($ctx -match '(?i)Startup') { $phase = 'Startup' }
            elseif ($ctx -match '(?i)Shutdown') { $phase = 'Shutdown' }
            $resolved = Resolve-GpoScriptPath -RawRef $rr -GpoPath $gpoPath -ScriptsRoot $ScriptsRoot -Phase $phase
            $refs.Add([pscustomobject]@{
                GpoId      = $GpoId
                SourceType = 'GPO'
                Phase      = $phase
                RawRef     = $rr
                ScriptPath = $resolved
            }) | Out-Null
        }
    }

    $dedup = @{}
    foreach ($r in $refs) {
        $k = "$($r.Phase)|$($r.ScriptPath)"
        if (-not $dedup.ContainsKey($k)) { $dedup[$k] = $r }
    }
    return @($dedup.Values)
}

function Get-GpoFunctionMap {
    param(
        [Parameter(Mandatory = $true)][hashtable]$GpoReportMap,
        [Parameter(Mandatory = $true)][hashtable]$Patterns
    )
    $out = @{}
    foreach ($gpoId in $GpoReportMap.Keys) {
        $txt = [string]$GpoReportMap[$gpoId]
        $cats = Get-PrimaryCategoriesFromText -Text $txt -Patterns $Patterns
        $out[$gpoId] = @($cats)
    }
    return $out
}

function Get-ScriptInventory {
    param(
        [Parameter(Mandatory = $true)][array]$ScriptRefs,
        [Parameter(Mandatory = $true)][hashtable]$Patterns
    )
    $items = @{}
    foreach ($r in $ScriptRefs) {
        $path = [string]$r.ScriptPath
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        $ext = [System.IO.Path]::GetExtension($path).ToLowerInvariant()
        if ($ext -notin $script:ScriptExtensions) { continue }
        if ($items.ContainsKey($path)) { continue }
        $exists = Test-Path -LiteralPath $path
        $content = $null
        $cats = @()
        if ($exists) {
            $content = Get-FileContentSafe -Path $path
            $textForCategory = ''
            if ($null -ne $content) { $textForCategory = [string]$content }
            $cats = Get-PrimaryCategoriesFromText -Text $textForCategory -Patterns $Patterns
        }
        $items[$path] = [pscustomobject]@{
            ScriptPath  = $path
            Extension   = $ext
            Exists      = [bool]$exists
            Categories  = @($cats)
            Content     = if ($IncludeContent) { $content } else { $null }
        }
    }
    return $items
}

function Get-CoverageForObject {
    param(
        [Parameter(Mandatory = $true)][array]$ObjectScriptRefs,
        [Parameter(Mandatory = $true)][hashtable]$ScriptInventory,
        [Parameter(Mandatory = $true)][array]$EffectiveGpos,
        [Parameter(Mandatory = $true)][hashtable]$GpoFunctionMap
    )
    $scriptCats = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
    foreach ($sr in $ObjectScriptRefs) {
        $path = [string]$sr.ScriptPath
        if ($ScriptInventory.ContainsKey($path)) {
            foreach ($c in $ScriptInventory[$path].Categories) { [void]$scriptCats.Add([string]$c) }
        }
    }
    $gpoCats = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
    foreach ($g in $EffectiveGpos) {
        $id = [string]$g.GpoId
        if ($GpoFunctionMap.ContainsKey($id)) {
            foreach ($c in $GpoFunctionMap[$id]) { [void]$gpoCats.Add([string]$c) }
        }
    }

    $covered = @()
    $missing = @()
    foreach ($c in $scriptCats) {
        if ($gpoCats.Contains($c)) { $covered += $c }
        else { $missing += $c }
    }
    $extraGpo = @()
    foreach ($c in $gpoCats) {
        if (-not $scriptCats.Contains($c)) { $extraGpo += $c }
    }

    $status = if ($scriptCats.Count -eq 0) { 'kein-script-bezug' }
    elseif ($missing.Count -eq 0) { 'abgedeckt' }
    elseif ($covered.Count -eq 0) { 'nicht-abgedeckt' }
    else { 'teilweise' }

    return [pscustomobject]@{
        ScriptCategories = @($scriptCats)
        GpoCategories    = @($gpoCats)
        Covered          = @($covered)
        Missing          = @($missing)
        ExtraGpo         = @($extraGpo)
        Status           = $status
    }
}

function New-Recommendations {
    param(
        [Parameter(Mandatory = $true)][array]$CoverageRows
    )
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($row in $CoverageRows) {
        foreach ($cat in @($row.Coverage.Missing)) {
            $target = if (@($row.EffectiveGpos).Count -gt 0) { [string]$row.EffectiveGpos[0].DisplayName } else { '(Neue GPO erforderlich)' }
            $list.Add([pscustomobject]@{
                ScopeType    = $row.ScopeType
                Principal    = $row.Principal
                OuDn         = $row.OuDn
                Category     = $cat
                MissingInGpo = $true
                Suggestion   = "Funktion '$cat' in GPO '$target' ergaenzen oder dedizierte Migrations-GPO erstellen."
            }) | Out-Null
        }
    }
    return @($list)
}

function Export-Report {
    param(
        [Parameter(Mandatory = $true)][string]$OutputFile,
        [Parameter(Mandatory = $true)][hashtable]$Payload
    )
    $json = $Payload | ConvertTo-Json -Depth 10 -Compress
    $jsonEscaped = $json -replace '</', '\u003c/'
    $html = @"
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <title>OU Script/GPO Abdeckungsanalyse</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
</head>
<body class="bg-slate-50 text-slate-900 min-h-screen">
  <div class="max-w-7xl mx-auto px-4 py-8">
    <header class="mb-8">
      <h1 class="text-3xl font-bold">OU-basierte Script/GPO-Abdeckungsanalyse</h1>
      <p class="mt-2 text-slate-600">Statische effektive GPO-Pruefung pro User/Computer (inkl. Logon/Logoff/Startup/Shutdown und AD scriptPath).</p>
    </header>

    <section class="mb-6 bg-white rounded-xl shadow p-4">
      <h2 class="text-lg font-semibold mb-2">Executive Summary</h2>
      <div class="grid grid-cols-2 md:grid-cols-5 gap-3 text-sm">
        <div class="rounded border p-3"><div class="text-slate-500">OUs</div><div id="kpi-ous" class="text-xl font-semibold">0</div></div>
        <div class="rounded border p-3"><div class="text-slate-500">User</div><div id="kpi-users" class="text-xl font-semibold">0</div></div>
        <div class="rounded border p-3"><div class="text-slate-500">Computer</div><div id="kpi-computers" class="text-xl font-semibold">0</div></div>
        <div class="rounded border p-3"><div class="text-slate-500">Skripte</div><div id="kpi-scripts" class="text-xl font-semibold">0</div></div>
        <div class="rounded border p-3"><div class="text-slate-500">Empfehlungen</div><div id="kpi-rec" class="text-xl font-semibold">0</div></div>
      </div>
    </section>

    <section class="mb-6 bg-white rounded-xl shadow p-4">
      <h2 class="text-lg font-semibold mb-2">Datenfluss</h2>
      <div class="mermaid">
flowchart LR
  startOu[StartOU] --> ouTree[OuTree]
  ouTree --> users[Users]
  ouTree --> computers[Computers]
  users --> userGpoEval[UserEffectiveGpoEval]
  computers --> computerGpoEval[ComputerEffectiveGpoEval]
  userGpoEval --> scriptMap[ScriptInventoryAndParsing]
  computerGpoEval --> scriptMap
  scriptMap --> functionMap[FunctionClassification]
  userGpoEval --> gpoFunctionMap[GpoFunctionExtraction]
  computerGpoEval --> gpoFunctionMap
  functionMap --> coverage[CoverageGapAnalysis]
  gpoFunctionMap --> coverage
  coverage --> htmlReport[HtmlReport]
      </div>
    </section>

    <section class="mb-6 bg-white rounded-xl shadow p-4">
      <div class="flex flex-wrap items-center gap-3">
        <label class="text-sm">Scope
          <select id="scopeFilter" class="ml-2 rounded border px-2 py-1">
            <option value="">Alle</option>
            <option value="User">User</option>
            <option value="Computer">Computer</option>
          </select>
        </label>
        <label class="text-sm">Status
          <select id="statusFilter" class="ml-2 rounded border px-2 py-1">
            <option value="">Alle</option>
            <option value="abgedeckt">abgedeckt</option>
            <option value="teilweise">teilweise</option>
            <option value="nicht-abgedeckt">nicht-abgedeckt</option>
            <option value="kein-script-bezug">kein-script-bezug</option>
          </select>
        </label>
      </div>
    </section>

    <section class="mb-6 bg-white rounded-xl shadow p-4 overflow-x-auto">
      <h2 class="text-lg font-semibold mb-3">Objektindividuelle Coverage</h2>
      <table class="w-full text-sm">
        <thead><tr class="border-b"><th class="py-2 pr-3">Typ</th><th class="py-2 pr-3">Objekt</th><th class="py-2 pr-3">OU</th><th class="py-2 pr-3">Status</th><th class="py-2 pr-3">Fehlend</th><th class="py-2 pr-3">Effektive GPOs</th></tr></thead>
        <tbody id="coverageBody"></tbody>
      </table>
    </section>

    <section class="mb-6 bg-white rounded-xl shadow p-4 overflow-x-auto">
      <h2 class="text-lg font-semibold mb-3">Fehlende/ergaenzbare GPO-Funktionen</h2>
      <table class="w-full text-sm">
        <thead><tr class="border-b"><th class="py-2 pr-3">Typ</th><th class="py-2 pr-3">Objekt</th><th class="py-2 pr-3">Kategorie</th><th class="py-2 pr-3">Vorschlag</th></tr></thead>
        <tbody id="recBody"></tbody>
      </table>
    </section>

    <section class="mb-6 bg-white rounded-xl shadow p-4 overflow-x-auto">
      <h2 class="text-lg font-semibold mb-3">Skriptinventar (vollstaendige Inhalte)</h2>
      <div id="scriptContainer" class="space-y-4"></div>
    </section>
  </div>

  <script type="application/json" id="reportData">$jsonEscaped</script>
  <script>
    mermaid.initialize({ startOnLoad: true, flowchart: { useMaxWidth: true, htmlLabels: true } });
    (function() {
      var raw = document.getElementById('reportData').textContent || '{}';
      var data = JSON.parse(raw);
      var cov = data.coverageRows || [];
      var rec = data.recommendations || [];
      var scripts = data.scriptInventory || [];

      document.getElementById('kpi-ous').textContent = (data.summary && data.summary.ouCount) || 0;
      document.getElementById('kpi-users').textContent = (data.summary && data.summary.userCount) || 0;
      document.getElementById('kpi-computers').textContent = (data.summary && data.summary.computerCount) || 0;
      document.getElementById('kpi-scripts').textContent = scripts.length;
      document.getElementById('kpi-rec').textContent = rec.length;

      function esc(s){ return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

      function renderCoverage(){
        var scope = document.getElementById('scopeFilter').value;
        var status = document.getElementById('statusFilter').value;
        var rows = cov.filter(function(r){
          if (scope && r.scopeType !== scope) return false;
          if (status && r.coverage.status !== status) return false;
          return true;
        });
        document.getElementById('coverageBody').innerHTML = rows.map(function(r){
          var gpos = (r.effectiveGpos || []).map(function(g){ return g.displayName; }).join(', ');
          return '<tr class="border-b align-top">'
            + '<td class="py-2 pr-3">' + esc(r.scopeType) + '</td>'
            + '<td class="py-2 pr-3">' + esc(r.principal) + '</td>'
            + '<td class="py-2 pr-3"><code>' + esc(r.ouDn) + '</code></td>'
            + '<td class="py-2 pr-3">' + esc(r.coverage.status) + '</td>'
            + '<td class="py-2 pr-3">' + esc((r.coverage.missing || []).join(', ')) + '</td>'
            + '<td class="py-2 pr-3">' + esc(gpos) + '</td>'
            + '</tr>';
        }).join('');
      }

      function renderRecommendations(){
        document.getElementById('recBody').innerHTML = rec.map(function(r){
          return '<tr class="border-b align-top">'
            + '<td class="py-2 pr-3">' + esc(r.scopeType) + '</td>'
            + '<td class="py-2 pr-3">' + esc(r.principal) + '</td>'
            + '<td class="py-2 pr-3">' + esc(r.category) + '</td>'
            + '<td class="py-2 pr-3">' + esc(r.suggestion) + '</td>'
            + '</tr>';
        }).join('');
      }

      function renderScripts(){
        var html = scripts.map(function(s){
          return '<details class="rounded border p-3"><summary class="font-medium">' + esc(s.scriptPath) + '</summary>'
            + '<div class="text-xs text-slate-600 mt-2">Typ: ' + esc(s.extension) + ' | Existiert: ' + esc(String(s.exists)) + ' | Kategorien: ' + esc((s.categories || []).join(', ')) + '</div>'
            + '<pre class="mt-2 bg-slate-900 text-slate-100 p-3 rounded overflow-x-auto text-xs"><code>' + esc(s.content || '') + '</code></pre>'
            + '</details>';
        }).join('');
        document.getElementById('scriptContainer').innerHTML = html;
      }

      document.getElementById('scopeFilter').addEventListener('change', renderCoverage);
      document.getElementById('statusFilter').addEventListener('change', renderCoverage);
      renderCoverage();
      renderRecommendations();
      renderScripts();
    })();
  </script>
</body>
</html>
"@
    $html | Set-Content -LiteralPath $OutputFile -Encoding UTF8
}

# --- MAIN ---
Initialize-RequiredModules
$domainCtx = Get-DomainContext -DomainFqdnParam $DomainFqdn
$checkpointResolved = Resolve-FullPathSafe -Path $CheckpointPath
$outputResolved = Resolve-FullPathSafe -Path $OutputPath
$outDir = [System.IO.Path]::GetDirectoryName($outputResolved)
if (-not [string]::IsNullOrWhiteSpace($outDir) -and -not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

$state = [ordered]@{
    Version = 1
    StartOuDn = $StartOuDn
    DomainFqdn = $domainCtx.DomainFqdn
    TimestampUtc = (Get-Date).ToUniversalTime()
    Summary = @{}
    OuTree = @()
    Users = @()
    Computers = @()
    Gpos = @()
    CoverageRows = @()
    Recommendations = @()
    ScriptInventory = @()
    Phases = @{
        ScopeBuilt = $false
        EffectiveGpoDone = $false
        ScriptAnalysisDone = $false
        CoverageDone = $false
        ReportExported = $false
    }
}

if ($Resume) {
    $cp = Read-CheckpointSafe -Path $checkpointResolved
    if ($cp -and $cp.StartOuDn -eq $StartOuDn -and $cp.DomainFqdn -eq $domainCtx.DomainFqdn) {
        Write-Host "Resume aus Checkpoint: $checkpointResolved" -ForegroundColor Yellow
        $state = [ordered]@{
            Version = 1
            StartOuDn = $cp.StartOuDn
            DomainFqdn = $cp.DomainFqdn
            TimestampUtc = $cp.TimestampUtc
            Summary = $cp.Summary
            OuTree = @($cp.OuTree)
            Users = @($cp.Users)
            Computers = @($cp.Computers)
            Gpos = @($cp.Gpos)
            CoverageRows = @($cp.CoverageRows)
            Recommendations = @($cp.Recommendations)
            ScriptInventory = @($cp.ScriptInventory)
            Phases = $cp.Phases
        }
    }
}

$patterns = Get-CategoryPatterns

if (-not $state.Phases.ScopeBuilt) {
    $ouTree = Get-OuSubtree -StartDn $StartOuDn
    $obj = Get-ObjectsInOuTree -StartDn $StartOuDn
    $state.OuTree = @($ouTree)
    $state.Users = @($obj.Users)
    $state.Computers = @($obj.Computers)
    $state.Summary = @{
        ouCount = @($ouTree).Count
        userCount = @($obj.Users).Count
        computerCount = @($obj.Computers).Count
    }
    $state.Phases.ScopeBuilt = $true
    Write-CheckpointSafe -State $state -Path $checkpointResolved
}

if (-not $state.Phases.EffectiveGpoDone -or -not $state.Phases.ScriptAnalysisDone -or -not $state.Phases.CoverageDone) {
    $allGpos = @()
    try { $allGpos = @(Get-GPO -All -ErrorAction Stop) } catch { $allGpos = @() }
    $gpoById = @{}
    foreach ($g in $allGpos) { $gpoById[[string]$g.Id] = $g }
    $gpoPermMap = Get-GpoPermissionsMap -Gpos $allGpos
    $gpoReports = Get-GpoReportMap -AllGpos $allGpos
    $gpoFunctions = Get-GpoFunctionMap -GpoReportMap $gpoReports -Patterns $patterns

    $allContainerDns = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
    foreach ($u in $state.Users) { [void]$allContainerDns.Add((Get-ContainerPathFromDn -DistinguishedName $u.DistinguishedName)) }
    foreach ($c in $state.Computers) { [void]$allContainerDns.Add((Get-ContainerPathFromDn -DistinguishedName $c.DistinguishedName)) }
    [void]$allContainerDns.Add($domainCtx.DomainDn)
    $inheritanceCache = Get-GpoInheritanceForContainers -ContainerDns @($allContainerDns)

    $rows = New-Object System.Collections.Generic.List[object]
    $allScriptRefs = New-Object System.Collections.Generic.List[object]

    $total = [Math]::Max(1, (@($state.Users).Count + @($state.Computers).Count))
    $done = 0

    foreach ($u in $state.Users) {
        $done++
        Write-Progress -Activity "Berechne effektive GPOs und Coverage" -Status "User $($u.SamAccountName)" -PercentComplete ([int](100 * $done / $total))
        $containerDn = Get-ContainerPathFromDn -DistinguishedName $u.DistinguishedName
        $token = Get-TokenForPrincipal -Dn $u.DistinguishedName -PrincipalType 'User' -Sid ([string]$u.SID.Value)
        $effective = Get-EffectiveGposForPrincipal -ContainerDn $containerDn -DomainDn $domainCtx.DomainDn -PrincipalType 'User' -TokenInfo $token -InheritanceCache $inheritanceCache -PermissionMap $gpoPermMap

        $objScriptRefs = New-Object System.Collections.Generic.List[object]
        if (-not [string]::IsNullOrWhiteSpace([string]$u.scriptPath)) {
            $adPath = [string]$u.scriptPath
            if ($adPath -notmatch '^[A-Za-z]:\\' -and $adPath -notlike '\\*') {
                $adPath = Join-Path -Path $domainCtx.ScriptsRoot -ChildPath $adPath
            }
            $objScriptRefs.Add([pscustomobject]@{
                GpoId      = ''
                SourceType = 'ADUser'
                Phase      = 'Logon'
                RawRef     = [string]$u.scriptPath
                ScriptPath = $adPath
            }) | Out-Null
        }
        foreach ($eg in $effective) {
            $refs = Get-ScriptRefsForGpo -GpoId $eg.GpoId -GpoById $gpoById -GpoReportMap $gpoReports -ScriptsRoot $domainCtx.ScriptsRoot
            foreach ($r in $refs) {
                if ($r.Phase -in @('Logon', 'Logoff', 'Unknown')) {
                    $objScriptRefs.Add($r) | Out-Null
                }
            }
        }
        foreach ($r in $objScriptRefs) { $allScriptRefs.Add($r) | Out-Null }

        $rows.Add([pscustomobject]@{
            ScopeType      = 'User'
            Principal      = [string]$u.SamAccountName
            OuDn           = $containerDn
            EffectiveGpos  = @($effective)
            ScriptRefs     = @($objScriptRefs)
            Coverage       = $null
        }) | Out-Null
    }

    foreach ($c in $state.Computers) {
        $done++
        Write-Progress -Activity "Berechne effektive GPOs und Coverage" -Status "Computer $($c.Name)" -PercentComplete ([int](100 * $done / $total))
        $containerDn = Get-ContainerPathFromDn -DistinguishedName $c.DistinguishedName
        $token = Get-TokenForPrincipal -Dn $c.DistinguishedName -PrincipalType 'Computer' -Sid ([string]$c.SID.Value)
        $effective = Get-EffectiveGposForPrincipal -ContainerDn $containerDn -DomainDn $domainCtx.DomainDn -PrincipalType 'Computer' -TokenInfo $token -InheritanceCache $inheritanceCache -PermissionMap $gpoPermMap

        $objScriptRefs = New-Object System.Collections.Generic.List[object]
        foreach ($eg in $effective) {
            $refs = Get-ScriptRefsForGpo -GpoId $eg.GpoId -GpoById $gpoById -GpoReportMap $gpoReports -ScriptsRoot $domainCtx.ScriptsRoot
            foreach ($r in $refs) {
                if ($r.Phase -in @('Startup', 'Shutdown', 'Unknown')) {
                    $objScriptRefs.Add($r) | Out-Null
                }
            }
        }
        foreach ($r in $objScriptRefs) { $allScriptRefs.Add($r) | Out-Null }

        $rows.Add([pscustomobject]@{
            ScopeType      = 'Computer'
            Principal      = [string]$c.Name
            OuDn           = $containerDn
            EffectiveGpos  = @($effective)
            ScriptRefs     = @($objScriptRefs)
            Coverage       = $null
        }) | Out-Null
    }
    Write-Progress -Activity "Berechne effektive GPOs und Coverage" -Completed

    $scriptInventoryMap = Get-ScriptInventory -ScriptRefs @($allScriptRefs) -Patterns $patterns
    foreach ($row in $rows) {
        $cov = Get-CoverageForObject -ObjectScriptRefs $row.ScriptRefs -ScriptInventory $scriptInventoryMap -EffectiveGpos $row.EffectiveGpos -GpoFunctionMap $gpoFunctions
        $row.Coverage = $cov
    }
    $recommendations = New-Recommendations -CoverageRows @($rows)

    $state.CoverageRows = @($rows)
    $state.Recommendations = @($recommendations)
    $state.ScriptInventory = @($scriptInventoryMap.Values | Sort-Object -Property ScriptPath)
    $state.Gpos = @($allGpos | Select-Object Id,DisplayName,GpoStatus,Path)
    $state.Phases.EffectiveGpoDone = $true
    $state.Phases.ScriptAnalysisDone = $true
    $state.Phases.CoverageDone = $true
    Write-CheckpointSafe -State $state -Path $checkpointResolved
}

$payload = @{
    summary = $state.Summary
    scope = @{
        startOuDn = $StartOuDn
        domainFqdn = $domainCtx.DomainFqdn
        scriptsRoot = $domainCtx.ScriptsRoot
    }
    ouTree = @($state.OuTree)
    coverageRows = @($state.CoverageRows | ForEach-Object {
        [ordered]@{
            scopeType = $_.ScopeType
            principal = $_.Principal
            ouDn = $_.OuDn
            effectiveGpos = @($_.EffectiveGpos | ForEach-Object {
                [ordered]@{
                    gpoId = $_.GpoId
                    displayName = $_.DisplayName
                    targetDn = $_.TargetDn
                    order = $_.Order
                    enforced = [bool]$_.Enforced
                    enabled = [bool]$_.Enabled
                    gpoStatus = $_.GpoStatus
                }
            })
            scriptRefs = @($_.ScriptRefs | ForEach-Object {
                [ordered]@{
                    sourceType = $_.SourceType
                    phase = $_.Phase
                    rawRef = $_.RawRef
                    scriptPath = $_.ScriptPath
                }
            })
            coverage = [ordered]@{
                status = $_.Coverage.Status
                scriptCategories = @($_.Coverage.ScriptCategories)
                gpoCategories = @($_.Coverage.GpoCategories)
                covered = @($_.Coverage.Covered)
                missing = @($_.Coverage.Missing)
                extraGpo = @($_.Coverage.ExtraGpo)
            }
        }
    })
    recommendations = @($state.Recommendations | ForEach-Object {
        [ordered]@{
            scopeType = $_.ScopeType
            principal = $_.Principal
            ouDn = $_.OuDn
            category = $_.Category
            suggestion = $_.Suggestion
        }
    })
    scriptInventory = @($state.ScriptInventory | ForEach-Object {
        [ordered]@{
            scriptPath = $_.ScriptPath
            extension = $_.Extension
            exists = [bool]$_.Exists
            categories = @($_.Categories)
            content = if ($IncludeContent) { $_.Content } else { '' }
        }
    })
}

Export-Report -OutputFile $outputResolved -Payload $payload
$jsonOut = [System.IO.Path]::ChangeExtension($outputResolved, '.json')
$payload | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $jsonOut -Encoding UTF8
$state.Phases.ReportExported = $true
Write-CheckpointSafe -State $state -Path $checkpointResolved

Write-Host "Report geschrieben: $outputResolved" -ForegroundColor Green
Write-Host "Daten geschrieben: $jsonOut" -ForegroundColor Green
Write-Host "Checkpoint: $checkpointResolved" -ForegroundColor Gray
