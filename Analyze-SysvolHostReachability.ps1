<#
.SYNOPSIS
    Extrahiert Servernamen und IP-Adressen aus SYSVOL\scripts und prüft deren Erreichbarkeit.

.DESCRIPTION
    Scannt alle Skript- und Textdateien unter dem angegebenen Stammpfad (SYSVOL\scripts),
    extrahiert Hostnamen und IPs per Regex (UNC-Pfade, URLs, net use, IPv4), führt pro Host
    eine Erreichbarkeitsanalyse durch (DNS, Ping, TCP-Ports 80/443/445/135/3389/5985, WinRM).
    Optional wird pro ermitteltem Host das zugehörige Subnetz (z. B. /24) nach pingbaren
    Endpunkten durchsucht. Ergebnis: HTML-Report mit Tailwind (Tabellen inkl. Subnet-Scan).
    Read-Only; keine Änderungen an SYSVOL oder Hosts.

.PARAMETER ScriptsPath
    Stammverzeichnis (z.B. \\domain\SYSVOL\domain\scripts). Muss existieren.

.PARAMETER OutputPath
    Pfad der zu erzeugenden HTML-Datei (Default: .\HostReachabilityReport.html).

.PARAMETER Resume
    Erzwingt das Fortsetzen aus Checkpoint/Artefakten, falls vorhanden.

.PARAMETER NoAutoResume
    Deaktiviert automatisches Resume. Ohne -Resume wird dann immer ein Neu-Lauf gestartet.

.PARAMETER CheckpointPath
    Optionaler Pfad für die Checkpoint-Datei. Standard: sysvol_host_reachability_checkpoint.json im aktuellen Verzeichnis.

.PARAMETER KeepResumeData
    Behält Checkpoint und Artefakt-Dateien nach erfolgreichem Lauf bei.

.PARAMETER Encoding
    Fallback-Encoding beim Lesen von Dateien (Default: UTF8).

.PARAMETER ThrottleLimit
    Maximale parallele Host-Checks beim Port-Scan (Default: 8).

.PARAMETER SubnetScan
    Pro ermitteltem Host das zugehörige Subnetz (/24) nach pingbaren Endpunkten durchsuchen (Default: deaktiviert).

.PARAMETER SubnetPrefixLength
    Präfixlänge für Subnetz-Scan in CIDR-Notation (Default: 24 = /24).

.EXAMPLE
    .\Analyze-SysvolHostReachability.ps1 -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts'

.EXAMPLE
    .\Analyze-SysvolHostReachability.ps1 -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts' -OutputPath 'D:\Reports\HostReach.html' -ThrottleLimit 4

.EXAMPLE
    .\Analyze-SysvolHostReachability.ps1 -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts' -Resume -CheckpointPath '.\state\hostreach.json' -KeepResumeData
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScriptsPath,

    [string]$OutputPath = ".\HostReachabilityReport.html",

    [switch]$Resume,

    [switch]$NoAutoResume,

    [string]$CheckpointPath = '',

    [switch]$KeepResumeData,

    [System.Text.Encoding]$Encoding = [System.Text.Encoding]::UTF8,

    [ValidateRange(1, 32)]
    [int]$ThrottleLimit = 8,

    [switch]$SubnetScan,

    [ValidateRange(8, 30)]
    [int]$SubnetPrefixLength = 24
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:FileExtensions = @('.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.kix', '.txt')
$script:ExcludedHosts = @('localhost', '127.0.0.1', '0.0.0.0', '::1', '')
$script:CheckpointFileName = 'sysvol_host_reachability_checkpoint.json'
$script:CheckpointVersion = 2

function Resolve-PathSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    try {
        $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
        return $resolved.ProviderPath
    }
    catch {
        return [System.IO.Path]::GetFullPath($Path)
    }
}

function Get-CheckpointPath {
    [CmdletBinding()]
    param(
        [string]$ProvidedPath
    )
    if ([string]::IsNullOrWhiteSpace($ProvidedPath)) {
        return Join-Path -Path (Get-Location) -ChildPath $script:CheckpointFileName
    }
    return Resolve-PathSafe -Path $ProvidedPath
}

function Get-ResumeArtifactPaths {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CheckpointPathValue
    )
    $baseDir = [System.IO.Path]::GetDirectoryName($CheckpointPathValue)
    if ([string]::IsNullOrWhiteSpace($baseDir)) {
        $baseDir = (Get-Location).Path
    }
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($CheckpointPathValue)
    if ([string]::IsNullOrWhiteSpace($baseName)) {
        $baseName = 'sysvol_host_reachability_checkpoint'
    }
    return [ordered]@{
        HostResults = Join-Path -Path $baseDir -ChildPath ("{0}.host-results.json" -f $baseName)
        SubnetData  = Join-Path -Path $baseDir -ChildPath ("{0}.subnet-data.json" -f $baseName)
    }
}

function ConvertTo-SerializableHostResults {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [array]$HostResults
    )
    return @($HostResults | ForEach-Object {
        $hr = $_
        $portStr = [ordered]@{}
        if ($hr.Ports -is [hashtable]) {
            foreach ($k in $hr.Ports.Keys) { $portStr["$k"] = [bool]$hr.Ports[$k] }
        }
        elseif ($null -ne $hr.Ports) {
            foreach ($p in $hr.Ports.PSObject.Properties) {
                $portStr["$($p.Name)"] = [bool]$p.Value
            }
        }
        [pscustomobject]@{
            Host       = [string]$hr.Host
            DnsOk      = [bool]$hr.DnsOk
            PingOk     = [bool]$hr.PingOk
            Ports      = $portStr
            WinRmOk    = $hr.WinRmOk
            TopFolders = @($hr.TopFolders)
        }
    })
}

function ConvertTo-NormalizedHostResults {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [array]$HostResults,
        [hashtable]$HostToTopFolders = @{}
    )
    $byHost = @{}
    foreach ($r in @($HostResults)) {
        if ($null -eq $r -or [string]::IsNullOrWhiteSpace($r.Host)) { continue }
        $ht = @{}
        if ($r.Ports -is [hashtable]) {
            foreach ($k in $r.Ports.Keys) { $ht[[int]$k] = [bool]$r.Ports[$k] }
        }
        elseif ($null -ne $r.Ports) {
            foreach ($p in $r.Ports.PSObject.Properties) { $ht[[int]$p.Name] = [bool]$p.Value }
        }
        foreach ($defaultPort in @(80, 443, 445, 135, 3389, 5985)) {
            if (-not $ht.ContainsKey($defaultPort)) { $ht[$defaultPort] = $false }
        }
        $tfs = @()
        if ($r.TopFolders) { $tfs = @($r.TopFolders) }
        elseif ($HostToTopFolders.ContainsKey([string]$r.Host)) { $tfs = @($HostToTopFolders[[string]$r.Host]) }
        $byHost[[string]$r.Host] = [pscustomobject]@{
            Host       = [string]$r.Host
            DnsOk      = [bool]$r.DnsOk
            PingOk     = [bool]$r.PingOk
            Ports      = $ht
            WinRmOk    = $r.WinRmOk
            TopFolders = @($tfs | Where-Object { $_ } | Sort-Object -Unique)
        }
    }
    if ($byHost.Count -eq 0) { return @() }
    return @($byHost.Values | Sort-Object -Property Host)
}

function ConvertTo-NormalizedUniqueHosts {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [array]$UniqueHosts
    )
    $byHost = @{}
    foreach ($entry in @($UniqueHosts)) {
        if ($entry -is [string]) {
            $hostName = $entry
            $tfs = @()
        }
        else {
            $hostName = [string]$entry.Host
            $tfs = @($entry.TopFolders)
        }
        if ([string]::IsNullOrWhiteSpace($hostName)) { continue }
        if (-not $byHost.ContainsKey($hostName)) {
            $byHost[$hostName] = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        }
        foreach ($tf in @($tfs)) {
            if (-not [string]::IsNullOrWhiteSpace($tf)) {
                [void]$byHost[$hostName].Add([string]$tf)
            }
        }
    }
    if ($byHost.Count -eq 0) { return @() }
    return @($byHost.Keys | Sort-Object | ForEach-Object {
        [pscustomobject]@{
            Host       = $_
            TopFolders = @($byHost[$_])
        }
    })
}

function ConvertTo-NormalizedSubnetData {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [array]$SubnetData
    )
    $bySubnet = @{}
    foreach ($s in @($SubnetData)) {
        if ($null -eq $s -or [string]::IsNullOrWhiteSpace([string]$s.Subnet)) { continue }
        $key = [string]$s.Subnet
        if ($bySubnet.ContainsKey($key)) { continue }
        $bySubnet[$key] = [pscustomobject]@{
            SourceHost       = [string]$s.SourceHost
            SourceTopFolders = @($s.SourceTopFolders | Where-Object { $_ } | Sort-Object -Unique)
            Subnet           = $key
            ReachableIPs     = @($s.ReachableIPs | Where-Object { $_ } | Sort-Object -Unique)
        }
    }
    if ($bySubnet.Count -eq 0) { return @() }
    return @($bySubnet.Values | Sort-Object -Property Subnet)
}

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
        # Ports in HostResults sind Hashtables mit int-Keys; JSON unterstützt nur string-Keys.
        $hostResultsSerializable = ConvertTo-SerializableHostResults -HostResults $State.HostResults
        $stateToSerialize = [ordered]@{
            Version            = $State.Version
            ScriptsPath        = $State.ScriptsPath
            OutputPath         = $State.OutputPath
            Parameters         = $State.Parameters
            TimestampUtc       = $State.TimestampUtc
            FilesScannedCount  = $State.FilesScannedCount
            FilesPerTopFolder  = $State.FilesPerTopFolder
            UniqueHosts        = $State.UniqueHosts
            HostResults        = $hostResultsSerializable
            SubnetScanData     = $State.SubnetScanData
            Phases             = $State.Phases
            Errors             = $State.Errors
        }
        $stateToSerialize | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $CheckpointPath -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        Write-Warning "Fehler beim Schreiben des Checkpoints: $($_.Exception.Message)"
    }
}

function New-HostReachabilityState {
    param(
        [string]$ScriptsPathValue,
        [string]$OutputPathValue,
        [int]$ThrottleLimitValue,
        [bool]$SubnetScanValue,
        [int]$SubnetPrefixLengthValue
    )
    return [ordered]@{
        Version            = $script:CheckpointVersion
        ScriptsPath        = $ScriptsPathValue
        OutputPath         = $OutputPathValue
        Parameters         = @{
            ThrottleLimit      = $ThrottleLimitValue
            SubnetScan         = $SubnetScanValue
            SubnetPrefixLength = $SubnetPrefixLengthValue
        }
        TimestampUtc       = (Get-Date).ToUniversalTime()
        FilesScannedCount  = 0
        FilesPerTopFolder  = @{}
        UniqueHosts         = @()
        HostResults        = @()
        SubnetScanData     = @()
        Phases             = @{
            FileScanCompleted   = $false
            HostChecksCompleted = $false
            SubnetScanCompleted = $false
            ReportExported      = $false
        }
        Errors              = @()
    }
}

function Write-ResumeArtifacts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$State,
        [Parameter(Mandatory = $true)]
        [hashtable]$ArtifactPaths
    )
    try {
        $hostPayload = [ordered]@{
            Version           = $State.Version
            ScriptsPath       = $State.ScriptsPath
            OutputPath        = $State.OutputPath
            TimestampUtc      = (Get-Date).ToUniversalTime()
            FilesScannedCount = $State.FilesScannedCount
            FilesPerTopFolder = $State.FilesPerTopFolder
            UniqueHosts       = $(ConvertTo-NormalizedUniqueHosts -UniqueHosts $State.UniqueHosts)
            HostResults       = $(ConvertTo-SerializableHostResults -HostResults $State.HostResults)
        }
        $subnetPayload = [ordered]@{
            Version       = $State.Version
            ScriptsPath   = $State.ScriptsPath
            OutputPath    = $State.OutputPath
            TimestampUtc  = (Get-Date).ToUniversalTime()
            SubnetScanData = $(ConvertTo-NormalizedSubnetData -SubnetData $State.SubnetScanData)
        }
        $hostPayload | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ArtifactPaths.HostResults -Encoding UTF8 -ErrorAction Stop
        $subnetPayload | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ArtifactPaths.SubnetData -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        Write-Warning "Fehler beim Schreiben der Resume-Artefakte: $($_.Exception.Message)"
    }
}

function Read-ResumeArtifacts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$ArtifactPaths,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedScriptsPath,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedOutputPath
    )
    $result = [ordered]@{
        HasData  = $false
        Messages = [System.Collections.Generic.List[string]]::new()
        HostData = $null
        SubnetData = $null
    }
    if (Test-Path -LiteralPath $ArtifactPaths.HostResults) {
        try {
            $hostData = (Get-Content -LiteralPath $ArtifactPaths.HostResults -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
            if ($hostData.ScriptsPath -eq $ExpectedScriptsPath -and $hostData.OutputPath -eq $ExpectedOutputPath) {
                $result.HostData = $hostData
                $result.HasData = $true
                [void]$result.Messages.Add("Host-Artefakt geladen")
            }
        }
        catch {
            [void]$result.Messages.Add("Host-Artefakt unlesbar")
        }
    }
    if (Test-Path -LiteralPath $ArtifactPaths.SubnetData) {
        try {
            $subnetData = (Get-Content -LiteralPath $ArtifactPaths.SubnetData -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
            if ($subnetData.ScriptsPath -eq $ExpectedScriptsPath -and $subnetData.OutputPath -eq $ExpectedOutputPath) {
                $result.SubnetData = $subnetData
                $result.HasData = $true
                [void]$result.Messages.Add("Subnet-Artefakt geladen")
            }
        }
        catch {
            [void]$result.Messages.Add("Subnet-Artefakt unlesbar")
        }
    }
    return $result
}

function Save-ResumeState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$State,
        [Parameter(Mandatory = $true)]
        [string]$CheckpointPathValue,
        [Parameter(Mandatory = $true)]
        [hashtable]$ArtifactPaths
    )
    $State.TimestampUtc = (Get-Date).ToUniversalTime()
    Write-Checkpoint -State $State -CheckpointPath $CheckpointPathValue
    Write-ResumeArtifacts -State $State -ArtifactPaths $ArtifactPaths
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

function Get-RelevantFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootPath
    )
    $files = Get-ChildItem -LiteralPath $RootPath -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in $script:FileExtensions }
    return @($files)
}

function Get-UniqueHostsFromContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content
    )
    if (-not $Content) { return @() }
    $opts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    $hosts = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    # UNC: \\Server\Share
    foreach ($m in [regex]::Matches($Content, '\\\\([^\\\s]+)', $opts)) {
        $h = $m.Groups[1].Value.Trim()
        if ($h) { [void]$hosts.Add($h) }
    }
    # IPv4 (einfach)
    foreach ($m in [regex]::Matches($Content, '\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')) {
        $h = $m.Groups[1].Value
        if ($h) { [void]$hosts.Add($h) }
    }
    # URL host: http(s)://host
    foreach ($m in [regex]::Matches($Content, 'https?://([^/\s:]+)', $opts)) {
        $h = $m.Groups[1].Value.Trim()
        if ($h) { [void]$hosts.Add($h) }
    }

    $result = @($hosts)
    return $result
}

function Get-AllUniqueHosts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Files,
        [Parameter(Mandatory = $true)]
        [string]$RootPath
    )
    $rootTrimmed = $RootPath.TrimEnd('\', '/')
    $hostToTopFolders = [System.Collections.Generic.Dictionary[string, [System.Collections.Generic.HashSet[string]]]]::new([StringComparer]::OrdinalIgnoreCase)
    $total = $Files.Count
    $i = 0
    foreach ($f in $Files) {
        $i++
        Write-Progress -Activity 'Dateien scannen' -Status $f.Name -PercentComplete ([math]::Min(100, [int](100 * $i / $total)))
        $relPath = $f.FullName
        if ($relPath.StartsWith($rootTrimmed, [StringComparison]::OrdinalIgnoreCase)) {
            $relPath = $relPath.Substring($rootTrimmed.Length).TrimStart('\', '/')
        }
        $topFolder = ($relPath -split '[\\/]')[0]
        if ([string]::IsNullOrWhiteSpace($topFolder)) { $topFolder = '(Root)' }
        $content = Get-FileContentSafe -Path $f.FullName
        if ($null -eq $content -or $content -eq '') { continue }
        $found = Get-UniqueHostsFromContent -Content $content
        foreach ($h in $found) {
            $h = $h.Trim()
            if ([string]::IsNullOrWhiteSpace($h)) { continue }
            if ($script:ExcludedHosts -contains $h) { continue }
            if ($h -match '^%') { continue }
            if (-not $hostToTopFolders.ContainsKey($h)) {
                $hostToTopFolders[$h] = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            }
            [void]$hostToTopFolders[$h].Add($topFolder)
        }
    }
    Write-Progress -Activity 'Dateien scannen' -Completed
    $out = @()
    foreach ($kv in $hostToTopFolders.GetEnumerator()) {
        $out += [pscustomobject]@{ Host = $kv.Key; TopFolders = @($kv.Value) }
    }
    return @($out)
}

function Test-TcpPort {
    param(
        [string]$ComputerName,
        [int]$Port,
        [int]$TimeoutMs = 2000
    )
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $connect = $tcp.BeginConnect($ComputerName, $Port, $null, $null)
        $ok = $connect.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($ok -and $tcp.Connected) {
            $tcp.Close()
            return $true
        }
        $tcp.Close()
        return $false
    }
    catch {
        return $false
    }
}

function Get-IPv4ForHost {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostOrIp
    )
    if ($HostOrIp -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        return $HostOrIp
    }
    try {
        $entry = [System.Net.Dns]::GetHostEntry($HostOrIp)
        $ipv4 = $entry.AddressList | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
        return $ipv4?.ToString()
    }
    catch {
        return $null
    }
}

function Get-SubnetBaseAndRange {
    param(
        [string]$Ip,
        [int]$PrefixLength = 24
    )
    if (-not $Ip -or $Ip -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') { return $null }
    $octets = $Ip.Split('.')
    if ($PrefixLength -eq 24) {
        return @{ Base = "$($octets[0]).$($octets[1]).$($octets[2])"; First = 1; Last = 254 }
    }
    if ($PrefixLength -eq 16) {
        return @{ Base = "$($octets[0]).$($octets[1])"; First = 0; Last = 255; Third = 0; Fourth = 255 }
    }
    return $null
}

function Get-PingableIPsInSubnet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubnetBase,
        [int]$First = 1,
        [int]$Last = 254,
        [int]$Throttle = 32
    )
    $reachable = @(
        $First..$Last | ForEach-Object -ThrottleLimit $Throttle -Parallel {
            $octet = $_
            $addr = "$using:SubnetBase.$octet"
            try {
                if (Test-Connection -ComputerName $addr -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                    $addr
                }
            }
            catch { }
        }
    ) | Where-Object { $_ }
    return @($reachable)
}

function Get-HostReachability {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostOrIp,
        [int[]]$Ports = @(80, 443, 445, 135, 3389, 5985)
    )
    $dnsOk = $false
    $pingOk = $false
    $portsResult = @{}
    $winRmOk = $null

    foreach ($p in $Ports) { $portsResult[$p] = $false }

    try {
        [System.Net.Dns]::GetHostEntry($HostOrIp) | Out-Null
        $dnsOk = $true
    }
    catch {
        $dnsOk = $false
    }

    try {
        $pingOk = Test-Connection -ComputerName $HostOrIp -Count 1 -Quiet -ErrorAction SilentlyContinue
    }
    catch {
        $pingOk = $false
    }

    foreach ($p in $Ports) {
        $portsResult[$p] = Test-TcpPort -ComputerName $HostOrIp -Port $p -TimeoutMs 2000
    }

    try {
        $null = Test-WSMan -ComputerName $HostOrIp -ErrorAction Stop
        $winRmOk = $true
    }
    catch {
        $winRmOk = $false
    }

    return [pscustomobject]@{
        Host     = $HostOrIp
        DnsOk    = $dnsOk
        PingOk   = $pingOk
        Ports    = $portsResult
        WinRmOk  = $winRmOk
    }
}

function Get-SafeTopFolderKey {
    [CmdletBinding()]
    param(
        [string]$TopFolder
    )
    if ([string]::IsNullOrWhiteSpace($TopFolder)) { return 'ALL' }
    $safe = $TopFolder -replace '[^A-Za-z0-9_-]', '_'
    if ([string]::IsNullOrWhiteSpace($safe)) { return 'ROOT' }
    return $safe
}

function Get-HostReachabilityDataFileName {
    [CmdletBinding()]
    param(
        [string]$TopFolder
    )
    $key = Get-SafeTopFolderKey -TopFolder $TopFolder
    return "HostReachability-$key.json"
}

function ConvertTo-ReportHostResults {
    [CmdletBinding()]
    param(
        [array]$Results
    )
    return @($Results | ForEach-Object {
        $tfs = @($_.TopFolders) | Where-Object { $_ } | Sort-Object -Unique
        $portsObj = @{}
        if ($_.Ports -is [hashtable]) {
            foreach ($k in $_.Ports.Keys) { $portsObj["$k"] = [bool]$_.Ports[$k] }
        }
        [pscustomobject]@{
            host       = $_.Host
            topFolders = @($tfs)
            dnsOk      = [bool]$_.DnsOk
            pingOk     = [bool]$_.PingOk
            ports      = $portsObj
            winRmOk    = $_.WinRmOk
        }
    })
}

function ConvertTo-ReportSubnetData {
    [CmdletBinding()]
    param(
        [array]$SubnetScanData
    )
    return @($SubnetScanData | ForEach-Object {
        [pscustomobject]@{
            sourceHost       = [string]$_.SourceHost
            sourceTopFolders = @($_.SourceTopFolders | Where-Object { $_ } | Sort-Object -Unique)
            subnet           = [string]$_.Subnet
            reachableIps     = @($_.ReachableIPs | Where-Object { $_ } | Sort-Object -Unique)
        }
    })
}

function New-HostReachabilityDataset {
    [CmdletBinding()]
    param(
        [array]$ReportResults,
        [array]$ReportSubnetData,
        [int]$FilesScanned,
        [hashtable]$FilesPerTopFolder,
        [string]$TopFolder = ''
    )
    $hostsFiltered = @($ReportResults)
    $subnetFiltered = @($ReportSubnetData)
    $filesCount = $FilesScanned
    if (-not [string]::IsNullOrWhiteSpace($TopFolder)) {
        $hostsFiltered = @($ReportResults | Where-Object {
            try {
                return @($_.topFolders) -contains $TopFolder
            }
            catch {
                return $false
            }
        })
        $subnetFiltered = @($ReportSubnetData | Where-Object {
            try {
                return @($_.sourceTopFolders) -contains $TopFolder
            }
            catch {
                return $false
            }
        })
        $filesCount = if ($FilesPerTopFolder.ContainsKey($TopFolder)) { [int]$FilesPerTopFolder[$TopFolder] } else { 0 }
    }
    $anyPortOpen = @($hostsFiltered | Where-Object {
        try {
            $_.ports.Values | Where-Object { $_ } | Select-Object -First 1
        }
        catch {
            $false
        }
    }).Count
    return [ordered]@{
        scopeTopFolder     = $TopFolder
        summary            = [ordered]@{
            filesScanned = $filesCount
            hostCount    = @($hostsFiltered).Count
            pingReachable = @($hostsFiltered | Where-Object { $_.pingOk }).Count
            anyPortOpen  = $anyPortOpen
        }
        results            = $hostsFiltered
        subnetScanData     = $subnetFiltered
    }
}

function Write-HostReachabilityDataFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Results,
        [Parameter(Mandatory = $true)]
        [string]$OutputDirectory,
        [int]$FilesScanned = 0,
        [hashtable]$FilesPerTopFolder = @{},
        [array]$SubnetScanData = @()
    )
    $reportResults = ConvertTo-ReportHostResults -Results $Results
    $reportSubnet = ConvertTo-ReportSubnetData -SubnetScanData $SubnetScanData
    $topFolders = @(
        $Results | ForEach-Object { $_.TopFolders } | Where-Object { $_ } | ForEach-Object { $_ }
    )
    if (@($reportSubnet).Count -gt 0) {
        $topFolders += @($reportSubnet | ForEach-Object { $_.sourceTopFolders } | Where-Object { $_ } | ForEach-Object { $_ })
    }
    $topFolders = @($topFolders | Sort-Object -Unique)

    $allDataset = New-HostReachabilityDataset -ReportResults $reportResults -ReportSubnetData $reportSubnet -FilesScanned $FilesScanned -FilesPerTopFolder $FilesPerTopFolder
    $allPath = Join-Path -Path $OutputDirectory -ChildPath (Get-HostReachabilityDataFileName -TopFolder '')
    ($allDataset | ConvertTo-Json -Depth 8 -Compress) | Set-Content -LiteralPath $allPath -Encoding UTF8
    Write-Host ("JSON geschrieben: {0}" -f ([System.IO.Path]::GetFileName($allPath))) -ForegroundColor Green

    foreach ($tf in $topFolders) {
        $dataset = New-HostReachabilityDataset -ReportResults $reportResults -ReportSubnetData $reportSubnet -FilesScanned $FilesScanned -FilesPerTopFolder $FilesPerTopFolder -TopFolder $tf
        $path = Join-Path -Path $OutputDirectory -ChildPath (Get-HostReachabilityDataFileName -TopFolder $tf)
        ($dataset | ConvertTo-Json -Depth 8 -Compress) | Set-Content -LiteralPath $path -Encoding UTF8
        Write-Host ("JSON für Top-Ordner '{0}' geschrieben: {1}" -f $tf, ([System.IO.Path]::GetFileName($path))) -ForegroundColor Green
    }
    return @($topFolders)
}

function Export-HostReachabilityTemplate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputFilePath,
        [string[]]$TopFolders = @()
    )
    $sortedTop = @($TopFolders | Where-Object { $_ } | Sort-Object -Unique)
    $dataIndex = @(
        [ordered]@{
            key   = 'ALL'
            label = 'Gesamt'
            file  = (Get-HostReachabilityDataFileName -TopFolder '')
        }
    )
    foreach ($tf in $sortedTop) {
        $dataIndex += [ordered]@{
            key   = (Get-SafeTopFolderKey -TopFolder $tf)
            label = $tf
            file  = (Get-HostReachabilityDataFileName -TopFolder $tf)
        }
    }
    $dataIndexJson = ($dataIndex | ConvertTo-Json -Depth 4 -Compress) -replace '</', '\u003c/'
    $dropdownOptions = ($dataIndex | ForEach-Object {
        $valueEnc = [System.Net.WebUtility]::HtmlEncode($_.key)
        $labelEnc = [System.Net.WebUtility]::HtmlEncode($_.label)
        "        <option value=`"$valueEnc`">$labelEnc</option>"
    }) -join "`n"

    $html = @"
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <title>SYSVOL Host-Erreichbarkeit</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 text-gray-900 min-h-screen">
  <div class="max-w-7xl mx-auto px-4 py-8">
    <header class="mb-8">
      <h1 class="text-3xl font-bold text-gray-900">SYSVOL Host-Erreichbarkeit</h1>
      <p class="mt-2 text-gray-600">Aus Skripten extrahierte Servernamen und IPs sowie Ergebnis der Erreichbarkeitsprüfung.</p>
    </header>

    <div class="mb-6 flex items-center gap-3">
      <label for="filter-topfolder" class="text-sm font-medium text-gray-700">Filter: Top-Ordner</label>
      <select id="filter-topfolder" class="rounded border border-gray-300 px-3 py-1.5 text-gray-900 focus:ring-2 focus:ring-blue-500">
$dropdownOptions
      </select>
      <span id="load-status" class="text-sm text-gray-500"></span>
    </div>

    <section class="mb-8 bg-white rounded-xl shadow p-4" id="summary-section">
      <h2 class="text-lg font-semibold text-gray-800 mb-3">Zusammenfassung</h2>
      <ul class="text-gray-700 space-y-1">
        <li><strong>Dateien gescannt:</strong> <span id="summary-files">0</span></li>
        <li><strong>Eindeutige Hosts:</strong> <span id="summary-hosts">0</span></li>
        <li><strong>Ping erreichbar:</strong> <span id="summary-ping">0</span></li>
        <li><strong>Mind. ein Port offen:</strong> <span id="summary-ports">0</span></li>
      </ul>
    </section>

    <section class="mb-8 bg-white rounded-xl shadow p-4 overflow-x-auto">
      <h2 class="text-lg font-semibold text-gray-800 mb-3">Erreichbarkeit pro Host</h2>
      <table class="w-full text-left border-collapse">
        <thead>
          <tr class="border-b border-gray-300">
            <th class="py-2 pr-4">Host</th>
            <th class="py-2 pr-4">DNS</th>
            <th class="py-2 pr-4">Ping</th>
            <th class="py-2 pr-4">80</th>
            <th class="py-2 pr-4">443</th>
            <th class="py-2 pr-4">445 (SMB)</th>
            <th class="py-2 pr-4">135 (RPC)</th>
            <th class="py-2 pr-4">3389 (RDP)</th>
            <th class="py-2 pr-4">5985 (WinRM)</th>
            <th class="py-2 pr-4">WinRM Test</th>
          </tr>
        </thead>
        <tbody id="hosts-tbody"></tbody>
      </table>
    </section>

    <section class="mb-8 bg-white rounded-xl shadow p-4 overflow-x-auto hidden" id="subnet-section">
      <h2 class="text-lg font-semibold text-gray-800 mb-3">Subnet-Scan (pingbare Endpunkte)</h2>
      <p class="text-sm text-gray-600 mb-3">Pro ermitteltem Host wurde das zugehörige Subnetz (/24) nach erreichbaren (pingbaren) IP-Adressen durchsucht.</p>
      <table class="w-full text-left border-collapse">
        <thead>
          <tr class="border-b border-gray-300">
            <th class="py-2 pr-4">Quell-Host</th>
            <th class="py-2 pr-4">Subnetz</th>
            <th class="py-2 pr-4">Anzahl erreichbar</th>
            <th class="py-2 pr-4">Erreichbare IPs</th>
          </tr>
        </thead>
        <tbody id="subnet-tbody"></tbody>
      </table>
    </section>
  </div>

  <script type="application/json" id="dataIndex">$dataIndexJson</script>
  <script>
  (function() {
    var dataIndex = [];
    try {
      dataIndex = JSON.parse(document.getElementById('dataIndex').textContent || '[]');
    } catch (_) { dataIndex = []; }

    var select = document.getElementById('filter-topfolder');
    var loadStatus = document.getElementById('load-status');
    var hostsTbody = document.getElementById('hosts-tbody');
    var subnetSection = document.getElementById('subnet-section');
    var subnetTbody = document.getElementById('subnet-tbody');
    var summaryFiles = document.getElementById('summary-files');
    var summaryHosts = document.getElementById('summary-hosts');
    var summaryPing = document.getElementById('summary-ping');
    var summaryPorts = document.getElementById('summary-ports');

    var badgeOk = 'bg-green-100 text-green-800 rounded px-2 py-0.5 text-sm';
    var badgeFail = 'bg-red-100 text-red-800 rounded px-2 py-0.5 text-sm';
    var badgeNa = 'bg-gray-100 text-gray-600 rounded px-2 py-0.5 text-sm';
    var portsOrder = [80, 443, 445, 135, 3389, 5985];

    function escapeHtml(s) {
      if (s == null) return '';
      return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
    }

    function badgeHtml(ok, naText) {
      if (naText != null) return '<span class="' + badgeNa + '">' + naText + '</span>';
      return '<span class="' + (ok ? badgeOk : badgeFail) + '">' + (ok ? 'OK' : 'Fehler') + '</span>';
    }

    function renderHosts(rows) {
      if (!hostsTbody) return;
      var html = [];
      (rows || []).forEach(function(r) {
        var ports = r.ports || {};
        var portCells = portsOrder.map(function(p) {
          var isOpen = !!ports[String(p)];
          var cls = isOpen ? badgeOk : badgeFail;
          var txt = isOpen ? 'Offen' : 'Geschlossen';
          return '<td><span class="' + cls + '" title="Port ' + p + '">' + txt + '</span></td>';
        }).join('');
        var winRmHtml = (r.winRmOk === null || typeof r.winRmOk === 'undefined')
          ? badgeHtml(false, 'N/A')
          : badgeHtml(!!r.winRmOk, null);
        html.push(
          '<tr>' +
            '<td class="font-mono">' + escapeHtml(r.host) + '</td>' +
            '<td>' + badgeHtml(!!r.dnsOk, null) + '</td>' +
            '<td>' + badgeHtml(!!r.pingOk, null) + '</td>' +
            portCells +
            '<td>' + winRmHtml + '</td>' +
          '</tr>'
        );
      });
      hostsTbody.innerHTML = html.join('');
    }

    function renderSubnet(rows) {
      if (!subnetTbody || !subnetSection) return;
      var list = rows || [];
      if (list.length === 0) {
        subnetSection.classList.add('hidden');
        subnetTbody.innerHTML = '';
        return;
      }
      subnetSection.classList.remove('hidden');
      var html = [];
      list.forEach(function(r) {
        var ips = (r.reachableIps || []).slice().sort();
        var ipsText = ips.join(', ');
        html.push(
          '<tr>' +
            '<td class="font-mono">' + escapeHtml(r.sourceHost) + '</td>' +
            '<td class="font-mono">' + escapeHtml(r.subnet) + '</td>' +
            '<td>' + ips.length + '</td>' +
            '<td class="font-mono text-sm max-w-md truncate" title="' + escapeHtml(ipsText) + '">' + escapeHtml(ipsText) + '</td>' +
          '</tr>'
        );
      });
      subnetTbody.innerHTML = html.join('');
    }

    function applySummary(summary) {
      var s = summary || {};
      if (summaryFiles) summaryFiles.textContent = String(s.filesScanned || 0);
      if (summaryHosts) summaryHosts.textContent = String(s.hostCount || 0);
      if (summaryPing) summaryPing.textContent = String(s.pingReachable || 0);
      if (summaryPorts) summaryPorts.textContent = String(s.anyPortOpen || 0);
    }

    function loadByKey(key) {
      var item = (dataIndex || []).find(function(x) { return x.key === key; }) || dataIndex[0];
      if (!item || !item.file) return;
      if (loadStatus) loadStatus.textContent = 'Lade Daten ...';
      fetch(item.file, { cache: 'no-store' })
        .then(function(resp) {
          if (!resp.ok) throw new Error('HTTP ' + resp.status);
          return resp.json();
        })
        .then(function(data) {
          applySummary(data.summary || {});
          renderHosts(data.results || []);
          renderSubnet(data.subnetScanData || []);
          if (loadStatus) loadStatus.textContent = '';
        })
        .catch(function(err) {
          if (loadStatus) loadStatus.textContent = 'Fehler beim Laden: ' + err.message;
        });
    }

    if (select) {
      select.addEventListener('change', function() { loadByKey(select.value); });
      loadByKey(select.value || 'ALL');
    }
  })();
  </script>
</body>
</html>
"@
    $html | Set-Content -Path $OutputFilePath -Encoding UTF8
    Write-Host "HTML geschrieben: $OutputFilePath" -ForegroundColor Green
}

# Main
if (-not (Test-Path -LiteralPath $ScriptsPath -PathType Container)) {
    Write-Error "Pfad existiert nicht oder ist kein Verzeichnis: $ScriptsPath"
}
$rootResolved = Resolve-Path -Path $ScriptsPath -ErrorAction Stop
# Provider-Qualifier (z.B. 'Microsoft.PowerShell.Core\FileSystem::') entfernen,
# damit $rootPath zum Format von $f.FullName passt.
$rootPath = $rootResolved.ProviderPath

$outResolved = Resolve-PathSafe -Path $OutputPath
$outDir = [System.IO.Path]::GetDirectoryName($outResolved)
if ([string]::IsNullOrEmpty($outDir)) {
    $outDir = (Get-Location).Path
}
if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
# Template früh bereitstellen; Daten werden später dynamisch nachgeladen.
Export-HostReachabilityTemplate -OutputFilePath $outResolved -TopFolders @()

$checkpointResolved = Get-CheckpointPath -ProvidedPath $CheckpointPath
$artifactPaths = Get-ResumeArtifactPaths -CheckpointPathValue $checkpointResolved
$autoResumeEnabled = -not $NoAutoResume
$resumeEnabled = $Resume.IsPresent -or $autoResumeEnabled

function ConvertTo-OrderedHashtable {
    param([object]$Obj)
    if ($null -eq $Obj) { return [ordered]@{} }
    $h = [ordered]@{}
    foreach ($p in $Obj.PSObject.Properties) {
        $h[$p.Name] = $p.Value
    }
    return $h
}

$state = New-HostReachabilityState -ScriptsPathValue $rootPath -OutputPathValue $outResolved -ThrottleLimitValue $ThrottleLimit -SubnetScanValue $SubnetScan.IsPresent -SubnetPrefixLengthValue $SubnetPrefixLength
$resumeSource = 'none'

if ($resumeEnabled) {
    $checkpoint = Read-Checkpoint -CheckpointPath $checkpointResolved
    $checkpointValid = $false
    if ($checkpoint) {
        $checkpointOutputPath = if ($checkpoint.OutputPath) { [string]$checkpoint.OutputPath } else { '' }
        $checkpointVersion = [int]$checkpoint.Version
        $checkpointValid = (
            $checkpointVersion -ge 1 -and
            $checkpoint.ScriptsPath -eq $rootPath -and
            ($checkpointOutputPath -eq '' -or $checkpointOutputPath -eq $outResolved)
        )
    }

    if ($checkpointValid) {
        Write-Host "Checkpoint gefunden, setze fort: $checkpointResolved" -ForegroundColor Yellow
        $fpTf = @{}
        if ($checkpoint.FilesPerTopFolder) {
            $checkpoint.FilesPerTopFolder.PSObject.Properties | ForEach-Object { $fpTf[$_.Name] = [int]$_.Value }
        }
        $phases = @{
            FileScanCompleted   = [bool]$checkpoint.Phases.FileScanCompleted
            HostChecksCompleted = [bool]$checkpoint.Phases.HostChecksCompleted
            SubnetScanCompleted = [bool]$checkpoint.Phases.SubnetScanCompleted
            ReportExported      = [bool]$checkpoint.Phases.ReportExported
        }
        $uniqueHostsNorm = @(ConvertTo-NormalizedUniqueHosts -UniqueHosts @($checkpoint.UniqueHosts))
        $hostToTopFoldersForResume = @{}
        foreach ($u in $uniqueHostsNorm) { $hostToTopFoldersForResume[$u.Host] = @($u.TopFolders) }
        $state = [ordered]@{
            Version            = $script:CheckpointVersion
            ScriptsPath        = $checkpoint.ScriptsPath
            OutputPath         = $(if ($checkpoint.OutputPath) { [string]$checkpoint.OutputPath } else { $outResolved })
            Parameters         = $(if ($checkpoint.Parameters) { ConvertTo-OrderedHashtable -Obj $checkpoint.Parameters } else { $state.Parameters })
            TimestampUtc       = $checkpoint.TimestampUtc
            FilesScannedCount  = [int]$checkpoint.FilesScannedCount
            FilesPerTopFolder  = $fpTf
            UniqueHosts        = $uniqueHostsNorm
            HostResults        = @($(ConvertTo-NormalizedHostResults -HostResults @($checkpoint.HostResults) -HostToTopFolders $hostToTopFoldersForResume))
            SubnetScanData     = @($(ConvertTo-NormalizedSubnetData -SubnetData @($checkpoint.SubnetScanData)))
            Phases             = $phases
            Errors             = @($checkpoint.Errors)
        }
        $resumeSource = 'checkpoint'
    }
    elseif ($checkpoint) {
        Write-Warning "Checkpoint ignoriert (ScriptsPath/OutputPath/Version passt nicht)."
    }

    if ($resumeSource -eq 'none') {
        $artifactData = Read-ResumeArtifacts -ArtifactPaths $artifactPaths -ExpectedScriptsPath $rootPath -ExpectedOutputPath $outResolved
        if ($artifactData.HasData) {
            $hostPayload = $artifactData.HostData
            $subnetPayload = $artifactData.SubnetData
            if ($hostPayload) {
                $fpTf = @{}
                if ($hostPayload.filesPerTopFolder) {
                    $hostPayload.filesPerTopFolder.PSObject.Properties | ForEach-Object { $fpTf[$_.Name] = [int]$_.Value }
                }
                $uniqueHostsNorm = @(ConvertTo-NormalizedUniqueHosts -UniqueHosts @($hostPayload.uniqueHosts))
                $hostToTopFoldersForResume = @{}
                foreach ($u in $uniqueHostsNorm) { $hostToTopFoldersForResume[$u.Host] = @($u.TopFolders) }
                $state.FilesScannedCount = [int]$hostPayload.filesScannedCount
                $state.FilesPerTopFolder = $fpTf
                $state.UniqueHosts = $uniqueHostsNorm
                $state.HostResults = @(ConvertTo-NormalizedHostResults -HostResults @($hostPayload.hostResults) -HostToTopFolders $hostToTopFoldersForResume)
            }
            if ($subnetPayload) {
                $state.SubnetScanData = @(ConvertTo-NormalizedSubnetData -SubnetData @($subnetPayload.subnetScanData))
            }
            $state.Phases.FileScanCompleted = ($state.FilesScannedCount -gt 0 -or @($state.UniqueHosts).Count -gt 0)
            $state.Phases.HostChecksCompleted = (@($state.UniqueHosts).Count -gt 0 -and @($state.HostResults).Count -ge @($state.UniqueHosts).Count)
            $state.Phases.SubnetScanCompleted = $false
            $state.Phases.ReportExported = $false
            $resumeSource = 'artifacts'
            Write-Host ("Resume über Teil-Artefakte: {0}" -f (($artifactData.Messages -join ', '))) -ForegroundColor Yellow
            Save-ResumeState -State $state -CheckpointPathValue $checkpointResolved -ArtifactPaths $artifactPaths
        }
    }
}

if ($resumeSource -eq 'none') {
    Write-Host "Kein verwertbarer Resume-Stand gefunden. Starte neuen Lauf." -ForegroundColor Gray
}
elseif ($resumeSource -eq 'checkpoint') {
    Write-Host ("Resume aus Checkpoint: Hosts={0}, Subnet-Einträge={1}" -f @($state.HostResults).Count, @($state.SubnetScanData).Count) -ForegroundColor Yellow
}
elseif ($resumeSource -eq 'artifacts') {
    Write-Host ("Resume aus Artefakten: Hosts={0}, Subnet-Einträge={1}" -f @($state.HostResults).Count, @($state.SubnetScanData).Count) -ForegroundColor Yellow
}

Write-Host "Scanne $rootPath ..." -ForegroundColor Cyan
$uniqueHosts = @()
if (-not $state.Phases.FileScanCompleted -or -not $state.UniqueHosts -or $state.UniqueHosts.Count -eq 0) {
    $files = @(Get-RelevantFiles -RootPath $rootPath)
    Write-Host "Gefunden: $($files.Count) Dateien." -ForegroundColor Cyan
    $rootTrimmed = $rootPath.TrimEnd('\', '/')
    $filesPerTopFolder = @{}
    foreach ($f in $files) {
        $rel = ''
        if ($f.FullName.Length -gt $rootTrimmed.Length) {
            $rel = $f.FullName.Substring($rootTrimmed.Length).TrimStart('\', '/')
        }
        $top = ($rel -split '[\\/]')[0]
        if (-not $top) { $top = '(Root)' }
        if (-not $filesPerTopFolder.ContainsKey($top)) { $filesPerTopFolder[$top] = 0 }
        $filesPerTopFolder[$top] += 1
    }
    $state.FilesPerTopFolder = $filesPerTopFolder
    $uniqueHosts = Get-AllUniqueHosts -Files $files -RootPath $rootPath
    $state.UniqueHosts = @($uniqueHosts)
    $state.FilesScannedCount = $files.Count
    $state.Phases.FileScanCompleted = $true
    Save-ResumeState -State $state -CheckpointPathValue $checkpointResolved -ArtifactPaths $artifactPaths
}
else {
    $uniqueHosts = @(ConvertTo-NormalizedUniqueHosts -UniqueHosts @($state.UniqueHosts))
    $state.UniqueHosts = @($uniqueHosts)
    Write-Host "Gefunden: $($state.FilesScannedCount) Dateien. (aus Checkpoint)" -ForegroundColor Cyan
}
$hostToTopFolders = @{}
foreach ($o in $uniqueHosts) {
    $h = $o.Host
    $tfs = $o.TopFolders
    if ($null -eq $tfs) { $tfs = @() }
    if ($tfs -isnot [array]) { $tfs = @($tfs) }
    $hostToTopFolders[$h] = @($tfs)
}
$resultsList = [System.Collections.ArrayList]::new()
foreach ($r in @(ConvertTo-NormalizedHostResults -HostResults @($state.HostResults) -HostToTopFolders $hostToTopFolders)) {
    $tfs = if ($r.TopFolders) { @($r.TopFolders) } else { $hostToTopFolders[$r.Host] }
    if ($null -eq $tfs) { $tfs = @() }
    [void]$resultsList.Add([pscustomobject]@{ Host = $r.Host; DnsOk = $r.DnsOk; PingOk = $r.PingOk; Ports = $r.Ports; WinRmOk = $r.WinRmOk; TopFolders = $tfs })
}
$checkedSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($r in @($resultsList)) { if ($r.Host) { [void]$checkedSet.Add([string]$r.Host) } }
Write-Host "Eindeutige Hosts/IPs: $($uniqueHosts.Count)" -ForegroundColor Cyan
if ($uniqueHosts.Count -gt 0 -and $checkedSet.Count -gt 0) {
    Write-Host ("Resume: HostChecks erledigt: {0}/{1}" -f $checkedSet.Count, $uniqueHosts.Count) -ForegroundColor Yellow
}

function Invoke-HostChecksBatch {
    param(
        [string[]]$Hosts,
        [int]$Throttle
    )
    return @($Hosts | ForEach-Object -ThrottleLimit $Throttle -Parallel {
        $h = $_
        $ports = @(80, 443, 445, 135, 3389, 5985)
        function Test-TcpPortInner {
            param($ComputerName, $Port, $TimeoutMs = 2000)
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $connect = $tcp.BeginConnect($ComputerName, $Port, $null, $null)
                $ok = $connect.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
                if ($ok -and $tcp.Connected) { $tcp.Close(); return $true }
                $tcp.Close()
                return $false
            }
            catch { return $false }
        }
        $dnsOk = $false
        try { [System.Net.Dns]::GetHostEntry($h) | Out-Null; $dnsOk = $true } catch { }
        $pingOk = $false
        try { $pingOk = Test-Connection -ComputerName $h -Count 1 -Quiet -ErrorAction SilentlyContinue } catch { }
        $portsResult = @{}
        foreach ($p in $ports) { $portsResult[$p] = Test-TcpPortInner -ComputerName $h -Port $p -TimeoutMs 2000 }
        $winRmOk = $null
        try { $null = Test-WSMan -ComputerName $h -ErrorAction Stop; $winRmOk = $true } catch { $winRmOk = $false }
        [pscustomobject]@{
            Host    = $h
            DnsOk   = $dnsOk
            PingOk  = $pingOk
            Ports   = $portsResult
            WinRmOk = $winRmOk
        }
    })
}

try {
    if ($uniqueHosts.Count -eq 0) {
        Write-Host "Keine Hosts gefunden. Leere HTML wird erzeugt." -ForegroundColor Yellow
    }
    else {
        $totalHosts = [math]::Max(1, $uniqueHosts.Count)
        $remaining = @($uniqueHosts | Where-Object { -not $checkedSet.Contains($_.Host) })
        if ($remaining.Count -gt 0) {
            $batchSize = 25
            for ($i = 0; $i -lt $remaining.Count; $i += $batchSize) {
                $batchHosts = @($remaining[$i..([math]::Min($i + $batchSize - 1, $remaining.Count - 1))] | ForEach-Object { $_.Host })
                $pct = [math]::Min(100, [int](100 * $checkedSet.Count / $totalHosts))
                Write-Progress -Activity 'Erreichbarkeit prüfen' -Status ("{0}/{1} Hosts" -f $checkedSet.Count, $uniqueHosts.Count) -PercentComplete $pct
                $batchResults = Invoke-HostChecksBatch -Hosts $batchHosts -Throttle $ThrottleLimit
                foreach ($br in $batchResults) {
                    if ($br.Host -and -not $checkedSet.Contains($br.Host)) {
                        $tfs = $hostToTopFolders[$br.Host]
                        if ($null -eq $tfs) { $tfs = @() }
                        [void]$resultsList.Add([pscustomobject]@{ Host = $br.Host; DnsOk = $br.DnsOk; PingOk = $br.PingOk; Ports = $br.Ports; WinRmOk = $br.WinRmOk; TopFolders = $tfs })
                        [void]$checkedSet.Add([string]$br.Host)
                    }
                }
                $state.HostResults = @(ConvertTo-NormalizedHostResults -HostResults @($resultsList) -HostToTopFolders $hostToTopFolders)
                Save-ResumeState -State $state -CheckpointPathValue $checkpointResolved -ArtifactPaths $artifactPaths
            }
        }
        Write-Progress -Activity 'Erreichbarkeit prüfen' -Completed
        if ($checkedSet.Count -ge $uniqueHosts.Count) {
            $state.Phases.HostChecksCompleted = $true
            Save-ResumeState -State $state -CheckpointPathValue $checkpointResolved -ArtifactPaths $artifactPaths
        }
    }
}
catch {
    $state.Errors += [pscustomobject]@{ TimestampUtc = (Get-Date).ToUniversalTime(); Message = $_.Exception.Message }
    Save-ResumeState -State $state -CheckpointPathValue $checkpointResolved -ArtifactPaths $artifactPaths
    throw
}

$results = @($resultsList)

$subnetScanData = [System.Collections.ArrayList]::new()
foreach ($s in @(ConvertTo-NormalizedSubnetData -SubnetData @($state.SubnetScanData))) { [void]$subnetScanData.Add($s) }
if ($SubnetScan -and $subnetScanData.Count -gt 0) {
    Write-Host ("Resume: Subnet-Scans vorhanden: {0}" -f $subnetScanData.Count) -ForegroundColor Yellow
}

if ($SubnetScan -and $results.Count -gt 0) {
    Write-Host "Ermittle Subnetze und scanne nach pingbaren Endpunkten ..." -ForegroundColor Cyan
    $scannedSubnetSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($s in @($subnetScanData)) { if ($s.Subnet) { [void]$scannedSubnetSet.Add([string]$s.Subnet) } }

    $subnetToHosts = @{}
    foreach ($r in $results) {
        $ip = Get-IPv4ForHost -HostOrIp $r.Host
        if (-not $ip) { continue }
        $info = Get-SubnetBaseAndRange -Ip $ip -PrefixLength $SubnetPrefixLength
        if (-not $info) { continue }
        $subnetKey = "$($info.Base).0/$SubnetPrefixLength"
        if (-not $subnetToHosts.ContainsKey($subnetKey)) {
            $subnetToHosts[$subnetKey] = [System.Collections.ArrayList]::new()
        }
        if ($subnetToHosts[$subnetKey] -notcontains $r.Host) {
            [void]$subnetToHosts[$subnetKey].Add($r.Host)
        }
    }

    $allSubnets = @($subnetToHosts.Keys)
    $totalSubnets = [math]::Max(1, $allSubnets.Count)
    $idx = 0
    foreach ($subnetKey in $allSubnets) {
        $idx++
        if ($scannedSubnetSet.Contains($subnetKey)) { continue }
        Write-Progress -Activity 'Subnet-Scan' -Status $subnetKey -PercentComplete ([math]::Min(100, [int](100 * $idx / $totalSubnets)))
        $info = Get-SubnetBaseAndRange -Ip ($subnetKey -replace '\.0/\d+$', '.1') -PrefixLength $SubnetPrefixLength
        if (-not $info -or $null -eq $info.Last) { continue }
        $reachable = Get-PingableIPsInSubnet -SubnetBase $info.Base -First $info.First -Last $info.Last -Throttle $ThrottleLimit
        $sourceHosts = @($subnetToHosts[$subnetKey])
        $sourceTopFoldersSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($sh in $sourceHosts) {
            $res = $results | Where-Object { $_.Host -eq $sh } | Select-Object -First 1
            if ($res -and $res.TopFolders) { foreach ($tf in $res.TopFolders) { [void]$sourceTopFoldersSet.Add($tf) } }
        }
        $entry = [pscustomobject]@{
            SourceHost       = ($sourceHosts -join ', ')
            SourceTopFolders = @($sourceTopFoldersSet)
            Subnet           = $subnetKey
            ReachableIPs     = @($reachable)
        }
        [void]$subnetScanData.Add($entry)
        [void]$scannedSubnetSet.Add($subnetKey)
        $state.SubnetScanData = @(ConvertTo-NormalizedSubnetData -SubnetData @($subnetScanData))
        Save-ResumeState -State $state -CheckpointPathValue $checkpointResolved -ArtifactPaths $artifactPaths
    }
    Write-Progress -Activity 'Subnet-Scan' -Completed
    if ($scannedSubnetSet.Count -ge $allSubnets.Count) {
        $state.Phases.SubnetScanCompleted = $true
    }
    Save-ResumeState -State $state -CheckpointPathValue $checkpointResolved -ArtifactPaths $artifactPaths
}
elseif (-not $SubnetScan) {
    $state.Phases.SubnetScanCompleted = $true
    Save-ResumeState -State $state -CheckpointPathValue $checkpointResolved -ArtifactPaths $artifactPaths
}

$subnetScanDataFinal = @($subnetScanData)
$topFoldersForTemplate = Write-HostReachabilityDataFiles -Results $results -OutputDirectory $outDir -FilesScanned $state.FilesScannedCount -FilesPerTopFolder $state.FilesPerTopFolder -SubnetScanData $subnetScanDataFinal
Export-HostReachabilityTemplate -OutputFilePath $outResolved -TopFolders $topFoldersForTemplate
$state.Phases.ReportExported = $true
Save-ResumeState -State $state -CheckpointPathValue $checkpointResolved -ArtifactPaths $artifactPaths

if ($state.Phases.FileScanCompleted -and $state.Phases.HostChecksCompleted -and (($SubnetScan -and $state.Phases.SubnetScanCompleted) -or (-not $SubnetScan)) -and $state.Phases.ReportExported) {
    Write-Host ("Lauf vollständig. Resume-Quelle: {0}" -f $resumeSource) -ForegroundColor Green
    if (-not $KeepResumeData) {
        Remove-Item -LiteralPath $checkpointResolved -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $artifactPaths.HostResults -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $artifactPaths.SubnetData -Force -ErrorAction SilentlyContinue
        Write-Host "Checkpoint/Artefakte gelöscht (Lauf vollständig)." -ForegroundColor Green
    }
    else {
        Write-Host "KeepResumeData aktiv: Checkpoint/Artefakte bleiben erhalten." -ForegroundColor Yellow
    }
}