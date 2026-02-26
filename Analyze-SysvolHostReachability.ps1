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

.PARAMETER Encoding
    Fallback-Encoding beim Lesen von Dateien (Default: UTF8).

.PARAMETER ThrottleLimit
    Maximale parallele Host-Checks beim Port-Scan (Default: 8).

.PARAMETER SubnetScan
    Pro ermitteltem Host das zugehörige Subnetz (/24) nach pingbaren Endpunkten durchsuchen (Default: aktiv).

.PARAMETER SubnetPrefixLength
    Präfixlänge für Subnetz-Scan in CIDR-Notation (Default: 24 = /24).

.EXAMPLE
    .\Analyze-SysvolHostReachability.ps1 -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts'

.EXAMPLE
    .\Analyze-SysvolHostReachability.ps1 -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts' -OutputPath 'D:\Reports\HostReach.html' -ThrottleLimit 4
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScriptsPath,

    [string]$OutputPath = ".\HostReachabilityReport.html",

    [System.Text.Encoding]$Encoding = [System.Text.Encoding]::UTF8,

    [ValidateRange(1, 32)]
    [int]$ThrottleLimit = 8,

    [switch]$SubnetScan = $true,

    [ValidateRange(8, 30)]
    [int]$SubnetPrefixLength = 24
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:FileExtensions = @('.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.kix', '.txt')
$script:ExcludedHosts = @('localhost', '127.0.0.1', '0.0.0.0', '::1', '')
$script:CheckpointFileName = 'sysvol_host_reachability_checkpoint.json'
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

function New-HostReachabilityState {
    param([string]$ScriptsPathValue)
    return [ordered]@{
        Version          = 1
        ScriptsPath      = $ScriptsPathValue
        TimestampUtc     = (Get-Date).ToUniversalTime()
        FilesScannedCount= 0
        UniqueHosts      = @()
        HostResults      = @()
        SubnetScanData   = @()
        Phases           = @{
            FileScanCompleted   = $false
            HostChecksCompleted = $false
            SubnetScanCompleted = $false
            ReportExported      = $false
        }
        Errors           = @()
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
    $allHosts = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $total = $Files.Count
    $i = 0
    foreach ($f in $Files) {
        $i++
        Write-Progress -Activity 'Dateien scannen' -Status $f.Name -PercentComplete ([math]::Min(100, [int](100 * $i / $total)))
        $content = Get-FileContentSafe -Path $f.FullName
        $found = Get-UniqueHostsFromContent -Content $content
        foreach ($h in $found) {
            $h = $h.Trim()
            if ([string]::IsNullOrWhiteSpace($h)) { continue }
            if ($script:ExcludedHosts -contains $h) { continue }
            if ($h -match '^%') { continue }
            [void]$allHosts.Add($h)
        }
    }
    Write-Progress -Activity 'Dateien scannen' -Completed
    return @($allHosts)
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

function Export-HostReachabilityHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Results,
        [Parameter(Mandatory = $true)]
        [string]$OutputFilePath,
        [int]$FilesScanned = 0,
        [array]$SubnetScanData = @()
    )
    $totalHosts = $Results.Count
    $reachableByPing = @($Results | Where-Object { $_.PingOk }).Count
    $anyPortOpen = @($Results | Where-Object {
        $_.Ports.Values | Where-Object { $_ } | Select-Object -First 1
    }).Count

    $badgeOk = 'bg-green-100 text-green-800 rounded px-2 py-0.5 text-sm'
    $badgeFail = 'bg-red-100 text-red-800 rounded px-2 py-0.5 text-sm'
    $badgeNa = 'bg-gray-100 text-gray-600 rounded px-2 py-0.5 text-sm'

    $rows = [System.Text.StringBuilder]::new()
    $portsOrder = @(80, 443, 445, 135, 3389, 5985)
    foreach ($r in $Results) {
        $hostEnc = [System.Net.WebUtility]::HtmlEncode($r.Host)
        $dnsClass = if ($r.DnsOk) { $badgeOk } else { $badgeFail }
        $dnsText = if ($r.DnsOk) { 'OK' } else { 'Fehler' }
        $pingClass = if ($r.PingOk) { $badgeOk } else { $badgeFail }
        $pingText = if ($r.PingOk) { 'OK' } else { 'Fehler' }
        $winRmClass = if ($null -eq $r.WinRmOk) { $badgeNa } elseif ($r.WinRmOk) { $badgeOk } else { $badgeFail }
        $winRmText = if ($null -eq $r.WinRmOk) { 'N/A' } elseif ($r.WinRmOk) { 'OK' } else { 'Fehler' }

        $portCells = ($portsOrder | ForEach-Object {
            $p = $_
            $open = $r.Ports[$p]
            $c = if ($open) { $badgeOk } else { $badgeFail }
            $t = if ($open) { 'Offen' } else { 'Geschlossen' }
            "<td><span class=`"$c`" title=`"Port $p`">$t</span></td>"
        }) -join ''
        [void]$rows.AppendLine("        <tr><td class=`"font-mono`">$hostEnc</td><td><span class=`"$dnsClass`">$dnsText</span></td><td><span class=`"$pingClass`">$pingText</span></td>$portCells<td><span class=`"$winRmClass`">$winRmText</span></td></tr>")
    }

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
    <section class="mb-8 bg-white rounded-xl shadow p-4">
      <h2 class="text-lg font-semibold text-gray-800 mb-3">Zusammenfassung</h2>
      <ul class="text-gray-700 space-y-1">
        <li><strong>Dateien gescannt:</strong> $FilesScanned</li>
        <li><strong>Eindeutige Hosts:</strong> $totalHosts</li>
        <li><strong>Ping erreichbar:</strong> $reachableByPing</li>
        <li><strong>Mind. ein Port offen:</strong> $anyPortOpen</li>
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
        <tbody>
$($rows.ToString())
        </tbody>
      </table>
    </section>
$(if ($SubnetScanData.Count -gt 0) {
    $subnetRows = [System.Text.StringBuilder]::new()
    foreach ($s in $SubnetScanData) {
      $hostEnc = [System.Net.WebUtility]::HtmlEncode($s.SourceHost)
      $subnetEnc = [System.Net.WebUtility]::HtmlEncode($s.Subnet)
      $count = $s.ReachableIPs.Count
      $ipsEnc = [System.Net.WebUtility]::HtmlEncode(($s.ReachableIPs | Sort-Object) -join ', ')
      [void]$subnetRows.AppendLine("        <tr><td class=`"font-mono`">$hostEnc</td><td class=`"font-mono`">$subnetEnc</td><td>$count</td><td class=`"font-mono text-sm max-w-md truncate`" title=`"$ipsEnc`">$ipsEnc</td></tr>")
    }
    "    <section class=`"mb-8 bg-white rounded-xl shadow p-4 overflow-x-auto`">
      <h2 class=`"text-lg font-semibold text-gray-800 mb-3`">Subnet-Scan (pingbare Endpunkte)</h2>
      <p class=`"text-sm text-gray-600 mb-3`">Pro ermitteltem Host wurde das zugehörige Subnetz (/24) nach erreichbaren (pingbaren) IP-Adressen durchsucht.</p>
      <table class=`"w-full text-left border-collapse`">
        <thead>
          <tr class=`"border-b border-gray-300`">
            <th class=`"py-2 pr-4`">Quell-Host</th>
            <th class=`"py-2 pr-4`">Subnetz</th>
            <th class=`"py-2 pr-4`">Anzahl erreichbar</th>
            <th class=`"py-2 pr-4`">Erreichbare IPs</th>
          </tr>
        </thead>
        <tbody>
$($subnetRows.ToString())
        </tbody>
      </table>
    </section>"
} else { '' })
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

function ConvertTo-OrderedHashtable {
    param([object]$Obj)
    if ($null -eq $Obj) { return [ordered]@{} }
    $h = [ordered]@{}
    foreach ($p in $Obj.PSObject.Properties) {
        $h[$p.Name] = $p.Value
    }
    return $h
}

$state = New-HostReachabilityState -ScriptsPathValue $rootPath
$checkpoint = Read-Checkpoint -CheckpointPath $script:CheckpointPath
if ($checkpoint -and $checkpoint.ScriptsPath -eq $rootPath -and $checkpoint.Version -eq 1) {
    Write-Host "Checkpoint gefunden, setze fort: $script:CheckpointFileName" -ForegroundColor Yellow
    $state = [ordered]@{
        Version           = 1
        ScriptsPath       = $checkpoint.ScriptsPath
        TimestampUtc      = $checkpoint.TimestampUtc
        FilesScannedCount = [int]$checkpoint.FilesScannedCount
        UniqueHosts       = @($checkpoint.UniqueHosts)
        HostResults       = @($checkpoint.HostResults)
        SubnetScanData    = @($checkpoint.SubnetScanData)
        Phases            = $checkpoint.Phases
        Errors            = @($checkpoint.Errors)
    }
}
elseif ($checkpoint) {
    Write-Warning "Checkpoint ignoriert (ScriptsPath oder Version passt nicht)."
}
else {
    Write-Host "Kein Checkpoint gefunden. Starte neuen Lauf." -ForegroundColor Gray
}

Write-Host "Scanne $rootPath ..." -ForegroundColor Cyan
$uniqueHosts = @()
if (-not $state.Phases.FileScanCompleted -or -not $state.UniqueHosts -or $state.UniqueHosts.Count -eq 0) {
    $files = Get-RelevantFiles -RootPath $rootPath
    Write-Host "Gefunden: $($files.Count) Dateien." -ForegroundColor Cyan
    $uniqueHosts = Get-AllUniqueHosts -Files $files -RootPath $rootPath
    $state.UniqueHosts = @($uniqueHosts)
    $state.FilesScannedCount = $files.Count
    $state.Phases.FileScanCompleted = $true
    Write-Checkpoint -State $state -CheckpointPath $script:CheckpointPath
}
else {
    $uniqueHosts = @($state.UniqueHosts)
    Write-Host "Gefunden: $($state.FilesScannedCount) Dateien. (aus Checkpoint)" -ForegroundColor Cyan
}
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

$resultsList = [System.Collections.ArrayList]::new()
foreach ($r in @($state.HostResults)) { [void]$resultsList.Add($r) }
$checkedSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($r in @($resultsList)) { if ($r.Host) { [void]$checkedSet.Add([string]$r.Host) } }

try {
    if ($uniqueHosts.Count -eq 0) {
        Write-Host "Keine Hosts gefunden. Leere HTML wird erzeugt." -ForegroundColor Yellow
    }
    else {
        $totalHosts = [math]::Max(1, $uniqueHosts.Count)
        $remaining = @($uniqueHosts | Where-Object { -not $checkedSet.Contains($_) })
        if ($remaining.Count -gt 0) {
            $batchSize = 25
            for ($i = 0; $i -lt $remaining.Count; $i += $batchSize) {
                $batch = $remaining[$i..([math]::Min($i + $batchSize - 1, $remaining.Count - 1))]
                $pct = [math]::Min(100, [int](100 * $checkedSet.Count / $totalHosts))
                Write-Progress -Activity 'Erreichbarkeit prüfen' -Status ("{0}/{1} Hosts" -f $checkedSet.Count, $uniqueHosts.Count) -PercentComplete $pct
                $batchResults = Invoke-HostChecksBatch -Hosts $batch -Throttle $ThrottleLimit
                foreach ($br in $batchResults) {
                    if ($br.Host -and -not $checkedSet.Contains($br.Host)) {
                        [void]$resultsList.Add($br)
                        [void]$checkedSet.Add([string]$br.Host)
                    }
                }
                $state.HostResults = @($resultsList)
                Write-Checkpoint -State $state -CheckpointPath $script:CheckpointPath
            }
        }
        Write-Progress -Activity 'Erreichbarkeit prüfen' -Completed
        if ($checkedSet.Count -ge $uniqueHosts.Count) {
            $state.Phases.HostChecksCompleted = $true
            Write-Checkpoint -State $state -CheckpointPath $script:CheckpointPath
        }
    }
}
catch {
    $state.Errors += [pscustomobject]@{ TimestampUtc = (Get-Date).ToUniversalTime(); Message = $_.Exception.Message }
    Write-Checkpoint -State $state -CheckpointPath $script:CheckpointPath
    throw
}

$results = @($resultsList)

$subnetScanData = [System.Collections.ArrayList]::new()
foreach ($s in @($state.SubnetScanData)) { [void]$subnetScanData.Add($s) }
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
        $entry = [pscustomobject]@{
            SourceHost   = ($sourceHosts -join ', ')
            Subnet       = $subnetKey
            ReachableIPs = @($reachable)
        }
        [void]$subnetScanData.Add($entry)
        [void]$scannedSubnetSet.Add($subnetKey)
        $state.SubnetScanData = @($subnetScanData)
        Write-Checkpoint -State $state -CheckpointPath $script:CheckpointPath
    }
    Write-Progress -Activity 'Subnet-Scan' -Completed
    $state.Phases.SubnetScanCompleted = $true
    Write-Checkpoint -State $state -CheckpointPath $script:CheckpointPath
}

$subnetScanDataFinal = @($subnetScanData)

$outResolved = $OutputPath
if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
    $outResolved = Join-Path -Path (Get-Location) -ChildPath $OutputPath
}
$outDir = [System.IO.Path]::GetDirectoryName($outResolved)
if (-not [string]::IsNullOrEmpty($outDir) -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
Export-HostReachabilityHtml -Results $results -OutputFilePath $outResolved -FilesScanned $state.FilesScannedCount -SubnetScanData $subnetScanDataFinal
$state.Phases.ReportExported = $true
Write-Checkpoint -State $state -CheckpointPath $script:CheckpointPath

if ($state.Phases.FileScanCompleted -and $state.Phases.HostChecksCompleted -and (($SubnetScan -and $state.Phases.SubnetScanCompleted) -or (-not $SubnetScan)) -and $state.Phases.ReportExported) {
    Remove-Item -LiteralPath $script:CheckpointPath -Force -ErrorAction SilentlyContinue
    Write-Host "Checkpoint gelöscht (Lauf vollständig): $script:CheckpointFileName" -ForegroundColor Green
}
