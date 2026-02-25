<#
.SYNOPSIS
    Analysiert SYSVOL\scripts in einer Active Directory Domäne auf Sicherheitsrisiken, Abhängigkeiten,
    Nutzung, Duplikate und Codequalität.

.DESCRIPTION
    Dieses Tool ist für große Umgebungen mit vielen Skriptdateien (z.B. ~19.000 Dateien im SYSVOL\scripts)
    ausgelegt. Es arbeitet read-only und sammelt Kennzahlen und Findings in verschiedenen Bereichen:

    - Sicherheitsanalyse (Hashes, Signaturen, verdächtige Muster)
    - Dependency-Tracking (Aufrufbeziehungen zwischen Skripten)
    - Nutzungsanalyse (GPO- und AD-Referenzen, Zeitstempel)
    - Duplikaterkennung (Hash-, Namens- und Inhaltsähnlichkeit)
    - Codequalität & Komplexität (LOC, Kommentare, Komplexität, Legacy-Befehle)

    Ergebnisse werden in JSON, CSV, optional Excel sowie einem HTML-Management-Report ausgegeben.
    Zusätzlich steht eine interaktive Konsolen-Nachbearbeitung zur Verfügung.

.PARAMETER ScriptsPath
    Wurzelpfad des SYSVOL-Skriptverzeichnisses (z.B. \\DOMAIN\SYSVOL\DOMAIN\scripts).

.PARAMETER Resume
    Setzt eine unterbrochene Analyse auf Basis einer Checkpoint-Datei fort.

.PARAMETER DryRun
    Generiert nur Empfehlungen und PowerShell-Beispiele, führt aber keine ändernden Operationen aus.
    (Die Analyse selbst ist immer read-only.)

.PARAMETER ParallelThreads
    Anzahl paralleler Worker für die Dateianalyse (Standard: 8).

.PARAMETER OutputPath
    Verzeichnis für alle Reports und Logs (Standard: .\AnalysisResults).

.EXAMPLE
    .\Analyze-SysvolScripts.ps1 -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts'

.EXAMPLE
    .\Analyze-SysvolScripts.ps1 -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts' -ParallelThreads 16 -OutputPath 'D:\Reports\Sysvol'

.EXAMPLE
    .\Analyze-SysvolScripts.ps1 -ScriptsPath '\\contoso.local\SYSVOL\contoso.local\scripts' -Resume

.NOTES
    - Erfordert PowerShell 7 oder höher.
    - Benötigt Leserechte auf SYSVOL und GPOs sowie Leserechte in AD.
    - Optionales ImportExcel-Modul für Excel-Export.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScriptsPath,

    [switch]$Resume,
    [switch]$DryRun,

    [ValidateRange(1, 64)]
    [int]$ParallelThreads = 8,

    [string]$OutputPath = ".\AnalysisResults",

    [System.Management.Automation.PSCredential]$Credential,

    [switch]$PromptForCredential
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# region Globale Variablen

$script:RunId = [guid]::NewGuid().ToString()
$script:CheckpointFileName = 'sysvol_analysis_checkpoint.json'
$script:CheckpointPath = Join-Path -Path (Get-Location) -ChildPath $script:CheckpointFileName
$script:AnalysisState = [ordered]@{
    Version                  = 1
    RunId                    = $script:RunId
    ScriptsPath              = $null
    OutputPath               = $null
    TimestampUtc             = (Get-Date).ToUniversalTime()
    Inventory                = @()
    UsageMap                 = @()
    ProcessedFiles           = @()
    SecurityFindings         = @()
    FileMetrics              = @()
    DependencyEdges          = @()
    DependencyGraph          = $null
    DuplicateGroups          = @()
    CodeQualitySummary       = @()
    Phases                   = @{
        InventoryCompleted      = $false
        UsageAnalysisCompleted  = $false
        ContentAnalysisCompleted= $false
        DuplicateAnalysisCompleted = $false
        DependencyGraphCompleted   = $false
        ReportsExported         = $false
    }
    Errors                  = @()
}

$script:TranscriptPath = $null
$script:LogFilePath    = $null

# endregion Globale Variablen

# region Hilfsfunktionen

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO',

        [string]$Category = 'General'
    )

    $timestamp = (Get-Date).ToString('s')
    $line = "[{0}] [{1}] [{2}] {3}" -f $timestamp, $Level, $Category, $Message
    Write-Verbose $line

    if ($script:LogFilePath) {
        try {
            Add-Content -Path $script:LogFilePath -Value $line -ErrorAction Stop
        }
        catch {
            Write-Verbose "Konnte Log-Datei nicht schreiben: $($_.Exception.Message)"
        }
    }
}

function Initialize-Environment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptsPath,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [System.Management.Automation.PSCredential]$Credential
    )

    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw "Dieses Skript erfordert PowerShell 7 oder höher. Aktuelle Version: $($PSVersionTable.PSVersion)"
    }

    $resolvedScriptsPath = Resolve-Path -Path $ScriptsPath -ErrorAction Stop
    $resolvedOutputPath = Resolve-Path -Path $OutputPath -ErrorAction SilentlyContinue
    if (-not $resolvedOutputPath) {
        $resolvedOutputPath = New-Item -ItemType Directory -Path $OutputPath -Force | Select-Object -ExpandProperty FullName
    }

    $logsPath  = Join-Path -Path $resolvedOutputPath -ChildPath 'logs'
    $csvPath   = Join-Path -Path $resolvedOutputPath -ChildPath 'csv'
    $jsonPath  = Join-Path -Path $resolvedOutputPath -ChildPath 'json'
    $htmlPath  = Join-Path -Path $resolvedOutputPath -ChildPath 'html'
    $excelPath = Join-Path -Path $resolvedOutputPath -ChildPath 'excel'

    foreach ($p in @($logsPath, $csvPath, $jsonPath, $htmlPath, $excelPath)) {
        if (-not (Test-Path -Path $p)) {
            New-Item -ItemType Directory -Path $p -Force | Out-Null
        }
    }

    $script:TranscriptPath = Join-Path -Path $logsPath -ChildPath ("transcript-{0}.log" -f $script:RunId)
    $script:LogFilePath    = Join-Path -Path $logsPath -ChildPath ("analysis-{0}.log" -f $script:RunId)

    try {
        Start-Transcript -Path $script:TranscriptPath -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Warning "Transcript konnte nicht gestartet werden: $($_.Exception.Message)"
    }

    Write-Log -Message "Analyse gestartet. ScriptsPath=$resolvedScriptsPath OutputPath=$resolvedOutputPath RunId=$script:RunId" -Level INFO -Category 'Init'

    $script:AnalysisState.ScriptsPath = $resolvedScriptsPath.Path
    $script:AnalysisState.OutputPath  = $resolvedOutputPath

    $adModuleAvailable = $false
    $gpModuleAvailable = $false
    $importExcelAvailable = $false

    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        $adModuleAvailable = $true
        Write-Log -Message "ActiveDirectory-Modul gefunden." -Category 'Init'
    }
    else {
        Write-Log -Message "ActiveDirectory-Modul nicht gefunden, verwende ADSI-Fallback." -Level WARN -Category 'Init'
    }

    if (Get-Module -ListAvailable -Name GroupPolicy) {
        $gpModuleAvailable = $true
        Write-Log -Message "GroupPolicy-Modul gefunden." -Category 'Init'
    }
    else {
        Write-Log -Message "GroupPolicy-Modul nicht gefunden, GPO-basierte Nutzungsanalyse eingeschränkt." -Level WARN -Category 'Init'
    }

    if (Get-Module -ListAvailable -Name ImportExcel) {
        $importExcelAvailable = $true
        Write-Log -Message "ImportExcel-Modul gefunden, Excel-Export wird aktiviert." -Category 'Init'
    }
    else {
        Write-Log -Message "ImportExcel-Modul nicht gefunden, Excel-Export wird deaktiviert." -Level WARN -Category 'Init'
    }

    return [pscustomobject]@{
        ScriptsPath         = $resolvedScriptsPath.Path
        OutputPath          = $resolvedOutputPath
        LogsPath            = $logsPath
        CsvPath             = $csvPath
        JsonPath            = $jsonPath
        HtmlPath            = $htmlPath
        ExcelPath           = $excelPath
        AdModuleAvailable   = $adModuleAvailable
        GpModuleAvailable   = $gpModuleAvailable
        ImportExcelAvailable= $importExcelAvailable
    }
}

function Read-Checkpoint {
    [CmdletBinding()]
    param(
        [string]$CheckpointPath
    )

    if (-not (Test-Path -Path $CheckpointPath)) {
        return $null
    }

    try {
        $json = Get-Content -Path $CheckpointPath -Raw -ErrorAction Stop
        if (-not $json) {
            return $null
        }

        $data = $json | ConvertFrom-Json -ErrorAction Stop
        Write-Log -Message "Checkpoint von $CheckpointPath geladen." -Category 'Checkpoint'
        return $data
    }
    catch {
        Write-Log -Message "Fehler beim Lesen des Checkpoints: $($_.Exception.Message)" -Level ERROR -Category 'Checkpoint'
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
        $json = $State | ConvertTo-Json -Depth 6
        $json | Set-Content -Path $CheckpointPath -Encoding UTF8 -ErrorAction Stop
        Write-Log -Message "Checkpoint nach $CheckpointPath geschrieben." -Category 'Checkpoint'
    }
    catch {
        Write-Log -Message "Fehler beim Schreiben des Checkpoints: $($_.Exception.Message)" -Level ERROR -Category 'Checkpoint'
    }
}

function Get-SysvolInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootPath
    )

    Write-Log -Message "Starte Inventarisierung für $RootPath" -Category 'Inventory'

    $items = @()

    try {
        $files = Get-ChildItem -Path $RootPath -Recurse -File -ErrorAction Stop
    }
    catch {
        Write-Log -Message "Fehler bei Get-ChildItem: $($_.Exception.Message)" -Level ERROR -Category 'Inventory'
        throw
    }

    foreach ($f in $files) {
        $isScript = $false
        $isExecutable = $false

        switch ($f.Extension.ToLowerInvariant()) {
            '.ps1' { $isScript = $true }
            '.psm1' { $isScript = $true }
            '.psd1' { $isScript = $true }
            '.vbs' { $isScript = $true }
            '.bat' { $isScript = $true }
            '.cmd' { $isScript = $true }
            '.kix' { $isScript = $true }
            '.exe' { $isExecutable = $true }
            '.com' { $isExecutable = $true }
            '.dll' { $isExecutable = $true }
            '.msi' { $isExecutable = $true }
            default { }
        }

        $item = [pscustomobject]@{
            Id              = [guid]::NewGuid().ToString()
            Name            = $f.Name
            FullPath        = $f.FullName
            Extension       = $f.Extension.ToLowerInvariant()
            Directory       = $f.DirectoryName
            Length          = $f.Length
            CreationTimeUtc = $f.CreationTimeUtc
            LastWriteTimeUtc= $f.LastWriteTimeUtc
            LastAccessTimeUtc= $f.LastAccessTimeUtc
            IsScript        = $isScript
            IsExecutable    = $isExecutable
        }
        $items += $item
    }

    Write-Log -Message "Inventarisierung abgeschlossen, Dateien: $($items.Count)" -Category 'Inventory'
    return $items
}

function Get-UsageFromGpoAndAd {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptsRoot,

        [Parameter(Mandatory = $true)]
        [bool]$AdModuleAvailable,

        [Parameter(Mandatory = $true)]
        [bool]$GpModuleAvailable
        ,

        [System.Management.Automation.PSCredential]$Credential
    )

    $usageEntries = @()

    # GPO-basierte Nutzung
    if ($GpModuleAvailable) {
        try {
            Write-Log -Message "Starte GPO-basierte Nutzungsanalyse." -Category 'Usage'
            Import-Module GroupPolicy -ErrorAction Stop
            $gpos = Get-GPO -All -ErrorAction Stop

            foreach ($gpo in $gpos) {
                try {
                    $xmlPath = [System.IO.Path]::GetTempFileName()
                    Get-GPOReport -Guid $gpo.Id -ReportType Xml -Path $xmlPath -ErrorAction Stop
                    $xml = [xml](Get-Content -Path $xmlPath -Raw)
                    Remove-Item -Path $xmlPath -Force -ErrorAction SilentlyContinue

                    $scriptNodes = $xml.GPO | Select-Xml -XPath "//Scripts/Scripts/*/Script"
                    foreach ($n in $scriptNodes) {
                        $scriptName = $n.Node.Name
                        if (-not $scriptName) { continue }

                        $usageEntries += [pscustomobject]@{
                            Source        = 'GPO'
                            SourceId      = $gpo.Id
                            SourceName    = $gpo.DisplayName
                            ScriptPathRaw = $scriptName
                            ScriptsRoot   = $ScriptsRoot
                        }
                    }
                }
                catch {
                    Write-Log -Message "Fehler bei GPO $($gpo.DisplayName): $($_.Exception.Message)" -Level WARN -Category 'Usage'
                }
            }
        }
        catch {
            Write-Log -Message "GPO-Analyse fehlgeschlagen: $($_.Exception.Message)" -Level WARN -Category 'Usage'
        }
    }

    # AD-basierte Nutzung (User/Computer scriptPath)
    if ($AdModuleAvailable) {
        try {
            Write-Log -Message "Starte AD-basierte Nutzungsanalyse (ActiveDirectory-Modul)." -Category 'Usage'
            Import-Module ActiveDirectory -ErrorAction Stop

            if ($Credential) {
                $users = Get-ADUser -LDAPFilter '(scriptPath=*)' -Properties scriptPath -Credential $Credential -ErrorAction Stop
            }
            else {
                $users = Get-ADUser -LDAPFilter '(scriptPath=*)' -Properties scriptPath -ErrorAction Stop
            }
            foreach ($u in $users) {
                if (-not $u.ScriptPath) { continue }
                $usageEntries += [pscustomobject]@{
                    Source        = 'ADUser'
                    SourceId      = $u.DistinguishedName
                    SourceName    = $u.SamAccountName
                    ScriptPathRaw = $u.ScriptPath
                    ScriptsRoot   = $ScriptsRoot
                }
            }

            if ($Credential) {
                $computers = Get-ADComputer -LDAPFilter '(scriptPath=*)' -Properties scriptPath -Credential $Credential -ErrorAction SilentlyContinue
            }
            else {
                $computers = Get-ADComputer -LDAPFilter '(scriptPath=*)' -Properties scriptPath -ErrorAction SilentlyContinue
            }
            foreach ($c in $computers) {
                if (-not $c.ScriptPath) { continue }
                $usageEntries += [pscustomobject]@{
                    Source        = 'ADComputer'
                    SourceId      = $c.DistinguishedName
                    SourceName    = $c.Name
                    ScriptPathRaw = $c.ScriptPath
                    ScriptsRoot   = $ScriptsRoot
                }
            }
        }
        catch {
            Write-Log -Message "AD-basierte Nutzungsanalyse (Modul) fehlgeschlagen: $($_.Exception.Message)" -Level WARN -Category 'Usage'
        }
    }
    else {
        try {
            Write-Log -Message "Starte AD-basierte Nutzungsanalyse (ADSI-Fallback)." -Category 'Usage'

            $searcher = $null
            if ($Credential) {
                $netCred = $Credential.GetNetworkCredential()
                $rootDse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE", $netCred.UserName, $netCred.Password)
                $defaultNamingContext = $rootDse.Properties['defaultNamingContext'][0]
                $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$defaultNamingContext", $netCred.UserName, $netCred.Password)
                $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
            }
            else {
                $searcher = [System.DirectoryServices.DirectorySearcher]::new()
            }
            $searcher.Filter = '(&(objectCategory=person)(objectClass=user)(scriptPath=*))'
            $searcher.PageSize = 1000
            $searcher.PropertiesToLoad.Clear()
            [void]$searcher.PropertiesToLoad.Add('scriptPath')
            [void]$searcher.PropertiesToLoad.Add('sAMAccountName')

            $results = $searcher.FindAll()
            foreach ($res in $results) {
                $path = $res.Properties['scriptPath']
                if (-not $path) { continue }
                $usageEntries += [pscustomobject]@{
                    Source        = 'ADSIUser'
                    SourceId      = $res.Path
                    SourceName    = ($res.Properties['sAMAccountName'] | Select-Object -First 1)
                    ScriptPathRaw = ($path | Select-Object -First 1)
                    ScriptsRoot   = $ScriptsRoot
                }
            }
        }
        catch {
            Write-Log -Message "ADSI-Fallback für Nutzungsanalyse fehlgeschlagen: $($_.Exception.Message)" -Level WARN -Category 'Usage'
        }
    }

    # Normalisierung der Pfade gegen ScriptsRoot
    foreach ($entry in $usageEntries) {
        $raw = $entry.ScriptPathRaw
        if (-not $raw) { continue }

        $norm = $raw.Trim()
        if ($norm -notlike '\\*' -and $norm -notmatch '^[A-Za-z]:\\') {
            $entry | Add-Member -NotePropertyName 'ScriptFullPath' -NotePropertyValue (Join-Path -Path $ScriptsRoot -ChildPath $norm) -Force
        }
        else {
            $entry | Add-Member -NotePropertyName 'ScriptFullPath' -NotePropertyValue $norm -Force
        }
    }

    Write-Log -Message "Nutzungsanalyse (Rohdaten) Einträge: $($usageEntries.Count)" -Category 'Usage'
    return $usageEntries
}

function Get-FileContentSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [int]$MaxBytes = 5MB
    )

    try {
        $fileInfo = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($fileInfo.Length -gt $MaxBytes) {
            $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            try {
                $bufferSize = [Math]::Min($MaxBytes, $fileInfo.Length)
                $buffer = New-Object byte[] $bufferSize
                [void]$fs.Read($buffer, 0, $bufferSize)
                $encoding = [System.Text.UTF8Encoding]::UTF8
                return $encoding.GetString($buffer)
            }
            finally {
                $fs.Close()
            }
        }
        else {
            return Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        }
    }
    catch {
        Write-Log -Message "Fehler beim Lesen von $Path  $($_.Exception.Message)" -Level WARN -Category 'Content'
        return $null
    }
}

function Get-SecurityAndMetricsForFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$FileItem,

        [Parameter(Mandatory = $true)]
        [string]$ScriptsRoot
    )

    $securityFindings = @()
    $metrics = [pscustomobject]@{
        FileId             = $FileItem.Id
        FullPath           = $FileItem.FullPath
        Extension          = $FileItem.Extension
        Length             = $FileItem.Length
        LocTotal           = 0
        LocComments        = 0
        CyclomaticComplexity = 1
        HasErrorHandling   = $false
        HasHardcodedCreds  = $false
        HasDeprecatedCmds  = $false
        Sha256             = $null
        NormalizedContentHash = $null
    }

    $dependencies = @()

    $content = Get-FileContentSafe -Path $FileItem.FullPath

    $sha = $null
    try {
        $sha = (Get-FileHash -LiteralPath $FileItem.FullPath -Algorithm SHA256 -ErrorAction Stop).Hash
    }
    catch {
        Write-Log -Message "Get-FileHash fehlgeschlagen für $($FileItem.FullPath): $($_.Exception.Message)" -Level WARN -Category 'Security'
    }
    $metrics.Sha256 = $sha

    if ($FileItem.IsExecutable) {
        $sigStatus = 'Unknown'
        try {
            $sig = Get-AuthenticodeSignature -FilePath $FileItem.FullPath -ErrorAction Stop
            $sigStatus = $sig.Status.ToString()
        }
        catch {
            $sigStatus = 'SignatureCheckError'
        }

        $risk = if ($sigStatus -eq 'Valid') { 'Medium' } else { 'High' }
        $details = "Ausführbare Datei ($($FileItem.Extension)), Signaturstatus: $sigStatus"
        $recommendation = if ($sigStatus -eq 'Valid') {
            "Signatur regelmäßig überprüfen und Quelle verifizieren."
        }
        else {
            "Signatur prüfen und Nutzung der Datei kritisch hinterfragen; ggf. entfernen oder ersetzen."
        }

        $cmd = "# Beispiel (Dry-Run): Datei für weitere Analyse verschieben`n# Move-Item -LiteralPath '{0}' -Destination '\\\\fileserver\\Quarantine' -WhatIf" -f $FileItem.FullPath

        $securityFindings += [pscustomobject]@{
            FileId        = $FileItem.Id
            FullPath      = $FileItem.FullPath
            Extension     = $FileItem.Extension
            IssueType     = 'ExecutableFile'
            RiskLevel     = $risk
            Details       = $details
            Sha256        = $sha
            SignatureStatus = $sigStatus
            Recommendation = $recommendation
            RecommendationCommand = $cmd
        }
    }

    if ($FileItem.Extension -in @('.py', '.rb', '.pl', '.jar')) {
        $securityFindings += [pscustomobject]@{
            FileId        = $FileItem.Id
            FullPath      = $FileItem.FullPath
            Extension     = $FileItem.Extension
            IssueType     = 'UnexpectedFileType'
            RiskLevel     = 'Medium'
            Details       = "Unerwarteter Dateityp im SYSVOL-Scripts-Verzeichnis ($($FileItem.Extension))."
            Sha256        = $sha
            SignatureStatus = $null
            Recommendation = "Prüfen, ob dieser Dateityp im SYSVOL notwendig ist; ggf. in gesonderte Verteilmechanismen auslagern."
            RecommendationCommand = "# Keine direkte Aktion vorgeschlagen (Review erforderlich)."
        }
    }

    if ($null -ne $content) {
        $lines = $content -split "`n"
        $metrics.LocTotal = $lines.Count

        # Klartext-Credentials: EN, DE, ES, PT, SV, ZH, IT
        $passwordRegex = '(?i)(\b(pass(word)?|pwd|passwort|kennwort|contraseña|clave|senha|palavra[- ]?passe|lösenord|lösen|passwd|parola)\s*[=:]|密码\s*[=:]|口令\s*[=:])'
        $downloadRegex = '(?i)(Invoke-WebRequest|Invoke-RestMethod|wget\s|curl\s|\.DownloadFile\()'
        $execBypassRegex = '(?i)(-ExecutionPolicy\s+Bypass|powershell\.exe.*-ep\s+Bypass|powershell\.exe.*-ExecutionPolicy\s+Bypass)'
        $base64Regex = '(?i)(-EncodedCommand\s+[A-Za-z0-9\+\/=]{20,})'
        # ConnectionString-ähnliche User/Password-Paare (mehrsprachig)
        $hardcodedCredRegex = '(?i)(User\s*[=:]\s*.+[;].*[Pp]assword\s*[=:]|uid\s*[=:].+[;].*pwd\s*[=:]|Benutzer\s*[=:].+[;].*Passwort\s*[=:]|usuario\s*[=:].+[;].*contraseña\s*[=:]|usu[aá]rio\s*[=:].+[;].*senha\s*[=:]|anv[aä]ndare\s*[=:].+[;].*l[oö]senord\s*[=:]|用户\s*[=:].+[;].*密码\s*[=:]|utente\s*[=:].+[;].*(?:password|parola)\s*[=:])'
        $deprecatedCmdRegex = '(?i)\bnet\s+use\b'

        $controlRegex = '(?i)\b(if|elseif|switch|for|foreach|while|do|catch|case)\b'

        $commentPrefix = switch ($FileItem.Extension) {
            '.ps1' { '#' }
            '.psm1' { '#' }
            '.psd1' { '#' }
            '.bat' { 'REM' }
            '.cmd' { 'REM' }
            '.vbs' { "'" }
            '.kix' { ';' }
            default { $null }
        }

        $complexity = 1
        $commentLines = 0

        foreach ($line in $lines) {
            $trim = $line.Trim()

            if ($commentPrefix) {
                if ($FileItem.Extension -in '.bat', '.cmd') {
                    if ($trim -like 'REM *' -or $trim -like ':: *') {
                        $commentLines++
                        continue
                    }
                }
                elseif ($trim.StartsWith($commentPrefix)) {
                    $commentLines++
                    continue
                }
            }

            if ($trim -match $controlRegex) {
                $complexity++
            }

            if (-not $metrics.HasErrorHandling) {
                if ($FileItem.Extension -in '.ps1', '.psm1') {
                    if ($trim -match '(?i)\btry\b' -or $trim -match '(?i)\bcatch\b') {
                        $metrics.HasErrorHandling = $true
                    }
                }
                elseif ($FileItem.Extension -eq '.vbs') {
                    if ($trim -match '(?i)On\s+Error\s+Resume\s+Next' -or $trim -match '(?i)On\s+Error\s+Goto') {
                        $metrics.HasErrorHandling = $true
                    }
                }
            }

            if (-not $metrics.HasDeprecatedCmds -and $trim -match $deprecatedCmdRegex) {
                $metrics.HasDeprecatedCmds = $true
            }

            if (-not $metrics.HasHardcodedCreds -and ($trim -match $passwordRegex -or $trim -match $hardcodedCredRegex)) {
                $metrics.HasHardcodedCreds = $true
            }

            if ($trim -match $passwordRegex) {
                $securityFindings += [pscustomobject]@{
                    FileId        = $FileItem.Id
                    FullPath      = $FileItem.FullPath
                    Extension     = $FileItem.Extension
                    IssueType     = 'CleartextPasswordPattern'
                    RiskLevel     = 'High'
                    Details       = "Mögliches Klartext-Passwort-Muster in einer Zeile."
                    Sha256        = $sha
                    SignatureStatus = $null
                    Recommendation = "Anmeldeinformationen in gesicherte Speicher (z.B. Credential Store, Secret Management) auslagern."
                    RecommendationCommand = "# Beispiel: Verwendung von Get-Credential / SecretManagement anstelle von Klartext."
                }
            }
            if ($trim -match $downloadRegex) {
                $securityFindings += [pscustomobject]@{
                    FileId        = $FileItem.Id
                    FullPath      = $FileItem.FullPath
                    Extension     = $FileItem.Extension
                    IssueType     = 'DownloadCommand'
                    RiskLevel     = 'Medium'
                    Details       = "Download- oder Webzugriffsbefehl gefunden."
                    Sha256        = $sha
                    SignatureStatus = $null
                    Recommendation = "Download-Quellen validieren und Skript gegen Missbrauch (z.B. Manipulation von URLs) absichern."
                    RecommendationCommand = "# Beispiel: Eingaben validieren, HTTPS erzwingen, Signaturen prüfen."
                }
            }
            if ($trim -match $execBypassRegex) {
                $securityFindings += [pscustomobject]@{
                    FileId        = $FileItem.Id
                    FullPath      = $FileItem.FullPath
                    Extension     = $FileItem.Extension
                    IssueType     = 'ExecutionPolicyBypass'
                    RiskLevel     = 'High'
                    Details       = "Execution-Policy-Bypass erkannt."
                    Sha256        = $sha
                    SignatureStatus = $null
                    Recommendation = "Einsatz von -ExecutionPolicy Bypass kritisch prüfen; wenn möglich entfernen oder auf signierte Skripte umstellen."
                    RecommendationCommand = "# Beispiel: Entfernen des -ExecutionPolicy Bypass Parameters und Signierungspfad etablieren."
                }
            }
            if ($trim -match $base64Regex) {
                $securityFindings += [pscustomobject]@{
                    FileId        = $FileItem.Id
                    FullPath      = $FileItem.FullPath
                    Extension     = $FileItem.Extension
                    IssueType     = 'Base64EncodedCommand'
                    RiskLevel     = 'High'
                    Details       = "Base64-codierter PowerShell-Befehl erkannt."
                    Sha256        = $sha
                    SignatureStatus = $null
                    Recommendation = "Inhalt des Base64-Kommandos prüfen und nach Möglichkeit im Klartext dokumentiert ablegen."
                    RecommendationCommand = "# Beispiel: Decode des Base64-Strings mit [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('...'))."
                }
            }
        }

        $metrics.LocComments = $commentLines
        $metrics.CyclomaticComplexity = $complexity

        $normalizedContent = ($lines | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') }) -join "`n"
        if ($normalizedContent) {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($normalizedContent)
            $ms = New-Object System.IO.MemoryStream(,$bytes)
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            $hashBytes = $sha256.ComputeHash($ms)
            $metrics.NormalizedContentHash = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '')
            $ms.Dispose()
            $sha256.Dispose()
        }

        if ($FileItem.IsScript) {
            $dir = $FileItem.Directory

            if ($FileItem.Extension -in '.ps1', '.psm1') {
                $psDepRegexes = @(
                    '(?i)(?:^|\s)&\s*["'']?(.+?\.(ps1|psm1|bat|cmd|vbs|kix))["'']?',
                    '(?i)(?:^|\s)\.\s*["'']?(.+?\.(ps1|psm1))["'']?',
                    '(?i)powershell\.exe.+?\s(["'']?(.+?\.(ps1|psm1))["'']?)'
                )
                foreach ($rx in $psDepRegexes) {
                    $matches = [regex]::Matches($content, $rx)
                    foreach ($m in $matches) {
                        $rawTarget = $m.Groups[1].Value
                        if (-not $rawTarget) { continue }
                        $rawTarget = $rawTarget.Trim('"', "'")
                        $resolved = $null
                        if ($rawTarget -like '\\*' -or $rawTarget -match '^[A-Za-z]:\\') {
                            $resolved = $rawTarget
                        }
                        else {
                            try {
                                $candidate = Join-Path -Path $dir -ChildPath $rawTarget
                                $resolvedPath = Resolve-Path -Path $candidate -ErrorAction SilentlyContinue
                                if ($resolvedPath) {
                                    $resolved = $resolvedPath.Path
                                }
                            }
                            catch { }
                        }

                        $dependencies += [pscustomobject]@{
                            SourcePath = $FileItem.FullPath
                            TargetPath = $resolved
                            TargetRaw  = $rawTarget
                            Depth      = 1
                            IsCycle    = $false
                        }
                    }
                }
            }
            elseif ($FileItem.Extension -eq '.vbs') {
                $vbsRegexes = @(
                    'WScript\.Shell\.Run\s*\(\s*["''](.+?)["'']',
                    '(?i)\bExecute(Global)?\s+["''](.+?\.vbs)["'']'
                )
                foreach ($rx in $vbsRegexes) {
                    $matches = [regex]::Matches($content, $rx)
                    foreach ($m in $matches) {
                        $rawTarget = $m.Groups[$m.Groups.Count - 1].Value
                        if (-not $rawTarget) { continue }
                        $rawTarget = $rawTarget.Trim('"', "'")
                        $resolved = $null
                        if ($rawTarget -like '\\*' -or $rawTarget -match '^[A-Za-z]:\\') {
                            $resolved = $rawTarget
                        }
                        else {
                            try {
                                $candidate = Join-Path -Path $dir -ChildPath $rawTarget
                                $resolvedPath = Resolve-Path -Path $candidate -ErrorAction SilentlyContinue
                                if ($resolvedPath) {
                                    $resolved = $resolvedPath.Path
                                }
                            }
                            catch { }
                        }

                        $dependencies += [pscustomobject]@{
                            SourcePath = $FileItem.FullPath
                            TargetPath = $resolved
                            TargetRaw  = $rawTarget
                            Depth      = 1
                            IsCycle    = $false
                        }
                    }
                }
            }
            elseif ($FileItem.Extension -in '.bat', '.cmd') {
                $batchLines = $content -split "`n"
                foreach ($l in $batchLines) {
                    $t = $l.Trim()
                    if ($t -match '^(?i)\s*(call|start|cmd\s+/c)\s+(.+)$') {
                        $cmd = $matches[2].Trim()
                        $targetToken = $cmd.Split(' ')[0]
                        $rawTarget = $targetToken
                        $resolved = $null

                        if ($rawTarget -notmatch '\.') {
                            foreach ($ext in @('.bat', '.cmd', '.ps1', '.vbs')) {
                                $candidate = Join-Path -Path $dir -ChildPath ($rawTarget + $ext)
                                if (Test-Path -Path $candidate) {
                                    $resolved = (Resolve-Path -Path $candidate -ErrorAction SilentlyContinue).Path
                                    break
                                }
                            }
                        }
                        else {
                            if ($rawTarget -like '\\*' -or $rawTarget -match '^[A-Za-z]:\\') {
                                $resolved = $rawTarget
                            }
                            else {
                                $candidate = Join-Path -Path $dir -ChildPath $rawTarget
                                $resolved = (Resolve-Path -Path $candidate -ErrorAction SilentlyContinue).Path
                            }
                        }

                        $dependencies += [pscustomobject]@{
                            SourcePath = $FileItem.FullPath
                            TargetPath = $resolved
                            TargetRaw  = $rawTarget
                            Depth      = 1
                            IsCycle    = $false
                        }
                    }
                }
            }
            elseif ($FileItem.Extension -eq '.kix') {
                $kixLines = $content -split "`n"
                foreach ($l in $kixLines) {
                    $t = $l.Trim()
                    if ($t -match '^(?i)\s*(CALL|RUN|SHELL)\s+(.+)$') {
                        $rawTarget = $matches[2].Trim().Split(' ')[0]
                        $resolved = $null
                        if ($rawTarget -like '\\*' -or $rawTarget -match '^[A-Za-z]:\\') {
                            $resolved = $rawTarget
                        }
                        else {
                            $candidate = Join-Path -Path $dir -ChildPath $rawTarget
                            $resolved = (Resolve-Path -Path $candidate -ErrorAction SilentlyContinue).Path
                        }
                        $dependencies += [pscustomobject]@{
                            SourcePath = $FileItem.FullPath
                            TargetPath = $resolved
                            TargetRaw  = $rawTarget
                            Depth      = 1
                            IsCycle    = $false
                        }
                    }
                }
            }
        }
    }

    return [pscustomobject]@{
        SecurityFindings = $securityFindings
        Metrics          = $metrics
        Dependencies     = $dependencies
    }
}

function Build-DependencyGraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject[]]$Edges
    )

    $nodes = @{}
    foreach ($e in $Edges) {
        if ($e.SourcePath -and -not $nodes.ContainsKey($e.SourcePath)) {
            $nodes[$e.SourcePath] = [pscustomobject]@{
                Id        = [guid]::NewGuid().ToString()
                FullPath  = $e.SourcePath
                InDegree  = 0
                OutDegree = 0
            }
        }
        if ($e.TargetPath -and -not $nodes.ContainsKey($e.TargetPath)) {
            $nodes[$e.TargetPath] = [pscustomobject]@{
                Id        = [guid]::NewGuid().ToString()
                FullPath  = $e.TargetPath
                InDegree  = 0
                OutDegree = 0
            }
        }
    }

    $adjacency = @{}
    foreach ($key in $nodes.Keys) {
        $adjacency[$key] = New-Object System.Collections.Generic.List[string]
    }

    foreach ($e in $Edges) {
        if ($e.SourcePath -and $e.TargetPath) {
            $adjacency[$e.SourcePath].Add($e.TargetPath)
            $nodes[$e.SourcePath].OutDegree++
            $nodes[$e.TargetPath].InDegree++
        }
    }

    $cycleEdges = New-Object System.Collections.Generic.HashSet[string]

    foreach ($nodeKey in $nodes.Keys) {
        $stack = New-Object System.Collections.Generic.Stack[string]
        $visited = New-Object System.Collections.Generic.HashSet[string]

        $stack.Push($nodeKey)
        while ($stack.Count -gt 0) {
            $current = $stack.Pop()
            if (-not $visited.Add($current)) {
                continue
            }

            $neighbors = $adjacency[$current]
            foreach ($n in $neighbors) {
                $edgeId = "$current`n$n"
                if ($visited.Contains($n)) {
                    [void]$cycleEdges.Add($edgeId)
                }
                else {
                    if ($stack.Count -lt 5) {
                        $stack.Push($n)
                    }
                }
            }
        }
    }

    foreach ($e in $Edges) {
        $edgeId = "$($e.SourcePath)`n$($e.TargetPath)"
        if ($cycleEdges.Contains($edgeId)) {
            $e.IsCycle = $true
        }
    }

    $nodeList = $nodes.Values

    $entryPoints = $nodeList | Where-Object { $_.InDegree -eq 0 }
    $leafNodes   = $nodeList | Where-Object { $_.OutDegree -eq 0 }

    $graph = [pscustomobject]@{
        Nodes       = $nodeList
        Edges       = $Edges
        EntryPoints = $entryPoints
        LeafNodes   = $leafNodes
    }

    return $graph
}

function Get-RiskSummary {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$SecurityFindings
    )

    # Defensive: force into array and handle $null
    $sf = @($SecurityFindings) | Where-Object { $_ -ne $null }

    $levels = @('Critical', 'High', 'Medium', 'Low')
    $summary = [ordered]@{}
    foreach ($lvl in $levels) {
        $summary[$lvl] = ($sf | Where-Object { $_.RiskLevel -eq $lvl } | Measure-Object).Count
    }
    return [pscustomobject]$summary
}

function Export-JsonReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$State,

        [Parameter(Mandatory = $true)]
        [string]$JsonPath
    )

    try {
        $file = Join-Path -Path $JsonPath -ChildPath 'analysis_results.json'
        $State | ConvertTo-Json -Depth 8 | Set-Content -Path $file -Encoding UTF8
        Write-Log -Message "JSON-Report geschrieben nach $file" -Category 'Export'
    }
    catch {
        Write-Log -Message "Fehler beim Schreiben des JSON-Reports: $($_.Exception.Message)" -Level ERROR -Category 'Export'
    }
}

function Export-CsvReports {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$State,

        [Parameter(Mandatory = $true)]
        [string]$CsvPath
    )

    try {
        $fileSecurity = Join-Path -Path $CsvPath -ChildPath 'security_findings.csv'
        $State.SecurityFindings | Export-Csv -Path $fileSecurity -NoTypeInformation -Encoding UTF8

        $fileDeps = Join-Path -Path $CsvPath -ChildPath 'dependencies.csv'
        $State.DependencyGraph.Edges | Export-Csv -Path $fileDeps -NoTypeInformation -Encoding UTF8

        $fileUsage = Join-Path -Path $CsvPath -ChildPath 'usage_analysis.csv'
        $State.Inventory | Select-Object *, UsageCategory, UsageSources | Export-Csv -Path $fileUsage -NoTypeInformation -Encoding UTF8

        $fileDup = Join-Path -Path $CsvPath -ChildPath 'duplicates.csv'
        $State.DuplicateGroups | Export-Csv -Path $fileDup -NoTypeInformation -Encoding UTF8

        $fileCode = Join-Path -Path $CsvPath -ChildPath 'code_quality.csv'
        $State.FileMetrics | Export-Csv -Path $fileCode -NoTypeInformation -Encoding UTF8

        Write-Log -Message "CSV-Reports geschrieben nach $CsvPath" -Category 'Export'
    }
    catch {
        Write-Log -Message "Fehler beim Schreiben der CSV-Reports: $($_.Exception.Message)" -Level ERROR -Category 'Export'
    }
}

function Export-ExcelReports {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$State,

        [Parameter(Mandatory = $true)]
        [string]$ExcelPath
    )

    if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
        Write-Log -Message "ImportExcel nicht verfügbar, Excel-Export wird übersprungen." -Level WARN -Category 'Export'
        return
    }

    try {
        Import-Module ImportExcel -ErrorAction Stop
        $file = Join-Path -Path $ExcelPath -ChildPath 'sysvol_analysis.xlsx'

        $State.SecurityFindings | Export-Excel -Path $file -WorksheetName 'Security' -AutoSize -AutoFilter -FreezeTopRow -BoldTopRow
        $State.DependencyGraph.Edges | Export-Excel -Path $file -WorksheetName 'Dependencies' -AutoSize -AutoFilter -FreezeTopRow -BoldTopRow
        $State.Inventory | Select-Object *, UsageCategory, UsageSources | Export-Excel -Path $file -WorksheetName 'Usage' -AutoSize -AutoFilter -FreezeTopRow -BoldTopRow
        $State.DuplicateGroups | Export-Excel -Path $file -WorksheetName 'Duplicates' -AutoSize -AutoFilter -FreezeTopRow -BoldTopRow
        $State.FileMetrics | Export-Excel -Path $file -WorksheetName 'CodeQuality' -AutoSize -AutoFilter -FreezeTopRow -BoldTopRow

        Write-Log -Message "Excel-Report geschrieben nach $file" -Category 'Export'
    }
    catch {
        Write-Log -Message "Fehler beim Schreiben des Excel-Reports: $($_.Exception.Message)" -Level ERROR -Category 'Export'
    }
}

function Export-HtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$State,

        [Parameter(Mandatory = $true)]
        [string]$HtmlPath
    )

    $file = Join-Path -Path $HtmlPath -ChildPath 'sysvol_analysis_report.html'
    $totalFiles = $State.Inventory.Count
    $securitySummary = Get-RiskSummary -SecurityFindings $State.SecurityFindings
    $criticalExamples = $State.SecurityFindings | Where-Object { $_.RiskLevel -in 'Critical','High' } | Select-Object -First 5

    $entryCount = if ($State.DependencyGraph -and $State.DependencyGraph.EntryPoints) { $State.DependencyGraph.EntryPoints.Count } else { 0 }
    $leafCount  = if ($State.DependencyGraph -and $State.DependencyGraph.LeafNodes) { $State.DependencyGraph.LeafNodes.Count } else { 0 }

    $html = @"
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="utf-8" />
    <title>SYSVOL Scripts Analyse Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; padding: 0; background-color: #f4f5f7; color: #222; }
        header { background-color: #1f2933; color: white; padding: 20px 40px; }
        h1 { margin: 0; font-size: 26px; }
        h2 { margin-top: 30px; font-size: 20px; }
        h3 { margin-top: 20px; font-size: 16px; }
        .container { padding: 20px 40px 40px 40px; }
        .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-top: 20px; }
        .kpi { background: white; border-radius: 6px; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .kpi-title { font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: #6c7a89; }
        .kpi-value { font-size: 22px; margin-top: 6px; }
        .kpi-sub { font-size: 12px; color: #6c7a89; margin-top: 4px; }
        .badge { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 11px; text-transform: uppercase; }
        .badge-critical { background-color: #c53030; color: white; }
        .badge-high { background-color: #dd6b20; color: white; }
        .badge-medium { background-color: #d69e2e; color: white; }
        .badge-low { background-color: #38a169; color: white; }
        .section { margin-top: 32px; }
        details { background: white; border-radius: 6px; padding: 12px 16px; margin-bottom: 10px; box-shadow: 0 1px 2px rgba(0,0,0,0.06); }
        summary { cursor: pointer; font-weight: 600; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
        th, td { padding: 6px 8px; border-bottom: 1px solid #e1e4e8; text-align: left; }
        th { background-color: #f9fafb; font-weight: 600; }
        tr:nth-child(even) { background-color: #fdfdfd; }
        code { font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 12px; background: #f1f1f1; padding: 2px 4px; border-radius: 3px; }
        .graph { background: white; border-radius: 6px; padding: 10px 12px; box-shadow: 0 1px 2px rgba(0,0,0,0.06); font-size: 12px; }
        .footer { margin-top: 40px; font-size: 11px; color: #6c7a89; }
    </style>
</head>
<body>
    <header>
        <h1>SYSVOL Scripts Analyse Report</h1>
        <div>RunId: $($State.RunId) &bull; Erstellt: $((Get-Date).ToString("yyyy-MM-dd HH:mm"))</div>
    </header>
    <div class="container">
        <section class="section">
            <h2>Executive Summary</h2>
            <div class="kpi-grid">
                <div class="kpi">
                    <div class="kpi-title">Analysierte Dateien</div>
                    <div class="kpi-value">$totalFiles</div>
                    <div class="kpi-sub">$($State.ScriptsPath)</div>
                </div>
                <div class="kpi">
                    <div class="kpi-title">Sicherheitsrisiken</div>
                    <div class="kpi-value">
                        <span class="badge badge-critical">Critical $($securitySummary.Critical)</span>
                        <span class="badge badge-high">High $($securitySummary.High)</span>
                    </div>
                    <div class="kpi-sub">Medium $($securitySummary.Medium) &bull; Low $($securitySummary.Low)</div>
                </div>
                <div class="kpi">
                    <div class="kpi-title">Dependency-Graph</div>
                    <div class="kpi-value">$entryCount Entry-Points</div>
                    <div class="kpi-sub">$leafCount Leaf-Skripte (keine weiteren Aufrufe)</div>
                </div>
                <div class="kpi">
                    <div class="kpi-title">Empfohlene Sofortmaßnahmen</div>
                    <div class="kpi-value">Top 5 kritische Findings</div>
                    <div class="kpi-sub">Details siehe unten</div>
                </div>
            </div>
        </section>

        <section class="section">
            <h2>Top 5 kritische / hohe Sicherheitsrisiken</h2>
            <table>
                <thead>
                    <tr>
                        <th>Datei</th>
                        <th>Issue</th>
                        <th>Risiko</th>
                        <th>Empfehlung</th>
                    </tr>
                </thead>
                <tbody>
"@

    foreach ($f in $criticalExamples) {
        $html += @"
                    <tr>
                        <td><code>$($f.FullPath)</code></td>
                        <td>$($f.IssueType)</td>
                        <td>$($f.RiskLevel)</td>
                        <td>$($f.Recommendation)</td>
                    </tr>
"@
    }

    $html += @"
                </tbody>
            </table>
        </section>

        <section class="section">
            <h2>Detaillierte Bereiche</h2>

            <details open>
                <summary>Sicherheitsanalyse</summary>
                <p>Alle erkannten Sicherheitsrisiken mit Risikostufe, Hashes, Signaturstatus und Handlungsempfehlungen.</p>
                <p>Details siehe <code>security_findings.csv</code> und JSON-Report.</p>
            </details>

            <details>
                <summary>Dependency-Graph</summary>
                <p>Interaktive Übersicht der Aufrufbeziehungen zwischen Skripten (vereinfachte Darstellung).</p>
                <div class="graph" id="dependencyGraph">
                </div>
            </details>

            <details>
                <summary>Nutzungsanalyse &amp; Verwaiste Skripte</summary>
                <p>Kategorisierung der Skripte: aktiv verwendet, wahrscheinlich aktiv, vermutlich ungenutzt, verwaist.</p>
                <p>Details siehe <code>usage_analysis.csv</code>.</p>
            </details>

            <details>
                <summary>Duplikate &amp; Konsolidierung</summary>
                <p>Gruppen identischer oder nahezu identischer Skripte mit Vorschlag, welche Kopie beibehalten werden soll.</p>
                <p>Details siehe <code>duplicates.csv</code>.</p>
            </details>

            <details>
                <summary>Codequalität &amp; Modernisierung</summary>
                <p>Metriken zu Dateigröße, LOC, Kommentarquote, Komplexität und Legacy-Befehlen.</p>
                <p>Details siehe <code>code_quality.csv</code>.</p>
            </details>
        </section>

        <div class="footer">
            Dieser Report wurde automatisch durch das SYSVOL Scripts Analyse Tool generiert.
        </div>
    </div>

    <script>
        (function() {
            var graphContainer = document.getElementById("dependencyGraph");
            if (!graphContainer) return;

            var edges = "@($State.DependencyGraph.Edges.Count) Kanten, @($State.DependencyGraph.Nodes.Count) Knoten";
            var entryPoints = "@($entryCount) Entry-Points";
            var leafs = "@($leafCount) Leaf-Skripte";

            graphContainer.innerHTML = ""
                + "<strong>Übersicht</strong><br/>"
                + edges + "<br/>"
                + entryPoints + "<br/>"
                + leafs + "<br/><br/>"
                + "Für tiefergehende Visualisierung kann die JSON-Datei <code>analysis_results.json</code> in externe Werkzeuge (z.B. D3.js, Mermaid) importiert werden.";
        })();
    </script>
</body>
</html>
"@

    try {
        $html | Set-Content -Path $file -Encoding UTF8
        Write-Log -Message "HTML-Report geschrieben nach $file" -Category 'Export'
    }
    catch {
        Write-Log -Message "Fehler beim Schreiben des HTML-Reports: $($_.Exception.Message)" -Level ERROR -Category 'Export'
    }
}

function Show-ConsoleSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$State
    )

    $secSummary = Get-RiskSummary -SecurityFindings ($State.SecurityFindings ?? @())
    $inv = @($State.Inventory ?? @())
    $total = $inv.Count
    $orphans = ($inv | Where-Object { $_.UsageCategory -eq 'Verwaist' }).Count

    Write-Host ""
    Write-Host "===== SYSVOL Scripts Analyse - Zusammenfassung =====" -ForegroundColor Cyan
    Write-Host "Pfad: $($State.ScriptsPath)"
    Write-Host "Analysierte Dateien: $total"
    Write-Host ""
    Write-Host "Sicherheitsrisiken:" -ForegroundColor White
    Write-Host ("  Critical: {0}" -f $secSummary.Critical) -ForegroundColor Red
    Write-Host ("  High    : {0}" -f $secSummary.High) -ForegroundColor DarkRed
    Write-Host ("  Medium  : {0}" -f $secSummary.Medium) -ForegroundColor Yellow
    Write-Host ("  Low     : {0}" -f $secSummary.Low) -ForegroundColor Green
    Write-Host ""
    Write-Host ("Verwaiste Skripte: {0}" -f $orphans) -ForegroundColor Yellow
    Write-Host ""
}

function Show-InteractiveMenu {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$State
    )

    while ($true) {
        Write-Host ""
        Write-Host "[1] Sicherheitsrisiken anzeigen"
        Write-Host "[2] Dependency-Graph exportieren (JSON bereits erstellt)"
        Write-Host "[3] Unbenutzte/verwaiste Skripte auflisten"
        Write-Host "[4] Duplikate anzeigen"
        Write-Host "[5] Vollständigen Report-Ordner öffnen"
        Write-Host "[Q] Beenden"
        Write-Host ""
        $rawInput = try { Read-Host "Auswahl" } catch { '' }
        $choice = ($rawInput ?? '').ToString().Trim().ToUpperInvariant()

        switch ($choice) {
            '1' {
                try {
                    $findings = @($State.SecurityFindings ?? @())
                    if ($findings.Count -eq 0) {
                        Write-Host "Keine Sicherheitsfindings vorhanden." -ForegroundColor Gray
                    }
                    else {
                        $riskOrder = @{ Critical = 4; High = 3; Medium = 2; Low = 1 }
                        $findings |
                            Sort-Object { ($riskOrder[$_.RiskLevel] ?? 0) } -Descending |
                            Select-Object -First 50 FullPath, IssueType, RiskLevel, Recommendation |
                            Format-Table -AutoSize
                    }
                }
                catch {
                    Write-Host "Fehler beim Anzeigen: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            '2' {
                Write-Host "Dependency-Graph ist in JSON verfügbar (analysis_results.json). Für Visualisierung bitte externes Tool verwenden." -ForegroundColor Cyan
            }
            '3' {
                try {
                    $inv = @($State.Inventory ?? @())
                    $orphans = $inv | Where-Object { $_.UsageCategory -eq 'Verwaist' }
                    if ($orphans.Count -eq 0) {
                        Write-Host "Keine verwaisten Skripte." -ForegroundColor Gray
                    }
                    else {
                        $orphans | Select-Object -First 50 FullPath, LastWriteTimeUtc, LastAccessTimeUtc |
                            Format-Table -AutoSize
                    }
                    Write-Host ("Insgesamt verwaist: {0}" -f $orphans.Count) -ForegroundColor Yellow
                }
                catch {
                    Write-Host "Fehler beim Anzeigen: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            '4' {
                try {
                    $dups = @($State.DuplicateGroups ?? @())
                    if ($dups.Count -eq 0) {
                        Write-Host "Keine Duplikatgruppen." -ForegroundColor Gray
                    }
                    else {
                        $dups | Select-Object -First 50 GroupId, RepresentativePath, DuplicateCount, RecommendedKeep |
                            Format-Table -AutoSize
                    }
                }
                catch {
                    Write-Host "Fehler beim Anzeigen: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            '5' {
                $out = $State.OutputPath
                if (-not $out) {
                    Write-Host "OutputPath nicht gesetzt." -ForegroundColor Yellow
                    break
                }
                Write-Host "Report-Ordner: $out" -ForegroundColor Cyan
                try {
                    if ($IsWindows) {
                        Start-Process explorer.exe -ArgumentList $out
                    }
                    else {
                        Start-Process $out
                    }
                }
                catch {
                    Write-Host "Konnte Ordner nicht öffnen: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
            'Q' { return }
            '' {
                Write-Host "Bitte 1–5 oder Q eingeben." -ForegroundColor Yellow
            }
            default {
                Write-Host "Ungültige Auswahl. Bitte 1–5 oder Q eingeben." -ForegroundColor Yellow
            }
        }
    }
}

# endregion Hilfsfunktionen

# region Hauptlogik

try {
    if ($PromptForCredential -and -not $Credential) {
        $Credential = Get-Credential -Message 'Anmeldeinformationen für AD-/GPO-/SYSVOL-Analyse (optional)'
    }

    $envInfo = Initialize-Environment -ScriptsPath $ScriptsPath -OutputPath $OutputPath -Credential $Credential

    $checkpointData = $null
    if ($Resume) {
        $checkpointData = Read-Checkpoint -CheckpointPath $script:CheckpointPath
        if ($checkpointData) {
            Write-Log -Message "Resume aktiviert, Checkpoint wird übernommen." -Category 'Main'
            $script:AnalysisState = @{}
            foreach ($p in $checkpointData.PSObject.Properties) {
                $script:AnalysisState[$p.Name] = $p.Value
            }
        }
        else {
            Write-Log -Message "Resume angefordert, aber kein gültiger Checkpoint gefunden. Starte Neu-Analyse." -Level WARN -Category 'Main'
        }
    }

    if (-not $script:AnalysisState.Phases.InventoryCompleted) {
        $inventory = Get-SysvolInventory -RootPath $envInfo.ScriptsPath
        $script:AnalysisState.Inventory = $inventory
        $script:AnalysisState.Phases.InventoryCompleted = $true
        Write-Checkpoint -State $script:AnalysisState -CheckpointPath $script:CheckpointPath
    }
    else {
        $inventory = $script:AnalysisState.Inventory
        Write-Log -Message "Inventar aus Checkpoint übernommen, Dateien: $($inventory.Count)" -Category 'Main'
    }

    if (-not $script:AnalysisState.Phases.UsageAnalysisCompleted) {
        $usageRaw = Get-UsageFromGpoAndAd -ScriptsRoot $envInfo.ScriptsPath -AdModuleAvailable $envInfo.AdModuleAvailable -GpModuleAvailable $envInfo.GpModuleAvailable -Credential $Credential
        $script:AnalysisState.UsageMap = $usageRaw

        $usageLookup = @{}
        foreach ($u in $usageRaw) {
            if (-not $u.ScriptFullPath) { continue }
            if (-not $usageLookup.ContainsKey($u.ScriptFullPath)) {
                $usageLookup[$u.ScriptFullPath] = New-Object System.Collections.Generic.List[object]
            }
            $usageLookup[$u.ScriptFullPath].Add($u)
        }

        foreach ($item in $inventory) {
            $category = 'Verwaist'
            $sources = @()

            if ($usageLookup.ContainsKey($item.FullPath)) {
                $category = 'Aktiv verwendet'
                $sources = $usageLookup[$item.FullPath]
            }
            else {
                $now = (Get-Date).ToUniversalTime()
                $lastAccess = $item.LastAccessTimeUtc
                $lastWrite  = $item.LastWriteTimeUtc
                $recentDate = if ($lastAccess -gt $lastWrite) { $lastAccess } else { $lastWrite }

                if ($recentDate -gt $now.AddMonths(-6)) {
                    $category = 'Wahrscheinlich aktiv'
                }
                elseif ($recentDate -lt $now.AddYears(-2)) {
                    $category = 'Vermutlich ungenutzt'
                }
            }

            $item | Add-Member -NotePropertyName 'UsageCategory' -NotePropertyValue $category -Force
            $item | Add-Member -NotePropertyName 'UsageSources' -NotePropertyValue $sources -Force
        }

        $script:AnalysisState.Inventory = $inventory
        $script:AnalysisState.Phases.UsageAnalysisCompleted = $true
        Write-Checkpoint -State $script:AnalysisState -CheckpointPath $script:CheckpointPath
    }
    else {
        Write-Log -Message "Nutzungsanalyse aus Checkpoint übernommen." -Category 'Main'
    }

    if (-not $script:AnalysisState.Phases.ContentAnalysisCompleted) {
        $securityFindingsAll = @()
        $metricsAll = @()
        $depsAll = @()

        $processed = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($p in $script:AnalysisState.ProcessedFiles) {
            [void]$processed.Add($p)
        }

        $pending = $inventory | Where-Object { -not $processed.Contains($_.FullPath) }
        # Erzeuge temporäres Modul mit Funktionen, die in Parallel-Runspaces benötigt werden.
        $helperFunctions = @('Write-Log', 'Get-FileContentSafe', 'Get-SecurityAndMetricsForFile')
        $tempDir = $env:TEMP ?? $env:TMPDIR ?? [System.IO.Path]::GetTempPath()
        $tempModulePath = Join-Path -Path $tempDir -ChildPath ("vaLogon_helpers_{0}.psm1" -f ([guid]::NewGuid().ToString()))
        $moduleText = ''
        foreach ($fn in $helperFunctions) {
            $cmd = Get-Command $fn -CommandType Function -ErrorAction SilentlyContinue
            if (-not $cmd) {
                throw "Funktion '$fn' nicht gefunden. Stelle sicher, dass sie im Skript definiert ist."
            }
            $sbText = $cmd.ScriptBlock.ToString()
            $moduleText += "function $fn {`n$sbText`n}`n`n"
        }
        $moduleText += "Export-ModuleMember -Function " + ($helperFunctions -join ',')
        Set-Content -Path $tempModulePath -Value $moduleText -Force -Encoding UTF8
        $totalCount = $pending.Count
        $batchSize = 500
        $index = 0
        $overallProcessed = $processed.Count
        $swOverall = [System.Diagnostics.Stopwatch]::StartNew()

        while ($index -lt $totalCount) {
            $batch = $pending[$index..([Math]::Min($index + $batchSize - 1, $totalCount - 1))]
            $batchCount = $batch.Count

            $swBatch = [System.Diagnostics.Stopwatch]::StartNew()
            $results = $batch | ForEach-Object -Parallel {
                Import-Module $using:tempModulePath -Force
                $fileItem = $_
                return Get-SecurityAndMetricsForFile -FileItem $fileItem -ScriptsRoot $using:envInfo.ScriptsPath
            } -ThrottleLimit $ParallelThreads

            foreach ($r in $results) {
                $securityFindingsAll += $r.SecurityFindings
                $metricsAll += $r.Metrics
                $depsAll += $r.Dependencies
            }

            foreach ($b in $batch) {
                [void]$processed.Add($b.FullPath)
            }

            $overallProcessed = $processed.Count
            $index += $batchCount
            $swBatch.Stop()

            $percent = if ($totalCount -gt 0) { [int](($index / [double]$totalCount) * 100) } else { 100 }
            $elapsedSec = $swOverall.Elapsed.TotalSeconds
            $eta = if ($index -gt 0) { (($elapsedSec / $index) * ($totalCount - $index)) } else { 0 }

            Write-Progress -Activity "Dateianalyse (Security, Dependencies, Codequalität)" -Status "$overallProcessed von $totalCount Dateien" -PercentComplete $percent -SecondsRemaining $eta

            $script:AnalysisState.SecurityFindings = @($script:AnalysisState.SecurityFindings + $securityFindingsAll)
            $script:AnalysisState.FileMetrics = @($script:AnalysisState.FileMetrics + $metricsAll)
            $script:AnalysisState.DependencyEdges = @($script:AnalysisState.DependencyEdges + $depsAll)
            $script:AnalysisState.ProcessedFiles = @($processed)

            Write-Checkpoint -State $script:AnalysisState -CheckpointPath $script:CheckpointPath

            $securityFindingsAll = @()
            $metricsAll = @()
            $depsAll = @()

            [GC]::Collect()
        }

        $swOverall.Stop()
        $script:AnalysisState.Phases.ContentAnalysisCompleted = $true
        Write-Checkpoint -State $script:AnalysisState -CheckpointPath $script:CheckpointPath
    }
    else {
        Write-Log -Message "Inhaltsanalyse aus Checkpoint übernommen." -Category 'Main'
    }

    if (-not $script:AnalysisState.Phases.DuplicateAnalysisCompleted) {
        $metrics = $script:AnalysisState.FileMetrics
        $groups = @()
        $groupId = 1

        $hashGroups = $metrics | Where-Object { $_.Sha256 } | Group-Object -Property Sha256 | Where-Object { $_.Count -gt 1 }
        foreach ($g in $hashGroups) {
            $paths = $g.Group.FullPath
            $recommended = $g.Group | Sort-Object { $_.Length } -Descending | Select-Object -First 1
            $groups += [pscustomobject]@{
                GroupId          = $groupId
                Type             = 'Hash'
                RepresentativePath = $recommended.FullPath
                DuplicatePaths   = $paths
                DuplicateCount   = $paths.Count
                RecommendedKeep  = $recommended.FullPath
            }
            $groupId++
        }

        $normGroups = $metrics | Where-Object { $_.NormalizedContentHash } | Group-Object -Property NormalizedContentHash | Where-Object { $_.Count -gt 1 }
        foreach ($g in $normGroups) {
            $paths = $g.Group.FullPath

            if ($groups | Where-Object { $_.DuplicatePaths -contains $paths[0] }) {
                continue
            }

            $recommended = $g.Group | Sort-Object { $_.Length } -Descending | Select-Object -First 1
            $groups += [pscustomobject]@{
                GroupId          = $groupId
                Type             = 'Content90'
                RepresentativePath = $recommended.FullPath
                DuplicatePaths   = $paths
                DuplicateCount   = $paths.Count
                RecommendedKeep  = $recommended.FullPath
            }
            $groupId++
        }

        $nameGroups = $metrics | Group-Object -Property FullPath | Where-Object { $_.Count -gt 1 }
        foreach ($g in $nameGroups) {
            $paths = $g.Group.FullPath
            if ($groups | Where-Object { $_.DuplicatePaths -contains $paths[0] }) {
                continue
            }
            $recommended = $g.Group | Sort-Object { $_.Length } -Descending | Select-Object -First 1
            $groups += [pscustomobject]@{
                GroupId          = $groupId
                Type             = 'Name'
                RepresentativePath = $recommended.FullPath
                DuplicatePaths   = $paths
                DuplicateCount   = $paths.Count
                RecommendedKeep  = $recommended.FullPath
            }
            $groupId++
        }

        $script:AnalysisState.DuplicateGroups = $groups
        $script:AnalysisState.Phases.DuplicateAnalysisCompleted = $true
        Write-Checkpoint -State $script:AnalysisState -CheckpointPath $script:CheckpointPath
    }

    if (-not $script:AnalysisState.Phases.DependencyGraphCompleted) {
        $deps = $script:AnalysisState.DependencyEdges
        $graph = Build-DependencyGraph -Edges $deps
        $script:AnalysisState.DependencyGraph = $graph
        $script:AnalysisState.Phases.DependencyGraphCompleted = $true
        Write-Checkpoint -State $script:AnalysisState -CheckpointPath $script:CheckpointPath
    }

    $codeQualitySummary = $script:AnalysisState.FileMetrics | ForEach-Object {
        $commentRatio = if ($_.LocTotal -gt 0) { [math]::Round(($_.LocComments / [double]$_.LocTotal) * 100, 1) } else { 0 }
        [pscustomobject]@{
            FullPath            = $_.FullPath
            Length              = $_.Length
            LocTotal            = $_.LocTotal
            CommentRatioPercent = $commentRatio
            CyclomaticComplexity = $_.CyclomaticComplexity
            HasErrorHandling    = $_.HasErrorHandling
            HasHardcodedCreds   = $_.HasHardcodedCreds
            HasDeprecatedCmds   = $_.HasDeprecatedCmds
        }
    }
    $script:AnalysisState.CodeQualitySummary = $codeQualitySummary

    if (-not $script:AnalysisState.Phases.ReportsExported) {
        Export-JsonReport -State $script:AnalysisState -JsonPath $envInfo.JsonPath
        Export-CsvReports -State $script:AnalysisState -CsvPath $envInfo.CsvPath
        if ($envInfo.ImportExcelAvailable) {
            Export-ExcelReports -State $script:AnalysisState -ExcelPath $envInfo.ExcelPath
        }
        Export-HtmlReport -State $script:AnalysisState -HtmlPath $envInfo.HtmlPath
        $script:AnalysisState.Phases.ReportsExported = $true
        Write-Checkpoint -State $script:AnalysisState -CheckpointPath $script:CheckpointPath
    }

    Show-ConsoleSummary -State $script:AnalysisState
    Show-InteractiveMenu -State $script:AnalysisState
}
catch {
    Write-Log -Message "Fataler Fehler in der Hauptlogik: $($_.Exception.Message)" -Level ERROR -Category 'Main'
    $script:AnalysisState.Errors += $_.Exception.ToString()
    Write-Checkpoint -State $script:AnalysisState -CheckpointPath $script:CheckpointPath
    throw
}
finally {
    try {
        Stop-Transcript | Out-Null
    }
    catch {
    }
}

# endregion Hauptlogik

