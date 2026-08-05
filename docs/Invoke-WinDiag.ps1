#Requires -Version 5.1
<#
    WinDiag -- Windows diagnostic data collector
    Copyright (c) 2026 Shalom Karr. All rights reserved.

    SOURCE-AVAILABLE, NOT OPEN SOURCE.
    Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0)
    with the Commons Clause condition added on top. See the LICENSE file
    distributed with this software for the binding terms.

    NON-COMMERCIAL USE ONLY. Personal, educational, research and evaluation
    use is permitted, subject to the AGPL copyleft obligation: if you copy,
    modify or build on any part of this code, you must release the complete
    corresponding source of your entire work under these same terms --
    including when you only run a modified version as a network service.

    COMMERCIAL AND BUSINESS USE REQUIRES A SEPARATE PAID LICENSE. That
    includes internal use by a for-profit company, deployment to employees,
    contractors, clients or customers, bundling with any paid product or
    support offering, offering it as a hosted or managed service, and use in
    consulting, agency or managed-service work delivered to a third party.
    Request one at https://github.com/Shalom-Karr/WinDiag

    Any copy, notice or attribution required by the license MUST also carry
    the Commons Clause condition notice.

    Windows and Sysinternals are trademarks of Microsoft Corporation. This is
    an independently developed tool, not endorsed by or affiliated with
    Microsoft. Other product and vendor names appearing here or in the output
    are the trademarks of their respective owners and are used only to
    identify what was observed on a machine.

    NO WARRANTY. This software reads system state and draws no conclusions of
    its own. Any interpretation of its output, and any action taken as a
    result, is the responsibility of whoever reads it. See sections 15 to 17
    of the license.
#>

<#
.SYNOPSIS
    Enterprise Windows diagnostic data collector. Read-only. Collects raw
    evidence only - performs NO analysis, NO diagnosis, NO recommendations.

.DESCRIPTION
    Collects an exhaustive snapshot of a Windows system's hardware, software,
    configuration, performance counters, logs and state, so that a remote
    technician or AI agent receiving ONLY the output package can determine the
    cause of slowness, instability, crashes, freezes, overheating or stutter.

    EXPLICITLY NOT AN ANALYSER.
    This toolkit reports facts. It does not flag, rank, judge, or suggest.
    Interpretation is left entirely to whoever reads the output.

    SAFETY
    Read-only by default. Modifies nothing. Every collector is isolated with
    try/catch, retries and timeouts. A failing collector is recorded and the
    run continues.

    DURABILITY
    All logs are written with immediate flush. If the machine crashes or the
    script is killed mid-run, everything collected up to that point is intact
    and readable on disk.

.PARAMETER Mode
    Quick  - fast collection, skips deep filesystem scans and counter capture
    Full   - default; everything except long performance capture
    Deep   - everything, including extended performance capture and 1000-item
             filesystem enumerations

.PARAMETER OutputPath
    Directory to create the diagnostic package in. Defaults to Desktop.

.PARAMETER PerformanceMinutes
    Duration of the performance counter capture. Default 2 (Full), 5 (Deep).

.PARAMETER NoCompress
    Skip creating the ZIP archive.

.PARAMETER NoInternet
    Suppress any collector that would touch the network.

.EXAMPLE
    .\Invoke-WinDiag.ps1
.EXAMPLE
    .\Invoke-WinDiag.ps1 -Mode Deep -PerformanceMinutes 10
.EXAMPLE
    .\Invoke-WinDiag.ps1 -Mode Quick -OutputPath D:\Diag -NoCompress

.NOTES
    Run elevated for complete data (SMART, pool memory, some event logs,
    driver detail, service configuration).
        Set-ExecutionPolicy -Scope Process Bypass -Force
        .\Invoke-WinDiag.ps1
#>

[CmdletBinding()]
param(
    [ValidateSet('Quick','Full','Deep')]
    [string]   $Mode               = 'Full',
    [string]   $OutputPath         = ([Environment]::GetFolderPath('Desktop')),
    [int]      $PerformanceMinutes = 0,
    [int]      $TopN               = 50,
    [int]      $EventDays          = 30,
    [int]      $RetryCount         = 2,
    [int]      $CollectorTimeoutSec= 180,
    [switch]   $NoCompress,
    [switch]   $NoInternet,
    [string[]] $OnlySection,
    [string[]] $SkipSection,
    [switch]   $NoElevate
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'

# ##############################################################################
# REGION: SELF-ELEVATION
#   Several collectors (SMART, kernel pool, filter drivers, component store,
#   some event logs) return nothing without administrator rights, and a silently
#   half-empty package is worse than an obvious prompt. So: resolve this
#   script's own path, and if not already elevated, relaunch itself through UAC
#   with the same arguments.
#
#   -NoElevate skips this entirely and runs unelevated (collectors needing admin
#   record themselves as skipped). The relaunch also passes -NoElevate so the
#   child can never bounce a second time, whatever the elevation check reports.
# ##############################################################################

function Test-IsElevated {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
                    [Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

$script:IsElevated = Test-IsElevated

if (-not $script:IsElevated -and -not $NoElevate) {

    # Resolve our own path. $PSCommandPath is empty when the script is piped in
    # or run from an interactive paste, so fall back through MyInvocation.
    $selfPath = $PSCommandPath
    if (-not $selfPath) { $selfPath = $MyInvocation.MyCommand.Path }
    if (-not $selfPath) { $selfPath = $MyInvocation.MyCommand.Definition }

    if (-not $selfPath -or -not (Test-Path -LiteralPath $selfPath)) {
        Write-Host ''
        Write-Host '  Not running as administrator, and this script could not determine its own' -ForegroundColor Yellow
        Write-Host '  path on disk to relaunch itself (it may have been pasted or piped in).'     -ForegroundColor Yellow
        Write-Host '  Continuing unelevated. Collectors that require administrator rights will'   -ForegroundColor Yellow
        Write-Host '  be recorded in the log as skipped.'                                          -ForegroundColor Yellow
        Write-Host ''
    }
    else {
        # Rebuild the original invocation so the elevated run behaves identically
        # to what was typed.
        #
        # This is handed to the child through -EncodedCommand rather than -File.
        # powershell.exe -File parses everything after the script path with
        # CMD rules, where a single quote is an ordinary character rather than a
        # string delimiter - so -OutputPath 'C:\Users\x\Desktop' arrives as the
        # literal value 'C:\Users\x\Desktop WITH the quotes attached, and every
        # later Join-Path fails with "a drive with the name ''C' does not exist".
        # -EncodedCommand carries a UTF-16LE PowerShell script instead, which the
        # child parses with PowerShell rules, so ordinary quoting works and no
        # amount of spaces, quotes or brackets in a path can break the handoff.
        $parts = @()
        foreach ($kv in $PSBoundParameters.GetEnumerator()) {
            $k = $kv.Key; $v = $kv.Value
            if ($k -eq 'NoElevate') { continue }
            if ($v -is [switch]) {
                if ($v.IsPresent) { $parts += "-$k" }
            }
            elseif ($v -is [array]) {
                $parts += "-$k " + (($v | ForEach-Object { "'" + ("$_" -replace "'","''") + "'" }) -join ',')
            }
            else {
                $parts += "-$k '" + ("$v" -replace "'","''") + "'"
            }
        }
        # OutputPath defaults to the Desktop of whoever is running. UAC can switch
        # user context, so pin the already-resolved path when it was not supplied.
        if (-not $PSBoundParameters.ContainsKey('OutputPath')) {
            $parts += "-OutputPath '" + ($OutputPath -replace "'","''") + "'"
        }
        $parts += '-NoElevate'

        $inner = "& '" + ($selfPath -replace "'","''") + "' " + ($parts -join ' ')
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))

        $argLine = @(
            '-NoProfile'
            '-ExecutionPolicy','Bypass'
            '-NoExit'
            '-EncodedCommand', $encoded
        )

        Write-Host ''
        Write-Host '  This collection needs administrator rights to be complete.' -ForegroundColor Cyan
        Write-Host '  Requesting elevation - approve the Windows prompt.'          -ForegroundColor Cyan
        Write-Host ''
        Write-Host ('  Command : ' + $inner) -ForegroundColor DarkGray
        Write-Host ''

        try {
            # Relaunch powershell.exe specifically, not whatever host is running.
            # powershell_ise.exe accepts -File but not -EncodedCommand, so under
            # the ISE the UAC prompt would succeed, nothing would be collected,
            # and this window would still report success.
            $psExe = (Get-Process -Id $PID).Path
            $leaf  = ''
            if ($psExe) { $leaf = [System.IO.Path]::GetFileName($psExe).ToLower() }
            if ($leaf -ne 'powershell.exe' -and $leaf -ne 'pwsh.exe') { $psExe = Join-Path $PSHOME 'powershell.exe' }
            if (-not (Test-Path -LiteralPath $psExe)) { $psExe = 'powershell.exe' }
            Start-Process -FilePath $psExe -ArgumentList $argLine -Verb RunAs -ErrorAction Stop | Out-Null
            Write-Host '  Elevated window started. Results are written there.' -ForegroundColor Green
            Write-Host '  This window can be closed.' -ForegroundColor Green
            Write-Host ''
            return
        }
        catch {
            # The user declined UAC, or no interactive desktop is available.
            Write-Host ''
            Write-Host ('  Elevation was not granted (' + $_.Exception.Message + ').') -ForegroundColor Yellow
            Write-Host '  Continuing unelevated. Collectors that require administrator'  -ForegroundColor Yellow
            Write-Host '  rights will be recorded in the log as skipped, so the analyst' -ForegroundColor Yellow
            Write-Host '  can tell missing data from a genuine negative result.'          -ForegroundColor Yellow
            Write-Host ''
        }
    }
}

# ##############################################################################
# REGION: CONFIGURATION OBJECT
# ##############################################################################

$script:Cfg = [pscustomobject]@{
    Mode                = $Mode
    StartTime           = Get-Date
    Stamp               = (Get-Date).ToString('yyyy-MM-dd_HHmmss')
    Computer            = $env:COMPUTERNAME
    User                = "$env:USERDOMAIN\$env:USERNAME"
    TopN                = $TopN
    EventDays           = $EventDays
    RetryCount          = $RetryCount
    TimeoutSec          = $CollectorTimeoutSec
    NoInternet          = [bool]$NoInternet
    PerformanceMinutes  = $(if ($PerformanceMinutes -gt 0) { $PerformanceMinutes }
                            elseif ($Mode -eq 'Deep')      { 5 }
                            elseif ($Mode -eq 'Quick')     { 0 }
                            else                           { 2 })
    DeepScan            = ($Mode -eq 'Deep')
    QuickScan           = ($Mode -eq 'Quick')
    IsAdmin             = ([Security.Principal.WindowsPrincipal]`
                            [Security.Principal.WindowsIdentity]::GetCurrent()
                          ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    PSVersion           = $PSVersionTable.PSVersion.ToString()
    OnlySection         = $OnlySection
    SkipSection         = $SkipSection
}

# file-count limits scale with mode
$script:Limits = @{
    TopFolders = $(if ($script:Cfg.DeepScan) { 1000 } elseif ($script:Cfg.QuickScan) { 50 }  else { 250 })
    TopFiles   = $(if ($script:Cfg.DeepScan) { 1000 } elseif ($script:Cfg.QuickScan) { 50 }  else { 250 })
    EventRows  = $(if ($script:Cfg.DeepScan) { 5000 } elseif ($script:Cfg.QuickScan) { 300 } else { 1500 })
    MaxExeScan = $(if ($script:Cfg.DeepScan) { 50000 } elseif ($script:Cfg.QuickScan) { 2000 } else { 15000 })
    ScanSecs   = $(if ($script:Cfg.DeepScan) { 900 }  elseif ($script:Cfg.QuickScan) { 60 }  else { 300 })
}

# ##############################################################################
# REGION: PACKAGE LAYOUT
# ##############################################################################

# PowerShell 5.1's -Encoding UTF8 writes a BOM. The package is meant to be
# parsed by another program, and a BOM makes json.load() fail outright and
# shows up glued to the first CSV column header. One shared no-BOM encoder.
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

$script:PkgName = "WinDiag_$($script:Cfg.Computer)_$($script:Cfg.Stamp)"

# Validate the output location before anything depends on it. If this is wrong
# every Join-Path downstream returns null, and the run would otherwise carry on
# and print a COLLECTION COMPLETE banner having collected nothing - the exact
# "looks like a result but isn't" outcome this toolkit exists to avoid.
function Stop-Fatal {
    param([string]$Message, [string]$Detail = '')
    Write-Host ''
    Write-Host '==============================================================================' -ForegroundColor Red
    Write-Host '   COLLECTION DID NOT START' -ForegroundColor Red
    Write-Host '==============================================================================' -ForegroundColor Red
    Write-Host ("   $Message") -ForegroundColor Red
    if ($Detail) { Write-Host ("   $Detail") -ForegroundColor DarkGray }
    Write-Host ''
    Write-Host '   Nothing was collected. Do not send anything - there is no package.' -ForegroundColor Yellow
    Write-Host '   Re-run with an explicit location, for example:' -ForegroundColor Yellow
    Write-Host '       .\Invoke-WinDiag.ps1 -OutputPath C:\WinDiag' -ForegroundColor Cyan
    Write-Host ''
    exit 1
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    Stop-Fatal 'No output location was supplied.'
}
# Strip stray quote characters. A path can legally contain almost anything, but
# a leading or trailing quote is always a quoting accident from the caller, and
# silently inheriting it produces the DriveNotFound failure described above.
$OutputPath = $OutputPath.Trim().Trim("'", '"')
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    Stop-Fatal 'The output location was empty after removing surrounding quotes.'
}
if (-not (Test-Path -LiteralPath $OutputPath)) {
    try { New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null }
    catch { Stop-Fatal "The output location does not exist and could not be created: $OutputPath" $_.Exception.Message }
}
try   { $OutputPath = (Resolve-Path -LiteralPath $OutputPath -ErrorAction Stop).ProviderPath }
catch { Stop-Fatal "The output location could not be resolved: $OutputPath" $_.Exception.Message }

$script:PkgRoot = Join-Path $OutputPath $script:PkgName
if ([string]::IsNullOrWhiteSpace($script:PkgRoot)) {
    Stop-Fatal "Could not build a package path under: $OutputPath"
}

$script:Dirs = @{
    Root     = $script:PkgRoot
    Logs     = Join-Path $script:PkgRoot 'logs'
    Json     = Join-Path $script:PkgRoot 'json'
    Csv      = Join-Path $script:PkgRoot 'csv'
    Raw      = Join-Path $script:PkgRoot 'raw'
    Events   = Join-Path $script:PkgRoot 'eventlogs'
    Counters = Join-Path $script:PkgRoot 'counters'
    Sysint   = Join-Path $script:PkgRoot 'sysinternals'
}

foreach ($d in $script:Dirs.Values) {
    if ([string]::IsNullOrWhiteSpace($d)) { Stop-Fatal 'A package directory path resolved to nothing.' }
    try { New-Item -ItemType Directory -Path $d -Force -ErrorAction Stop | Out-Null }
    catch { Stop-Fatal "Cannot create $d" $_.Exception.Message }
    # -Force suppresses some failures, so confirm the directory is really there
    # rather than trusting that the call returned without throwing.
    if (-not (Test-Path -LiteralPath $d)) { Stop-Fatal "Directory was not created: $d" }
}

# ##############################################################################
# REGION: LOGGING LIBRARY  (incremental, auto-flush, multi-stream)
# ##############################################################################

$script:Streams = @{}

function Open-LogStream {
    param([string]$Key, [string]$FileName)
    $path = Join-Path $script:Dirs.Logs $FileName
    try {
        $sw = New-Object System.IO.StreamWriter($path, $true, (New-Object System.Text.UTF8Encoding($false)))
        $sw.AutoFlush = $true          # <-- durability guarantee
        $script:Streams[$Key] = @{ Writer = $sw; Path = $path }
    } catch {
        Write-Host "WARN: cannot open log stream $FileName - $_" -ForegroundColor Yellow
    }
}

Open-LogStream 'Master'      'Master.log'
Open-LogStream 'Errors'      'Errors.log'
Open-LogStream 'Warnings'    'Warnings.log'
Open-LogStream 'Verbose'     'Verbose.log'
Open-LogStream 'Performance' 'Performance.log'
Open-LogStream 'Timeline'    'Timeline.log'

function Write-Stream {
    param([string]$Key, [string]$Text)
    $s = $script:Streams[$Key]
    if ($s) {
        try { $s.Writer.WriteLine($Text); return } catch { }
    }
    # fallback path so a stream failure never loses data
    try { Add-Content -LiteralPath (Join-Path $script:Dirs.Logs "$Key.fallback.log") -Value $Text -Encoding UTF8 } catch { }
}

function Get-Ts { return (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff') }

function Write-DiagLog {
    <#
      Canonical log line format (per spec):
        [timestamp] [SEVERITY] [function] [+elapsed] message
    #>
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG','DATA','SECTION','CHECK')]
        [string]$Severity = 'INFO',
        [string]$Function = '',
        [double]$Elapsed  = -1,
        [switch]$NoConsole
    )
    $el = ''
    if ($Elapsed -ge 0) { $el = ('[+{0:N3}s] ' -f $Elapsed) }
    $fn = ''
    if ($Function) { $fn = "[$Function] " }
    $line = "[{0}] [{1,-7}] {2}{3}{4}" -f (Get-Ts), $Severity, $fn, $el, $Message

    Write-Stream 'Master' $line
    Write-Stream 'Verbose' $line
    if ($Severity -eq 'ERROR') { Write-Stream 'Errors'   $line }
    if ($Severity -eq 'WARN')  { Write-Stream 'Warnings' $line }

    if (-not $NoConsole) {
        switch ($Severity) {
            'ERROR'   { Write-Host "    ! $Message" -ForegroundColor Red }
            'WARN'    { Write-Host "    ~ $Message" -ForegroundColor Yellow }
            'SECTION' { }
            default   { }
        }
    }
}

function Write-Timeline {
    param([string]$Event, [double]$Elapsed = -1)
    $el = ''
    if ($Elapsed -ge 0) { $el = (' ({0:N2}s)' -f $Elapsed) }
    Write-Stream 'Timeline' ("[{0}] {1}{2}" -f (Get-Ts), $Event, $el)
}

# ------------------------------------------------------------------ data files
# Each collector writes its own labelled .txt in raw/ so nothing is lost even if
# JSON serialisation of an exotic object fails.

$script:CurrentRawFile = $null

function Open-RawFile {
    param([string]$Name)
    $script:CurrentRawFile = Join-Path $script:Dirs.Raw "$Name.txt"
    if (-not (Test-Path -LiteralPath $script:CurrentRawFile)) {
        Set-Content -LiteralPath $script:CurrentRawFile -Value '' -Encoding UTF8
    }
}

function Out-Raw {
    param([string]$Text = '')
    if (-not $script:CurrentRawFile) { Open-RawFile 'misc' }
    try { Add-Content -LiteralPath $script:CurrentRawFile -Value $Text -Encoding UTF8 } catch { }
}

function Out-RawObject {
    <# Dump any object as an aligned table into the current raw file. #>
    param($Object, [string]$Label = '')
    if ($Label) { Out-Raw ''; Out-Raw ("### $Label"); Out-Raw ('-' * 100) }
    if ($null -eq $Object) { Out-Raw '(no data)'; return }
    $arr = @($Object)
    if ($arr.Count -eq 0) { Out-Raw '(empty result set)'; return }
    try {
        $txt = $Object | Format-Table -AutoSize | Out-String -Width 500
        foreach ($l in ($txt -split "`r?`n")) { if ($l.Trim()) { Out-Raw $l.TrimEnd() } }
    } catch {
        try {
            $txt = $Object | Format-List | Out-String -Width 500
            foreach ($l in ($txt -split "`r?`n")) { if ($l.Trim()) { Out-Raw $l.TrimEnd() } }
        } catch { Out-Raw "(could not format object: $_)" }
    }
}

function Out-RawList {
    param($Object, [string]$Label = '')
    if ($Label) { Out-Raw ''; Out-Raw ("### $Label"); Out-Raw ('-' * 100) }
    if ($null -eq $Object) { Out-Raw '(no data)'; return }
    try {
        $txt = $Object | Format-List * | Out-String -Width 500
        foreach ($l in ($txt -split "`r?`n")) { if ($l.Trim()) { Out-Raw $l.TrimEnd() } }
    } catch { Out-Raw "(could not format object: $_)" }
}

function Out-KV {
    param([string]$Key, $Value)
    Out-Raw ('{0,-46}: {1}' -f $Key, $Value)
}

function Save-Json {
    param($Object, [string]$Name, [int]$Depth = 6)
    if ($null -eq $Object) { return }
    $p = Join-Path $script:Dirs.Json "$Name.json"
    try {
        $Object | ConvertTo-Json -Depth $Depth -ErrorAction Stop |
            Out-File -LiteralPath $p -Encoding UTF8 -Force
        Write-DiagLog "wrote json/$Name.json" 'DEBUG' 'Save-Json' -NoConsole
    } catch {
        Write-DiagLog "JSON export failed for $Name : $($_.Exception.Message)" 'WARN' 'Save-Json'
        try { $Object | Out-File -LiteralPath (Join-Path $script:Dirs.Json "$Name.txt") -Encoding UTF8 -Force } catch { }
    }
}

function Save-Csv {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return }
    $p = Join-Path $script:Dirs.Csv "$Name.csv"
    try {
        $csv = $Object | ConvertTo-Csv -NoTypeInformation -ErrorAction Stop
        [System.IO.File]::WriteAllLines($p, $csv, $script:Utf8NoBom)
        if (-not (Test-Path -LiteralPath $p)) { throw "csv file absent after write: $p" }
        Write-DiagLog "wrote csv/$Name.csv" 'DEBUG' 'Save-Csv' -NoConsole
    } catch {
        Write-DiagLog "CSV export failed for $Name : $($_.Exception.Message)" 'WARN' 'Save-Csv'
    }
}

# ##############################################################################
# REGION: EXECUTION ENGINE  (isolation, retry, timeout, timing)
# ##############################################################################

$script:Stats = [pscustomobject]@{
    Sections   = 0
    Collectors = 0
    Succeeded  = 0
    Failed     = 0
    Skipped    = 0
    Retried    = 0
}

function Test-SectionMatch {
    # A filter token matches if it equals, or is a wildcard/substring match against,
    # either the section's display name or its short key. Case-insensitive.
    param([string[]]$Tokens, [string]$Name, [string]$Key)
    foreach ($t in $Tokens) {
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        if ($Name -like $t -or $Key -like $t)                 { return $true }
        if ($Name -like "*$t*" -or $Key -like "*$t*")         { return $true }
    }
    return $false
}

function Test-SectionEnabled {
    param([string]$Name, [string]$Key)
    if ($script:Cfg.OnlySection -and -not (Test-SectionMatch $script:Cfg.OnlySection $Name $Key)) { return $false }
    if ($script:Cfg.SkipSection -and      (Test-SectionMatch $script:Cfg.SkipSection $Name $Key)) { return $false }
    return $true
}

function Invoke-Section {
    param([string]$Name, [string]$RawFile, [scriptblock]$Body)

    if (-not (Test-SectionEnabled $Name $RawFile)) {
        Write-DiagLog "section '$Name' skipped by parameter" 'INFO' 'Invoke-Section'
        return
    }

    $script:Stats.Sections++
    $n = $script:Stats.Sections
    Open-RawFile $RawFile

    Out-Raw ('=' * 100)
    Out-Raw ("SECTION {0}: {1}" -f $n, $Name.ToUpper())
    Out-Raw ("Host: {0}   Collected: {1}" -f $script:Cfg.Computer, (Get-Ts))
    Out-Raw ("Elevated: {0}   Mode: {1}" -f $script:Cfg.IsAdmin, $script:Cfg.Mode)
    Out-Raw ('=' * 100)

    Write-DiagLog ("=== SECTION $n : $Name ===") 'SECTION' 'Invoke-Section'
    Write-Timeline "SECTION START: $Name"
    Write-Host ''
    Write-Host ("[$n] $Name") -ForegroundColor Cyan

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try { & $Body }
    catch {
        Write-DiagLog "section '$Name' raised: $($_.Exception.Message)" 'ERROR' 'Invoke-Section'
        Out-Raw ''
        Out-Raw "!!! SECTION-LEVEL EXCEPTION: $($_.Exception.Message)"
    }
    $sw.Stop()
    Write-Timeline "SECTION END: $Name" $sw.Elapsed.TotalSeconds
    Write-DiagLog ("section '$Name' finished") 'SECTION' 'Invoke-Section' $sw.Elapsed.TotalSeconds
    Out-Raw ''
    Out-Raw ("--- section completed in {0:N2}s ---" -f $sw.Elapsed.TotalSeconds)
}

function Invoke-Collector {
    <#
      Runs one collector with full isolation.
        - retries transient failures
        - records failures in Errors.log AND in the raw file
        - times execution into Performance.log
        - NEVER throws
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Body,
        [string]$Describe = '',
        [switch]$NeedsAdmin,
        [switch]$NeedsInternet,
        [int]$Retries = -1
    )
    if ($Retries -lt 0) { $Retries = $script:Cfg.RetryCount }

    $script:Stats.Collectors++
    $id = 'C{0:D4}' -f $script:Stats.Collectors

    Out-Raw ''
    Out-Raw ('-' * 100)
    Out-Raw ("[$id] $Name")
    if ($Describe) { Out-Raw ("       $Describe") }
    Out-Raw ('-' * 100)

    if ($NeedsAdmin -and -not $script:Cfg.IsAdmin) {
        Out-Raw 'SKIPPED: requires elevation. Re-run as Administrator to collect this.'
        Write-DiagLog "$id $Name - skipped (needs admin)" 'WARN' $Name
        $script:Stats.Skipped++
        return
    }
    if ($NeedsInternet -and $script:Cfg.NoInternet) {
        Out-Raw 'SKIPPED: -NoInternet specified.'
        Write-DiagLog "$id $Name - skipped (no internet)" 'INFO' $Name
        $script:Stats.Skipped++
        return
    }

    $attempt = 0
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    while ($attempt -le $Retries) {
        $attempt++
        try {
            # Non-terminating errors - which is what most cmdlets raise when a
            # WMI class is absent, a path is denied, or a provider is not
            # installed - do NOT reach the catch below, and with the default
            # preference they print raw red text over the progress output. On a
            # machine missing an optional WMI class that looks alarming while
            # being entirely expected.
            #
            # So: silence them for the duration of the body, then drain whatever
            # landed in $Error into the section file and Errors.log. They end up
            # recorded where an analyst can use them instead of scrolling past
            # them, and a non-terminating error still does not abort a collector
            # that can carry on without that one value.
            $errMark = $global:Error.Count
            $prevEap = $ErrorActionPreference
            $ErrorActionPreference = 'SilentlyContinue'
            try     { & $Body }
            finally {
                $ErrorActionPreference = $prevEap
                $newErrs = $global:Error.Count - $errMark
                if ($newErrs -gt 0) {
                    Out-Raw ''
                    Out-Raw ("  [{0} non-terminating error(s) during this collector - recorded, not fatal]" -f $newErrs)
                    for ($ei = $newErrs - 1; $ei -ge 0; $ei--) {
                        $er = $global:Error[$ei]
                        if ($null -eq $er) { continue }
                        $msg = "$er"
                        $where = ''
                        try { if ($er.InvocationInfo) { $where = ' @ ' + $er.InvocationInfo.MyCommand } } catch { }
                        Out-Raw ("    - " + $msg + $where)
                        Write-Stream 'Warnings' ("{0,-45} {1}" -f $Name, ($msg + $where))
                    }
                }
            }
            $sw.Stop()
            $script:Stats.Succeeded++
            Out-Raw ("[collector OK - {0:N2}s]" -f $sw.Elapsed.TotalSeconds)
            Write-Stream 'Performance' ("{0,-60} {1,8:N2}s  attempts={2}" -f $Name, $sw.Elapsed.TotalSeconds, $attempt)
            Write-DiagLog "$id $Name" 'CHECK' $Name $sw.Elapsed.TotalSeconds -NoConsole
            Write-Host ("    - $Name") -ForegroundColor DarkGray
            return
        }
        catch {
            $e = $_
            if ($attempt -le $Retries) {
                $script:Stats.Retried++
                Out-Raw ("  [retry $attempt/$Retries] $($e.Exception.Message)")
                Write-DiagLog "$id $Name retry $attempt : $($e.Exception.Message)" 'WARN' $Name
                Start-Sleep -Milliseconds 350
            }
            else {
                $sw.Stop()
                $script:Stats.Failed++
                Out-Raw ''
                Out-Raw '!!! COLLECTOR FAILED - data below is absent, not empty !!!'
                Out-Raw ("    Exception : " + $e.Exception.GetType().FullName)
                Out-Raw ("    Message   : " + $e.Exception.Message)
                if ($e.InvocationInfo) {
                    Out-Raw ("    Line      : " + $e.InvocationInfo.ScriptLineNumber)
                    Out-Raw ("    Statement : " + ($e.InvocationInfo.Line -replace '\s+',' ').Trim())
                }
                Out-Raw ("    Stack     : " + ($e.ScriptStackTrace -replace "`r?`n", ' | '))
                Write-DiagLog "$id $Name FAILED: $($e.Exception.Message)" 'ERROR' $Name $sw.Elapsed.TotalSeconds
                Write-Host ("    ! $Name [failed]") -ForegroundColor Red
            }
        }
    }
}

# ##############################################################################
# REGION: SHARED HELPERS
# ##############################################################################

function ConvertTo-GB { param($b) ; if ($null -eq $b) { return 0 } ; return [math]::Round(([double]$b)/1GB, 3) }
function ConvertTo-MB { param($b) ; if ($null -eq $b) { return 0 } ; return [math]::Round(([double]$b)/1MB, 2) }

function Get-FolderSize {
    param([string]$Path, [int]$MaxSeconds = 0)
    if ($MaxSeconds -le 0) { $MaxSeconds = $script:Limits.ScanSecs }
    if ([string]::IsNullOrWhiteSpace($Path)) { return @{ Bytes = 0; Files = 0; Truncated = $false } }
    if (-not (Test-Path -LiteralPath $Path)) { return @{ Bytes = 0; Files = 0; Truncated = $false } }
    $bytes = [long]0; $files = 0; $trunc = $false
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $en = Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue
        foreach ($f in $en) {
            $bytes += $f.Length; $files++
            if ($sw.Elapsed.TotalSeconds -gt $MaxSeconds) { $trunc = $true; break }
        }
    } catch { }
    return @{ Bytes = $bytes; Files = $files; Truncated = $trunc }
}

function Invoke-NativeCapture {
    <# Run a native command and capture stdout+stderr into the raw file and a file in raw/. #>
    param([string]$Label, [string]$Command, [string]$SaveAs = '')
    Out-Raw ''
    Out-Raw ("### $Label")
    Out-Raw ("    command: $Command")
    Out-Raw ('-' * 100)
    try {
        $out = cmd.exe /c "$Command 2>&1" | Out-String
        foreach ($l in ($out -split "`r?`n")) { if ($l.Trim()) { Out-Raw ("  " + $l.TrimEnd()) } }
        if ($SaveAs) {
            $p = Join-Path $script:Dirs.Raw $SaveAs
            $out | Out-File -LiteralPath $p -Encoding UTF8 -Force
        }
    } catch {
        Out-Raw "  (command failed: $($_.Exception.Message))"
    }
}

function Get-SysinternalsTool {
    param([string]$Exe)
    $c = Get-Command $Exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    foreach ($p in @(
        (Join-Path $PSScriptRoot $Exe),
        (Join-Path $PSScriptRoot "Sysinternals\$Exe"),
        "C:\Sysinternals\$Exe",
        "C:\Tools\Sysinternals\$Exe",
        "$env:USERPROFILE\Sysinternals\$Exe")) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    return $null
}

# ##############################################################################
# REGION: BANNER
# ##############################################################################

Write-Host ''
Write-Host ('=' * 78) -ForegroundColor Green
Write-Host '   WINDOWS DIAGNOSTIC COLLECTION TOOLKIT' -ForegroundColor Green
Write-Host '   Read-only evidence collection. No analysis, no changes.' -ForegroundColor Gray
Write-Host ('=' * 78) -ForegroundColor Green
Write-Host ("   Mode      : $($script:Cfg.Mode)")
Write-Host ("   Package   : $($script:PkgRoot)")
Write-Host ("   Elevated  : $($script:Cfg.IsAdmin)") -ForegroundColor $(if ($script:Cfg.IsAdmin) { 'Green' } else { 'Yellow' })
if (-not $script:Cfg.IsAdmin) {
    Write-Host '   NOTE: some collectors require elevation and will be skipped.' -ForegroundColor Yellow
}
Write-Host ''

Write-DiagLog '================ COLLECTION RUN STARTED ================' 'INFO' 'Main'
Write-DiagLog ("Mode=$($script:Cfg.Mode) Elevated=$($script:Cfg.IsAdmin) PS=$($script:Cfg.PSVersion)") 'INFO' 'Main'
Write-DiagLog ("Package root: $($script:PkgRoot)") 'INFO' 'Main'
Write-Timeline 'RUN START'

# Manifest describing the package, written first so it survives any crash.
$manifest = [pscustomobject]@{
    Tool               = 'Invoke-WinDiag'
    SchemaVersion      = 1
    Purpose            = 'Raw diagnostic evidence collection. Contains NO analysis or conclusions.'
    GeneratedUtc       = (Get-Date).ToUniversalTime().ToString('o')
    Computer           = $script:Cfg.Computer
    User               = $script:Cfg.User
    Mode               = $script:Cfg.Mode
    Elevated           = $script:Cfg.IsAdmin
    PowerShellVersion  = $script:Cfg.PSVersion
    ReaderInstructions = @(
        'This package contains raw system data only. No conclusions are drawn.',
        'raw/*.txt          - human-readable dumps, one file per section',
        'json/*.json        - structured data for programmatic analysis',
        'csv/*.csv          - tabular exports',
        'logs/Master.log    - full execution log with millisecond timestamps',
        'logs/Errors.log    - collectors that failed (data ABSENT, not empty)',
        'logs/Performance.log - per-collector execution time',
        'logs/Timeline.log  - ordered event timeline',
        'eventlogs/         - exported Windows event logs',
        'counters/          - performance counter captures',
        'IMPORTANT: a collector listed in Errors.log produced NO data. Do not',
        'interpret its absence as a negative finding.'
    )
}
Save-Json $manifest 'MANIFEST' 4

# ##############################################################################
# REGION: COLLECTORS
#   Every collector definition follows. Single self-contained file by design:
#   this script gets handed to someone else and run, so it must not depend on a
#   sibling file arriving with it.
#
#   RULE FOR THIS REGION: collect, never conclude. No thresholds, no severities,
#   no "this value is too high". Where a number needs reference to be readable,
#   emit a CONTEXT line stating a documented Windows default or the unit --
#   never a verdict about this machine.
# ##############################################################################

function Invoke-AllSections {

# =============================================================== 0. SUMMARY
# Mirrors Windows Settings > System > About, so the analyst sees the machine's
# identity on the first page of the log before any detail.
Invoke-Section 'System Summary' 'summary' {

    Invoke-Collector 'About-page equivalent' {
        $cs   = Get-CimInstance Win32_ComputerSystem
        $os   = Get-CimInstance Win32_OperatingSystem
        $cpu  = @(Get-CimInstance Win32_Processor)
        $gpu  = @(Get-CimInstance Win32_VideoController)
        $bios = Get-CimInstance Win32_BIOS
        $mods = @(Get-CimInstance Win32_PhysicalMemory)

        Out-Raw '================ DEVICE SPECIFICATIONS ================'
        Out-KV 'Device name'   $env:COMPUTERNAME
        Out-KV 'Full computer name' ($cs.DNSHostName + $(if ($cs.Domain) { '.' + $cs.Domain } else { '' }))
        Out-KV 'Manufacturer'  $cs.Manufacturer
        Out-KV 'Model'         $cs.Model
        Out-KV 'System SKU'    $cs.SystemSKUNumber
        Out-KV 'Serial number' $bios.SerialNumber

        Out-Raw ''
        foreach ($c in $cpu) {
            Out-KV 'Processor'          $c.Name
            Out-KV '  Base speed'       ('{0:N2} GHz' -f ($c.MaxClockSpeed / 1000))
            Out-KV '  Current speed'    ('{0:N2} GHz' -f ($c.CurrentClockSpeed / 1000))
            Out-KV '  Physical cores'   $c.NumberOfCores
            Out-KV '  Logical processors' $c.NumberOfLogicalProcessors
            Out-KV '  Socket'           $c.SocketDesignation
            Out-KV '  L2 cache (KB)'    $c.L2CacheSize
            Out-KV '  L3 cache (KB)'    $c.L3CacheSize
            Out-KV '  Architecture'     $c.Architecture
            Out-KV '  Virtualisation firmware enabled' $c.VirtualizationFirmwareEnabled
        }
        Out-Raw 'CONTEXT: Architecture 9 = x64. Hybrid Intel CPUs report the combined P-core + E-core count.'
        Out-Raw 'CONTEXT: MaxClockSpeed is the rated base frequency; turbo frequencies are not reported by WMI.'

        Out-Raw ''
        $totalKB = $os.TotalVisibleMemorySize
        $physB   = $cs.TotalPhysicalMemory
        Out-KV 'Installed RAM'      ('{0:N1} GB installed ({1:N1} GB usable)' -f ($physB/1GB), ($totalKB/1MB))
        Out-KV '  Installed modules' $mods.Count
        $slot = 0
        foreach ($m in $mods) {
            $slot++
            $vendor = (('' + $m.Manufacturer).Trim() + ' ' + ('' + $m.PartNumber).Trim()).Trim()
            if (-not $vendor) { $vendor = '(no manufacturer/part in SPD)' }
            $loc = ('' + $m.DeviceLocator).Trim()
            if (-not $loc) { $loc = 'slot ' + $slot }
            Out-KV ('  [' + $slot + '] ' + $loc) ('{0} GB @ {1} MT/s rated, {2} MT/s configured, bank "{3}" - {4}' -f `
                [math]::Round($m.Capacity/1GB,0), $m.Speed, $m.ConfiguredClockSpeed, ('' + $m.BankLabel).Trim(), $vendor)
        }
        Out-Raw 'CONTEXT: Soldered LPDDR memory commonly reports DeviceLocator "Motherboard" and leaves manufacturer and part number blank; that is a firmware reporting characteristic, not missing hardware.'
        Out-Raw 'CONTEXT: Usable RAM is lower than installed because firmware, integrated graphics and hardware reservations claim a portion.'

        Out-Raw ''
        foreach ($g in $gpu) {
            Out-KV 'Graphics card'  $g.Name
            $vram = $g.AdapterRAM
            Out-KV '  Reported VRAM' $(if ($vram -and $vram -gt 0) { '{0:N0} MB' -f ($vram/1MB) } else { 'not reported' })
            Out-KV '  Driver version' $g.DriverVersion
            Out-KV '  Driver date'    $g.DriverDate
            Out-KV '  Current mode'   $g.VideoModeDescription
            Out-KV '  Refresh (Hz)'   $g.CurrentRefreshRate
        }
        Out-Raw 'CONTEXT: For integrated graphics, AdapterRAM reports only the BIOS pre-allocated aperture.'
        Out-Raw 'CONTEXT: Integrated GPUs additionally share system RAM dynamically, well above the reported figure.'

        Out-Raw ''
        Out-Raw '--- Storage ---'
        foreach ($d in (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')) {
            # An unformatted or recovering volume can report Size 0. Dividing
            # by it throws, which would abort the entire About-page collector.
            $used = 0
            if ($d.Size) { $used = $d.Size - $d.FreeSpace }
            $freePct = 'n/a'
            if ($d.Size -gt 0) { $freePct = [math]::Round(($d.FreeSpace / $d.Size) * 100, 1) }
            Out-KV $d.DeviceID ('{0:N0} GB of {1:N0} GB used ({2}% free) - {3} {4}' -f `
                ($used/1GB), ($d.Size/1GB), $freePct, $d.FileSystem, $d.VolumeName)
        }
        foreach ($p in (Get-PhysicalDisk -ErrorAction SilentlyContinue)) {
            Out-KV ('  Physical: ' + $p.FriendlyName) ('{0:N0} GB, {1}, bus {2}, health {3}' -f `
                ($p.Size/1GB), $p.MediaType, $p.BusType, $p.HealthStatus)
        }

        Out-Raw ''
        Out-KV 'System type'   ($os.OSArchitecture + ' operating system, ' + $(if ($env:PROCESSOR_ARCHITECTURE -eq 'AMD64') { 'x64-based processor' } else { $env:PROCESSOR_ARCHITECTURE }))
        Out-KV 'Device ID'     (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\SQMClient' -Name MachineId -ErrorAction SilentlyContinue).MachineId
        Out-KV 'Product ID'    (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductId -ErrorAction SilentlyContinue).ProductId
        Out-KV 'Pen and touch' $(if ((Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPClass -eq 'HIDClass' -and $_.Name -match 'touch screen|pen' })) { 'Touch or pen input detected' } else { 'No pen or touch input is available for this display' })

        Out-Raw ''
        Out-Raw '================ WINDOWS SPECIFICATIONS ================'
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        Out-KV 'Edition (registry ProductName)' $cv.ProductName
        Out-KV 'Build-derived generation' $(if ([int]$cv.CurrentBuild -ge 22000) { 'Windows 11 (CurrentBuild ' + $cv.CurrentBuild + ' >= 22000)' } else { 'Windows 10 (CurrentBuild ' + $cv.CurrentBuild + ' < 22000)' })
        Out-Raw 'CONTEXT: The registry ProductName value still reads "Windows 10" on many Windows 11 installations - Microsoft did not update it in place on upgrade. Build number is the reliable generation indicator: 22000 and above is Windows 11.'
        Out-KV 'Version'         $cv.DisplayVersion
        Out-KV 'OS build'        ($cv.CurrentBuild + '.' + $cv.UBR)
        Out-KV 'Installed on'    ([DateTimeOffset]::FromUnixTimeSeconds($cv.InstallDate).LocalDateTime)
        Out-KV 'Experience'      $cv.BuildBranch
        Out-KV 'Registered owner' $cv.RegisteredOwner
        Out-KV 'Last boot'       $os.LastBootUpTime
        Out-KV 'Uptime (hours)'  ([math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours,2))

        Save-Json ([pscustomobject]@{
            DeviceName   = $env:COMPUTERNAME
            Manufacturer = $cs.Manufacturer
            Model        = $cs.Model
            Processor    = $cpu[0].Name
            Cores        = $cpu[0].NumberOfCores
            LogicalProcs = $cpu[0].NumberOfLogicalProcessors
            InstalledRAM_GB = [math]::Round($physB/1GB,1)
            UsableRAM_GB    = [math]::Round($totalKB/1MB,1)
            Graphics     = ($gpu | ForEach-Object { $_.Name }) -join '; '
            OSArch       = $os.OSArchitecture
            OSEdition    = $cv.ProductName
            OSVersion    = $cv.DisplayVersion
            OSBuild      = ($cv.CurrentBuild + '.' + $cv.UBR)
        }) 'system_summary'
    }
}

# =============================================================== 1. SYSTEM
Invoke-Section 'System Identity and Hardware' 'system' {

    Invoke-Collector 'Computer system' {
        $cs = Get-CimInstance Win32_ComputerSystem
        Out-RawList $cs 'Win32_ComputerSystem (all properties)'
        Save-Json $cs 'hw_computersystem'
    }

    Invoke-Collector 'Operating system' {
        $os = Get-CimInstance Win32_OperatingSystem
        Out-RawList $os 'Win32_OperatingSystem (all properties)'
        Out-Raw ''
        Out-KV 'LastBootUpTime' $os.LastBootUpTime
        Out-KV 'UptimeHours'    ([math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours,2))
        Out-KV 'UptimeDays'     ([math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays,2))
        Save-Json $os 'os_info'
    }

    Invoke-Collector 'BIOS / firmware / baseboard' {
        Out-RawList (Get-CimInstance Win32_BIOS)          'Win32_BIOS'
        Out-RawList (Get-CimInstance Win32_BaseBoard)     'Win32_BaseBoard'
        Out-RawList (Get-CimInstance Win32_SystemEnclosure) 'Win32_SystemEnclosure'
    }

    Invoke-Collector 'Processor detail' {
        $cpu = Get-CimInstance Win32_Processor
        Out-RawList $cpu 'Win32_Processor (all properties, all sockets)'
        Out-Raw ''
        Out-Raw 'CONTEXT: CurrentClockSpeed is a WMI snapshot polled infrequently.'
        Out-Raw 'CONTEXT: MaxClockSpeed is the rated base frequency, not the turbo ceiling.'
        Save-Json $cpu 'hw_cpu'
    }

    Invoke-Collector 'Memory modules and slots' {
        $mods = Get-CimInstance Win32_PhysicalMemory
        Out-RawList $mods 'Win32_PhysicalMemory (per DIMM)'
        # Multi-socket machines return one object per memory controller, and
        # Object[] / Int32 is not a valid operation - it would throw here.
        $arr = @(Get-CimInstance Win32_PhysicalMemoryArray)
        Out-RawList $arr 'Win32_PhysicalMemoryArray'
        Out-Raw ''
        Out-KV 'Modules installed' (@($mods).Count)
        Out-KV 'Memory arrays'     $arr.Count
        Out-KV 'Slots on board'    (($arr | Measure-Object MemoryDevices -Sum).Sum)
        Out-KV 'Board max (GB)'    ([math]::Round(((($arr | Measure-Object MaxCapacityEx -Sum).Sum)/1MB),0))
        $banks = @($mods | Select-Object -ExpandProperty BankLabel -Unique)
        Out-KV 'Distinct bank labels' ($banks -join ', ')
        Out-Raw ''
        Out-Raw 'CONTEXT: Dual-channel operation requires modules in matched channel slots.'
        Out-Raw 'CONTEXT: ConfiguredClockSpeed is the running speed; Speed is the module rating.'
        Save-Json $mods 'hw_memory_modules'
    }

    Invoke-Collector 'TPM / Secure Boot / firmware security' {
        try { Out-RawList (Get-Tpm) 'Get-Tpm' } catch { Out-Raw "Get-Tpm: $($_.Exception.Message)" }
        try { Out-KV 'SecureBootEnabled' (Confirm-SecureBootUEFI) } catch { Out-Raw "Confirm-SecureBootUEFI: $($_.Exception.Message)" }
        try {
            $dg = Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard
            Out-RawList $dg 'Win32_DeviceGuard (VBS / HVCI / Credential Guard)'
            Out-Raw 'CONTEXT: VirtualizationBasedSecurityStatus 0=Off 1=Configured 2=Running.'
        } catch { Out-Raw "DeviceGuard: $($_.Exception.Message)" }
    }

    Invoke-Collector 'Battery and power adapter' {
        Out-RawList (Get-CimInstance Win32_Battery) 'Win32_Battery'
        try {
            $s = Get-CimInstance -Namespace root\WMI -ClassName BatteryStaticData -ErrorAction Stop
            $f = Get-CimInstance -Namespace root\WMI -ClassName BatteryFullChargedCapacity -ErrorAction Stop
            Out-RawList $s 'BatteryStaticData'
            Out-RawList $f 'BatteryFullChargedCapacity'
            if ($s -and $f -and $s.DesignedCapacity -gt 0) {
                Out-KV 'DesignedCapacity_mWh'   $s.DesignedCapacity
                Out-KV 'FullChargedCapacity_mWh' $f.FullChargedCapacity
                Out-KV 'RatioPercent' ([math]::Round(($f.FullChargedCapacity/$s.DesignedCapacity)*100,1))
            }
        } catch { Out-Raw "Battery WMI: $($_.Exception.Message)" }
        Invoke-NativeCapture 'powercfg /batteryreport' 'powercfg /batteryreport /output "%TEMP%\batteryreport.html"'
    }

    Invoke-Collector 'Thermal zones' {
        try {
            $t = Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature
            foreach ($z in $t) {
                Out-KV $z.InstanceName ('{0} C' -f [math]::Round(($z.CurrentTemperature/10)-273.15,1))
            }
            Out-Raw 'CONTEXT: CurrentTemperature is in tenths of a Kelvin.'
        } catch { Out-Raw "MSAcpi_ThermalZoneTemperature not exposed by this firmware: $($_.Exception.Message)" }
        Out-RawObject (Get-CimInstance Win32_Fan) 'Win32_Fan'
        Out-RawObject (Get-CimInstance Win32_TemperatureProbe) 'Win32_TemperatureProbe'
    }

    Invoke-Collector 'GPU and displays' {
        Out-RawList (Get-CimInstance Win32_VideoController) 'Win32_VideoController (all properties)'
        Out-RawObject (Get-CimInstance Win32_DesktopMonitor) 'Win32_DesktopMonitor'
        try {
            Out-RawObject (Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorBasicDisplayParams) 'WmiMonitorBasicDisplayParams'
            Out-RawObject (Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID) 'WmiMonitorID'
        } catch { }
        $gfx = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' -ErrorAction SilentlyContinue
        Out-KV 'HwSchMode (HAGS)' $gfx.HwSchMode
        Out-Raw 'CONTEXT: HwSchMode 2 = hardware-accelerated GPU scheduling on, 0/absent = software.'
    }

    Invoke-Collector 'PnP devices with problem codes' {
        $bad = Get-CimInstance Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 }
        Out-RawObject ($bad | Select-Object Name, DeviceID, ConfigManagerErrorCode, Status, Service) 'Devices reporting non-zero ConfigManagerErrorCode'
        Out-Raw ''
        Out-Raw 'CONTEXT: 0=OK 1=not configured 10=cannot start 22=disabled 28=no driver 43=reported failure.'
        Save-Json $bad 'hw_problem_devices'
    }

    Invoke-Collector 'All PnP devices (full inventory)' {
        $all = Get-CimInstance Win32_PnPEntity | Select-Object Name, Manufacturer, DeviceID, Service, Status, ConfigManagerErrorCode
        Out-RawObject ($all | Sort-Object Name) 'Win32_PnPEntity (complete)'
        Save-Csv $all 'devices_all'
    }

    Invoke-Collector 'USB / Thunderbolt / Bluetooth' {
        Out-RawObject (Get-CimInstance Win32_USBController) 'Win32_USBController'
        Out-RawObject (Get-PnpDevice -Class USB -ErrorAction SilentlyContinue | Select-Object FriendlyName, Status, InstanceId) 'USB devices'
        Out-RawObject (Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Select-Object FriendlyName, Status) 'Bluetooth devices'
    }
}

# =============================================================== 2. CPU
Invoke-Section 'CPU and Scheduling' 'cpu' {

    Invoke-Collector 'Per-core utilisation (3 samples)' -Describe 'Per-core sampling, so single-core saturation is visible separately from the average.' -Body {
        $s = Get-Counter '\Processor(*)\% Processor Time' -SampleInterval 2 -MaxSamples 3 -ErrorAction SilentlyContinue
        $rows = $s.CounterSamples | Group-Object InstanceName | ForEach-Object {
            [pscustomobject]@{ Core = $_.Name; AvgPct = [math]::Round((($_.Group | Measure-Object CookedValue -Average).Average),2) }
        }
        Out-RawObject $rows 'Average % Processor Time per core'
        Save-Json $rows 'cpu_percore'
    }

    Invoke-Collector 'Processor queue length' -Describe 'Count of threads waiting for a CPU slice.' -Body {
        $q = Get-Counter '\System\Processor Queue Length' -SampleInterval 1 -MaxSamples 5 -ErrorAction SilentlyContinue
        Out-RawObject ($q.CounterSamples | Select-Object TimeStamp, @{n='QueueLength';e={$_.CookedValue}}) 'Samples'
        Out-KV 'Average' ([math]::Round((($q.CounterSamples | Measure-Object CookedValue -Average).Average),2))
        Out-Raw 'CONTEXT: This counter is a system-wide total, not per logical processor.'
    }

    Invoke-Collector 'CPU time breakdown: user / privileged / DPC / interrupt / idle' {
        $c = @('\Processor(_Total)\% User Time','\Processor(_Total)\% Privileged Time',
               '\Processor(_Total)\% DPC Time','\Processor(_Total)\% Interrupt Time',
               '\Processor(_Total)\% Idle Time')
        $s = Get-Counter $c -SampleInterval 2 -MaxSamples 3 -ErrorAction SilentlyContinue
        $rows = $s.CounterSamples | Group-Object Path | ForEach-Object {
            [pscustomobject]@{ Counter = ($_.Name -split '\\')[-1]; AvgPct = [math]::Round((($_.Group | Measure-Object CookedValue -Average).Average),3) }
        }
        Out-RawObject $rows 'CPU time distribution'
        Out-Raw 'CONTEXT: DPC and Interrupt time is kernel work on behalf of device drivers.'
    }

    Invoke-Collector 'Context switches, system calls, interrupts' {
        $c = @('\System\Context Switches/sec','\System\System Calls/sec','\Processor(_Total)\Interrupts/sec')
        $s = Get-Counter $c -SampleInterval 2 -MaxSamples 3 -ErrorAction SilentlyContinue
        $rows = $s.CounterSamples | Group-Object Path | ForEach-Object {
            [pscustomobject]@{ Counter = ($_.Name -split '\\')[-1]; Average = [math]::Round((($_.Group | Measure-Object CookedValue -Average).Average),0) }
        }
        Out-RawObject $rows 'Rates'
        Out-Raw 'CONTEXT: Default Windows timer resolution is 15.6ms, producing roughly 64 timer interrupts/sec at idle.'
        Out-Raw 'CONTEXT: An application calling timeBeginPeriod(1) raises this to roughly 1000/sec.'
    }

    Invoke-Collector 'Per-core interrupt distribution' {
        $s = Get-Counter '\Processor(*)\Interrupts/sec' -SampleInterval 2 -MaxSamples 3 -ErrorAction SilentlyContinue
        Out-RawObject ($s.CounterSamples | Group-Object InstanceName | ForEach-Object {
            [pscustomobject]@{ Core = $_.Name; InterruptsPerSec = [math]::Round((($_.Group | Measure-Object CookedValue -Average).Average),0) }
        }) 'Interrupts/sec by core'
        Out-Raw 'CONTEXT: Without MSI-X or RSS, device interrupts concentrate on CPU 0.'
    }

    Invoke-Collector 'Processor performance state (actual vs base frequency)' {
        $s = Get-Counter @('\Processor Information(_Total)\% Processor Performance',
                           '\Processor Information(_Total)\Processor Frequency') -SampleInterval 2 -MaxSamples 3 -ErrorAction SilentlyContinue
        Out-RawObject ($s.CounterSamples | Group-Object Path | ForEach-Object {
            [pscustomobject]@{ Counter = ($_.Name -split '\\')[-1]; Average = [math]::Round((($_.Group | Measure-Object CookedValue -Average).Average),1) }
        }) 'Performance state'
        Out-Raw 'CONTEXT: % Processor Performance is expressed relative to base clock; values above 100 indicate turbo.'
    }

    Invoke-Collector 'Power scheme and processor power policy' {
        Invoke-NativeCapture 'Active scheme'        'powercfg /getactivescheme'
        Invoke-NativeCapture 'Processor subgroup'   'powercfg /query SCHEME_CURRENT SUB_PROCESSOR' 'powercfg_processor.txt'
        Invoke-NativeCapture 'Available sleep states' 'powercfg /a'
        Invoke-NativeCapture 'Last wake source'     'powercfg /lastwake'
        Invoke-NativeCapture 'Wake timers'          'powercfg /waketimers'
        Out-Raw 'CONTEXT: PROCTHROTTLEMAX is the maximum processor state as a percentage of base clock.'
        Out-Raw 'CONTEXT: Processor Performance Boost Mode 0 = turbo disabled.'
    }

    Invoke-Collector 'Processes at High or RealTime priority' {
        Out-RawObject (Get-Process -ErrorAction SilentlyContinue |
            Where-Object { $_.PriorityClass -eq 'High' -or $_.PriorityClass -eq 'RealTime' } |
            Select-Object Name, Id, PriorityClass, @{n='CPUSec';e={[math]::Round($_.CPU,1)}},
                          @{n='WS_MB';e={ConvertTo-MB $_.WorkingSet64}}, @{n='Threads';e={$_.Threads.Count}}) 'Elevated priority processes'
        Out-Raw 'CONTEXT: csrss, audiodg and some system processes run at High by design.'
    }

    Invoke-Collector 'Lifetime CPU consumption per process' {
        $rows = Get-Process -ErrorAction SilentlyContinue |
            Where-Object { $_.CPU -gt 0 -and $null -ne $_.StartTime } | ForEach-Object {
                $rt = ((Get-Date) - $_.StartTime).TotalSeconds
                [pscustomobject]@{
                    Name = $_.ProcessName; Id = $_.Id
                    CPUSec = [math]::Round($_.CPU,1)
                    RuntimeHours = [math]::Round($rt/3600,2)
                    AvgCoresUsed = if ($rt -gt 0) { [math]::Round($_.CPU/$rt,4) } else { 0 }
                    WS_MB = ConvertTo-MB $_.WorkingSet64
                }
            } | Sort-Object CPUSec -Descending
        Out-RawObject $rows 'All processes by cumulative CPU seconds'
        Out-Raw 'CONTEXT: AvgCoresUsed = CPU seconds / wall-clock seconds. 1.0 equals one core fully occupied for the process lifetime.'
        Save-Csv $rows 'cpu_lifetime'
    }

    Invoke-Collector 'Kernel processor power events' {
        $ev = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-Processor-Power'} -MaxEvents 100 -ErrorAction SilentlyContinue
        Out-RawObject ($ev | Select-Object TimeCreated, Id, LevelDisplayName, Message) 'Kernel-Processor-Power events'
        Out-Raw 'CONTEXT: Event ID 37 is logged when processor speed is limited by system firmware.'
    }

    Invoke-Collector 'Hypervisor presence' {
        $cs = Get-CimInstance Win32_ComputerSystem
        Out-KV 'HypervisorPresent' $cs.HypervisorPresent
        Out-KV 'Manufacturer' $cs.Manufacturer
        Out-KV 'Model' $cs.Model
        Out-Raw 'CONTEXT: HypervisorPresent is True both inside a VM and when VBS/Hyper-V is enabled on bare metal.'
    }

    Invoke-Collector 'powercfg energy trace (10s)' -NeedsAdmin {
        $out = Join-Path $script:Dirs.Raw 'powercfg_energy.html'
        Invoke-NativeCapture 'Energy trace' "powercfg /energy /output `"$out`" /duration 10"
        Out-KV 'Report written to' $out
    }
}

# =============================================================== 3. MEMORY
Invoke-Section 'Memory' 'memory' {

    Invoke-Collector 'Physical and virtual memory totals' {
        $os = Get-CimInstance Win32_OperatingSystem
        Out-KV 'TotalVisibleMemory_GB'  ([math]::Round($os.TotalVisibleMemorySize/1MB,3))
        Out-KV 'FreePhysicalMemory_GB'  ([math]::Round($os.FreePhysicalMemory/1MB,3))
        Out-KV 'TotalVirtualMemory_GB'  ([math]::Round($os.TotalVirtualMemorySize/1MB,3))
        Out-KV 'FreeVirtualMemory_GB'   ([math]::Round($os.FreeVirtualMemory/1MB,3))
        if ($os.TotalVisibleMemorySize -gt 0) {
            Out-KV 'UsedPhysicalPercent' ([math]::Round((($os.TotalVisibleMemorySize-$os.FreePhysicalMemory)/$os.TotalVisibleMemorySize)*100,2))
        } else {
            Out-KV 'UsedPhysicalPercent' '(TotalVisibleMemorySize reported as zero - cannot compute)'
        }
    }

    Invoke-Collector 'Memory performance counters' {
        $c = @('\Memory\Available MBytes','\Memory\Committed Bytes','\Memory\Commit Limit',
               '\Memory\% Committed Bytes In Use','\Memory\Pages/sec','\Memory\Page Faults/sec',
               '\Memory\Pages Input/sec','\Memory\Pages Output/sec','\Memory\Cache Bytes',
               '\Memory\Pool Paged Bytes','\Memory\Pool Nonpaged Bytes',
               '\Memory\Free System Page Table Entries','\Memory\Transition Pages RePurposed/sec',
               '\Memory\Demand Zero Faults/sec','\Memory\Standby Cache Normal Priority Bytes',
               '\Memory\Modified Page List Bytes','\Memory\Free & Zero Page List Bytes')
        foreach ($n in $c) {
            try {
                $s = Get-Counter $n -SampleInterval 1 -MaxSamples 3 -ErrorAction Stop
                Out-KV (($n -split '\\')[-1]) ([math]::Round((($s.CounterSamples | Measure-Object CookedValue -Average).Average),2))
            } catch { Out-KV (($n -split '\\')[-1]) "unavailable: $($_.Exception.Message)" }
        }
        Out-Raw ''
        Out-Raw 'CONTEXT: Pages/sec counts hard faults resolved from disk. Page Faults/sec includes soft faults resolved from RAM.'
        Out-Raw 'CONTEXT: Commit Limit = physical RAM + page file size. Committed Bytes can exceed physical RAM because the page file extends the limit.'
        Out-Raw 'CONTEXT: Free System PTEs are kernel virtual address mappings; the pool is sized dynamically on 64-bit Windows.'
    }

    Invoke-Collector 'Page file configuration and usage' {
        Out-RawList (Get-CimInstance Win32_PageFileUsage)   'Win32_PageFileUsage'
        Out-RawList (Get-CimInstance Win32_PageFileSetting) 'Win32_PageFileSetting'
        $mm = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -ErrorAction SilentlyContinue
        Out-RawList ($mm | Select-Object -Property * -ExcludeProperty PS*) 'Memory Management registry key'
        Out-Raw 'CONTEXT: DisablePagingExecutive 1 keeps kernel code resident. ClearPageFileAtShutdown 1 zeroes the page file on shutdown.'
    }

    Invoke-Collector 'Memory Compression process' {
        $mc = Get-Process 'Memory Compression' -ErrorAction SilentlyContinue
        if ($mc) {
            Out-KV 'WorkingSet_MB'     (ConvertTo-MB $mc.WorkingSet64)
            Out-KV 'PrivateBytes_MB'   (ConvertTo-MB $mc.PrivateMemorySize64)
        } else { Out-Raw 'Memory Compression process not found.' }
        Out-Raw 'CONTEXT: Windows compresses pages in RAM before writing to the page file; this process holds the compressed store.'
    }

    Invoke-Collector 'Process memory inventory (all processes)' {
        $rows = Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject]@{
                Name = $_.ProcessName; Id = $_.Id
                WorkingSet_MB   = ConvertTo-MB $_.WorkingSet64
                PrivateBytes_MB = ConvertTo-MB $_.PrivateMemorySize64
                PagedMem_MB     = ConvertTo-MB $_.PagedMemorySize64
                NonPagedMem_MB  = ConvertTo-MB $_.NonpagedSystemMemorySize64
                VirtualMem_MB   = ConvertTo-MB $_.VirtualMemorySize64
                PeakWS_MB       = ConvertTo-MB $_.PeakWorkingSet64
                Handles         = $_.HandleCount
                Threads         = $_.Threads.Count
            }
        } | Sort-Object WorkingSet_MB -Descending
        Out-RawObject $rows 'All processes by memory'
        Save-Csv  $rows 'memory_processes'
        Save-Json $rows 'memory_processes'
        Out-Raw 'CONTEXT: PrivateBytes is committed address space regardless of physical residence. WorkingSet is the subset currently in physical RAM. The difference is in the page file or has not been accessed.'
    }

    Invoke-Collector 'GDI and USER object counts per process' {
        try {
            if (-not ('Win32.WinDiagGdi' -as [type])) {   # must be namespace-qualified or this guard never matches
                Add-Type -Name WinDiagGdi -Namespace Win32 -MemberDefinition @'
[DllImport("user32.dll")] public static extern int GetGuiResources(IntPtr hProcess, int uiFlags);
'@ -ErrorAction Stop
            }
            $rows = Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
                $g = -1; $u = -1
                try { $g = [Win32.WinDiagGdi]::GetGuiResources($_.Handle, 0) } catch { }
                try { $u = [Win32.WinDiagGdi]::GetGuiResources($_.Handle, 1) } catch { }
                if ($g -gt 0 -or $u -gt 0) {
                    [pscustomobject]@{ Name = $_.ProcessName; Id = $_.Id; GDIObjects = $g; USERObjects = $u; Handles = $_.HandleCount }
                }
            } | Sort-Object GDIObjects -Descending
            Out-RawObject $rows 'GDI / USER object counts'
            Save-Csv $rows 'memory_gdi_user'
        } catch { Out-Raw "GetGuiResources unavailable: $($_.Exception.Message)" }
        Out-Raw 'CONTEXT: Default per-process quota is 10,000 GDI objects and 10,000 USER objects.'
    }

    Invoke-Collector 'Private memory growth over 30 seconds' {
        if ($script:Cfg.QuickScan) { Out-Raw 'Skipped in Quick mode.'; return }
        Out-Raw 'Sampling private bytes, waiting 30 seconds between snapshots...'
        $snap = @{}
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $snap[$_.Id] = $_.PrivateMemorySize64 }
        Start-Sleep -Seconds 30
        $rows = Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            if ($snap.ContainsKey($_.Id)) {
                $d = $_.PrivateMemorySize64 - $snap[$_.Id]
                [pscustomobject]@{
                    Name = $_.ProcessName; Id = $_.Id
                    DeltaMB = [math]::Round($d/1MB,2)
                    ExtrapolatedMBPerHour = [math]::Round(($d/1MB)*120,1)
                    CurrentPrivateMB = ConvertTo-MB $_.PrivateMemorySize64
                }
            }
        } | Sort-Object DeltaMB -Descending
        Out-RawObject $rows 'Private byte delta over 30s (all processes, sorted)'
        Out-Raw 'CONTEXT: Extrapolation assumes a constant rate; short-lived allocation spikes will overstate it.'
        Save-Csv $rows 'memory_growth_30s'
    }

    Invoke-Collector '.NET CLR heaps' {
        try {
            $s = Get-Counter '\.NET CLR Memory(*)\# Bytes in all Heaps' -ErrorAction Stop
            Out-RawObject ($s.CounterSamples | Where-Object { $_.InstanceName -notmatch '^(_global_)?$' } |
                Sort-Object CookedValue -Descending |
                Select-Object InstanceName, @{n='HeapMB';e={[math]::Round($_.CookedValue/1MB,1)}}) '.NET heap sizes'
        } catch { Out-Raw "CLR counters unavailable: $($_.Exception.Message)" }
    }

    Invoke-Collector 'WSL / Hyper-V vmmem reservation' {
        Out-RawObject (Get-Process vmmem*,vmwp -ErrorAction SilentlyContinue |
            Select-Object Name, Id, @{n='WS_MB';e={ConvertTo-MB $_.WorkingSet64}}) 'vmmem processes'
        Out-Raw 'CONTEXT: vmmem memory belongs to a Hyper-V/WSL2 virtual machine and is not released to the host until the VM stops.'
        Invoke-NativeCapture 'WSL distributions' 'wsl.exe --list --verbose'
    }
}

# =============================================================== 4. STORAGE
Invoke-Section 'Storage' 'storage' {

    Invoke-Collector 'Logical volumes' {
        $v = Get-CimInstance Win32_LogicalDisk
        Out-RawList $v 'Win32_LogicalDisk (all properties)'
        Out-RawObject ($v | Where-Object DriveType -eq 3 | Select-Object DeviceID, VolumeName, FileSystem,
            @{n='TotalGB';e={ConvertTo-GB $_.Size}}, @{n='FreeGB';e={ConvertTo-GB $_.FreeSpace}},
            @{n='FreePct';e={ if ($_.Size -gt 0) { [math]::Round(($_.FreeSpace/$_.Size)*100,2) } else { 0 } }}) 'Fixed disks summary'
        Save-Json $v 'storage_volumes'
    }

    Invoke-Collector 'Physical disks' {
        Out-RawList (Get-PhysicalDisk) 'Get-PhysicalDisk (all properties)'
        Out-RawList (Get-Disk)         'Get-Disk'
        Out-RawObject (Get-Partition)  'Get-Partition'
        Out-RawList (Get-CimInstance Win32_DiskDrive) 'Win32_DiskDrive'
    }

    Invoke-Collector 'SMART / storage reliability counters' -NeedsAdmin {
        foreach ($p in (Get-PhysicalDisk)) {
            Out-Raw ''
            Out-Raw ("Disk: {0}  (Serial {1})" -f $p.FriendlyName, $p.SerialNumber)
            $rc = $p | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue
            Out-RawList $rc 'StorageReliabilityCounter'
        }
        try {
            Out-RawObject (Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop) 'FailurePredictStatus'
        } catch { Out-Raw "FailurePredictStatus: $($_.Exception.Message)" }
        Out-Raw 'CONTEXT: Wear is reported as a percentage of rated endurance consumed. Temperature is in Celsius.'
    }

    Invoke-Collector 'TRIM, dirty bit, encryption, filter drivers' {
        Invoke-NativeCapture 'TRIM setting'  'fsutil behavior query DisableDeleteNotify'
        Out-Raw 'CONTEXT: DisableDeleteNotify 0 means TRIM is enabled.'
        foreach ($d in (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')) {
            Invoke-NativeCapture ("Dirty bit " + $d.DeviceID) ("fsutil dirty query " + $d.DeviceID)
        }
        Invoke-NativeCapture 'Filesystem filter drivers' 'fltmc filters' 'fltmc_filters.txt'
        Invoke-NativeCapture 'Filter instances'          'fltmc instances' 'fltmc_instances.txt'
        Out-Raw 'CONTEXT: Every registered minifilter sees each file I/O operation. Altitude determines ordering.'
        try { Out-RawObject (Get-BitlockerVolume | Select-Object MountPoint, VolumeStatus, EncryptionPercentage, ProtectionStatus) 'BitLocker' } catch { }
    }

    Invoke-Collector 'Volume fragmentation analysis' -NeedsAdmin {
        foreach ($d in (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')) {
            $l = $d.DeviceID.TrimEnd(':')
            try { Out-RawList (Optimize-Volume -DriveLetter $l -Analyze -Verbose 4>&1) ("Optimize-Volume -Analyze " + $d.DeviceID) }
            catch { Out-Raw "Analyze $($d.DeviceID): $($_.Exception.Message)" }
        }
    }

    Invoke-Collector 'Disk performance counters' {
        $c = @('\PhysicalDisk(_Total)\Current Disk Queue Length','\PhysicalDisk(_Total)\Avg. Disk Queue Length',
               '\PhysicalDisk(_Total)\Avg. Disk sec/Read','\PhysicalDisk(_Total)\Avg. Disk sec/Write',
               '\PhysicalDisk(_Total)\Disk Reads/sec','\PhysicalDisk(_Total)\Disk Writes/sec',
               '\PhysicalDisk(_Total)\Disk Bytes/sec','\PhysicalDisk(_Total)\% Idle Time')
        foreach ($n in $c) {
            try {
                $s = Get-Counter $n -SampleInterval 1 -MaxSamples 5 -ErrorAction Stop
                Out-KV (($n -split '\\')[-1]) ([math]::Round((($s.CounterSamples | Measure-Object CookedValue -Average).Average),5))
            } catch { Out-KV (($n -split '\\')[-1]) 'unavailable' }
        }
        Out-Raw 'CONTEXT: Avg. Disk sec/Read and sec/Write are in seconds; multiply by 1000 for milliseconds.'
    }

    Invoke-Collector 'VSS shadow storage and writers' -NeedsAdmin {
        Invoke-NativeCapture 'Shadow storage' 'vssadmin list shadowstorage' 'vss_shadowstorage.txt'
        Invoke-NativeCapture 'VSS writers'    'vssadmin list writers'       'vss_writers.txt'
    }

    Invoke-Collector 'NTFS volume flags and filesystem properties' {
        foreach ($v in (Get-Volume | Where-Object { $_.DriveLetter })) {
            Invoke-NativeCapture ("volumeinfo " + $v.DriveLetter) ("fsutil volumeinfo " + $v.DriveLetter + ":\")
        }
        Out-Raw 'CONTEXT: NTFS on-disk format version has been 3.1 since Windows XP and does not change on OS upgrade.'
    }

    Invoke-Collector 'NTFS MFT geometry and zone' -NeedsAdmin {
        foreach ($v in (Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter -and $_.FileSystem -eq 'NTFS' })) {
            Invoke-NativeCapture ("ntfsinfo " + $v.DriveLetter) ("fsutil fsinfo ntfsinfo " + $v.DriveLetter + ":\") ("ntfsinfo_" + $v.DriveLetter + ".txt")
        }
        Out-Raw 'CONTEXT: The MFT stores one 1024-byte record per file and directory. The MFT zone is a reserved region, 12.5% of volume capacity by default, kept clear so the MFT can grow contiguously.'
        Out-Raw 'CONTEXT: "Mft Valid Data Length" is the current in-use MFT size. Once the MFT grows beyond its zone the MFT itself fragments across the volume.'
        Out-Raw 'CONTEXT: Bytes Per Cluster is the NTFS allocation unit; the format-time default is 4096 for volumes under 16 TB.'
    }

    Invoke-Collector 'USN change journal configuration' -NeedsAdmin {
        foreach ($v in (Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter -and $_.FileSystem -eq 'NTFS' })) {
            Invoke-NativeCapture ("usn journal " + $v.DriveLetter) ("fsutil usn queryjournal " + $v.DriveLetter + ":\")
        }
        Out-Raw 'CONTEXT: The USN journal is a circular log of filesystem metadata changes. Search, antivirus, backup and replication agents read it for incremental change detection instead of scanning the whole tree.'
        Out-Raw 'CONTEXT: When the journal wraps faster than a consumer reads it, that consumer misses entries and falls back to a full volume scan. Format-time default maximum is typically 32-64 MB.'
    }

    Invoke-Collector 'NTFS behaviour settings (8.3 names, last access, quotas)' {
        Invoke-NativeCapture '8.3 name generation (global)' 'fsutil behavior query disable8dot3'
        Out-Raw 'CONTEXT: disable8dot3 values - 0 enabled everywhere, 1 disabled everywhere, 2 per-volume from the boot record, 3 per-volume from registry.'
        Out-Raw 'CONTEXT: When enabled, NTFS writes a second directory entry for every name that does not fit 8.3, roughly doubling directory-index work on create and delete.'
        Invoke-NativeCapture 'Last access timestamp policy' 'fsutil behavior query disablelastaccess'
        Out-Raw 'CONTEXT: disablelastaccess values - 0 and 2 user-managed with updates enabled, 1 and 3 system-managed. Vista and later default to 1. When updates are enabled every file read also writes an MFT timestamp.'
        Invoke-NativeCapture 'Memory usage behaviour' 'fsutil behavior query memoryusage'
        Invoke-NativeCapture 'MFT zone reservation'      'fsutil behavior query mftzone'
        foreach ($v in (Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter -and $_.FileSystem -eq 'NTFS' })) {
            Invoke-NativeCapture ("quota " + $v.DriveLetter) ("fsutil quota query " + $v.DriveLetter + ":\")
        }
        Out-RawObject (Get-CimInstance Win32_DiskQuota -ErrorAction SilentlyContinue) 'Win32_DiskQuota entries'
        Out-Raw 'CONTEXT: With hard quota enforcement active, a write that would exceed a user quota returns ERROR_DISK_FULL even when the volume has free space.'
    }

    Invoke-Collector 'Sector size and partition alignment' {
        foreach ($v in (Get-Volume | Where-Object { $_.DriveLetter })) {
            Invoke-NativeCapture ("sectorinfo " + $v.DriveLetter) ("fsutil fsinfo sectorinfo " + $v.DriveLetter + ":\")
        }
        Out-Raw ''
        Out-RawObject (Get-Disk -ErrorAction SilentlyContinue |
            Select-Object Number, FriendlyName, LogicalSectorSize, PhysicalSectorSize, PartitionStyle,
                @{n='SectorMode';e={
                    if ($_.PhysicalSectorSize -eq 4096 -and $_.LogicalSectorSize -eq 512)  { '512e (4K physical, 512 logical)' }
                    elseif ($_.PhysicalSectorSize -eq 4096 -and $_.LogicalSectorSize -eq 4096) { '4Kn (native 4K)' }
                    else { '512n or other' } }}) 'Disk sector geometry'
        Out-Raw 'CONTEXT: 512e means the drive has 4096-byte physical sectors emulated as 512-byte logical sectors; a write that does not align to the physical sector forces a read-modify-write inside the drive.'
        Out-Raw ''
        Out-RawObject (Get-CimInstance Win32_DiskPartition |
            Select-Object DiskIndex, Index, Name, StartingOffset, BlockSize, NumberOfBlocks, Type, Bootable,
                @{n='Offset_MiB';e={[math]::Round($_.StartingOffset/1MB,3)}},
                @{n='DivisibleBy4096';e={($_.StartingOffset % 4096) -eq 0}},
                @{n='DivisibleBy1MiB';e={($_.StartingOffset % 1048576) -eq 0}} |
            Sort-Object DiskIndex, Index) 'Partition starting offsets'
        Out-Raw 'CONTEXT: The legacy MBR default started partitions at sector 63 - offset 32,256 bytes, which is not divisible by 4096. Vista and later default the first data partition to a 1 MiB (1,048,576 byte) offset, which satisfies 512n, 512e, 4Kn and common RAID stripe sizes.'
    }

    Invoke-Collector 'SMART raw attribute and threshold arrays' -NeedsAdmin {
        foreach ($cls in @('MSStorageDriver_FailurePredictStatus','MSStorageDriver_FailurePredictData',
                           'MSStorageDriver_FailurePredictThresholds','MSStorageDriver_FailurePredictEvent')) {
            Out-Raw ''
            Out-Raw "### $cls"
            try { Out-RawList (Get-CimInstance -Namespace root\wmi -ClassName $cls -ErrorAction Stop) '' }
            catch { Out-Raw ("  unavailable: " + $_.Exception.Message) }
        }
        # Decode the ATA attribute table out of the raw vendor array.
        try {
            foreach ($d in (Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictData -ErrorAction Stop)) {
                Out-Raw ''
                Out-Raw ('### Decoded SMART attributes: ' + $d.InstanceName)
                $b = $d.VendorSpecific
                if ($b -and $b.Length -ge 362) {
                    $rows = @()
                    for ($i = 2; $i -lt 362; $i += 12) {
                        $id = $b[$i]
                        if ($id -eq 0) { continue }
                        $raw = 0
                        for ($k = 5; $k -ge 0; $k--) { $raw = ($raw * 256) + $b[$i + 5 + $k] }
                        $rows += [pscustomobject]@{
                            AttrId = $id; Flags = $b[$i+1]
                            Current = $b[$i+3]; Worst = $b[$i+4]; RawValue = $raw
                        }
                    }
                    Out-RawObject $rows 'ATA attribute table (12-byte entries from offset 2)'
                }
            }
        } catch { Out-Raw ("Decode skipped: " + $_.Exception.Message) }
        Out-Raw 'CONTEXT: The vendor array is a 512-byte dump. The ATA layout packs 12-byte entries from offset 2: attribute id, status flags, current value, worst value, then a 6-byte little-endian raw value.'
        Out-Raw 'CONTEXT: Attribute ids commonly cited as predictive - 5 Reallocated Sector Count, 187 Reported Uncorrectable Errors, 197 Current Pending Sector Count, 198 Offline Uncorrectable Sector Count. Current and Worst are normalised 1-253 scales where higher is better; RawValue is vendor-defined.'
    }

    Invoke-Collector 'NVMe and storage controller PCIe link properties' {
        $devs = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
            $_.Class -eq 'DiskDrive' -or $_.Class -eq 'SCSIAdapter' -or
            $_.FriendlyName -match 'NVMe|NVM Express|AHCI|RAID|SATA|SSD' }
        Out-RawObject ($devs | Select-Object FriendlyName, Class, Status, InstanceId) 'Storage devices'
        foreach ($d in $devs) {
            Out-Raw ''
            Out-Raw ('### ' + $d.FriendlyName)
            Out-RawObject (Get-PnpDeviceProperty -InstanceId $d.InstanceId -ErrorAction SilentlyContinue |
                Select-Object KeyName, Type, Data) 'All PnP properties'
        }
        Out-Raw ''
        Out-Raw 'CONTEXT: PnP property key {3AB22E31-8264-4B4E-9AF5-A8D2D8E33E62} indices 2=MaxLinkSpeed 3=MaxLinkWidth 4=CurrentLinkSpeed 5=CurrentLinkWidth.'
        Out-Raw 'CONTEXT: Link speed values - 1 = 2.5 GT/s Gen1, 2 = 5 GT/s Gen2, 3 = 8 GT/s Gen3, 4 = 16 GT/s Gen4, 5 = 32 GT/s Gen5. Width values are the lane count.'
        Out-Raw 'CONTEXT: Approximate ceilings at x4 width - Gen3 3.9 GB/s, Gen4 7.9 GB/s, Gen5 15.8 GB/s. A current link below the max link means the device negotiated down from what it supports.'
    }

    Invoke-Collector 'Write cache and physical disk full properties' {
        Out-RawList (Get-PhysicalDisk -ErrorAction SilentlyContinue) 'Get-PhysicalDisk (all properties)'
        foreach ($p in (Get-PhysicalDisk -ErrorAction SilentlyContinue)) {
            Out-Raw ''
            Out-Raw ('### Storage node view: ' + $p.FriendlyName)
            try { Out-RawList ($p | Get-PhysicalDiskStorageNodeView -ErrorAction Stop) '' } catch { Out-Raw ('  ' + $_.Exception.Message) }
        }
        Out-Raw 'CONTEXT: Write caching buffers acknowledged-but-uncommitted writes in volatile on-drive DRAM. A null WriteCacheEnabled means the miniport does not report the property, which is not the same as it being disabled.'
    }

    Invoke-Collector 'Storage Spaces pools, virtual disks, tiers and jobs' {
        Out-RawList (Get-StoragePool  -ErrorAction SilentlyContinue) 'Storage pools'
        Out-RawList (Get-VirtualDisk  -ErrorAction SilentlyContinue) 'Virtual disks'
        Out-RawList (Get-StorageTier  -ErrorAction SilentlyContinue) 'Storage tiers'
        Out-RawList (Get-StorageJob   -ErrorAction SilentlyContinue) 'Active storage jobs'
        Out-Raw 'CONTEXT: Resilience types - Simple is striped with no redundancy, Mirror writes to N disks, Parity is RAID-5/6 equivalent and carries write amplification plus parity computation.'
        Out-Raw 'CONTEXT: A virtual disk reporting Degraded runs rebuild I/O in the background concurrently with normal I/O. Get-StorageJob surfaces rebuild, resync and initialisation work.'
    }

    Invoke-Collector 'Data Deduplication' {
        if (Get-Command Get-DedupVolume -ErrorAction SilentlyContinue) {
            Out-RawList (Get-DedupVolume   -ErrorAction SilentlyContinue) 'Dedup volumes'
            Out-RawList (Get-DedupStatus   -ErrorAction SilentlyContinue) 'Dedup status'
            Out-RawList (Get-DedupSchedule -ErrorAction SilentlyContinue) 'Dedup schedule'
            Out-RawList (Get-DedupJob      -ErrorAction SilentlyContinue) 'Active dedup jobs'
        } else {
            Out-Raw 'Data Deduplication cmdlets not present. The feature is a Windows Server role service and is not installable on Windows 10/11 client.'
        }
    }

    Invoke-Collector 'Page file host drive media type' {
        Out-RawList (Get-CimInstance Win32_PageFileSetting -ErrorAction SilentlyContinue) 'Page file settings'
        Out-RawList (Get-CimInstance Win32_PageFileUsage   -ErrorAction SilentlyContinue) 'Page file usage'
        foreach ($d in (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')) {
            $pf = Join-Path ($d.DeviceID + '\') 'pagefile.sys'
            if (Test-Path $pf) {
                $f = Get-Item $pf -Force -ErrorAction SilentlyContinue
                $letter = $d.DeviceID.TrimEnd(':')
                $part = Get-Partition -DriveLetter $letter -ErrorAction SilentlyContinue
                $media = 'unknown'; $bus = 'unknown'
                if ($part) {
                    $pd = Get-PhysicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.DeviceId -eq "$($part.DiskNumber)" }
                    if ($pd) { $media = $pd.MediaType; $bus = $pd.BusType }
                }
                Out-KV $pf ('{0} GB, disk media {1}, bus {2}' -f [math]::Round($f.Length/1GB,2), $media, $bus)
            }
        }
        Out-Raw 'CONTEXT: Page file read latency determines how long a hard page fault stalls the faulting thread, so the media type and bus of the hosting disk bound that latency.'
        Out-Raw 'CONTEXT: PeakUsage equal to AllocatedBaseSize means the file reached its current size ceiling at least once since boot.'
    }

    Invoke-Collector 'Per-process cumulative I/O counters' {
        Out-RawObject (Get-CimInstance Win32_Process |
            Select-Object Name, ProcessId, CreationDate,
                ReadOperationCount, WriteOperationCount, OtherOperationCount,
                @{n='ReadMB';e={ConvertTo-MB $_.ReadTransferCount}},
                @{n='WriteMB';e={ConvertTo-MB $_.WriteTransferCount}},
                @{n='OtherMB';e={ConvertTo-MB $_.OtherTransferCount}} |
            Sort-Object WriteMB -Descending) 'Cumulative I/O since process start'
        Out-Raw 'CONTEXT: These are lifetime totals since process creation, not rates. A rate needs two samples over a known interval.'
        Out-Raw 'CONTEXT: OtherTransferCount is metadata I/O - directory enumerations, attribute queries, security descriptor reads - which is more latency-sensitive than sequential data I/O.'
    }

    Invoke-Collector 'Reparse points, junctions and symbolic links' {
        Out-RawObject (Get-ChildItem 'C:\' -Recurse -Depth 5 -Force -Attributes ReparsePoint -ErrorAction SilentlyContinue |
            Select-Object FullName, Attributes, LinkType, @{n='Target';e={$_.Target -join '; '}}, LastWriteTime) 'Reparse points under C:\ to depth 5'
        Out-Raw 'CONTEXT: Reparse tag 0xA0000003 is a mount point or directory junction, 0xA000000C is a symbolic link.'
        Out-Raw 'CONTEXT: "C:\Users\Default User" -> "C:\Users\Default" and "C:\Documents and Settings" -> "C:\Users" are intentional OS junctions present on every installation.'
        Out-Raw 'CONTEXT: A junction whose target is an ancestor of itself creates a traversal loop; recursive scanners entering it continue until they hit a path-length limit.'
    }

    Invoke-Collector 'Recycle Bin per volume' {
        foreach ($d in (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')) {
            $rb = $d.DeviceID + '\$Recycle.Bin'
            Out-Raw ''
            Out-Raw "### $rb"
            if (Test-Path $rb -ErrorAction SilentlyContinue) {
                $items = Get-ChildItem $rb -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer }
                Out-KV '  item count' (@($items).Count)
                Out-KV '  total MB'   (ConvertTo-MB (($items | Measure-Object Length -Sum).Sum))
            } else { Out-Raw '  not present or not accessible' }
        }
        Out-Raw 'CONTEXT: Recycled items still occupy volume space. Each deleted item is stored as a pair: $I<hash> holding the original path, deletion time and size, and $R<hash> holding the data.'
    }

    Invoke-Collector 'Pending chkdsk and disk error event history' {
        Out-RawList (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name BootExecute -ErrorAction SilentlyContinue |
            Select-Object BootExecute) 'BootExecute'
        Out-Raw 'CONTEXT: The default BootExecute value is "autocheck autochk *", which checks only volumes carrying the dirty bit. An explicit /f entry forces a full check of the named volume at next boot.'
        foreach ($p in @('Microsoft-Windows-Chkdsk','Wininit')) {
            Out-RawObject (Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName=$p} -MaxEvents 40 -ErrorAction SilentlyContinue |
                Select-Object TimeCreated, Id, LevelDisplayName, Message) "Application log: $p"
        }
        # Get-WinEvent -FilterHashtable rejects the WHOLE filter with "The
        # parameter is incorrect" when even one named provider is not registered
        # on this machine, and storage miniport providers vary by hardware. So
        # resolve against what is actually registered, then query each provider
        # separately so one absentee cannot void the rest.
        $storProviders = @('disk','Ntfs','storport','stornvme','iaStor','iaStorA','iaStorAVC','atapi','volsnap','vhdmp')
        $registered = @()
        try { $registered = @(Get-WinEvent -ListProvider * -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name) } catch { }
        Out-KV 'storage providers present'      (($storProviders | Where-Object { $registered -contains $_ }) -join ', ')
        Out-KV 'storage providers not present'  (($storProviders | Where-Object { $registered -notcontains $_ }) -join ', ')
        Out-Raw 'CONTEXT: A provider listed as not present is not registered on this machine, which is normal - storage miniport providers depend on the controller and driver in use.'
        foreach ($prov in $storProviders) {
            if ($registered -notcontains $prov) { continue }
            try {
                $pe = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName=$prov} -MaxEvents 200 -ErrorAction Stop
                Out-RawObject ($pe | Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message) ("System log provider: " + $prov)
            } catch {
                Out-Raw ("  provider '" + $prov + "': " + $_.Exception.Message)
            }
        }
        Out-Raw 'CONTEXT: disk event 7 and 11 are hardware errors, 51 is a paging error during I/O, Ntfs 55 is filesystem structure corruption, storport records I/O timeouts and retries.'
    }

    Invoke-Collector 'System restore points' {
        try { Out-RawList (Get-ComputerRestorePoint -ErrorAction Stop) 'Restore points' }
        catch { Out-Raw ("Get-ComputerRestorePoint: " + $_.Exception.Message) }
        Out-RawList (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' -ErrorAction SilentlyContinue |
            Select-Object -Property * -ExcludeProperty PS*) 'System Restore configuration'
        Out-Raw 'CONTEXT: RestorePointType values - 0 application install, 1 application uninstall, 6 manual restore, 7 scheduled checkpoint, 10 device driver install, 12 system restore.'
        Out-Raw 'CONTEXT: Restore points consume VSS shadow storage. When the allocation fills, the oldest is deleted automatically.'
    }

    Invoke-Collector 'WinSAT disk assessment' {
        Out-RawList (Get-CimInstance Win32_WinSAT -ErrorAction SilentlyContinue) 'Win32_WinSAT'
        Out-Raw 'CONTEXT: DiskScore is a unitless 1.0-9.9 value derived mainly from sequential throughput. WinSAT does not run automatically on Windows 10/11, so a stored assessment can be years old - read TimeTaken before using the score.'
        Out-Raw 'CONTEXT: The assessment does not measure random I/O, queue-depth behaviour or latency.'
        $ws = "$env:windir\Performance\WinSAT\DataStore"
        if (Test-Path $ws) {
            Out-RawObject (Get-ChildItem $ws -Filter '*.xml' -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object Name, Length, LastWriteTime) 'WinSAT data store'
        }
    }

    Invoke-Collector 'Disk to partition to volume chain' {
        Out-RawList (Get-CimInstance Win32_DiskDrive)              'Win32_DiskDrive'
        Out-RawObject (Get-CimInstance Win32_DiskPartition)        'Win32_DiskPartition'
        Out-RawObject (Get-CimInstance Win32_LogicalDiskToPartition) 'LogicalDiskToPartition associations'
        Out-Raw 'CONTEXT: Win32_DiskDrive.Index matches the \\.\PhysicalDriveN device path and the PhysicalDisk(N) performance counter instance name, which is how counter data is correlated with drive-letter data.'
    }

    Invoke-Collector 'High-file-count directories' {
        $risk = @("$env:USERPROFILE\node_modules", "$env:APPDATA\npm\node_modules", "$env:LOCALAPPDATA\npm-cache",
                  "$env:USERPROFILE\.nuget\packages", "$env:LOCALAPPDATA\pip\Cache", $env:TEMP, "$env:SystemRoot\Temp",
                  "$env:USERPROFILE\.gradle\caches", "$env:USERPROFILE\.m2\repository",
                  "$env:USERPROFILE\.cargo\registry", "$env:SystemRoot\Prefetch",
                  "$env:SystemRoot\System32\winevt\Logs", "$env:SystemRoot\Installer")
        foreach ($p in $risk) {
            if ($p -and (Test-Path $p -ErrorAction SilentlyContinue)) {
                try {
                    Out-KV $p ('{0} immediate files, {1} immediate subdirectories' -f `
                        ([System.IO.Directory]::GetFiles($p).Count), ([System.IO.Directory]::GetDirectories($p).Count))
                } catch { Out-KV $p ('access error: ' + $_.Exception.Message) }
            }
        }
        Out-Raw 'CONTEXT: NTFS resolves a name within a directory through the $I30 index B-tree, so lookup cost grows with the number of entries in that single directory. NTFS sets no hard per-directory limit.'
        Out-Raw 'CONTEXT: node_modules trees commonly reach several hundred thousand files; .git/objects shards across two levels but can hold millions of loose objects in a long-lived repository.'
    }

    Invoke-Collector 'Known space consumers' {
        $paths = @(
            @{N='User TEMP';                P=$env:TEMP},
            @{N='Windows TEMP';             P="$env:SystemRoot\Temp"},
            @{N='Windows Update download';  P="$env:SystemRoot\SoftwareDistribution\Download"},
            @{N='Delivery Optimization';    P="$env:SystemRoot\SoftwareDistribution\DeliveryOptimization"},
            @{N='WinSxS';                   P="$env:SystemRoot\WinSxS"},
            @{N='Installer cache';          P="$env:SystemRoot\Installer"},
            @{N='Prefetch';                 P="$env:SystemRoot\Prefetch"},
            @{N='Windows.old';              P="$env:SystemDrive\Windows.old"},
            @{N='Minidumps';                P="$env:SystemRoot\Minidump"},
            @{N='CrashDumps';               P="$env:LOCALAPPDATA\CrashDumps"},
            @{N='WER';                      P="$env:PROGRAMDATA\Microsoft\Windows\WER"},
            @{N='Recycle Bin';              P="$env:SystemDrive\`$Recycle.Bin"},
            @{N='Search index';             P="$env:PROGRAMDATA\Microsoft\Search\Data"},
            @{N='Thumbnail cache';          P="$env:LOCALAPPDATA\Microsoft\Windows\Explorer"},
            @{N='npm cache';                P="$env:APPDATA\npm-cache"},
            @{N='pip cache';                P="$env:LOCALAPPDATA\pip\Cache"},
            @{N='NuGet packages';           P="$env:USERPROFILE\.nuget\packages"},
            @{N='Docker';                   P="$env:LOCALAPPDATA\Docker"},
            @{N='Downloads';                P="$env:USERPROFILE\Downloads"}
        )
        $rows = foreach ($p in $paths) {
            $r = Get-FolderSize $p.P
            [pscustomobject]@{ Location = $p.N; SizeGB = ConvertTo-GB $r.Bytes; Files = $r.Files; Truncated = $r.Truncated; Path = $p.P }
        }
        Out-RawObject ($rows | Sort-Object SizeGB -Descending) 'Known consumers'
        Save-Csv $rows 'storage_known_consumers'
        $hib = "$env:SystemDrive\hiberfil.sys"
        if (Test-Path $hib) { Out-KV 'hiberfil.sys GB' (ConvertTo-GB (Get-Item $hib -Force).Length) }
        $pgf = "$env:SystemDrive\pagefile.sys"
        if (Test-Path $pgf) { Out-KV 'pagefile.sys GB' (ConvertTo-GB (Get-Item $pgf -Force).Length) }
    }

    Invoke-Collector 'Largest folders' {
        if ($script:Cfg.QuickScan) { Out-Raw 'Skipped in Quick mode.'; return }
        $roots = @($env:USERPROFILE, $env:LOCALAPPDATA, $env:APPDATA, $env:ProgramData,
                   $env:ProgramFiles, ${env:ProgramFiles(x86)}) |
                 Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
        $all = @()
        foreach ($root in $roots) {
            Out-Raw ''
            Out-Raw ("### Under $root")
            $rows = @()
            foreach ($k in (Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue)) {
                $r = Get-FolderSize $k.FullName
                if ($r.Bytes -gt 10MB) {
                    $rows += [pscustomobject]@{ SizeGB = ConvertTo-GB $r.Bytes; Files = $r.Files; Path = $k.FullName }
                }
            }
            $rows = $rows | Sort-Object SizeGB -Descending | Select-Object -First $script:Limits.TopFolders
            Out-RawObject $rows
            $all += $rows
        }
        Save-Csv $all 'storage_top_folders'
    }

    Invoke-Collector 'Largest files' {
        if ($script:Cfg.QuickScan) { Out-Raw 'Skipped in Quick mode.'; return }
        $rows = @()
        foreach ($root in @($env:USERPROFILE, $env:ProgramData, "$env:SystemRoot\Logs")) {
            if (-not (Test-Path $root)) { continue }
            $rows += Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue |
                     Where-Object { $_.Length -gt 200MB } |
                     Select-Object @{n='SizeGB';e={ConvertTo-GB $_.Length}}, LastWriteTime, FullName
        }
        $rows = $rows | Sort-Object SizeGB -Descending | Select-Object -First $script:Limits.TopFiles
        Out-RawObject $rows 'Files over 200 MB'
        Save-Csv $rows 'storage_top_files'
    }

    Invoke-Collector 'Cloud sync clients' {
        foreach ($n in @('OneDrive','Dropbox','googledrivesync','GoogleDriveFS','Box','egnyte')) {
            $p = Get-Process $n -ErrorAction SilentlyContinue
            if ($p) { Out-RawObject ($p | Select-Object Name, Id, @{n='WS_MB';e={ConvertTo-MB $_.WorkingSet64}}, @{n='CPUSec';e={[math]::Round($_.CPU,1)}}) "$n processes" }
        }
        foreach ($d in @("$env:USERPROFILE\OneDrive","$env:USERPROFILE\Dropbox","$env:USERPROFILE\Google Drive")) {
            if (Test-Path $d) { $r = Get-FolderSize $d; Out-KV "$d GB" (ConvertTo-GB $r.Bytes) }
        }
    }
}

# =============================================================== 5. PROCESSES
Invoke-Section 'Processes and Services' 'processes' {

    Invoke-Collector 'Full process inventory with command lines' {
        $procs = Get-CimInstance Win32_Process
        $rows = foreach ($p in $procs) {
            $ps = Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue
            [pscustomobject]@{
                Name = $p.Name; PID = $p.ProcessId; PPID = $p.ParentProcessId
                Path = $p.ExecutablePath
                CommandLine = $p.CommandLine
                CreationDate = $p.CreationDate
                WS_MB = ConvertTo-MB $p.WorkingSetSize
                Handles = $p.HandleCount
                Threads = $p.ThreadCount
                Priority = $p.Priority
                ReadMB = ConvertTo-MB $p.ReadTransferCount
                WriteMB = ConvertTo-MB $p.WriteTransferCount
                Company = if ($ps) { $ps.Company } else { $null }
                Product = if ($ps) { $ps.Product } else { $null }
            }
        }
        Out-RawObject ($rows | Sort-Object WS_MB -Descending) 'All processes'
        Save-Csv  $rows 'processes_all'
        Save-Json $rows 'processes_all' 4
    }

    Invoke-Collector 'Process count grouped by executable name' {
        Out-RawObject (Get-Process | Group-Object ProcessName | Sort-Object Count -Descending |
            Select-Object @{n='Process';e={$_.Name}}, Count,
                          @{n='TotalWS_MB';e={ConvertTo-MB (($_.Group | Measure-Object WorkingSet64 -Sum).Sum)}}) 'Instance counts'
        Out-KV 'Total process count' (Get-Process).Count
        Out-Raw 'CONTEXT: Chromium-based browsers spawn one renderer process per site-isolated origin.'
    }

    Invoke-Collector 'Digital signature status of running executables' {
        $rows = Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath } |
            Select-Object -Unique ExecutablePath | ForEach-Object {
                $sig = Get-AuthenticodeSignature $_.ExecutablePath -ErrorAction SilentlyContinue
                [pscustomobject]@{
                    Path = $_.ExecutablePath
                    Status = if ($sig) { $sig.Status } else { 'Unknown' }
                    Signer = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
                }
            }
        Out-RawObject ($rows | Sort-Object Status, Path) 'Signature status of running images'
        Save-Csv $rows 'processes_signatures'
        Out-Raw 'CONTEXT: Status Valid means the Authenticode signature verified. NotSigned means no embedded signature was present.'
    }

    Invoke-Collector 'Loaded modules per process (Deep mode only)' {
        if (-not $script:Cfg.DeepScan) { Out-Raw 'Collected in Deep mode only.'; return }
        foreach ($p in (Get-Process -ErrorAction SilentlyContinue | Sort-Object WorkingSet64 -Descending | Select-Object -First 25)) {
            Out-Raw ''
            Out-Raw ("### Modules for $($p.ProcessName) [$($p.Id)]")
            try { Out-RawObject ($p.Modules | Select-Object ModuleName, FileName, FileVersion) } catch { Out-Raw "  (access denied)" }
        }
    }

    Invoke-Collector 'All services' {
        $svc = Get-CimInstance Win32_Service
        Out-RawObject ($svc | Select-Object Name, DisplayName, State, StartMode, StartName, ProcessId, PathName | Sort-Object Name) 'Win32_Service (complete)'
        Save-Csv  $svc 'services_all'
        Save-Json $svc 'services_all' 4
        Out-KV 'Total services'        (@($svc).Count)
        Out-KV 'Running'               (@($svc | Where-Object State -eq 'Running').Count)
        Out-KV 'Automatic'             (@($svc | Where-Object StartMode -eq 'Auto').Count)
        Out-KV 'Automatic not running' (@($svc | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' }).Count)
    }

    Invoke-Collector 'Non-Microsoft running services' {
        Out-RawObject (Get-CimInstance Win32_Service |
            Where-Object { $_.State -eq 'Running' -and $_.PathName -notlike "*$env:SystemRoot*" } |
            Select-Object Name, DisplayName, StartMode, StartName, PathName | Sort-Object Name) 'Third-party running services'
    }

    Invoke-Collector 'Service recovery configuration' {
        Invoke-NativeCapture 'sc queryex' 'sc queryex type= service state= all' 'sc_queryex.txt'
    }
}

# =============================================================== 6. STARTUP
Invoke-Section 'Startup and Drivers' 'startup' {

    Invoke-Collector 'Registry Run keys' {
        $keys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        )
        $rows = foreach ($k in $keys) {
            if (Test-Path $k) {
                $p = Get-ItemProperty $k
                foreach ($prop in $p.PSObject.Properties) {
                    if ($prop.Name -notmatch '^PS') {
                        [pscustomobject]@{ Key = $k; Name = $prop.Name; Command = $prop.Value }
                    }
                }
            }
        }
        Out-RawObject $rows 'Run key entries'
        Save-Csv $rows 'startup_runkeys'
    }

    Invoke-Collector 'Startup folders' {
        foreach ($f in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
            if (Test-Path $f) { Out-RawObject (Get-ChildItem $f -Force | Select-Object Name, Length, LastWriteTime, FullName) $f }
        }
    }

    Invoke-Collector 'Scheduled tasks (complete)' {
        $t = Get-ScheduledTask -ErrorAction SilentlyContinue
        $rows = foreach ($x in $t) {
            $i = $x | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            [pscustomobject]@{
                TaskName = $x.TaskName; TaskPath = $x.TaskPath; State = $x.State
                Author = $x.Author
                LastRunTime = if ($i) { $i.LastRunTime } else { $null }
                NextRunTime = if ($i) { $i.NextRunTime } else { $null }
                LastResult  = if ($i) { $i.LastTaskResult } else { $null }
                Actions = ($x.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ' ; '
            }
        }
        Out-RawObject ($rows | Sort-Object TaskPath, TaskName) 'All scheduled tasks'
        Save-Csv $rows 'startup_scheduledtasks'
        Out-RawObject ($rows | Where-Object State -eq 'Running') 'Tasks currently running'
    }

    Invoke-Collector 'Shell extensions and context menu handlers' {
        $roots = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved',
            'HKLM:\SOFTWARE\Classes\*\shellex\ContextMenuHandlers',
            'HKLM:\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers',
            'HKLM:\SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers',
            'HKLM:\SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers'
        )
        foreach ($r in $roots) {
            if (Test-Path $r) {
                Out-Raw ''
                Out-Raw "### $r"
                try { Out-RawList (Get-ItemProperty $r | Select-Object -Property * -ExcludeProperty PS*) } catch { }
                Out-RawObject (Get-ChildItem $r -ErrorAction SilentlyContinue | ForEach-Object {
                    $d = (Get-ItemProperty $_.PSPath -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                    $n = $null
                    if ($d) { $n = (Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$d\InprocServer32" -Name '(default)' -ErrorAction SilentlyContinue).'(default)' }
                    [pscustomobject]@{ Handler = $_.PSChildName; CLSID = $d; DLL = $n }
                })
            }
        }
        Out-Raw 'CONTEXT: Shell extensions load into explorer.exe and every common file dialog.'
    }

    Invoke-Collector 'Drivers (complete inventory)' {
        $d = Get-CimInstance Win32_SystemDriver
        Out-RawObject ($d | Select-Object Name, DisplayName, State, StartMode, PathName | Sort-Object Name) 'Win32_SystemDriver'
        Save-Csv $d 'drivers_system'
        $sd = Get-CimInstance Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, DriverDate, Manufacturer, DriverProviderName, InfName, IsSigned
        Out-RawObject ($sd | Sort-Object DriverDate) 'Win32_PnPSignedDriver (sorted oldest first)'
        Save-Csv $sd 'drivers_signed'
        Out-Raw 'CONTEXT: DriverDate is the INF date, not the install date.'
    }

    Invoke-Collector 'Non-Microsoft kernel drivers' {
        Out-RawObject (Get-CimInstance Win32_SystemDriver |
            Where-Object { $_.State -eq 'Running' -and $_.PathName -notmatch '\\Windows\\System32\\drivers\\' } |
            Select-Object Name, DisplayName, PathName, StartMode) 'Running drivers outside System32\drivers'
    }

    Invoke-Collector 'Pending file rename operations' {
        $sm = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue
        $p = $sm.PendingFileRenameOperations
        Out-KV 'RawEntryCount' (@($p).Count)
        Out-Raw 'CONTEXT: Entries are stored in pairs (source, destination). An empty destination means delete on reboot.'
        if ($p) { foreach ($e in $p) { Out-Raw "  $e" } }
    }
}

# =============================================================== 7. NETWORK
Invoke-Section 'Network' 'network' {

    Invoke-Collector 'Adapters and configuration' {
        Out-RawList (Get-NetAdapter) 'Get-NetAdapter (all properties)'
        Out-RawList (Get-NetIPConfiguration -Detailed -ErrorAction SilentlyContinue) 'Get-NetIPConfiguration'
        Out-RawObject (Get-NetIPAddress | Select-Object InterfaceAlias, AddressFamily, IPAddress, PrefixLength, SuffixOrigin, AddressState) 'IP addresses'
        Out-RawObject (Get-NetRoute | Sort-Object RouteMetric) 'Routing table'
        Out-RawObject (Get-NetNeighbor -ErrorAction SilentlyContinue | Where-Object State -ne 'Permanent') 'ARP / neighbour cache'
        Save-Json (Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress, DriverVersion, DriverDate) 'net_adapters'
    }

    Invoke-Collector 'Adapter statistics since boot' {
        Out-RawObject (Get-NetAdapterStatistics | Select-Object Name,
            @{n='RecvGB';e={ConvertTo-GB $_.ReceivedBytes}}, @{n='SentGB';e={ConvertTo-GB $_.SentBytes}},
            ReceivedUnicastPackets, SentUnicastPackets, ReceivedDiscardedPackets, ReceivedPacketErrors,
            OutboundDiscardedPackets, OutboundPacketErrors) 'Adapter statistics'
    }

    Invoke-Collector '30-day data usage per network profile' {
        Add-Type -AssemblyName System.Runtime.WindowsRuntime
        $m = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
                $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
                $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
        if ($null -eq $m) {
            Out-Raw 'SKIPPED: the AsTask overload for IAsyncOperation`1 was not found on this runtime, so WinRT usage data cannot be read. This is absent data, not zero usage.'
            return
        }
        [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime] | Out-Null
        [Windows.Networking.Connectivity.NetworkUsage,Windows.Networking.Connectivity,ContentType=WindowsRuntime] | Out-Null
        $end = [DateTimeOffset]::Now; $start = $end.AddDays(-30)
        $st = New-Object Windows.Networking.Connectivity.NetworkUsageStates
        $st.Roaming = [Windows.Networking.Connectivity.TriStates]::DoNotCare
        $st.Shared  = [Windows.Networking.Connectivity.TriStates]::DoNotCare
        $rows = @()
        foreach ($p in [Windows.Networking.Connectivity.NetworkInformation]::GetConnectionProfiles()) {
            try {
                $op = $p.GetNetworkUsageAsync($start,$end,[Windows.Networking.Connectivity.DataUsageGranularity]::Total,$st)
                $t = $m.MakeGenericMethod([System.Collections.Generic.IReadOnlyList[Windows.Networking.Connectivity.NetworkUsage]]).Invoke($null,@($op))
                # -1 is Timeout.Infinite. A wedged Network List Manager would
                # hang the entire run, once per saved network profile.
                if (-not $t.Wait(15000)) { Out-Raw ("  [profile '" + $p.ProfileName + "' timed out after 15s - skipped]"); continue }
                $r=0;$s=0; foreach ($u in $t.Result) { $r+=$u.BytesReceived; $s+=$u.BytesSent }
                if (($r+$s) -gt 0) { $rows += [pscustomobject]@{ Profile=$p.ProfileName; RecvGB=ConvertTo-GB $r; SentGB=ConvertTo-GB $s; TotalGB=ConvertTo-GB ($r+$s) } }
            } catch { }
        }
        Out-RawObject $rows '30-day usage by profile'
        Save-Json $rows 'net_usage_30d'
    }

    Invoke-Collector 'Wi-Fi state and profiles' {
        Invoke-NativeCapture 'Interfaces'      'netsh wlan show interfaces'  'wlan_interfaces.txt'
        Invoke-NativeCapture 'Networks (BSSID)' 'netsh wlan show networks mode=bssid' 'wlan_networks.txt'
        Invoke-NativeCapture 'Profiles'        'netsh wlan show profiles'    'wlan_profiles.txt'
        Invoke-NativeCapture 'Drivers'         'netsh wlan show drivers'     'wlan_drivers.txt'
        Out-Raw 'CONTEXT: 2.4GHz has three non-overlapping 20MHz channels (1, 6, 11). 5GHz and 6GHz have many more.'
    }

    Invoke-Collector 'DNS configuration, cache and resolution timing' {
        Out-RawObject (Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses }) 'Configured DNS servers'
        Out-RawObject (Get-DnsClientGlobalSetting) 'DNS global settings'
        foreach ($h in @('www.microsoft.com','www.google.com')) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $r = Resolve-DnsName $h -ErrorAction SilentlyContinue
            $sw.Stop()
            Out-KV "Resolve $h (ms)" $sw.ElapsedMilliseconds
        }
        $cache = Get-DnsClientCache -ErrorAction SilentlyContinue
        Out-KV 'DNS cache entries' (@($cache).Count)
        Out-RawObject ($cache | Select-Object Entry, RecordName, RecordType, Status, TimeToLive | Sort-Object Entry) 'DNS cache contents'
    }

    Invoke-Collector 'Proxy configuration' {
        Invoke-NativeCapture 'WinHTTP proxy' 'netsh winhttp show proxy'
        $ie = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
        Out-RawList ($ie | Select-Object ProxyEnable, ProxyServer, ProxyOverride, AutoConfigURL, AutoDetect) 'WinINET proxy settings'
        Out-Raw 'CONTEXT: AutoConfigURL points at a PAC script fetched on demand. AutoDetect enables WPAD discovery.'
    }

    Invoke-Collector 'Hosts file' {
        $hp = "$env:SystemRoot\System32\drivers\etc\hosts"
        $lines = Get-Content $hp -ErrorAction SilentlyContinue
        $active = $lines | Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' }
        Out-KV 'FileSizeKB'     ([math]::Round((Get-Item $hp).Length/1KB,2))
        Out-KV 'TotalLines'     (@($lines).Count)
        Out-KV 'ActiveEntries'  (@($active).Count)
        Out-Raw 'CONTEXT: The default Windows hosts file contains only comments and no active entries.'
        Out-Raw 'CONTEXT: The hosts file is consulted before DNS for every name resolution.'
        if (@($active).Count -le 200) { foreach ($l in $active) { Out-Raw "  $l" } }
        else { Out-Raw "  (first 200 of $(@($active).Count))"; foreach ($l in ($active | Select-Object -First 200)) { Out-Raw "  $l" } }
    }

    Invoke-Collector 'Mapped drives reachability' {
        $job = Start-Job -ScriptBlock {
            foreach ($d in (Get-CimInstance Win32_MappedLogicalDisk -ErrorAction SilentlyContinue)) {
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $ok = Test-Path $d.ProviderName -ErrorAction SilentlyContinue
                $sw.Stop()
                [pscustomobject]@{ Drive=$d.Name; UNC=$d.ProviderName; Reachable=$ok; CheckMs=$sw.ElapsedMilliseconds }
            }
        }
        $res = $job | Wait-Job -Timeout 20 | Receive-Job
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        Out-RawObject $res 'Mapped drive probe'
        Out-Raw 'CONTEXT: Explorer and common file dialogs enumerate mapped drives on open.'
    }

    Invoke-Collector 'TCP connections and listening ports' {
        $est = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        Out-RawObject ($est | Group-Object OwningProcess | ForEach-Object {
            $p = Get-Process -Id $_.Name -ErrorAction SilentlyContinue
            [pscustomobject]@{ PID=$_.Name; Process=if($p){$p.Name}else{'(exited)'}; Established=$_.Count }
        } | Sort-Object Established -Descending) 'Established connections by process'
        Out-RawObject (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Select-Object LocalAddress, LocalPort, @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}, OwningProcess |
            Sort-Object LocalPort) 'Listening ports'
        Out-RawObject (Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
            Select-Object LocalAddress, LocalPort, @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}) 'UDP endpoints'
    }

    Invoke-Collector 'TCP settings and offload' {
        Out-RawList (Get-NetTCPSetting -ErrorAction SilentlyContinue) 'Get-NetTCPSetting'
        Out-RawObject (Get-NetAdapterAdvancedProperty -ErrorAction SilentlyContinue |
            Select-Object Name, DisplayName, DisplayValue, RegistryKeyword) 'Adapter advanced properties'
        Out-RawObject (Get-NetAdapterRss -ErrorAction SilentlyContinue) 'RSS configuration'
        Out-RawObject (Get-NetAdapterPowerManagement -ErrorAction SilentlyContinue) 'Adapter power management'
        Out-RawObject (Get-NetAdapterBinding -ErrorAction SilentlyContinue | Where-Object Enabled | Select-Object Name, DisplayName, ComponentID) 'Enabled NDIS bindings'
        Out-Raw 'CONTEXT: Each enabled NDIS filter binding processes every packet on that adapter.'
    }

    Invoke-Collector 'Firewall profiles and rule counts' {
        Out-RawList (Get-NetFirewallProfile) 'Firewall profiles'
        Out-RawObject (Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue | Group-Object Direction |
            Select-Object @{n='Direction';e={$_.Name}}, Count) 'Enabled rule counts'
    }

    Invoke-Collector 'Latency probes' -NeedsInternet {
        foreach ($t in @('1.1.1.1','8.8.8.8')) {
            $r = Test-Connection -ComputerName $t -Count 4 -ErrorAction SilentlyContinue
            if ($r) {
                Out-KV "$t avg ms" ([math]::Round((($r | Measure-Object ResponseTime -Average).Average),1))
                Out-KV "$t replies" (@($r).Count)
            } else { Out-KV "$t" 'no reply' }
        }
        $gw = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
        if ($gw) {
            $g = Test-Connection -ComputerName $gw.NextHop -Count 4 -ErrorAction SilentlyContinue
            Out-KV "Gateway $($gw.NextHop) avg ms" $(if ($g) { [math]::Round((($g | Measure-Object ResponseTime -Average).Average),1) } else { 'no reply' })
        }
    }

    Invoke-Collector 'Internet throughput measurement' -NeedsInternet -Retries 0 {
        # These are process-wide statics. Left set, they would force TLS 1.2
        # only on every collector that runs after this one.
        $prevProto = [Net.ServicePointManager]::SecurityProtocol
        $prevE100  = [Net.ServicePointManager]::Expect100Continue
        $prevConn  = [Net.ServicePointManager]::DefaultConnectionLimit
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        [Net.ServicePointManager]::Expect100Continue = $false
        [Net.ServicePointManager]::DefaultConnectionLimit = 64
        try {

        Out-Raw 'Method: single-stream HTTP against the Cloudflare speed-test edge (speed.cloudflare.com).'
        Out-Raw 'CONTEXT: A single TCP stream is throughput-limited by latency and window size. Consumer speed-test sites open 6-16 parallel streams and therefore report higher numbers. Treat these figures as a single-connection floor, not a line-rate ceiling.'
        Out-Raw 'CONTEXT: Mbps here means megabits per second, computed as (bytes * 8) / seconds / 1,000,000.'
        Out-Raw ''

        # ---- latency / time-to-first-byte ----
        Out-Raw '--- Latency to speed-test edge (10 HTTPS requests, time to first byte) ---'
        $lat = @()
        for ($i = 1; $i -le 10; $i++) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $rq = [Net.HttpWebRequest]::Create('https://speed.cloudflare.com/__down?bytes=1')
                $rq.Timeout = 10000; $rq.UserAgent = 'WinDiag'
                $rs = $rq.GetResponse()
                $st = $rs.GetResponseStream(); $st.ReadByte() | Out-Null
                $sw.Stop(); $st.Close(); $rs.Close()
                $lat += $sw.Elapsed.TotalMilliseconds
            } catch { $sw.Stop(); Out-KV ("  request $i") ('failed: ' + $_.Exception.Message) }
        }
        if ($lat.Count -gt 0) {
            $sorted = $lat | Sort-Object
            Out-KV '  samples'      $lat.Count
            Out-KV '  min ms'       ([math]::Round(($lat | Measure-Object -Minimum).Minimum,2))
            Out-KV '  median ms'    ([math]::Round($sorted[[int]($sorted.Count/2)],2))
            Out-KV '  mean ms'      ([math]::Round(($lat | Measure-Object -Average).Average,2))
            Out-KV '  max ms'       ([math]::Round(($lat | Measure-Object -Maximum).Maximum,2))
            Out-KV '  jitter ms (max-min)' ([math]::Round((($lat | Measure-Object -Maximum).Maximum - ($lat | Measure-Object -Minimum).Minimum),2))
            Out-Raw '  all samples: '
            Out-Raw ('    ' + (($lat | ForEach-Object { [math]::Round($_,1) }) -join ', '))
        }

        # ---- download ----
        Out-Raw ''
        Out-Raw '--- Download throughput ---'
        $dlRows = @()
        foreach ($bytes in @(1000000, 10000000, 25000000)) {
            try {
                $rq = [Net.HttpWebRequest]::Create("https://speed.cloudflare.com/__down?bytes=$bytes")
                $rq.Timeout = 60000; $rq.ReadWriteTimeout = 60000
                $rq.UserAgent = 'WinDiag'; $rq.AllowAutoRedirect = $true
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $rs = $rq.GetResponse()
                $st = $rs.GetResponseStream()
                $buf = New-Object byte[] 131072
                $total = 0
                while (($n = $st.Read($buf, 0, $buf.Length)) -gt 0) { $total += $n }
                $sw.Stop(); $st.Close(); $rs.Close()
                $secs = $sw.Elapsed.TotalSeconds
                $mbps = if ($secs -gt 0) { [math]::Round((($total * 8) / $secs) / 1000000, 2) } else { 0 }
                $row = [pscustomobject]@{
                    Direction = 'download'; RequestedBytes = $bytes; ReceivedBytes = $total
                    Seconds = [math]::Round($secs,3); Mbps = $mbps
                    MegabytesPerSec = [math]::Round(($total/1MB)/$secs,2)
                    Server = $rs.Headers['Server']; CfRay = $rs.Headers['cf-ray']; CfColo = $rs.Headers['cf-meta-colo']
                }
                $dlRows += $row
                Out-KV ("  " + [math]::Round($bytes/1MB,1) + ' MB') ('{0} Mbps  ({1} MB/s, {2}s, {3} bytes received)' -f $mbps, $row.MegabytesPerSec, $row.Seconds, $total)
            } catch {
                Out-KV ("  " + [math]::Round($bytes/1MB,1) + ' MB') ('failed: ' + $_.Exception.Message)
            }
        }

        # ---- upload ----
        Out-Raw ''
        Out-Raw '--- Upload throughput ---'
        $ulRows = @()
        foreach ($bytes in @(1000000, 5000000)) {
            try {
                $payload = New-Object byte[] $bytes
                (New-Object Random 42).NextBytes($payload)
                $rq = [Net.HttpWebRequest]::Create('https://speed.cloudflare.com/__up')
                $rq.Method = 'POST'; $rq.Timeout = 60000; $rq.ReadWriteTimeout = 60000
                $rq.ContentType = 'application/octet-stream'
                $rq.ContentLength = $payload.Length
                $rq.UserAgent = 'WinDiag'
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $reqStream = $rq.GetRequestStream()
                $reqStream.Write($payload, 0, $payload.Length)
                $reqStream.Flush(); $reqStream.Close()
                $rs = $rq.GetResponse()
                $sw.Stop()
                $rs.Close()
                $secs = $sw.Elapsed.TotalSeconds
                $mbps = if ($secs -gt 0) { [math]::Round((($bytes * 8) / $secs) / 1000000, 2) } else { 0 }
                $ulRows += [pscustomobject]@{
                    Direction = 'upload'; SentBytes = $bytes
                    Seconds = [math]::Round($secs,3); Mbps = $mbps
                    MegabytesPerSec = [math]::Round(($bytes/1MB)/$secs,2)
                }
                Out-KV ("  " + [math]::Round($bytes/1MB,1) + ' MB') ('{0} Mbps  ({1} MB/s, {2}s)' -f $mbps, [math]::Round(($bytes/1MB)/$secs,2), [math]::Round($secs,3))
            } catch {
                Out-KV ("  " + [math]::Round($bytes/1MB,1) + ' MB') ('failed: ' + $_.Exception.Message)
            }
        }

        Out-Raw ''
        Out-Raw '--- Link capability for comparison ---'
        foreach ($a in (Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up')) {
            Out-KV ('  ' + $a.Name) ('negotiated link speed ' + $a.LinkSpeed + ' (' + $a.InterfaceDescription + ')')
        }
        Out-Raw 'CONTEXT: Negotiated link speed is the local NIC-to-AP/switch rate. It bounds, but does not indicate, internet throughput.'
        Out-Raw 'CONTEXT: On Wi-Fi the negotiated rate is a PHY rate; usable throughput is typically a fraction of it because of protocol overhead and airtime contention.'
        Out-Raw 'CONTEXT: If a content filter or TLS-inspecting proxy is in the path (see the Content Filtering section), these figures measure the path through that device, not the raw circuit.'

        Save-Json ([pscustomobject]@{
            LatencyMs = $lat
            Download  = $dlRows
            Upload    = $ulRows
        }) 'net_throughput'
        }
        finally {
            [Net.ServicePointManager]::SecurityProtocol       = $prevProto
            [Net.ServicePointManager]::Expect100Continue      = $prevE100
            [Net.ServicePointManager]::DefaultConnectionLimit = $prevConn
        }
    }

    Invoke-Collector 'Time synchronisation' {
        Invoke-NativeCapture 'w32tm status' 'w32tm /query /status'
        Invoke-NativeCapture 'w32tm peers'  'w32tm /query /peers'
        Out-Raw 'CONTEXT: Kerberos rejects tickets when clock skew exceeds 5 minutes by default.'
    }

    Invoke-Collector 'Delivery Optimization and BITS' {
        $cfg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -ErrorAction SilentlyContinue
        Out-RawList ($cfg | Select-Object -Property * -ExcludeProperty PS*) 'Delivery Optimization config'
        Out-Raw 'CONTEXT: DODownloadMode 0=HTTP only 1=LAN peers 2=group 3=internet peers 99=bypass.'
        try { Out-RawObject (Get-DeliveryOptimizationStatus -ErrorAction Stop) 'Active DO transfers' } catch { Out-Raw 'Get-DeliveryOptimizationStatus unavailable.' }
        try { Import-Module BitsTransfer -ErrorAction SilentlyContinue
              Out-RawObject (Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue |
                Select-Object DisplayName, JobState, Priority, BytesTotal, BytesTransferred, OwnerAccount) 'BITS jobs' } catch { }
    }
}

# =============================================================== 7b. FILTERING
# Content filters sit in the network path and can add latency, break TLS, or
# block endpoints that software depends on. Their presence is reported as an
# observation; whether it is desired configuration is not this tool's call.
Invoke-Section 'Content Filtering and Interception' 'filtering' {

    function Get-HttpProbe {
        param([string]$Url, [int]$TimeoutMs = 10000)
        $r = [ordered]@{
            Url = $Url; Reached = $false; StatusCode = $null; StatusText = $null
            Server = $null; ContentType = $null; ContentLength = $null
            FinalUri = $null; ElapsedMs = $null; Headers = @{}; BodySample = $null
            Exception = $null
        }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $req = [System.Net.HttpWebRequest]::Create($Url)
            $req.Timeout = $TimeoutMs
            $req.ReadWriteTimeout = $TimeoutMs
            $req.AllowAutoRedirect = $true
            $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) WinDiag'
            $resp = $req.GetResponse()
            $r.Reached = $true
            $r.StatusCode = [int]$resp.StatusCode
            $r.StatusText = $resp.StatusCode.ToString()
            $r.ContentType = $resp.ContentType
            $r.ContentLength = $resp.ContentLength
            $r.FinalUri = $resp.ResponseUri.AbsoluteUri
            # HttpWebResponse exposes Server as a property; the header collection can come
            # back empty for it. Read the property first, fall back to the header.
            $r.Server = $resp.Server
            if (-not $r.Server) { $r.Server = $resp.Headers['Server'] }
            foreach ($k in $resp.Headers.AllKeys) { $r.Headers[$k] = $resp.Headers[$k] }
            $rd = New-Object System.IO.StreamReader($resp.GetResponseStream())
            $body = $rd.ReadToEnd()
            $rd.Close(); $resp.Close()
            $r.BodySample = $body.Substring(0, [Math]::Min(1500, $body.Length))
        } catch [System.Net.WebException] {
            $r.Exception = $_.Exception.Message
            $er = $_.Exception.Response
            if ($er) {
                $r.Reached = $true
                $r.StatusCode = [int]$er.StatusCode
                $r.StatusText = $er.StatusCode.ToString()
                $r.Server = $er.Server
                if (-not $r.Server) { $r.Server = $er.Headers['Server'] }
                $r.ContentType = $er.ContentType
                foreach ($k in $er.Headers.AllKeys) { $r.Headers[$k] = $er.Headers[$k] }
                # Substring(0,1500) throws when the body is shorter than 1500
                # chars, which block pages routinely are - so the sample was
                # lost on exactly the responses this probe is for, and the
                # reader was never closed.
                $rd = $null
                try {
                    $rd = New-Object System.IO.StreamReader($er.GetResponseStream())
                    $body = $rd.ReadToEnd()
                    $r.BodySample = $body.Substring(0, [Math]::Min(1500, $body.Length))
                } catch { }
                finally { if ($rd) { try { $rd.Dispose() } catch { } } }
            }
        } catch {
            $r.Exception = $_.Exception.Message
        }
        $sw.Stop(); $r.ElapsedMs = $sw.ElapsedMilliseconds
        return [pscustomobject]$r
    }

    Invoke-Collector 'Techloq filter endpoint probe' -NeedsInternet -Retries 0 {
        $p = Get-HttpProbe 'https://filter.techloq.com/'
        Out-KV 'URL'          $p.Url
        Out-KV 'Reached'      $p.Reached
        Out-KV 'StatusCode'   $p.StatusCode
        Out-KV 'Server header' $p.Server
        Out-KV 'FinalUri'     $p.FinalUri
        Out-KV 'ElapsedMs'    $p.ElapsedMs
        Out-KV 'Exception'    $p.Exception
        Out-Raw ''
        Out-Raw '--- All response headers ---'
        foreach ($k in $p.Headers.Keys) { Out-KV ('  ' + $k) $p.Headers[$k] }
        Out-Raw ''
        Out-Raw '--- Body sample ---'
        Out-Raw $p.BodySample
        Out-Raw ''
        Out-Raw 'CONTEXT: filter.techloq.com is the Techloq filter service endpoint. It is reachable only from a machine whose traffic is routed through Techloq; from an unfiltered network the request does not resolve or does not complete.'
        Out-Raw 'CONTEXT: "Reached = False" and "Reached = True" are both meaningful results here. Record which one occurred rather than treating a failure as missing data.'
        Save-Json $p 'filter_techloq_probe'
    }

    Invoke-Collector 'Reference site probes and block-page header capture' -NeedsInternet -Retries 0 {
        # Two groups. The first are rarely filtered and establish what an
        # unfiltered response looks like from this machine. The second are the
        # categories filters commonly act on - without them the probe never
        # exercises the block path and a filtered machine can look clean.
        $targets = @(
            'https://www.google.com/','https://www.wikipedia.org/','http://www.msftconnecttest.com/connecttest.txt',
            'https://www.youtube.com/','https://www.instagram.com/','https://www.facebook.com/',
            'https://x.com/','https://www.reddit.com/','https://www.tiktok.com/'
        )
        $all = @()
        foreach ($t in $targets) {
            $p = Get-HttpProbe $t
            Out-Raw ''
            Out-Raw ('### ' + $t)
            Out-KV '  Reached'     $p.Reached
            Out-KV '  StatusCode'  $p.StatusCode
            Out-KV '  Server'      $p.Server
            Out-KV '  ContentType' $p.ContentType
            Out-KV '  ContentLength' $p.ContentLength
            Out-KV '  FinalUri'    $p.FinalUri
            Out-KV '  ElapsedMs'   $p.ElapsedMs
            Out-KV '  Exception'   $p.Exception
            Out-Raw '  --- headers ---'
            foreach ($k in $p.Headers.Keys) { Out-KV ('    ' + $k) $p.Headers[$k] }
            Out-Raw '  --- body sample ---'
            Out-Raw $p.BodySample
            $all += $p
        }
        Out-Raw ''
        Out-Raw '--- Livigent / Gentech presence markers (any X-Livigent-* header, on ANY response) ---'
        $livSeen = $false
        foreach ($p in $all) {
            foreach ($k in $p.Headers.Keys) {
                if ($k -match '^X-Livigent') {
                    $livSeen = $true
                    Out-KV ($p.Url + ' -> ' + $k) $p.Headers[$k]
                }
            }
        }
        if (-not $livSeen) { Out-Raw '  No X-Livigent-* header on any probed response.' }
        Out-Raw 'CONTEXT: An X-Livigent-* header is emitted by the Livigent engine (used by Gentech) on responses it has passed through, INCLUDING pages it allowed. Its presence indicates the engine is in the path; it does not by itself indicate the page was blocked.'
        Out-Raw 'CONTEXT: Observed values of X-Livigent-Modified include "adblock" (page delivered from the origin with content rewritten to suppress elements) and "blocked" (origin content replaced with a block page). Record the value rather than testing for any single one.'
        Out-Raw 'CONTEXT: On a rewritten-but-allowed page the origin Server header is passed through unchanged (youtube.com returns "ESF"), and the final URL stays on the requested host. A normal-looking Server header and final URL therefore do NOT rule out an active filter.'
        Out-Raw 'CONTEXT: Rewriting the body of an HTTPS response requires terminating and re-originating TLS. An X-Livigent-* header on an https:// URL is therefore direct evidence of TLS interception, independent of the root-certificate check in the next collector.'

        Out-Raw ''
        Out-Raw '--- Response body injection markers ---'
        foreach ($p in $all) {
            if ($p.BodySample -match '\.ytp-ad-module|\.video-ads|DIV\[id="comments"\]|livigent|techloq|gentech|netspark') {
                Out-KV ($p.Url + ' -> body contains filter-injected markup') 'yes (see body sample above)'
            }
        }
        Out-Raw 'CONTEXT: Injected CSS selectors targeting site-specific element ids or classes appear at the very top of the returned document, before the site''s own markup. The origin does not serve these.'

        Out-Raw ''
        Out-Raw '--- Other interception marker headers observed across probes ---'
        foreach ($p in $all) {
            foreach ($k in $p.Headers.Keys) {
                if ($k -match 'Livigent|X-Filter|X-Block|X-Squid|X-Cache|Cache-Status|Proxy|X-Forefront|X-Barracuda|X-Zscaler|X-Netskope|X-WebSense|X-Bluecoat|X-Sophos|X-Fortinet|X-Cisco-Umbrella|Techloq|Gentech|NetSpark') {
                    Out-KV ($p.Url + ' -> ' + $k) $p.Headers[$k]
                }
            }
            if ($p.Server -match 'Livigent|Squid|BlueCoat|Barracuda|Zscaler|Netskope|WebSense|Fortinet|McAfee|Sophos') {
                Out-KV ($p.Url + ' -> Server') $p.Server
            }
            # Redirect-style blocks: the request completes with 200 but the final
            # URL is the filter's own block page rather than the requested origin.
            # Compare host to host. Matching the requested host against the
            # entire final URL fails whenever the block page carries the
            # original URL in a query parameter - which Techloq's does.
            if ($p.FinalUri) {
                $reqHost = ''
                $finHost = ''
                try { $reqHost = ([Uri]$p.Url).Host }     catch { }
                try { $finHost = ([Uri]$p.FinalUri).Host } catch { }
                if ($finHost -and $reqHost -and $finHost -ne $reqHost) {
                    Out-KV ($p.Url + ' -> final host differs') ($reqHost + '  ->  ' + $finHost)
                    Out-KV ($p.Url + ' -> final URL')          $p.FinalUri
                }
            }
        }
        Out-Raw ''
        Out-Raw 'CONTEXT: A filtered request generally still completes with HTTP 200. Status code alone does not distinguish an allowed page from a block page, so compare the FINAL URL and the headers instead.'
        Out-Raw 'CONTEXT: Two block mechanisms are seen in the field, and which one appears identifies the product. Both are captured above.'
        Out-Raw 'CONTEXT:   (1) REDIRECT to a block page - characteristic of TECHLOQ. The final URL becomes filter.techloq.com carrying an "error=access" query and an X-Block-Info parameter, and the serving node appears in a Cache-Status header such as "node3.env1.dc3.us.techloq.com". There is no Server header at all in this form.'
        Out-Raw 'CONTEXT:   (2) INLINE substitution - characteristic of GENTECH, which fronts the Livigent engine. The requested URL is preserved and the block page is returned in place of the origin content, carrying "Server: Livigent" and "X-Livigent-Modified: blocked". Confirmed against a live Gentech machine.'
        Out-Raw 'CONTEXT:   (3) ERROR STATUS - the same Livigent deployment returned 403 Forbidden for at least one site rather than a 200 block page. An error status is therefore NOT evidence that the origin rejected the request; the headers on the error response must be read before attributing it to the origin. This collector captures headers on error responses as well as successful ones.'
        Out-Raw 'CONTEXT: On the Gentech machine tested, blocked sites returned Server "Livigent" while an allowed-but-rewritten site returned the origin''s own Server value ("ESF" for youtube.com) - so the Server header distinguishes a substituted page from a rewritten one, and X-Livigent-Modified distinguishes blocked from adblock.'
        Out-Raw 'CONTEXT: So: a Livigent Server header points to Gentech, a filter.techloq.com final URL points to Techloq. Read the FINAL URL field and the Server header together - either one alone can be absent depending on which product is in the path.'
        Out-Raw 'CONTEXT: For reference when reading the FINAL URL field: youtube.com normally returns Server "ESF", google.com returns "gws", and wikipedia.org returns "mw-web...". A final URL on a different host than the one requested is the clearest single indicator.'
        Out-Raw 'CONTEXT: msftconnecttest.com/connecttest.txt returns exactly the body "Microsoft Connect Test" when unintercepted. Any other body indicates the response was generated by something other than the origin.'
        Save-Json $all 'filter_site_probes'
    }

    Invoke-Collector 'Filtering software installed (services, processes, programs)' {
        $patterns = 'Techloq|Livigent|Gentech|GenTech|NetSpark|Nativ|K9 Web|OpenDNS|Umbrella|Zscaler|Netskope|WebSense|Forcepoint|Barracuda|BlueCoat|Blue Coat|Lightspeed|Securly|GoGuardian|Qustodio|NetNanny|Net Nanny|CleanBrowsing|Circle |Bark |Covenant Eyes|CovenantEyes|Accountable2You|Canopy|Mobicip|FamilyShield|SafeDNS|DNSFilter|Cisco AnyConnect Umbrella'

        Out-Raw '--- Services matching filter/parental-control vendors ---'
        Out-RawObject (Get-CimInstance Win32_Service |
            Where-Object { $_.Name -match $patterns -or $_.DisplayName -match $patterns -or $_.PathName -match $patterns } |
            Select-Object Name, DisplayName, State, StartMode, StartName, PathName) ''

        Out-Raw '--- Processes matching filter vendors ---'
        Out-RawObject (Get-CimInstance Win32_Process |
            Where-Object { $_.Name -match $patterns -or $_.ExecutablePath -match $patterns } |
            Select-Object Name, ProcessId, ExecutablePath, CommandLine) ''

        Out-Raw '--- Installed programs matching filter vendors ---'
        $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                   'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                   'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
        Out-RawObject (Get-ItemProperty $paths -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match $patterns -or $_.Publisher -match $patterns } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation) ''

        Out-Raw '--- Kernel drivers matching filter vendors ---'
        Out-RawObject (Get-CimInstance Win32_SystemDriver |
            Where-Object { $_.Name -match $patterns -or $_.DisplayName -match $patterns -or $_.PathName -match $patterns } |
            Select-Object Name, DisplayName, State, StartMode, PathName) ''

        Out-Raw '--- Install directories present on disk ---'
        foreach ($d in @("$env:ProgramFiles\Techloq", "${env:ProgramFiles(x86)}\Techloq",
                         "$env:ProgramData\Techloq", "$env:LOCALAPPDATA\Techloq",
                         "$env:ProgramFiles\Gentech", "${env:ProgramFiles(x86)}\Gentech",
                         "$env:ProgramData\Gentech", "$env:ProgramFiles\NetSpark",
                         "${env:ProgramFiles(x86)}\NetSpark")) {
            Out-KV $d $(if (Test-Path $d) { 'EXISTS - ' + (@(Get-ChildItem $d -Recurse -File -ErrorAction SilentlyContinue).Count) + ' files' } else { 'not present' })
        }
        Out-Raw 'CONTEXT: Names are matched against a fixed vendor list. Absence from this list is not evidence that no filter is installed - only that none of these specific vendor strings appeared.'
    }

    Invoke-Collector 'TLS certificate chains as presented on the wire' -NeedsInternet -Retries 0 {
        # Connects directly with SslStream so the chain recorded is the one this
        # machine is actually served, not what a browser cached or what the OS
        # substituted. The validation callback always returns true so a chain is
        # still captured when it would otherwise be rejected.
        function Get-TlsChain {
            param([string]$HostName, [int]$Port = 443, [int]$TimeoutMs = 10000)
            $res = [ordered]@{
                Host = $HostName; Connected = $false; Protocol = $null; Cipher = $null
                CipherStrength = $null; KeyExchange = $null; Hash = $null
                PolicyErrors = $null; ChainCount = 0; Chain = @()
                LeafSubject = $null; LeafIssuer = $null; LeafThumbprint = $null
                LeafNotBefore = $null; LeafNotAfter = $null; LeafSans = $null
                RootSubject = $null; RootThumbprint = $null; Error = $null
            }
            $tcp = $null; $ssl = $null; $bc = $null; $leaf = $null
            try {
                $tcp = New-Object Net.Sockets.TcpClient
                $iar = $tcp.BeginConnect($HostName, $Port, $null, $null)
                if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { throw "connect timeout" }
                $tcp.EndConnect($iar)
                $res.Connected = $true

                # Accept any certificate so a chain is still captured when the
                # cert would be rejected. The callback only returns a value - it
                # does not export state, because a scriptblock invoked as a
                # delegate has its own session state and $script: writes made
                # inside it do not reach this scope.
                $cb = [Net.Security.RemoteCertificateValidationCallback]{ return $true }
                # AuthenticateAsClient reads from the NetworkStream, whose
                # ReadTimeout defaults to Infinite. A middlebox that completes
                # the TCP handshake and then sends nothing would hang the whole
                # run here - which is precisely the behaviour being probed for.
                $tcp.ReceiveTimeout = $TimeoutMs
                $tcp.SendTimeout    = $TimeoutMs
                $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, $cb)
                $ssl.ReadTimeout  = $TimeoutMs
                $ssl.WriteTimeout = $TimeoutMs
                $ssl.AuthenticateAsClient($HostName)

                $res.Protocol       = $ssl.SslProtocol.ToString()
                $res.Cipher         = $ssl.CipherAlgorithm.ToString()
                $res.CipherStrength = $ssl.CipherStrength
                $res.KeyExchange    = $ssl.KeyExchangeAlgorithm.ToString()
                $res.Hash           = $ssl.HashAlgorithm.ToString()

                # Read the served certificate off the stream, then build the
                # chain against this machine's stores - that build is what
                # resolves an intercepted leaf back to the re-signing root.
                $leaf = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
                $bc = New-Object Security.Cryptography.X509Certificates.X509Chain
                $bc.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                $built = $bc.Build($leaf)
                $res.PolicyErrors = $(if ($built) { 'none - chain validated against local stores' }
                                      else { (($bc.ChainStatus | ForEach-Object { $_.Status.ToString() }) -join ', ') })
                $script:__tlsChain = $bc
                $res.LeafSubject    = $leaf.Subject
                $res.LeafIssuer     = $leaf.Issuer
                $res.LeafThumbprint = $leaf.Thumbprint
                $res.LeafNotBefore  = $leaf.NotBefore
                $res.LeafNotAfter   = $leaf.NotAfter
                $san = $leaf.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
                if ($san) { $res.LeafSans = ($san.Format($false)) }

                if ($script:__tlsChain -and $script:__tlsChain.ChainElements) {
                    $res.ChainCount = $script:__tlsChain.ChainElements.Count
                    $i = 0
                    foreach ($el in $script:__tlsChain.ChainElements) {
                        $c = $el.Certificate
                        $res.Chain += [pscustomobject]@{
                            Position   = $i
                            Subject    = $c.Subject
                            Issuer     = $c.Issuer
                            Thumbprint = $c.Thumbprint
                            NotBefore  = $c.NotBefore
                            NotAfter   = $c.NotAfter
                            SigAlg     = $c.SignatureAlgorithm.FriendlyName
                            KeySize    = $(try { $c.PublicKey.Key.KeySize } catch { $null })
                            SelfSigned = ($c.Subject -eq $c.Issuer)
                        }
                        $i++
                    }
                    # Only call it a root if the chain actually climbed past the
                    # leaf. A single-element chain means the build could not
                    # resolve the issuer locally, and reporting the leaf as its
                    # own root would be wrong.
                    if ($res.ChainCount -gt 1) {
                        $last = $script:__tlsChain.ChainElements[$res.ChainCount - 1].Certificate
                        $res.RootSubject    = $last.Subject
                        $res.RootThumbprint = $last.Thumbprint
                    } else {
                        $res.RootSubject    = '(chain did not resolve past the leaf on this machine)'
                        $res.RootThumbprint = $null
                    }
                }
            } catch { $res.Error = $_.Exception.Message }
            finally {
                if ($ssl)  { try { $ssl.Dispose() }  catch { } }
                if ($tcp)  { try { $tcp.Close() }    catch { } }
                # X509Chain and X509Certificate2 own native cert contexts.
                if ($bc)   { try { $bc.Dispose() }   catch { } }
                if ($leaf) { try { $leaf.Dispose() } catch { } }
            }
            return [pscustomobject]$res
        }

        # Deliberately spread across unrelated operators using different public
        # CAs. Under normal conditions these chains terminate at several
        # different roots; an intercepting proxy re-signs them all with one.
        $hosts = @('www.google.com','www.microsoft.com','github.com','www.wikipedia.org',
                   'www.cloudflare.com','www.amazon.com','login.microsoftonline.com','api.github.com')

        $chains = @()
        foreach ($h in $hosts) {
            $c = Get-TlsChain $h
            $chains += $c
            Out-Raw ''
            Out-Raw ("### " + $h)
            Out-KV '  Connected'     $c.Connected
            Out-KV '  Error'         $c.Error
            Out-KV '  TLS protocol'  $c.Protocol
            Out-KV '  Cipher'        ("$($c.Cipher) $($c.CipherStrength)-bit, kex $($c.KeyExchange), hash $($c.Hash)")
            Out-KV '  Policy errors' $c.PolicyErrors
            Out-KV '  Leaf subject'  $c.LeafSubject
            Out-KV '  Leaf issuer'   $c.LeafIssuer
            Out-KV '  Leaf thumbprint' $c.LeafThumbprint
            Out-KV '  Leaf valid'    ("$($c.LeafNotBefore) .. $($c.LeafNotAfter)")
            Out-KV '  Leaf SANs'     $c.LeafSans
            Out-KV '  Chain length'  $c.ChainCount
            Out-KV '  Chain root'    $c.RootSubject
            Out-Raw '  --- full chain ---'
            foreach ($e in $c.Chain) {
                Out-Raw ("    [{0}] {1}" -f $e.Position, $e.Subject)
                Out-Raw ("         issuer     : " + $e.Issuer)
                Out-Raw ("         thumbprint : " + $e.Thumbprint)
                Out-Raw ("         valid      : {0} .. {1}   sig {2}, key {3}" -f $e.NotBefore, $e.NotAfter, $e.SigAlg, $e.KeySize)
            }
        }

        # ---- shared-issuer analysis ----
        # Grouping is on the LEAF ISSUER, not the chain root. The issuer is
        # always present on a served certificate, whereas a locally-built chain
        # only resolves to a root when the intermediates happen to be in a local
        # store - on this machine most public sites did not resolve past the
        # leaf, which would have produced a misleading "root" per host.
        Out-Raw ''
        Out-Raw '=== Leaf issuer grouping across the probed hosts ==='
        $ok = $chains | Where-Object { $_.Connected -and $_.LeafIssuer }
        $groups = $ok | Group-Object LeafIssuer | Sort-Object Count -Descending
        Out-KV 'hosts probed'           $hosts.Count
        Out-KV 'hosts that served a certificate' (@($ok).Count)
        Out-KV 'distinct signing issuers'        (@($groups).Count)
        foreach ($g in $groups) {
            Out-Raw ''
            Out-KV 'issuer' $g.Name
            Out-KV '  hosts signed by it' (($g.Group | ForEach-Object { $_.Host }) -join ', ')
            Out-KV '  count'              $g.Count
        }
        Out-Raw ''
        Out-Raw 'CONTEXT: These hosts belong to unrelated organisations that buy certificates from different certificate authorities. Served directly, their leaf certificates are normally signed by several DIFFERENT issuers - commonly Google Trust Services (WR2/WE2), DigiCert, Amazon, Sectigo and ISRG/Let''s Encrypt.'
        Out-Raw 'CONTEXT: A proxy that terminates TLS can only issue certificates from the one CA whose private key it holds, so it necessarily re-signs every site with the SAME issuer.'
        Out-Raw 'CONTEXT: "distinct signing issuers = 1" across these unrelated hosts is therefore the strongest single indicator in this collector, and the issuer name identifies the party doing the re-signing. A count matching the number of hosts is the unintercepted case.'
        Out-Raw 'CONTEXT: Chain roots are reported per host above where they resolved. A root shown as "chain did not resolve past the leaf" means the issuing intermediate is not in a local store - that is normal for public sites and is not itself an interception indicator.'

        # ---- root attribution ----
        $publicCA = 'DigiCert|Baltimore|GlobalSign|GeoTrust|Thawte|VeriSign|Entrust|Sectigo|Comodo|AddTrust|USERTrust|GoDaddy|Starfield|Amazon|Google Trust|GTS |ISRG|Let''s Encrypt|Microsoft|Symantec|QuoVadis|Certum|SecureTrust|Actalis|Buypass|D-TRUST|IdenTrust|SwissSign|T-TeleSec|Cybertrust|AffirmTrust|SSL\.com|HARICA|Telia|emSign|Atos|Certainly|OISTE|Trustwave|Hongkong|TrustAsia|E-Tugra|Security Communication|Staat der|NetLock|XRamp|Chambers|AAA Certificate'
        $vendorPat = 'Techloq|Livigent|Gentech|NetSpark|Zscaler|Netskope|Forcepoint|WebSense|BlueCoat|Blue Coat|Barracuda|Fortinet|FortiGate|Sophos|McAfee|Kaspersky|ESET|Bitdefender|Avast|AVG|Norton|Symantec Web|Cisco Umbrella|Palo Alto|Check Point|Sangfor|Untangle|Smoothwall|Lightspeed|Securly|GoGuardian|Qustodio|NetNanny|Covenant|Bark|Mobicip|Canopy|Fiddler|Charles Proxy|mitmproxy|Burp|Portswigger|Squid|SonicWall|WatchGuard|Trend Micro|ContentKeeper|iboss|Menlo|Skyhigh|Cloudflare Gateway|Proofpoint'

        Out-Raw ''
        Out-Raw '=== Attribution of chain roots ==='
        foreach ($g in $groups) {
            $subj = $g.Name
            Out-Raw ''
            Out-KV 'signing issuer' $subj
            Out-KV '  hosts'        (($g.Group | ForEach-Object { $_.Host }) -join ', ')
            Out-KV '  matches a public-CA name' $(if ($subj -match $publicCA) { 'yes' } else { 'no' })
            $vm = [regex]::Match($subj, $vendorPat)
            Out-KV '  matches a known interception-product name' $(if ($vm.Success) { $vm.Value } else { 'no match in list' })
            # Locate this root in the local certificate stores.
            $found = $false
            $cn = ''
            $m = [regex]::Match($subj, 'CN=([^,]+)')
            if ($m.Success) { $cn = $m.Groups[1].Value.Trim() }
            foreach ($store in @('Cert:\LocalMachine\Root','Cert:\LocalMachine\CA','Cert:\LocalMachine\AuthRoot',
                                 'Cert:\CurrentUser\Root','Cert:\CurrentUser\CA')) {
                $hit = Get-ChildItem $store -ErrorAction SilentlyContinue | Where-Object { $cn -and $_.Subject -like "*$cn*" }
                if ($hit) {
                    $found = $true
                    Out-KV '  present in store' $store
                    Out-KV '    friendly name'  $hit.FriendlyName
                    Out-KV '    issued'         ("$($hit.NotBefore) .. $($hit.NotAfter)")
                    Out-KV '    self-signed'    ($hit.Subject -eq $hit.Issuer)
                }
            }
            if (-not $found) { Out-Raw '  present in store              : not found in any local store' }
        }
        Out-Raw ''
        Out-Raw 'CONTEXT: For an intercepted connection to be accepted without a browser warning, the re-signing CA must be installed in a local trust store. A chain root that is NOT a public CA and IS present in a local store is the combination that identifies locally-installed interception.'
        Out-Raw 'CONTEXT: The store it sits in indicates the scope: LocalMachine\Root applies to every user on the machine, CurrentUser\Root only to this profile.'
        Out-Raw 'CONTEXT: The product-name match is against a fixed list. A no-match result means the root''s name did not contain any listed vendor string, not that the root is a public CA - read the public-CA line for that.'
        Out-Raw 'CONTEXT: Legitimate causes of a non-public root re-signing traffic include corporate proxies, endpoint security with HTTPS scanning, and developer proxies such as Fiddler, Charles, mitmproxy and Burp. This collector does not distinguish sanctioned from unsanctioned deployment.'

        Save-Json ([pscustomobject]@{
            Hosts = $chains
            RootGroups = ($groups | ForEach-Object {
                [pscustomobject]@{ Thumbprint = $_.Name; Subject = $_.Group[0].RootSubject
                                   Hosts = ($_.Group | ForEach-Object { $_.Host }) }
            })
        }) 'tls_chains'
    }

    Invoke-Collector 'TLS interception evidence (non-public root CAs)' {
        $wellKnown = 'Microsoft|DigiCert|VeriSign|GlobalSign|Baltimore|Thawte|GeoTrust|Entrust|Comodo|Sectigo|AddTrust|USERTrust|GoDaddy|Starfield|Symantec|Amazon|Google Trust|ISRG|Let''s Encrypt|Certum|QuoVadis|SecureTrust|Actalis|Buypass|D-TRUST|IdenTrust|SwissSign|T-TeleSec|Network Solutions|Hongkong|WoSign|TrustAsia|Chambers|Autoridad|AAA Certificate|COMODO|Cybertrust|Deutsche Telekom|Hellenic|NetLock|Security Communication|Staat der|TeliaSonera|UCA |XRamp|thawte|Certainly|SSL.com|HARICA|Telia|Atos|emSign|GDCA|E-Tugra|OISTE|Trustwave|AffirmTrust|Go Daddy'

        foreach ($store in @('Cert:\LocalMachine\Root','Cert:\CurrentUser\Root')) {
            Out-Raw ''
            Out-Raw "### $store"
            $certs = Get-ChildItem $store -ErrorAction SilentlyContinue
            Out-KV '  total root certificates' (@($certs).Count)
            $odd = $certs | Where-Object { $_.Subject -notmatch $wellKnown }
            Out-KV '  not matching the public-CA name list' (@($odd).Count)
            Out-RawObject ($odd | Select-Object Subject, Issuer, NotBefore, NotAfter, Thumbprint,
                @{n='SelfSigned';e={$_.Subject -eq $_.Issuer}}) '  Certificates outside the public-CA name list'
        }
        Out-Raw ''
        Out-Raw 'CONTEXT: A TLS-inspecting filter must install its own signing certificate into a trusted root store, otherwise every HTTPS page would show a certificate warning.'
        Out-Raw 'CONTEXT: Enterprise device-management, corporate VPNs, developer tooling (Fiddler, Charles), and antivirus HTTPS scanning also install root certificates. Presence of a non-public root is not by itself attributable to any one cause.'
        Out-Raw 'CONTEXT: The name list used here covers common public CAs only. A legitimate CA absent from the list will appear in this output.'
    }

    Invoke-Collector 'DNS resolver and DoH configuration' {
        Out-RawObject (Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses }) 'Configured DNS servers per interface'
        Out-Raw 'CONTEXT: Filtering services commonly operate by directing DNS to their own resolvers. Known filtering resolver ranges include OpenDNS/Umbrella (208.67.222.x, 208.67.220.x), CleanBrowsing (185.228.168.x), and SafeDNS (195.46.39.x).'
        Invoke-NativeCapture 'DNS encryption settings' 'netsh dns show encryption'
        Invoke-NativeCapture 'Global DNS state'        'netsh dns show state'
        $doh = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -ErrorAction SilentlyContinue
        Out-RawList ($doh | Select-Object -Property * -ExcludeProperty PS*) 'Dnscache parameters'
    }

    Invoke-Collector 'Network filter drivers and LSP chain' {
        Out-RawObject (Get-NetAdapterBinding -ErrorAction SilentlyContinue | Where-Object Enabled |
            Select-Object Name, DisplayName, ComponentID | Sort-Object Name, DisplayName) 'Enabled NDIS bindings per adapter'
        Out-Raw 'CONTEXT: ComponentID values beginning "ms_" are Microsoft-supplied. Any other prefix indicates a third-party filter driver in the packet path.'
        Invoke-NativeCapture 'Winsock catalog' 'netsh winsock show catalog' 'winsock_catalog.txt'
        Out-Raw 'CONTEXT: A Layered Service Provider in the Winsock catalog intercepts socket calls for every application that uses Winsock.'
        Invoke-NativeCapture 'WFP filters' 'netsh wfp show state file=-' 'wfp_state.txt'
    }
}

# =============================================================== 7c. HIJACK
# Search-engine, homepage and start-page settings, plus the persistence points
# that unwanted software uses to change them. Values are reported as configured;
# whether a given setting was chosen by the user is not determinable from here.
Invoke-Section 'Search, Homepage and Persistence Settings' 'hijack' {

    Invoke-Collector 'Chromium default search engine and startup pages' {
        $browsers = @(
            @{N='Chrome';  R="$env:LOCALAPPDATA\Google\Chrome\User Data"},
            @{N='Edge';    R="$env:LOCALAPPDATA\Microsoft\Edge\User Data"},
            @{N='Brave';   R="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"},
            @{N='Vivaldi'; R="$env:LOCALAPPDATA\Vivaldi\User Data"},
            @{N='Opera';   R="$env:APPDATA\Opera Software\Opera Stable"}
        )
        foreach ($b in $browsers) {
            if (-not (Test-Path $b.R)) { continue }
            Out-Raw ''
            Out-Raw ('### ' + $b.N)
            $profiles = Get-ChildItem -LiteralPath $b.R -Directory -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' }
            if (-not $profiles -and (Test-Path (Join-Path $b.R 'Preferences'))) {
                $profiles = @(Get-Item -LiteralPath $b.R)
            }
            foreach ($pr in $profiles) {
                $pf = Join-Path $pr.FullName 'Preferences'
                if (-not (Test-Path $pf)) { continue }
                Out-Raw ("  -- profile: " + $pr.Name)
                try {
                    $j = Get-Content $pf -Raw -ErrorAction Stop | ConvertFrom-Json
                    $dsp = $j.default_search_provider_data.template_url_data
                    Out-KV '    search engine name'    $dsp.short_name
                    Out-KV '    search keyword'        $dsp.keyword
                    Out-KV '    search URL'            $dsp.url
                    Out-KV '    suggest URL'           $dsp.suggestions_url
                    Out-KV '    new tab URL'           $dsp.new_tab_url
                    Out-KV '    created by policy'     $dsp.created_by_policy
                    Out-KV '    prepopulate id'        $dsp.prepopulate_id
                    Out-KV '    homepage'              $j.homepage
                    Out-KV '    homepage is newtab'    $j.homepage_is_newtabpage
                    Out-KV '    startup restore type'  $j.session.restore_on_startup
                    Out-KV '    startup URLs'          ($j.session.startup_urls -join ' | ')
                    Out-Raw '    CONTEXT: prepopulate_id is non-zero for search engines that ship with the browser (1=Google, 2=Yahoo, 3=Bing, 4=Ask, 5=AOL, 6=MyWebSearch). A value of 0 means the engine was added rather than built in.'
                    Out-Raw '    CONTEXT: restore_on_startup 1=restore last session, 4=open specific pages, 5=new tab page.'
                    Out-Raw '    CONTEXT: created_by_policy true means an administrative policy set the engine, not the user or an installer.'
                } catch { Out-Raw ("    Preferences parse failed: " + $_.Exception.Message) }
            }
            $secPref = Get-ChildItem -LiteralPath $b.R -Recurse -Filter 'Secure Preferences' -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($secPref) {
                try {
                    $sj = Get-Content $secPref.FullName -Raw | ConvertFrom-Json
                    Out-KV '    (Secure Preferences) search name' $sj.default_search_provider_data.template_url_data.short_name
                    Out-KV '    (Secure Preferences) search URL'  $sj.default_search_provider_data.template_url_data.url
                } catch { }
            }
        }
        Out-Raw ''
        Out-Raw 'CONTEXT: Chromium stores the active engine in Preferences and a signed copy in Secure Preferences. A mismatch between the two is what the browser itself treats as tampering.'
    }

    Invoke-Collector 'Firefox search and homepage settings' {
        $root = "$env:APPDATA\Mozilla\Firefox\Profiles"
        if (-not (Test-Path $root)) { Out-Raw 'Firefox profile directory not present.'; return }
        foreach ($pr in (Get-ChildItem $root -Directory -ErrorAction SilentlyContinue)) {
            Out-Raw ''
            Out-Raw ('### ' + $pr.Name)
            $prefs = Join-Path $pr.FullName 'prefs.js'
            if (Test-Path $prefs) {
                Out-RawObject (Get-Content $prefs -ErrorAction SilentlyContinue |
                    Where-Object { $_ -match 'browser\.startup\.homepage|browser\.search|keyword\.URL|browser\.newtab|defaultenginename|browser\.urlbar' }) 'Search / homepage prefs'
            }
            $userjs = Join-Path $pr.FullName 'user.js'
            if (Test-Path $userjs) {
                Out-Raw '  user.js present (overrides prefs.js on every start):'
                Out-RawObject (Get-Content $userjs -ErrorAction SilentlyContinue) ''
            }
            foreach ($f in @('search.json.mozlz4','extensions.json','addons.json')) {
                $p = Join-Path $pr.FullName $f
                if (Test-Path $p) { Out-KV ('  ' + $f) ('present, ' + (ConvertTo-MB (Get-Item $p).Length) + ' MB') }
            }
        }
        Out-Raw 'CONTEXT: search.json.mozlz4 holds the installed search engine list in a compressed format that is not plain-text readable. A user.js file is not created by Firefox itself.'
    }

    Invoke-Collector 'Browser enterprise policies' {
        $polKeys = @(
            'HKLM:\SOFTWARE\Policies\Google\Chrome',
            'HKLM:\SOFTWARE\Policies\Google\Update',
            'HKLM:\SOFTWARE\Policies\Microsoft\Edge',
            'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave',
            'HKLM:\SOFTWARE\Policies\Mozilla\Firefox',
            'HKCU:\SOFTWARE\Policies\Google\Chrome',
            'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        )
        foreach ($k in $polKeys) {
            if (Test-Path $k) {
                Out-Raw ''
                Out-Raw "### $k"
                Out-RawList (Get-ItemProperty $k | Select-Object -Property * -ExcludeProperty PS*) ''
                foreach ($sub in (Get-ChildItem $k -Recurse -ErrorAction SilentlyContinue)) {
                    Out-Raw ("  -- " + $sub.PSPath.Replace('Microsoft.PowerShell.Core\Registry::',''))
                    Out-RawList (Get-ItemProperty $sub.PSPath -ErrorAction SilentlyContinue | Select-Object -Property * -ExcludeProperty PS*) ''
                }
            }
        }
        Out-Raw ''
        Out-Raw 'CONTEXT: Policy keys override in-browser settings and grey out the UI control. Managed corporate devices legitimately populate these. Unwanted software also writes here because a policy-set engine cannot be changed back through the browser UI.'
        Out-Raw 'CONTEXT: Relevant policy names include DefaultSearchProviderEnabled, DefaultSearchProviderSearchURL, HomepageLocation, RestoreOnStartupURLs, NewTabPageLocation, ExtensionInstallForcelist.'
    }

    Invoke-Collector 'Browser shortcut target arguments' {
        $dirs = @("$env:USERPROFILE\Desktop", "$env:PUBLIC\Desktop",
                  "$env:APPDATA\Microsoft\Windows\Start Menu\Programs",
                  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
                  "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar")
        $sh = New-Object -ComObject WScript.Shell
        foreach ($d in $dirs) {
            if (-not (Test-Path $d)) { continue }
            foreach ($lnk in (Get-ChildItem $d -Recurse -Filter '*.lnk' -ErrorAction SilentlyContinue)) {
                try {
                    $s = $sh.CreateShortcut($lnk.FullName)
                    if ($s.TargetPath -match 'chrome|msedge|firefox|brave|opera|vivaldi|iexplore') {
                        Out-Raw ''
                        Out-KV 'Shortcut'  $lnk.FullName
                        Out-KV '  Target'  $s.TargetPath
                        Out-KV '  Arguments' $s.Arguments
                        Out-KV '  WorkingDir' $s.WorkingDirectory
                    }
                } catch { }
            }
        }
        Out-Raw ''
        Out-Raw 'CONTEXT: A browser shortcut normally has empty arguments. A URL appended as an argument makes that page open on every launch from that shortcut, independent of the browser''s configured homepage.'
    }

    Invoke-Collector 'Force-installed browser extensions' {
        foreach ($k in @(
            'HKLM:\SOFTWARE\Wow6432Node\Google\Chrome\Extensions',
            'HKLM:\SOFTWARE\Google\Chrome\Extensions',
            'HKCU:\SOFTWARE\Google\Chrome\Extensions',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Edge\Extensions',
            'HKLM:\SOFTWARE\Microsoft\Edge\Extensions',
            'HKCU:\SOFTWARE\Microsoft\Edge\Extensions')) {
            if (Test-Path $k) {
                Out-Raw ''
                Out-Raw "### $k"
                foreach ($e in (Get-ChildItem $k -ErrorAction SilentlyContinue)) {
                    Out-KV ('  ' + $e.PSChildName) (Get-ItemProperty $e.PSPath -ErrorAction SilentlyContinue | Select-Object -Property * -ExcludeProperty PS* | Out-String).Trim()
                }
            }
        }
        Out-Raw 'CONTEXT: Extensions registered under these keys are installed by the browser at next start without a user prompt, and appear in the extension list as installed by an administrator or by a third party.'
    }

    Invoke-Collector 'Protocol and file-type handler registration' {
        foreach ($proto in @('http','https','ftp')) {
            $k = "HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\$proto\UserChoice"
            if (Test-Path $k) { Out-KV "$proto default (UserChoice ProgId)" (Get-ItemProperty $k -ErrorAction SilentlyContinue).ProgId }
            $c = "HKLM:\SOFTWARE\Classes\$proto\shell\open\command"
            if (Test-Path $c) { Out-KV "$proto open command" (Get-ItemProperty $c -Name '(default)' -ErrorAction SilentlyContinue).'(default)' }
        }
        foreach ($ext in @('.htm','.html','.pdf')) {
            $k = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$ext\UserChoice"
            if (Test-Path $k) { Out-KV "$ext default (ProgId)" (Get-ItemProperty $k -ErrorAction SilentlyContinue).ProgId }
        }
        Out-Raw 'CONTEXT: UserChoice carries a hash that Windows validates; it can only be written correctly by the shell UI or by code that reproduces the hash algorithm.'
    }

    Invoke-Collector 'Internet Explorer / WinINET search and start page' {
        foreach ($k in @('HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main',
                         'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main',
                         'HKCU:\SOFTWARE\Microsoft\Internet Explorer\SearchScopes',
                         'HKLM:\SOFTWARE\Microsoft\Internet Explorer\SearchScopes')) {
            if (Test-Path $k) {
                Out-Raw ''
                Out-Raw "### $k"
                Out-RawList (Get-ItemProperty $k | Select-Object -Property * -ExcludeProperty PS*) ''
                foreach ($s in (Get-ChildItem $k -ErrorAction SilentlyContinue)) {
                    Out-Raw ("  -- scope " + $s.PSChildName)
                    Out-RawList (Get-ItemProperty $s.PSPath -ErrorAction SilentlyContinue | Select-Object -Property * -ExcludeProperty PS*) ''
                }
            }
        }
        $bho = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects'
        if (Test-Path $bho) {
            Out-Raw ''
            Out-Raw '### Browser Helper Objects'
            foreach ($b in (Get-ChildItem $bho -ErrorAction SilentlyContinue)) {
                $clsid = $b.PSChildName
                $nm = (Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$clsid" -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                $dll = (Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32" -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                Out-KV ('  ' + $clsid) ("name='$nm' dll='$dll'")
            }
        } else { Out-Raw 'No Browser Helper Objects registered.' }
    }

    Invoke-Collector 'Proxy, DNS and hosts entries affecting search traffic' {
        $ie = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
        Out-RawList ($ie | Select-Object ProxyEnable, ProxyServer, ProxyOverride, AutoConfigURL, AutoDetect) 'Per-user proxy settings'
        Out-Raw 'CONTEXT: A proxy or AutoConfigURL set on a machine that is not managed and not behind a corporate network routes all browser traffic through the named host.'
        $hp = "$env:SystemRoot\System32\drivers\etc\hosts"
        $active = Get-Content $hp -ErrorAction SilentlyContinue | Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' }
        Out-KV 'hosts file active entries' (@($active).Count)
        Out-RawObject ($active | Where-Object { $_ -match 'google|bing|yahoo|duckduckgo|search|update|microsoft|mozilla|avast|norton|mcafee' }) 'Active hosts entries mentioning search or vendor domains'
    }

    Invoke-Collector 'Recently installed programs and their publishers' {
        $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                   'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                   'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
        $apps = Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object DisplayName |
            Select-Object @{n='Name';e={$_.DisplayName}}, @{n='Version';e={$_.DisplayVersion}},
                          Publisher, InstallDate, InstallLocation, UninstallString
        Out-RawObject ($apps | Sort-Object InstallDate -Descending) 'All installed programs, newest install date first'
        Out-Raw ''
        Out-Raw '--- Entries with no publisher recorded ---'
        Out-RawObject ($apps | Where-Object { -not $_.Publisher }) ''
        Out-Raw ''
        Out-Raw '--- Entries whose uninstall string points outside Program Files ---'
        Out-RawObject ($apps | Where-Object { $_.UninstallString -and $_.UninstallString -notmatch 'Program Files|MsiExec|Windows\\System32' }) ''
        Out-Raw 'CONTEXT: InstallDate is recorded by the installer and is frequently absent or wrong. Cross-reference against InstallLocation folder creation time in the storage section when the date matters.'
        Out-Raw 'CONTEXT: Bundled software installed alongside a wanted application typically shares that application''s install date.'
    }

    Invoke-Collector 'Scheduled tasks and services created outside Windows' {
        Out-Raw '--- Scheduled tasks not under \Microsoft\ ---'
        $t = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' }
        Out-RawObject ($t | ForEach-Object {
            $i = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            [pscustomobject]@{
                TaskName = $_.TaskName; TaskPath = $_.TaskPath; State = $_.State; Author = $_.Author
                LastRun = if ($i) { $i.LastRunTime } else { $null }
                Actions = ($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ' ; '
                Triggers = ($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ', '
            }
        } | Sort-Object TaskPath, TaskName) ''
        Out-Raw ''
        Out-Raw '--- Services whose binary is outside the Windows directory ---'
        Out-RawObject (Get-CimInstance Win32_Service |
            Where-Object { $_.PathName -and $_.PathName -notmatch [regex]::Escape($env:SystemRoot) } |
            Select-Object Name, DisplayName, State, StartMode, StartName, PathName | Sort-Object Name) ''
        Out-Raw 'CONTEXT: Third-party applications legitimately create tasks and services here. This lists them so each can be attributed to a known installed program.'
    }
}

# =============================================================== 8. BROWSERS
Invoke-Section 'Browsers' 'browsers' {

    $browsers = @(
        @{N='Chrome';      R="$env:LOCALAPPDATA\Google\Chrome\User Data";                   C=$true},
        @{N='Edge';        R="$env:LOCALAPPDATA\Microsoft\Edge\User Data";                  C=$true},
        @{N='Brave';       R="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data";     C=$true},
        @{N='Vivaldi';     R="$env:LOCALAPPDATA\Vivaldi\User Data";                         C=$true},
        @{N='Opera';       R="$env:APPDATA\Opera Software\Opera Stable";                    C=$true},
        @{N='OperaGX';     R="$env:APPDATA\Opera Software\Opera GX Stable";                 C=$true},
        @{N='Firefox';     R="$env:APPDATA\Mozilla\Firefox\Profiles";                       C=$false}
    )

    foreach ($b in $browsers) {
        if (-not (Test-Path $b.R)) { continue }
        Invoke-Collector ("Browser: " + $b.N) {
            Out-KV 'Root' $b.R
            $t = Get-FolderSize $b.R
            Out-KV 'TotalSizeGB' (ConvertTo-GB $t.Bytes)
            Out-KV 'FileCount'   $t.Files

            if ($b.C) {
                $profiles = Get-ChildItem -LiteralPath $b.R -Directory -ErrorAction SilentlyContinue |
                            Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' -or $_.Name -like 'Guest*' }
                foreach ($pr in $profiles) {
                    Out-Raw ''
                    Out-Raw ("### Profile: " + $pr.Name)
                    $friendly = $null
                    $prefFile = Join-Path $pr.FullName 'Preferences'
                    if (Test-Path $prefFile) {
                        try {
                            $j = Get-Content $prefFile -Raw -ErrorAction Stop | ConvertFrom-Json
                            $friendly = $j.profile.name
                            Out-KV 'ProfileName' $friendly
                            Out-KV 'HardwareAccelerationDisabled' $j.hardware_acceleration_mode_previous
                            Out-KV 'StartupBehaviour' $j.session.restore_on_startup
                            Out-KV 'StartupUrls' ($j.session.startup_urls -join ', ')
                            Out-Raw 'CONTEXT: restore_on_startup 1=restore last session 4=open specific pages 5=new tab.'
                        } catch { Out-Raw "  (Preferences parse failed: $($_.Exception.Message))" }
                    }
                    foreach ($cd in @('Cache','Code Cache','GPUCache','ShaderCache','DawnCache','GrShaderCache',
                                      'Service Worker','IndexedDB','Local Storage','Session Storage','Storage','File System')) {
                        $sz = (Get-FolderSize (Join-Path $pr.FullName $cd)).Bytes
                        if ($sz -gt 0) { Out-KV ("  cache: " + $cd + " (GB)") (ConvertTo-GB $sz) }
                    }
                    foreach ($db in @('History','Cookies','Web Data','Favicons','Login Data','Top Sites')) {
                        $f = Join-Path $pr.FullName $db
                        if (Test-Path $f) { Out-KV ("  db: " + $db + " (MB)") (ConvertTo-MB (Get-Item $f -Force).Length) }
                    }
                    $ext = Join-Path $pr.FullName 'Extensions'
                    if (Test-Path $ext) {
                        $rows = foreach ($e in (Get-ChildItem $ext -Directory -ErrorAction SilentlyContinue)) {
                            $ver = Get-ChildItem $e.FullName -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
                            $nm = $null
                            if ($ver) {
                                $mf = Join-Path $ver.FullName 'manifest.json'
                                if (Test-Path $mf) {
                                    try { $m = Get-Content $mf -Raw | ConvertFrom-Json; $nm = $m.name } catch { }
                                }
                            }
                            [pscustomobject]@{ ExtensionId = $e.Name; Name = $nm
                                               Version = if ($ver) { $ver.Name } else { $null }
                                               SizeMB = ConvertTo-MB (Get-FolderSize $e.FullName).Bytes }
                        }
                        Out-RawObject $rows ('Extensions in ' + $pr.Name)
                        Out-KV '  ExtensionCount' (@($rows).Count)
                    }
                }
                # Each vendor has its own policy hive. Falling through to
                # Chrome's meant that on a machine with Chrome installed, its
                # policies were reported under Brave/Opera/Vivaldi as if they
                # were that browser's.
                $polMap = @{ 'Chrome'='Google\Chrome'; 'Edge'='Microsoft\Edge'
                             'Brave'='BraveSoftware\Brave-Browser'
                             'Opera'='OPSoftware\Opera'; 'OperaGX'='OPSoftware\Opera GX'
                             'Vivaldi'='Vivaldi\Vivaldi' }
                $polSub = $polMap[$b.N]
                if ($polSub) {
                    $pol = "HKLM:\SOFTWARE\Policies\$polSub"
                    Out-KV '    policy hive' $pol
                    if (Test-Path $pol) { Out-RawList (Get-ItemProperty $pol | Select-Object -Property * -ExcludeProperty PS*) 'Enterprise policies' }
                    else { Out-Raw '    (no enterprise policy hive for this browser)' }
                }
            } else {
                foreach ($pr in (Get-ChildItem -LiteralPath $b.R -Directory -ErrorAction SilentlyContinue)) {
                    Out-KV ("Profile " + $pr.Name + " GB") (ConvertTo-GB (Get-FolderSize $pr.FullName).Bytes)
                    foreach ($f in @('places.sqlite','cookies.sqlite','prefs.js','extensions.json')) {
                        $p = Join-Path $pr.FullName $f
                        if (Test-Path $p) { Out-KV ("  " + $f + " MB") (ConvertTo-MB (Get-Item $p -Force).Length) }
                    }
                }
            }
        }
    }

    Invoke-Collector 'Browser process counts and memory' {
        foreach ($n in @('chrome','msedge','firefox','brave','opera','vivaldi')) {
            $p = Get-Process $n -ErrorAction SilentlyContinue
            if ($p) {
                Out-KV "$n process count" (@($p).Count)
                Out-KV "$n total WS (MB)" (ConvertTo-MB (($p | Measure-Object WorkingSet64 -Sum).Sum))
            }
        }
        Out-Raw 'CONTEXT: Chromium spawns separate processes for the browser, GPU, network service, and one renderer per site-isolated origin.'
    }
}

# =============================================================== 9. SOFTWARE
Invoke-Section 'Installed Software' 'software' {

    Invoke-Collector 'Installed programs (registry)' {
        $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                   'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                   'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
        $apps = foreach ($p in $paths) {
            Get-ItemProperty $p -ErrorAction SilentlyContinue | Where-Object DisplayName |
                Select-Object @{n='Name';e={$_.DisplayName}}, @{n='Version';e={$_.DisplayVersion}},
                              Publisher, InstallDate, InstallLocation,
                              @{n='SizeMB';e={ if ($_.EstimatedSize) { [math]::Round($_.EstimatedSize/1024,1) } else { $null } }}
        }
        $apps = $apps | Sort-Object Name -Unique
        Out-KV 'Count' (@($apps).Count)
        Out-RawObject $apps 'Installed programs'
        Save-Csv  $apps 'software_installed'
        Save-Json $apps 'software_installed'
    }

    Invoke-Collector 'Store / UWP packages' {
        $pk = Get-AppxPackage -ErrorAction SilentlyContinue | Select-Object Name, PackageFullName, Version, Publisher, InstallLocation
        Out-KV 'Count' (@($pk).Count)
        Out-RawObject ($pk | Sort-Object Name) 'Appx packages'
        Save-Csv $pk 'software_appx'
    }

    Invoke-Collector 'All executables on disk (application directories)' {
        $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData,
                   "$env:LOCALAPPDATA\Programs", "$env:LOCALAPPDATA", "$env:APPDATA",
                   "$env:SystemDrive\Tools", "$env:SystemDrive\Apps") |
                 Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
        $rows = @()
        foreach ($r in $roots) {
            Out-Raw ''
            Out-Raw "### Scanning $r"
            $found = Get-ChildItem -LiteralPath $r -Recurse -File -Include *.exe -Force -ErrorAction SilentlyContinue |
                     Select-Object -First $script:Limits.MaxExeScan
            Out-KV '  executables found' (@($found).Count)
            foreach ($f in $found) {
                $vi = $f.VersionInfo
                $rows += [pscustomobject]@{
                    Name         = $f.Name
                    SizeMB       = ConvertTo-MB $f.Length
                    LastWrite    = $f.LastWriteTime
                    Company      = $vi.CompanyName
                    Product      = $vi.ProductName
                    FileVersion  = $vi.FileVersion
                    Description  = $vi.FileDescription
                    Root         = $r
                    FullPath     = $f.FullName
                }
            }
        }
        Out-RawObject ($rows | Sort-Object Company, Name) 'All .exe files under application directories'
        Save-Csv  $rows 'software_executables'
        Save-Json $rows 'software_executables'
        Out-KV 'TOTAL executables catalogued' (@($rows).Count)
        Out-Raw ''
        Out-Raw '--- Grouped by publisher ---'
        Out-RawObject ($rows | Group-Object Company | Sort-Object Count -Descending |
            Select-Object @{n='Company';e={ if ($_.Name) { $_.Name } else { '(no company in version info)' } }}, Count,
                          @{n='TotalMB';e={[math]::Round((($_.Group | Measure-Object SizeMB -Sum).Sum),1)}}) ''
        Out-Raw 'CONTEXT: Missing CompanyName in version info means the binary carries no version resource. Many legitimate build tools and installers ship without one.'
    }

    Invoke-Collector 'System executables (Windows directories)' {
        $sysRoots = @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64", "$env:SystemRoot")
        $rows = @()
        foreach ($r in $sysRoots) {
            if (-not (Test-Path $r)) { continue }
            $found = Get-ChildItem -LiteralPath $r -File -Include *.exe -Force -ErrorAction SilentlyContinue
            Out-KV "$r executables" (@($found).Count)
            foreach ($f in $found) {
                $vi = $f.VersionInfo
                $rows += [pscustomobject]@{
                    Name        = $f.Name
                    SizeKB      = [math]::Round($f.Length/1KB,1)
                    LastWrite   = $f.LastWriteTime
                    Company     = $vi.CompanyName
                    Description = $vi.FileDescription
                    FileVersion = $vi.FileVersion
                    Directory   = $r
                }
            }
        }
        Out-RawObject ($rows | Sort-Object Directory, Name) 'System executables'
        Save-Csv $rows 'software_system_executables'
        Out-KV 'TOTAL system executables' (@($rows).Count)
        Out-Raw ''
        Out-Raw '--- Non-Microsoft binaries sitting in Windows system directories ---'
        Out-RawObject ($rows | Where-Object { $_.Company -and $_.Company -notmatch 'Microsoft' } |
            Sort-Object Company, Name) ''
        Out-Raw 'CONTEXT: Third-party binaries in System32 are commonly placed there by driver packages, printer software and security products.'
    }

    Invoke-Collector 'System DLL and driver file inventory' {
        $drvDir = "$env:SystemRoot\System32\drivers"
        if (Test-Path $drvDir) {
            $rows = Get-ChildItem -LiteralPath $drvDir -File -Include *.sys -Force -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $vi = $_.VersionInfo
                    [pscustomobject]@{
                        Name = $_.Name; SizeKB = [math]::Round($_.Length/1KB,1)
                        LastWrite = $_.LastWriteTime
                        Company = $vi.CompanyName; Description = $vi.FileDescription
                        FileVersion = $vi.FileVersion
                    }
                }
            Out-RawObject ($rows | Sort-Object Company, Name) 'Driver files (.sys) in System32\drivers'
            Save-Csv $rows 'software_driver_files'
            Out-KV 'TOTAL .sys files' (@($rows).Count)
            Out-RawObject ($rows | Where-Object { $_.Company -and $_.Company -notmatch 'Microsoft' }) 'Non-Microsoft driver files'
        }
    }

    Invoke-Collector 'Windows optional features' {
        try { Out-RawObject (Get-WindowsOptionalFeature -Online | Where-Object State -eq 'Enabled' | Select-Object FeatureName, State) 'Enabled optional features' }
        catch { Out-Raw "Get-WindowsOptionalFeature: $($_.Exception.Message)" }
    }

    Invoke-Collector 'Installed fonts' {
        $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts' -ErrorAction SilentlyContinue
        $n = 0
        if ($reg) { $n = @($reg.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }).Count }
        Out-KV 'RegisteredFonts' $n
        Out-KV 'FontFilesOnDisk' (@(Get-ChildItem "$env:SystemRoot\Fonts" -File -ErrorAction SilentlyContinue).Count)
        Out-Raw 'CONTEXT: A clean Windows 11 installation registers roughly 200 to 400 fonts.'
    }

    Invoke-Collector 'Environment and PATH' {
        Out-RawObject (Get-ChildItem Env: | Sort-Object Name) 'Environment variables'
        $p = $env:PATH -split ';'
        Out-KV 'PATH length (chars)' $env:PATH.Length
        Out-KV 'PATH entries' (@($p).Count)
        Out-Raw 'CONTEXT: The PATH environment variable has a 32,767 character limit.'
        foreach ($e in $p) { if ($e.Trim()) { Out-Raw ("  " + $e + $(if (Test-Path $e -ErrorAction SilentlyContinue) { '' } else { '   [does not exist]' })) } }
    }
}

# =============================================================== 10. WINDOWS
Invoke-Section 'Windows Configuration' 'windows' {

    Invoke-Collector 'Windows Update history' {
        Out-RawObject (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object HotFixID, Description, InstalledOn, InstalledBy) 'Installed hotfixes'
        try {
            $s = New-Object -ComObject Microsoft.Update.Session
            $q = $s.CreateUpdateSearcher()
            $n = $q.GetTotalHistoryCount()
            if ($n -gt 0) {
                Out-RawObject ($q.QueryHistory(0,[Math]::Min($n,200)) |
                    Select-Object Date, Title, @{n='Result';e={$_.ResultCode}}, @{n='HResult';e={'0x{0:X8}' -f $_.HResult}}) 'Update history (COM)'
                Out-Raw 'CONTEXT: ResultCode 2=Succeeded 3=SucceededWithErrors 4=Failed 5=Aborted.'
            }
        } catch { Out-Raw "Update COM API: $($_.Exception.Message)" }
    }

    Invoke-Collector 'Pending reboot indicators' {
        Out-KV 'CBS RebootPending'     (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
        Out-KV 'WU RebootRequired'     (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
        Out-KV 'PendingFileRename'     ($null -ne (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue))
    }

    Invoke-Collector 'Defender configuration and exclusions' {
        try {
            Out-RawList (Get-MpComputerStatus) 'Get-MpComputerStatus'
            $p = Get-MpPreference
            Out-RawList ($p | Select-Object DisableRealtimeMonitoring, ScanAvgCPULoadFactor, DisableCpuThrottleOnIdleScans, ExclusionPath, ExclusionExtension, ExclusionProcess) 'Get-MpPreference (exclusions)'
            Out-KV 'ExclusionPathCount'      (@($p.ExclusionPath).Count)
            Out-KV 'ExclusionProcessCount'   (@($p.ExclusionProcess).Count)
            Out-KV 'ExclusionExtensionCount' (@($p.ExclusionExtension).Count)
            Out-Raw 'CONTEXT: ScanAvgCPULoadFactor is the maximum average CPU percentage Defender targets during scans; default is 50.'
        } catch { Out-Raw "Defender cmdlets: $($_.Exception.Message)" }
        Out-RawObject (Get-Process MsMpEng -ErrorAction SilentlyContinue | Select-Object Id, @{n='CPUSec';e={[math]::Round($_.CPU,1)}}, @{n='WS_MB';e={ConvertTo-MB $_.WorkingSet64}}) 'MsMpEng'
    }

    Invoke-Collector 'Third-party security products' {
        try { Out-RawObject (Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName, productState, pathToSignedProductExe) 'Registered AV products' } catch { }
        try { Out-RawObject (Get-CimInstance -Namespace root\SecurityCenter2 -ClassName FirewallProduct | Select-Object displayName, productState) 'Registered firewall products' } catch { }
    }

    Invoke-Collector 'Power configuration' {
        Invoke-NativeCapture 'Power schemes' 'powercfg /list'
        Invoke-NativeCapture 'Active scheme detail' 'powercfg /query' 'powercfg_full.txt'
        $hb = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -ErrorAction SilentlyContinue
        Out-KV 'HiberbootEnabled (Fast Startup)' $hb.HiberbootEnabled
    }

    Invoke-Collector 'WMI repository' {
        $p = "$env:SystemRoot\System32\wbem\Repository"
        if (Test-Path $p) { Out-KV 'RepositorySizeMB' (ConvertTo-MB (Get-FolderSize $p).Bytes) }
        Out-KV 'winmgmt service' (Get-Service winmgmt -ErrorAction SilentlyContinue).Status
        Out-RawObject (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; Level=@(2,3)} -MaxEvents 50 -ErrorAction SilentlyContinue |
            Select-Object TimeCreated, Id, Message) 'WMI errors/warnings'
    }

    Invoke-Collector 'Search index' {
        $r = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Search' -ErrorAction SilentlyContinue
        Out-KV 'SetupCompletedSuccessfully' $r.SetupCompletedSuccessfully
        Out-KV 'WSearch service' (Get-Service WSearch -ErrorAction SilentlyContinue).Status
        $edb = "$env:ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb"
        if (Test-Path $edb) { Out-KV 'Windows.edb GB' (ConvertTo-GB (Get-Item $edb -Force).Length) }
    }

    Invoke-Collector 'User profiles' {
        Out-RawObject (Get-CimInstance Win32_UserProfile | Select-Object LocalPath, SID, LastUseTime, Special, Loaded) 'User profiles'
        $nt = "$env:USERPROFILE\NTUSER.DAT"
        if (Test-Path $nt) { Out-KV 'NTUSER.DAT MB' (ConvertTo-MB (Get-Item $nt -Force).Length) }
    }

    Invoke-Collector 'Component store' -NeedsAdmin {
        Invoke-NativeCapture 'DISM AnalyzeComponentStore' 'DISM /Online /Cleanup-Image /AnalyzeComponentStore' 'dism_componentstore.txt'
    }

    Invoke-Collector 'Group policy' {
        Invoke-NativeCapture 'gpresult' 'gpresult /r /scope:computer' 'gpresult_computer.txt'
    }

    Invoke-Collector 'Windows 11 feature flags' {
        foreach ($k in @(
            @{N='GameDVR';   P='HKCU:\System\GameConfigStore'},
            @{N='GameBar';   P='HKCU:\Software\Microsoft\GameBar'},
            @{N='WindowsAI'; P='HKCU:\Software\Microsoft\Windows\CurrentVersion\WindowsAI'},
            @{N='Explorer';  P='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'})) {
            if (Test-Path $k.P) { Out-RawList (Get-ItemProperty $k.P | Select-Object -Property * -ExcludeProperty PS*) $k.N }
        }
    }
}

# =============================================================== 11. EVENTS
Invoke-Section 'Event Logs' 'eventlogs' {

    Invoke-Collector 'Event log inventory' {
        Out-RawObject (Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
            Where-Object { $_.RecordCount -gt 0 } |
            Select-Object LogName, RecordCount, @{n='FileSizeMB';e={ConvertTo-MB $_.FileSize}}, IsEnabled, LogMode |
            Sort-Object FileSizeMB -Descending) 'Logs with records'
    }

    foreach ($log in @('System','Application','Setup')) {
        Invoke-Collector ("Errors and criticals: $log") {
            $ev = Get-WinEvent -FilterHashtable @{LogName=$log; Level=1,2; StartTime=(Get-Date).AddDays(-$script:Cfg.EventDays)} -ErrorAction SilentlyContinue
            Out-KV 'EventCount' (@($ev).Count)
            Out-RawObject ($ev | Group-Object ProviderName, Id | Sort-Object Count -Descending |
                Select-Object @{n='Provider/Id';e={$_.Name}}, Count,
                              @{n='Sample';e={ ($_.Group | Select-Object -First 1).Message -replace "`r?`n",' ' }}) "Grouped by provider and event ID (last $($script:Cfg.EventDays) days)"
            Out-RawObject ($ev | Select-Object -First $script:Limits.EventRows TimeCreated, ProviderName, Id, LevelDisplayName, Message) 'Individual events'
            Save-Csv ($ev | Select-Object TimeCreated, ProviderName, Id, LevelDisplayName, Message) ("events_" + $log.ToLower())
        }
    }

    Invoke-Collector 'Application crashes and hangs (1000/1001/1002)' {
        $ev = Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000,1001,1002; StartTime=(Get-Date).AddDays(-$script:Cfg.EventDays)} -ErrorAction SilentlyContinue
        Out-KV 'Count' (@($ev).Count)
        Out-RawObject ($ev | Select-Object TimeCreated, Id, Message) 'Crash and hang events'
        Out-Raw 'CONTEXT: Event 1000 is an application crash, 1002 is an application hang, 1001 is a Windows Error Reporting record.'
    }

    Invoke-Collector 'Unexpected shutdowns and bugchecks (41/1001/6008)' {
        $ev = Get-WinEvent -FilterHashtable @{LogName='System'; Id=41,6008,1001; StartTime=(Get-Date).AddDays(-90)} -ErrorAction SilentlyContinue
        Out-KV 'Count (90 days)' (@($ev).Count)
        Out-RawObject ($ev | Select-Object TimeCreated, ProviderName, Id, Message) 'Shutdown and bugcheck events'
        Out-Raw 'CONTEXT: Event 41 is logged when the system rebooted without a clean shutdown. 6008 is the previous shutdown was unexpected.'
    }

    Invoke-Collector 'Disk and storage subsystem events (7/11/51/153/129)' {
        $ev = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7,11,51,129,153; StartTime=(Get-Date).AddDays(-90)} -ErrorAction SilentlyContinue
        Out-KV 'Count (90 days)' (@($ev).Count)
        Out-RawObject ($ev | Select-Object TimeCreated, ProviderName, Id, Message) 'Storage events'
        Out-Raw 'CONTEXT: Event 7 is a bad block, 51 is a paging error, 129 is a storage controller reset, 153 is an I/O retry.'
    }

    Invoke-Collector 'GPU driver resets (4101)' {
        $ev = Get-WinEvent -FilterHashtable @{LogName='System'; Id=4101; StartTime=(Get-Date).AddDays(-90)} -ErrorAction SilentlyContinue
        Out-KV 'Count (90 days)' (@($ev).Count)
        Out-RawObject ($ev | Select-Object TimeCreated, Message) 'Display driver reset events'
        Out-Raw 'CONTEXT: Event 4101 is logged when the display driver stopped responding and was recovered (TDR).'
    }

    Invoke-Collector 'Boot and logon performance (100/101/200/201)' {
        foreach ($id in @(100,101,200,201)) {
            $ev = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Diagnostics-Performance/Operational'; Id=$id} -MaxEvents 30 -ErrorAction SilentlyContinue
            Out-RawObject ($ev | Select-Object TimeCreated, Id, Message) "Event ID $id"
        }
        Out-Raw 'CONTEXT: 100 is boot completed, 200 is logon completed. 101 and 201 name individual processes that extended those times.'
    }

    Invoke-Collector 'Export raw event logs' {
        foreach ($log in @('System','Application')) {
            $out = Join-Path $script:Dirs.Events "$log.evtx"
            Invoke-NativeCapture "Export $log" ("wevtutil epl $log `"$out`" /ow:true")
        }
    }

    Invoke-Collector 'Crash dumps present' {
        foreach ($d in @("$env:SystemRoot\Minidump", "$env:SystemRoot\MEMORY.DMP", "$env:LOCALAPPDATA\CrashDumps")) {
            if (Test-Path $d) {
                Out-RawObject (Get-ChildItem $d -File -Recurse -ErrorAction SilentlyContinue |
                    Select-Object Name, @{n='SizeMB';e={ConvertTo-MB $_.Length}}, LastWriteTime, FullName) $d
            }
        }
    }
}

# =============================================================== 12. COUNTERS
Invoke-Section 'Performance Capture' 'counters' {
    Invoke-Collector 'Sustained performance counter capture' {
        $mins = $script:Cfg.PerformanceMinutes
        if ($mins -le 0) { Out-Raw 'Performance capture disabled for this mode.'; return }
        $samples = [int]($mins * 60 / 5)
        Out-KV 'DurationMinutes' $mins
        Out-KV 'SampleIntervalSeconds' 5
        Out-KV 'SampleCount' $samples
        $c = @('\Processor(_Total)\% Processor Time','\Memory\Available MBytes',
               '\PhysicalDisk(_Total)\Avg. Disk Queue Length','\PhysicalDisk(_Total)\Avg. Disk sec/Read',
               '\PhysicalDisk(_Total)\Avg. Disk sec/Write','\System\Processor Queue Length',
               '\System\Context Switches/sec','\Memory\Pages/sec',
               '\Network Interface(*)\Bytes Total/sec')
        $out = Join-Path $script:Dirs.Counters 'capture.csv'
        Out-Raw ("Capturing to " + $out)
        Get-Counter -Counter $c -SampleInterval 5 -MaxSamples $samples -ErrorAction SilentlyContinue |
            Export-Counter -Path $out -FileFormat CSV -Force -ErrorAction SilentlyContinue
        Out-Raw 'Capture complete.'
    }
}

# =============================================================== 13. SYSINTERNALS
Invoke-Section 'Sysinternals' 'sysinternals' {
    $tools = @(
        @{Exe='autorunsc.exe'; Args='-accepteula -nobanner -a * -c -h'; Out='autoruns.csv'},
        @{Exe='handle.exe';    Args='-accepteula -nobanner -s';         Out='handle_summary.txt'},
        @{Exe='pslist.exe';    Args='-accepteula -nobanner -t';         Out='pslist_tree.txt'},
        @{Exe='psinfo.exe';    Args='-accepteula -nobanner -s -d';      Out='psinfo.txt'},
        @{Exe='psservice.exe'; Args='-accepteula -nobanner';            Out='psservice.txt'},
        @{Exe='tcpvcon.exe';   Args='-accepteula -nobanner -a -n';      Out='tcpvcon.txt'},
        @{Exe='sigcheck.exe';  Args=('-accepteula -nobanner -u -e -s "' + $env:SystemRoot + '\System32"'); Out='sigcheck_unsigned.txt'},
        @{Exe='coreinfo.exe';  Args='-accepteula -nobanner';            Out='coreinfo.txt'}
    )
    foreach ($t in $tools) {
        Invoke-Collector ("Sysinternals: " + $t.Exe) {
            $p = Get-SysinternalsTool $t.Exe
            if (-not $p) { Out-Raw ("$($t.Exe) not found on PATH or beside the script - skipped."); return }
            Out-KV 'Found at' $p
            $dest = Join-Path $script:Dirs.Sysint $t.Out
            Invoke-NativeCapture $t.Exe ("`"$p`" " + $t.Args) $t.Out
        }
    }
    Invoke-Collector 'Sysinternals availability note' {
        Out-Raw 'CONTEXT: Sysinternals Suite is available at https://learn.microsoft.com/sysinternals/downloads/sysinternals-suite'
        Out-Raw 'Place the executables beside this script or on PATH to enable the collectors above.'
    }
}

} # end Invoke-AllSections


# ##############################################################################
# REGION: RUN
# ##############################################################################

try {
    Invoke-AllSections
}
catch {
    Write-DiagLog "UNHANDLED: $($_.Exception.Message)" 'ERROR' 'Main'
    Write-DiagLog ($_.ScriptStackTrace | Out-String) 'ERROR' 'Main'
}
finally {
    # ---------------------------------------------------------------- run stats
    try {
        Write-Timeline 'RUN END'
        $dur = (Get-Date) - $script:Cfg.StartTime

        $runInfo = [pscustomobject]@{
            DurationMinutes = [math]::Round($dur.TotalMinutes, 2)
            Sections        = $script:Stats.Sections
            Collectors      = $script:Stats.Collectors
            Succeeded       = $script:Stats.Succeeded
            Failed          = $script:Stats.Failed
            Skipped         = $script:Stats.Skipped
            Retried         = $script:Stats.Retried
            CompletedUtc    = (Get-Date).ToUniversalTime().ToString('o')
        }
        Save-Json $runInfo 'RUNINFO' 3

        Write-DiagLog '================ COLLECTION RUN FINISHED ================' 'INFO' 'Main'
        Write-DiagLog ("duration={0:N2}min sections={1} collectors={2} ok={3} failed={4} skipped={5}" -f `
            $dur.TotalMinutes, $script:Stats.Sections, $script:Stats.Collectors,
            $script:Stats.Succeeded, $script:Stats.Failed, $script:Stats.Skipped) 'INFO' 'Main'
    } catch { }

    # ------------------------------------------------------------ close streams
    foreach ($k in @($script:Streams.Keys)) {
        try { $script:Streams[$k].Writer.Flush(); $script:Streams[$k].Writer.Close(); $script:Streams[$k].Writer.Dispose() } catch { }
    }

    # ------------------------------------------------------------------- zip it
    if (-not $NoCompress) {
        try {
            $zip = Join-Path $OutputPath "$($script:PkgName).zip"
            if (Test-Path $zip) { Remove-Item $zip -Force -ErrorAction SilentlyContinue }
            Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
            [System.IO.Compression.ZipFile]::CreateFromDirectory($script:PkgRoot, $zip)
            Write-Host ''
            Write-Host "   ZIP archive : $zip" -ForegroundColor White
        } catch {
            Write-Host "   ZIP failed ($_). The folder is still complete." -ForegroundColor Yellow
        }
    }

    $dur2 = (Get-Date) - $script:Cfg.StartTime

    # A run that collected nothing must not look like a successful one. Sending
    # an empty package wastes the analyst's time and, worse, invites them to
    # read "no findings" into what is actually "no data".
    $ranNothing = ($script:Stats.Collectors -eq 0)
    $bannerColour = if ($ranNothing) { 'Red' } else { 'Green' }

    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor $bannerColour
    if ($ranNothing) {
        Write-Host '   COLLECTION PRODUCED NOTHING' -ForegroundColor Red
    } else {
        Write-Host '   COLLECTION COMPLETE' -ForegroundColor Green
    }
    Write-Host ("   Duration   : {0:N1} minutes" -f $dur2.TotalMinutes)
    Write-Host ("   Collectors : {0} run / {1} ok / {2} failed / {3} skipped" -f `
        $script:Stats.Collectors, $script:Stats.Succeeded, $script:Stats.Failed, $script:Stats.Skipped)
    Write-Host ("   Package    : $($script:PkgRoot)") -ForegroundColor White
    Write-Host ('=' * 78) -ForegroundColor $bannerColour
    Write-Host ''

    if ($ranNothing) {
        Write-Host '   No collector ran, so the package is empty. Do NOT send it -' -ForegroundColor Yellow
        Write-Host '   an empty package reads as "nothing wrong" when it actually' -ForegroundColor Yellow
        Write-Host '   means "nothing was looked at".' -ForegroundColor Yellow
        Write-Host ''
        if ($script:Cfg.OnlySection) {
            Write-Host ('   -OnlySection was set to: ' + ($script:Cfg.OnlySection -join ', ')) -ForegroundColor Gray
            Write-Host '   No section matched that name. Re-run without -OnlySection.' -ForegroundColor Gray
        } else {
            Write-Host '   Check logs\Errors.log in the package for what went wrong.' -ForegroundColor Gray
        }
        Write-Host ''
    } else {
        Write-Host '   Send the ZIP (or folder) to whoever is analysing it.' -ForegroundColor Gray
        Write-Host '   This toolkit drew no conclusions - the data is unfiltered.' -ForegroundColor Gray
        Write-Host ''
        if ($script:Stats.Failed -gt 0) {
            Write-Host ("   {0} collector(s) failed and are listed in logs\Errors.log." -f $script:Stats.Failed) -ForegroundColor Yellow
            Write-Host '   Their data is absent, not empty - the log says so explicitly.' -ForegroundColor Yellow
            Write-Host ''
        }
        # Only meaningful with an interactive desktop; on a service or
        # headless session this leaks a detached process instead.
        if ([Environment]::UserInteractive) {
            try { Start-Process explorer.exe $script:PkgRoot } catch { }
        }
    }
}
