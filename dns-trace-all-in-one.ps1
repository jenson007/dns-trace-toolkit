param(
    [int]$BaselineDurationSec = 300,
    [int]$OptimizedDurationSec = 300,
    [int]$WorkloadLoops = 20,
    [string[]]$Domains = @("microsoft.com", "github.com", "office.com", "bing.com", "learn.microsoft.com"),
    [string]$OutDir = ".\dns-trace-results",
    [switch]$DisableSmartNameResolution = $true,
    [switch]$DisableLLMNR = $true,
    [switch]$DisableBrowserDnsPrefetch = $true,
    [switch]$ClearDnsCacheBeforeEachPhase = $true,
    [switch]$RunGpUpdate = $true,
    [switch]$RollbackAtEnd
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).
        IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        throw "Bitte PowerShell als Administrator starten."
    }
}

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @()
    )

    $null = & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Befehl fehlgeschlagen: $FilePath $($Arguments -join ' ') (ExitCode=$LASTEXITCODE)"
    }
}

function Test-Command {
    param([Parameter(Mandatory = $true)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Invoke-DnsWorkload {
    param(
        [int]$Loops,
        [string[]]$WorkloadDomains,
        [int]$DurationSec
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $DurationSec) {
        for ($i = 0; $i -lt $Loops; $i++) {
            foreach ($d in $WorkloadDomains) {
                Resolve-DnsName $d -Type A | Out-Null
                Resolve-DnsName $d -Type AAAA | Out-Null
            }
            Start-Sleep -Milliseconds 300
            if ($sw.Elapsed.TotalSeconds -ge $DurationSec) { break }
        }
    }
}

function Get-TsharkCounts {
    param(
        [Parameter(Mandatory = $true)][string]$PcapPath
    )

    $tshark = Get-Command tshark -ErrorAction SilentlyContinue
    if (-not $tshark) {
        return [pscustomobject]@{
            QueryPackets    = $null
            ResponsePackets = $null
            Analyzer        = "none"
        }
    }

    $queries = (& $tshark.Source -r $PcapPath -Y "dns.flags.response==0" -T fields -e frame.number 2>$null | Measure-Object).Count
    $responses = (& $tshark.Source -r $PcapPath -Y "dns.flags.response==1" -T fields -e frame.number 2>$null | Measure-Object).Count

    return [pscustomobject]@{
        QueryPackets    = [int]$queries
        ResponsePackets = [int]$responses
        Analyzer        = "tshark"
    }
}

function Set-DnsOptimization {
    $dnsPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    New-Item -Path $dnsPolicyPath -Force | Out-Null

    if ($DisableSmartNameResolution) {
        New-ItemProperty -Path $dnsPolicyPath -Name "DisableSmartNameResolution" -PropertyType DWord -Value 1 -Force | Out-Null
    }

    if ($DisableLLMNR) {
        New-ItemProperty -Path $dnsPolicyPath -Name "EnableMulticast" -PropertyType DWord -Value 0 -Force | Out-Null
    }

    if ($DisableBrowserDnsPrefetch) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DnsPrefetchingEnabled" -PropertyType DWord -Value 0 -Force | Out-Null

        New-Item -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "DnsPrefetchingEnabled" -PropertyType DWord -Value 0 -Force | Out-Null
    }

    if ($RunGpUpdate -and (Test-Command -Name "gpupdate")) {
        gpupdate /force | Out-Null
    }
}

function Reset-DnsOptimization {
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "DisableSmartNameResolution" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DnsPrefetchingEnabled" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "DnsPrefetchingEnabled" -ErrorAction SilentlyContinue

    if ($RunGpUpdate -and (Test-Command -Name "gpupdate")) {
        gpupdate /force | Out-Null
    }
}

function Invoke-CapturePhase {
    param(
        [Parameter(Mandatory = $true)][string]$PhaseName,
        [Parameter(Mandatory = $true)][int]$DurationSec,
        [Parameter(Mandatory = $true)][string]$SessionDir
    )

    $etlPath = Join-Path $SessionDir "$PhaseName.etl"
    $pcapPath = Join-Path $SessionDir "$PhaseName.pcapng"
    $txtPath = Join-Path $SessionDir "$PhaseName.txt"

    try { & pktmon stop | Out-Null } catch {}
    try { & pktmon unload | Out-Null } catch {}

    Invoke-External -FilePath "pktmon" -Arguments @("filter", "remove")
    Invoke-External -FilePath "pktmon" -Arguments @("filter", "add", "DNS-UDP", "-t", "UDP", "-p", "53")
    Invoke-External -FilePath "pktmon" -Arguments @("filter", "add", "DNS-TCP", "-t", "TCP", "-p", "53")
    Invoke-External -FilePath "pktmon" -Arguments @("reset")

    if ($ClearDnsCacheBeforeEachPhase) {
        Clear-DnsClientCache
    }

    Invoke-External -FilePath "pktmon" -Arguments @(
        "start",
        "--capture",
        "--pkt-size", "0",
        "--file-name", $etlPath,
        "--file-size", "1024",
        "--log-mode", "circular"
    )

    Invoke-DnsWorkload -Loops $WorkloadLoops -WorkloadDomains $Domains -DurationSec $DurationSec

    Invoke-External -FilePath "pktmon" -Arguments @("stop")
    Invoke-External -FilePath "pktmon" -Arguments @("etl2pcap", $etlPath, "-o", $pcapPath)
    Invoke-External -FilePath "pktmon" -Arguments @("etl2txt", $etlPath, "-o", $txtPath)

    $counts = Get-TsharkCounts -PcapPath $pcapPath
    $queryRate = if ($counts.QueryPackets -ne $null -and $DurationSec -gt 0) {
        [math]::Round(($counts.QueryPackets / $DurationSec), 3)
    } else {
        $null
    }

    [pscustomobject]@{
        Phase           = $PhaseName
        DurationSec     = $DurationSec
        EtlPath         = $etlPath
        PcapPath        = $pcapPath
        TxtPath         = $txtPath
        QueryPackets    = $counts.QueryPackets
        ResponsePackets = $counts.ResponsePackets
        QueriesPerSec   = $queryRate
        Analyzer        = $counts.Analyzer
    }
}

Assert-Admin

if (-not (Test-Command -Name "pktmon")) {
    throw "pktmon ist nicht verfuegbar."
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$sessionDir = Join-Path $OutDir $timestamp
New-Item -Path $sessionDir -ItemType Directory -Force | Out-Null

Write-Host "Phase 1: Baseline..." -ForegroundColor Cyan
$baseline = Invoke-CapturePhase -PhaseName "baseline" -DurationSec $BaselineDurationSec -SessionDir $sessionDir

Write-Host "Setze DNS-Optimierung..." -ForegroundColor Yellow
Set-DnsOptimization

Write-Host "Phase 2: Optimized..." -ForegroundColor Cyan
$optimized = Invoke-CapturePhase -PhaseName "optimized" -DurationSec $OptimizedDurationSec -SessionDir $sessionDir

$deltaAbs = $null
$deltaPct = $null
if ($baseline.QueryPackets -ne $null -and $optimized.QueryPackets -ne $null) {
    $deltaAbs = $optimized.QueryPackets - $baseline.QueryPackets
    if ($baseline.QueryPackets -gt 0) {
        $deltaPct = [math]::Round((($optimized.QueryPackets - $baseline.QueryPackets) / $baseline.QueryPackets) * 100, 2)
    }
}

$summary = [pscustomobject]@{
    CreatedAt               = (Get-Date).ToString("s")
    SessionDir              = (Resolve-Path $sessionDir).Path
    BaselineDurationSec     = $baseline.DurationSec
    BaselineQueryPackets    = $baseline.QueryPackets
    BaselineQueriesPerSec   = $baseline.QueriesPerSec
    OptimizedDurationSec    = $optimized.DurationSec
    OptimizedQueryPackets   = $optimized.QueryPackets
    OptimizedQueriesPerSec  = $optimized.QueriesPerSec
    QueryDeltaAbsolute      = $deltaAbs
    QueryDeltaPercent       = $deltaPct
    Analyzer                = $optimized.Analyzer
    BaselinePcap            = $baseline.PcapPath
    OptimizedPcap           = $optimized.PcapPath
    BaselineTxt             = $baseline.TxtPath
    OptimizedTxt            = $optimized.TxtPath
    DisableSmartResolution  = [bool]$DisableSmartNameResolution
    DisableLLMNRSetting     = [bool]$DisableLLMNR
    DisableBrowserPrefetch  = [bool]$DisableBrowserDnsPrefetch
}

$jsonPath = Join-Path $sessionDir "summary.json"
$csvPath = Join-Path $sessionDir "summary.csv"
$summary | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
$summary | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

if ($RollbackAtEnd) {
    Write-Host "Rollback der DNS-Optimierung..." -ForegroundColor Yellow
    Reset-DnsOptimization
    if ($ClearDnsCacheBeforeEachPhase) { Clear-DnsClientCache }
}

Write-Host ""
Write-Host "Fertig." -ForegroundColor Green
$summary | Format-List
Write-Host "Summary JSON: $jsonPath"
Write-Host "Summary CSV : $csvPath"
