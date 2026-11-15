param(
    [int]$BaselineDurationSec = 300,
    [int]$OptimizedDurationSec = 300,
    [string]$OutDir = ".\dns-trace-results",
    [string]$BaselineWorkloadScript = "",
    [string]$OptimizedWorkloadScript = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).
        IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        throw "Bitte PowerShell als Administrator starten (erforderlich fuer pktmon Capture)."
    }
}

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @()
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Befehl fehlgeschlagen: $FilePath $($Arguments -join ' ') (ExitCode=$LASTEXITCODE)"
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

function Invoke-CapturePhase {
    param(
        [Parameter(Mandatory = $true)][string]$PhaseName,
        [Parameter(Mandatory = $true)][int]$DurationSec,
        [string]$WorkloadScriptPath = "",
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

    Invoke-External -FilePath "pktmon" -Arguments @(
        "start",
        "--capture",
        "--pkt-size", "0",
        "--file-name", $etlPath,
        "--file-size", "1024",
        "--log-mode", "circular"
    )

    if ($WorkloadScriptPath -and (Test-Path -LiteralPath $WorkloadScriptPath)) {
        & $WorkloadScriptPath
    } else {
        Start-Sleep -Seconds $DurationSec
    }

    Invoke-External -FilePath "pktmon" -Arguments @("stop")
    Invoke-External -FilePath "pktmon" -Arguments @("etl2pcap", $etlPath, "-o", $pcapPath)
    Invoke-External -FilePath "pktmon" -Arguments @("etl2txt", $etlPath, "-o", $txtPath)

    $counts = Get-TsharkCounts -PcapPath $pcapPath
    $queryRate = if ($counts.QueryPackets -ne $null -and $DurationSec -gt 0) {
        [math]::Round(($counts.QueryPackets / $DurationSec), 3)
    } else {
        $null
    }

    return [pscustomobject]@{
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

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$sessionDir = Join-Path $OutDir $timestamp
New-Item -Path $sessionDir -ItemType Directory -Force | Out-Null

Write-Host "Phase 1: Baseline Capture startet..." -ForegroundColor Cyan
$baseline = Invoke-CapturePhase -PhaseName "baseline" -DurationSec $BaselineDurationSec -WorkloadScriptPath $BaselineWorkloadScript -SessionDir $sessionDir

Write-Host ""
Write-Host "Jetzt DNS-Optimierung setzen (GPO/Registry/Browser), dann Enter fuer Phase 2." -ForegroundColor Yellow
[void](Read-Host)

Write-Host "Phase 2: Optimized Capture startet..." -ForegroundColor Cyan
$optimized = Invoke-CapturePhase -PhaseName "optimized" -DurationSec $OptimizedDurationSec -WorkloadScriptPath $OptimizedWorkloadScript -SessionDir $sessionDir

$deltaAbs = $null
$deltaPct = $null
if ($baseline.QueryPackets -ne $null -and $optimized.QueryPackets -ne $null) {
    $deltaAbs = $optimized.QueryPackets - $baseline.QueryPackets
    if ($baseline.QueryPackets -gt 0) {
        $deltaPct = [math]::Round((($optimized.QueryPackets - $baseline.QueryPackets) / $baseline.QueryPackets) * 100, 2)
    }
}

$summary = [pscustomobject]@{
    CreatedAt                 = (Get-Date).ToString("s")
    SessionDir                = (Resolve-Path $sessionDir).Path
    BaselineDurationSec       = $baseline.DurationSec
    BaselineQueryPackets      = $baseline.QueryPackets
    BaselineQueriesPerSec     = $baseline.QueriesPerSec
    OptimizedDurationSec      = $optimized.DurationSec
    OptimizedQueryPackets     = $optimized.QueryPackets
    OptimizedQueriesPerSec    = $optimized.QueriesPerSec
    QueryDeltaAbsolute        = $deltaAbs
    QueryDeltaPercent         = $deltaPct
    Analyzer                  = $optimized.Analyzer
    BaselinePcap              = $baseline.PcapPath
    OptimizedPcap             = $optimized.PcapPath
    BaselineTxt               = $baseline.TxtPath
    OptimizedTxt              = $optimized.TxtPath
}

$jsonPath = Join-Path $sessionDir "summary.json"
$csvPath = Join-Path $sessionDir "summary.csv"

$summary | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
$summary | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Fertig. Ergebnisse:" -ForegroundColor Green
$summary | Format-List
Write-Host ""
Write-Host "Summary JSON: $jsonPath"
Write-Host "Summary CSV : $csvPath"
