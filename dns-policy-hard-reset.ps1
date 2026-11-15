Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).
        IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        throw "Bitte PowerShell als Administrator starten."
    }
}

Assert-Admin

$targets = @(
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Name = "DisableSmartNameResolution" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"; Name = "EnableMulticast" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"; Name = "DnsPrefetchingEnabled" },
    @{ Path = "HKLM:\SOFTWARE\Policies\Google\Chrome"; Name = "DnsPrefetchingEnabled" },
    @{ Path = "HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Edge"; Name = "DnsPrefetchingEnabled" },
    @{ Path = "HKLM:\SOFTWARE\WOW6432Node\Policies\Google\Chrome"; Name = "DnsPrefetchingEnabled" }
)

foreach ($t in $targets) {
    Remove-ItemProperty -Path $t.Path -Name $t.Name -ErrorAction SilentlyContinue
}

Clear-DnsClientCache

Write-Host "Reset ausgefuehrt. Aktuelle Werte:" -ForegroundColor Green
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ErrorAction SilentlyContinue |
    Select-Object DisableSmartNameResolution, EnableMulticast | Format-List
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -ErrorAction SilentlyContinue |
    Select-Object DnsPrefetchingEnabled | Format-List
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -ErrorAction SilentlyContinue |
    Select-Object DnsPrefetchingEnabled | Format-List

Write-Host "Hinweis: Wenn Werte spaeter wieder erscheinen, werden sie zentral per GPO/Intune erneut gesetzt." -ForegroundColor Yellow
