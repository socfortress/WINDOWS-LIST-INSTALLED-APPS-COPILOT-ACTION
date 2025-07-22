[CmdletBinding()]
param(
    [string]$LogPath = "$env:TEMP\List-Installed-Apps.log",
    [string]$ARLog = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$HostName = $env:COMPUTERNAME
$Start = Get-Date

function Test-DigitalSignature {
    param([string]$FilePath)
    try {
        if (Test-Path $FilePath) {
            $sig = Get-AuthenticodeSignature -FilePath $FilePath
            return $sig.Status -eq 'Valid'
        }
    } catch {
        return $false
    }
    return $false
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    Add-Content -Path $LogPath -Value "[$timestamp][$Level] $Message"
    Write-Host "[$timestamp][$Level] $Message"
}

Write-Log "=== SCRIPT START : List Installed Programs ==="

$RegPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$Programs = @()
foreach ($path in $RegPaths) {
    $Programs += Get-ItemProperty $path -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{
            name           = $_.DisplayName
            version        = $_.DisplayVersion
            publisher      = $_.Publisher
            install_date   = $_.InstallDate
            uninstall_cmd  = $_.UninstallString
            registry_key   = $path
            flagged_reasons = @()
        }
    }
}

$Programs = $Programs | Where-Object { $_.name -and $_.name.Trim() -ne "" }

foreach ($program in $Programs) {
    if ($program.name -match "WireGuard|Surfshark|NordVPN|ExpressVPN") {
        $program.flagged_reasons += "VPN software"
        Write-Log "Flagged: $($program.name) -> VPN software" "WARN"
    }

    if ($program.uninstall_cmd -match "Users\\[^\\]+\\AppData") {
        $program.flagged_reasons += "Installed in AppData/User directory"
        Write-Log "Flagged: $($program.name) -> Installed in AppData/User directory" "WARN"
    }

    if (-not $program.publisher -or $program.publisher.Trim() -eq "") {
        $program.flagged_reasons += "Unknown publisher"
        Write-Log "Flagged: $($program.name) -> Unknown publisher" "WARN"
    }

    if ($program.uninstall_cmd -match "\.exe|\.msi") {
        $exe = ($program.uninstall_cmd -replace '["''\s]', '') -split '\s' | Select-Object -First 1
        if ($exe -and -not (Test-DigitalSignature -FilePath $exe)) {
            $program.flagged_reasons += "Unsigned uninstall binary"
            Write-Log "Flagged: $($program.name) -> Unsigned uninstall binary ($exe)" "WARN"
        }
    }
}

$timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffffffK")
$FullInventory = @{
    host           = $HostName
    timestamp      = $timestamp
    action         = "list_installed_programs"
    program_count  = $Programs.Count
    programs       = $Programs
}

$FlaggedOnly = @{
    host             = $HostName
    timestamp        = $timestamp
    action           = "list_installed_programs_flagged"
    flagged_count    = ($Programs | Where-Object { $_.flagged_reasons.Count -gt 0 }).Count
    flagged_programs = $Programs | Where-Object { $_.flagged_reasons.Count -gt 0 }
}

Write-Log "Total programs found: $($Programs.Count)"
Write-Log "Flagged programs: $($FlaggedOnly.flagged_count)"

foreach ($program in $FlaggedOnly.flagged_programs) {
    Write-Log "Flagged Program -> Name: $($program.name) | Publisher: $($program.publisher) | Reasons: $($program.flagged_reasons -join ', ')" "WARN"
}

$FullInventory | ConvertTo-Json -Depth 5 | Add-Content -Path $ARLog
$FlaggedOnly   | ConvertTo-Json -Depth 5 | Add-Content -Path $ARLog

$Duration = (Get-Date) - $Start
Write-Log "=== SCRIPT END : duration $($Duration.TotalSeconds)s ==="
