[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\List-Installed-Apps.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$HostName = $env:COMPUTERNAME
$Start    = Get-Date

function Test-DigitalSignature {
  param([string]$FilePath)
  try {
    if (Test-Path $FilePath) {
      $sig = Get-AuthenticodeSignature -FilePath $FilePath
      return $sig.Status -eq 'Valid'
    }
  } catch { return $false }
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

try {
  $Programs = @()
  foreach ($path in $RegPaths) {
    $Programs += Get-ItemProperty $path -ErrorAction SilentlyContinue | ForEach-Object {
      [PSCustomObject]@{
        name            = $_.DisplayName
        version         = $_.DisplayVersion
        publisher       = $_.Publisher
        install_date    = $_.InstallDate
        uninstall_cmd   = $_.UninstallString
        registry_key    = $path
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

  $timestamp    = (Get-Date).ToString("o")
  $flaggedOnly  = $Programs | Where-Object { $_.flagged_reasons.Count -gt 0 }
  $totalCount   = $Programs.Count
  $flaggedCount = $flaggedOnly.Count

  Write-Log "Total programs found: $totalCount"
  Write-Log "Flagged programs: $flaggedCount"
  foreach ($program in $flaggedOnly) {
    Write-Log "Flagged Program -> Name: $($program.name) | Publisher: $($program.publisher) | Reasons: $($program.flagged_reasons -join ', ')" "WARN"
  }

  # Build NDJSON: summary line + one line per program
  $lines = @()

  $lines += ([pscustomobject]@{
    timestamp      = $timestamp
    host           = $HostName
    action         = "list_installed_programs_summary"
    program_count  = $totalCount
    flagged_count  = $flaggedCount
    copilot_action = $true
  } | ConvertTo-Json -Depth 3 -Compress)

  foreach ($p in $Programs) {
    $lines += ([pscustomobject]@{
      timestamp       = $timestamp
      host            = $HostName
      action          = "list_installed_programs"
      name            = $p.name
      version         = $p.version
      publisher       = $p.publisher
      install_date    = $p.install_date
      uninstall_cmd   = $p.uninstall_cmd
      registry_key    = $p.registry_key
      flagged         = $p.flagged_reasons.Count -gt 0
      flagged_reasons = if ($p.flagged_reasons.Count) { ($p.flagged_reasons -join ', ') } else { $null }
      copilot_action  = $true
    } | ConvertTo-Json -Depth 4 -Compress)
  }

  $ndjson  = [string]::Join("`n", $lines)
  $tempFile = "$env:TEMP\arlog.tmp"
  Set-Content -Path $tempFile -Value $ndjson -Encoding ascii -Force

  $recordCount = $lines.Count
  try {
    Move-Item -Path $tempFile -Destination $ARLog -Force
    Write-Log "Wrote $recordCount NDJSON record(s) to $ARLog"
  } catch {
    Move-Item -Path $tempFile -Destination "$ARLog.new" -Force
    Write-Log "ARLog locked; wrote to $($ARLog).new" "WARN"
  }

  $Duration = [int]((Get-Date) - $Start).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${Duration}s ==="
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $errorObj = [pscustomobject]@{
    timestamp      = (Get-Date).ToString('o')
    host           = $HostName
    action         = "list_installed_programs_error"
    status         = "error"
    error          = $_.Exception.Message
    copilot_action = $true
  }
  $ndjson = ($errorObj | ConvertTo-Json -Compress -Depth 3)
  $tempFile = "$env:TEMP\arlog.tmp"
  Set-Content -Path $tempFile -Value $ndjson -Encoding ascii -Force
  try {
    Move-Item -Path $tempFile -Destination $ARLog -Force
    Write-Log "Error JSON written to $ARLog"
  } catch {
    Move-Item -Path $tempFile -Destination "$ARLog.new" -Force
    Write-Log "ARLog locked; wrote error to $($ARLog).new" "WARN"
  }
}
