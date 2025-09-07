[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\List-Installed-Apps.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

if ($Arg1) { $NameFilter = $Arg1 }

$ErrorActionPreference = 'Stop'
$HostName = $env:COMPUTERNAME
$LogMaxKB = 100
$LogKeep  = 5
$Start    = Get-Date

function Write-Log {
  param([string]$Message, [ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level = "INFO")
  $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
  $line = "[$ts][$Level] $Message"
  switch ($Level) {
    'ERROR' { Write-Host $line -ForegroundColor Red }
    'WARN'  { Write-Host $line -ForegroundColor Yellow }
    'DEBUG' { if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) { Write-Verbose $line } }
    default { Write-Host $line }
  }
  Add-Content -Path $LogPath -Value $line -Encoding utf8
}

function Rotate-Log {
  if (Test-Path $LogPath -PathType Leaf) {
    if ((Get-Item $LogPath).Length/1KB -gt $LogMaxKB) {
      for ($i = $LogKeep - 1; $i -ge 0; $i--) {
        $old = "$LogPath.$i"; $new = "$LogPath." + ($i + 1)
        if (Test-Path $old) { Rename-Item $old $new -Force }
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function To-ISO8601 {
  param($dt)
  if ($dt -and $dt -is [datetime] -and $dt.Year -gt 1900) { $dt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
}

function New-NdjsonLine { param([hashtable]$Data) ($Data | ConvertTo-Json -Compress -Depth 7) }

function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp = Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
  $payload = ($JsonLines -join [Environment]::NewLine) + [Environment]::NewLine
  Set-Content -Path $tmp -Value $payload -Encoding ascii -Force
  try { Move-Item -Path $tmp -Destination $Path -Force }
  catch { Move-Item -Path $tmp -Destination ($Path + '.new') -Force }
}

function Test-DigitalSignature {
  param([string]$FilePath)
  try {
    if (Test-Path $FilePath) {
      $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
      return $sig.Status -eq 'Valid'
    }
  } catch { return $false }
  return $false
}

Rotate-Log
Write-Log "=== SCRIPT START : List Installed Programs (host=$HostName) ==="

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
  if ($NameFilter) {
    $Programs = $Programs | Where-Object { $_.name -like "*$NameFilter*" }
    Write-Log "Applied NameFilter='$NameFilter'" 'INFO'
  }

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
      $exe = ($program.uninstall_cmd -replace '["'']', '') -split '\s+' | Select-Object -First 1
      if ($exe -and -not (Test-DigitalSignature -FilePath $exe)) {
        $program.flagged_reasons += "Unsigned uninstall binary"
        Write-Log "Flagged: $($program.name) -> Unsigned uninstall binary ($exe)" "WARN"
      }
    }
  }

  $tsNow       = To-ISO8601 (Get-Date)
  $totalCount  = ($Programs | Measure-Object).Count
  $flaggedOnly = $Programs | Where-Object { $_.flagged_reasons.Count -gt 0 }
  $flaggedCount = ($flaggedOnly | Measure-Object).Count

  if ($totalCount -eq 0) {
    $nores = New-NdjsonLine @{
      timestamp      = $tsNow
      host           = $HostName
      action         = "list_installed_programs"
      copilot_action = $true
      item           = "status"
      status         = "no_results"
      description    = "No installed programs found for the current scope"
      name_filter    = $NameFilter
    }
    Write-NDJSONLines -JsonLines @($nores) -Path $ARLog
    Write-Log "No programs found; wrote status line to AR log" 'INFO'
    $Duration = [int]((Get-Date) - $Start).TotalSeconds
    Write-Log "=== SCRIPT END : duration ${Duration}s ==="
    return
  }

  $lines = New-Object System.Collections.ArrayList

  [void]$lines.Add( (New-NdjsonLine @{
    timestamp      = $tsNow
    host           = $HostName
    action         = "list_installed_programs"
    copilot_action = $true
    item           = "summary"
    description    = "Run summary and counts"
    program_count  = $totalCount
    flagged_count  = $flaggedCount
    name_filter    = $NameFilter
  }) )

  foreach ($p in $Programs) {
    $desc = "Program '$($p.name)' v$($p.version) by '$($p.publisher)'; flagged=" + ([bool]($p.flagged_reasons.Count -gt 0))
    [void]$lines.Add( (New-NdjsonLine @{
      timestamp       = $tsNow
      host            = $HostName
      action          = "list_installed_programs"
      copilot_action  = $true
      item            = "program"
      description     = $desc
      name            = $p.name
      version         = $p.version
      publisher       = $p.publisher
      install_date    = $p.install_date
      uninstall_cmd   = $p.uninstall_cmd
      registry_key    = $p.registry_key
      flagged         = ($p.flagged_reasons.Count -gt 0)
      flagged_reasons = $p.flagged_reasons
    }) )
  }

  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log ("Wrote {0} NDJSON record(s) to {1}" -f $lines.Count, $ARLog)

  $Duration = [int]((Get-Date) - $Start).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${Duration}s ==="
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $err = New-NdjsonLine @{
    timestamp      = To-ISO8601 (Get-Date)
    host           = $HostName
    action         = "list_installed_programs"
    copilot_action = $true
    item           = "error"
    description    = "Unhandled error"
    error          = $_.Exception.Message
  }
  Write-NDJSONLines -JsonLines @($err) -Path $ARLog
  Write-Log "Error NDJSON written to AR log" 'INFO'
}
