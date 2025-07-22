# PowerShell List Installed Programs Template

This repository provides a template for PowerShell-based active response scripts for security automation and incident response. The template ensures consistent logging, error handling, and execution flow for software inventory and suspicious application detection.

---

## Overview

The `List-installed-apps.ps1` script inventories all installed applications on a Windows system, flags suspicious or risky programs (such as VPNs, unsigned uninstallers, or unknown publishers), and logs all actions, results, and errors in both a script log and an active-response log. This makes it suitable for integration with SOAR platforms, SIEMs, and incident response workflows.

---

## Template Structure

### Core Components

- **Parameter Definitions**: Configurable script parameters
- **Logging Framework**: Consistent logging with timestamps
- **Flagging Logic**: Identifies risky or suspicious programs
- **JSON Output**: Standardized response format
- **Execution Timing**: Performance monitoring

---

## How Scripts Are Invoked

### Command Line Execution

```powershell
.\List-installed-apps.ps1 [-LogPath <string>] [-ARLog <string>]
```

### Parameters

| Parameter | Type   | Default Value                                                    | Description                                  |
|-----------|--------|------------------------------------------------------------------|----------------------------------------------|
| `LogPath` | string | `$env:TEMP\List-Installed-Apps.log`                              | Path for execution logs                      |
| `ARLog`   | string | `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log` | Path for active response JSON output         |

---

### Example Invocations

```powershell
# Basic execution with default parameters
.\List-installed-apps.ps1

# Custom log path
.\List-installed-apps.ps1 -LogPath "C:\Logs\InstalledApps.log"

# Integration with OSSEC/Wazuh active response
.\List-installed-apps.ps1 -ARLog "C:\ossec\active-responses.log"
```

---

## Template Functions

### `Write-Log`
**Purpose**: Standardized logging with severity levels and console output.

**Parameters**:
- `Message` (string): The log message
- `Level` (string): Log level - 'INFO', 'WARN', 'ERROR', 'DEBUG'

**Features**:
- Timestamped output
- File logging
- Console output

**Usage**:
```powershell
Write-Log "Flagged: $($program.name) -> VPN software" "WARN"
Write-Log "Flagged: $($program.name) -> Unsigned uninstall binary ($exe)" "WARN"
Write-Log "Total programs found: $($Programs.Count)"
```

---

### `Test-DigitalSignature`
**Purpose**: Checks if a file (such as an uninstaller) is digitally signed.

**Parameters**:
- `FilePath` (string): Path to the executable or MSI

**Features**:
- Returns `$true` if the file is signed and valid, `$false` otherwise

---

## Script Execution Flow

1. **Initialization**
   - Parameter validation and assignment
   - Error action preference
   - Start time logging

2. **Execution**
   - Enumerates installed programs from registry
   - Flags programs based on:
     - VPN software name
     - Installation in user directories (AppData)
     - Unknown publisher
     - Unsigned uninstallers
   - Logs findings

3. **Completion**
   - Outputs full inventory and flagged programs as JSON to the active response log
   - Logs script end and duration

---

## JSON Output Format

### Full Inventory Example

```json
{
  "host": "HOSTNAME",
  "timestamp": "2025-07-22T10:30:45.123Z",
  "action": "list_installed_programs",
  "program_count": 123,
  "programs": [
    {
      "name": "ExampleApp",
      "version": "1.2.3",
      "publisher": "ExampleCorp",
      "install_date": "20240101",
      "uninstall_cmd": "\"C:\\Program Files\\ExampleApp\\uninstall.exe\"",
      "registry_key": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\...",
      "flagged_reasons": []
    }
  ]
}
```

### Flagged Programs Example

```json
{
  "host": "HOSTNAME",
  "timestamp": "2025-07-22T10:30:45.123Z",
  "action": "list_installed_programs_flagged",
  "flagged_count": 2,
  "flagged_programs": [
    {
      "name": "WireGuard",
      "version": "0.5.3",
      "publisher": "",
      "install_date": "20240101",
      "uninstall_cmd": "...",
      "registry_key": "...",
      "flagged_reasons": ["VPN software", "Unknown publisher"]
    }
  ]
}
```

---

## Implementation Guidelines

1. Use the provided logging and error handling functions.
2. Customize the flagging logic as needed for your environment.
3. Ensure JSON output matches your SOAR/SIEM requirements.
4. Test thoroughly in a non-production environment.

---

## Security Considerations

- Run with the minimum required privileges.
- Validate all input parameters.
- Secure log files and output locations.
- Monitor for errors and failed inventory.

---

## Troubleshooting

- **Permission Errors**: Run as Administrator.
- **Registry Access Issues**: Ensure the script has access to all registry hives.
- **Log Output**: Check file permissions and disk space.

---

## License

This template is provided as-is for security automation and incident response
