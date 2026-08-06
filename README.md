# Network Tools

This is a small PowerShell module for everyday network checks and lab tasks.

It is built to run cross platform on Windows and Linux with PowerShell 7.

It currently includes four commands:

- Send-Stimulus: sends UDP broadcast traffic from a chosen local interface and source port.
- Test-TcpPort: tests TCP connectivity to one or more ports with timeout and latency details.
- Convert-FromCidr: converts CIDR notation into a dotted subnet mask.
- Invoke-NetworkScan: runs a parallel ping sweep and returns IP, MAC, and latency where available.

## Requirements

- PowerShell 7+
- Windows or Linux

## Quick Start

Import the module from this folder:

```powershell
Import-Module .\Network-Tools.psm1 -Force
```

## Examples

Send stimulus frames:

```powershell
Send-Stimulus -InterfaceIP 192.168.1.10 -LocalPort 40000 -Count 25 -DelayMs 10
```

Convert CIDR to subnet mask:

```powershell
Convert-FromCidr -Cidr 192.168.10.0/24
```

Test TCP ports:

```powershell
Test-TcpPort -ComputerName 192.168.1.20 -Port 22,443 -TimeoutMs 800
```

Scan a subnet:

```powershell
Invoke-NetworkScan -Target 192.168.1.0/24 -TimeoutMs 300 -ThrottleLimit 50
```

## Tests

Run the Pester tests:

```powershell
Invoke-Pester -Script .\tests\Network-Tools.Tests.ps1
```

## Notes

This module is focused on practical network workflows. If behavior needs to be stricter for production use, the tests are already set up so changes can be validated quickly.
