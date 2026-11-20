# Network Tools

This is a small PowerShell module for everyday network checks and lab tasks.

It is built to run cross platform on Windows and Linux with PowerShell 7.

It currently includes seven commands:

- Send-Stimulus: sends UDP broadcast traffic from a chosen local interface and source port.
- Test-TcpPort: tests TCP connectivity to one or more ports with timeout and latency details.
- Resolve-MacVendor: normalizes MAC addresses and maps OUI prefixes to likely vendors.
- Convert-FromCidr: converts CIDR notation into a dotted subnet mask.
- Invoke-NetworkScan: runs a parallel ping sweep and returns IP, MAC, latency, and optional MAC vendor mapping.
- Get-SnmpInterface: reads interface inventory plus traffic, error, and discard counters over SNMP v1/v2c/v3, optionally sampling rates.
- Invoke-BandwidthMonitor (alias Invoke-BwMon): a live, htop-style SNMP bandwidth and error-counter monitor for every interface on a device.

Invoke-NetworkScan now emits result objects as hosts are discovered, so output appears live during the scan.

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

Resolve MAC vendor:

```powershell
Resolve-MacVendor -MacAddress 00-50-56-11-22-33
```

Resolve MAC vendor with optional API fallback:

```powershell
Resolve-MacVendor -MacAddress AA-BB-CC-11-22-33 -UseOnlineApi
```

Scan a subnet:

```powershell
Invoke-NetworkScan -Target 192.168.1.0/24 -TimeoutMs 300 -ThrottleLimit 50
```

Scan a subnet and resolve MAC vendors:

```powershell
Invoke-NetworkScan -Target 192.168.1.0/24 -ResolveMacVendor
```

## SNMP bandwidth and error monitoring

Watch every interface on a switch live (SNMPv2c):

```powershell
Invoke-BwMon 10.0.0.1 -V2c -Community public
```

The default **grid** view packs one meter per interface into as many columns as it takes to fit the whole switch on one screen. A 52-port switch fits in two columns on a 30-line terminal and in three columns at 80×24.

Inbound traffic (green) grows from the left edge of each meter toward the centre, and outbound traffic (red) grows from the right edge toward the centre. Both are scaled to the interface speed, so the edges are 0 and the centre is line rate. The port name sits in the middle with compact rates beside it:

```
[██▓                    70Mb Gi1/0/1 198Mb       ▓███████] [█░                     34Mb Gi1/0/27 93Mb          ▓███]
[██████████████████████859Mb Gi1/0/3 253Mb     ▓█████████] [                          Gi1/0/28                     ]
[░                     8.9Mb Gi1/0/5 265Mb     ░█████████] [████████████████████▒  511Mb Gi1/0/30 81Mb         ░███]
```

Long names are abbreviated (`GigabitEthernet` becomes `Gi`, `TenGigabitEthernet` becomes `Te`, and so on). If a name still doesn't fit, its start is cut off so the distinguishing end stays visible (`…ink-ae12`). Use `-NameTruncation End` or the `n` key to keep the start instead.

A meter's brackets turn yellow when the port has errors or discards, and red while they are increasing. A port's name turns magenta for a minute after its link goes up or down.

The two header lines are built for working an incident:

```
 lab-edge  192.0.2.10  Example 24-port switch  up 6d 01:02:39  v2c  poll 120ms        grid  0.5s avg 3s  sort index
 CPU [▓         ]  8% ▁▁▁▁  Σ in 78Kb out 218Kb  ports up 3/5  err/disc in 0/0 out 47466/4345  ▲ vpn +138  ⇅ ether4 down 12s ago
```

- **Line 1, device and data health.**
  - Name, address, model, uptime, SNMP version and poll latency.
  - Uptime turns red under an hour (a likely reboot) and yellow under a day.
  - The poll field turns red (`poll failing`, or `STALE 12s`) when the screen can no longer be trusted.
- **Line 2, what is happening now.**
  - CPU and memory from HOST-RESOURCES-MIB, when the device provides them. The sparkline shows each core.
  - Total throughput across physical ports, ports up, and total errors/discards.
  - Live alerts: ports whose errors are climbing (with the count added in the current burst), link changes from the last five minutes, and agent restarts.
- **Narrow terminals** drop the least important items first. Alerts stay the longest.

Press `v` to cycle through the views:
- **Grid**: bandwidth meters, as above.
- **Errors**: the same grid, showing `in errors/discards  port  out errors/discards`.
- **List**: one wide row per interface, with alias, speed, full rates and separate error columns.

Error counts show the device's totals by default. Press `e` (or start with `-ErrorsSinceStart`) to count only from when the monitor started.

The monitor polls every 0.5 s by default. Rates are measured between the polls at which a counter actually changed, then averaged over the last 3 seconds (`-AverageSeconds`, or the `a` key). `-AverageSeconds 0` turns averaging off, and the header shows `avg off`; each rate then covers only the latest counter refresh. Many agents refresh their counters only every second or so (RouterOS) or every few seconds (many switches). Without this, fast polling would flicker between 0 and double the real rate. Raise `-IntervalSeconds` on switches with weak management CPUs.

Ports that are down stay in their positions, shown dimmed. Virtual interfaces that are down are hidden until you press `d`. Partial cells use shaded blocks (`░ ▒ ▓`). Use `-BarStyle Ascii` for `| % #` on terminals without block glyphs.

Keys:

| Key | Action |
|---|---|
| `q` | Quit |
| `v` | Cycle views: grid, errors, list |
| `s` | Cycle sort: index, name, in, out, total, errors |
| `l` | Toggle log scale |
| `a` | Cycle averaging: off, 1, 3, 5, 10, 30 s |
| `+` / `-` | Change poll interval |
| `d` | Show every interface |
| `e` | Error totals or since start |
| `n` | Keep the start or end of long names |
| `r` | Reset since-start counts |
| Arrows, PgUp/PgDn | Scroll |

Interfaces are discovered from IF-MIB, and only those with readable in/out octet counters are shown. 64-bit `ifHC*` counters are used where available (v2c/v3), with a fallback to 32-bit counters, including wrap handling.

SNMPv3 (USM) with authentication and privacy:

```powershell
$auth = Read-Host -AsSecureString 'Auth password'
$priv = Read-Host -AsSecureString 'Priv password'
Invoke-BwMon core1 -V3 -UserName monitor -AuthProtocol SHA256 -AuthPassword $auth -PrivProtocol AES -PrivPassword $priv
```

- Auth protocols: MD5, SHA (SHA-1), SHA256, SHA384, SHA512.
- Privacy protocols: DES, AES (128), AES192/AES256 (Blumenthal key extension, net-snmp `AES192`/`AES256`), and AES192C/AES256C (Reeder key extension, used by Cisco).
- Omitting `-PrivPassword` gives authNoPriv. Passwords can be strings or SecureStrings, must be at least 8 characters, and can't be empty when given. Inconsistent options are rejected before anything is sent: v3 options without `-UserName`, or with `-V1`/`-V2c`, are errors rather than a silent fallback to v2c.
- Replies must match the request's security level, user, engine, context and request ID, and must come from the agent's address and port. Anything else is ignored.
- An unauthenticated report can explain a timeout, for example when the agent rejects the username or credentials. A protected session keeps its confirmed engine and keys. If the agent's engine ID changes, open a new session to verify it.
- Interface discovery enforces time, row, and size limits for each column and for the inventory as a whole. An incomplete interface column produces an error.
- Verified against MikroTik RouterOS 7.25.1 over v2c and over v3 authPriv (SHA256/AES). Other combinations are tested against the RFC 3414 key test vectors and the loopback test agent.

Limit the view to some interfaces (by index, name, description, or alias; wildcards are allowed):

```powershell
Invoke-BwMon 10.0.0.1 -Community public -Interface 'Te1/1/*', 'Po*' -IntervalSeconds 5
```

Interface discovery reads the full IF-MIB table and can time out after 60 seconds on very large or slow devices. The `-Interface` filter applies after discovery.

Scripted counters, for example to find ports that are taking errors:

```powershell
Get-SnmpInterface 10.0.0.1 -Community public | Where-Object { $_.InErrors -gt 0 -or $_.OutErrors -gt 0 }
```

Sample rates and error deltas over 10 seconds:

```powershell
Get-SnmpInterface 10.0.0.1 -Community public -SampleSeconds 10 | Sort-Object InBitsPerSec -Descending
```

To try the monitor without a device, the tests include a loopback SNMP agent:

```powershell
. .\tests\SnmpTestAgent.ps1
$agent = Start-SnmpTestAgent -ModulePath .\Network-Tools.psm1 -Mib (New-SnmpTestMib -InterfaceCount 8)
Invoke-BwMon 127.0.0.1 -Port $agent.Port
Stop-SnmpTestAgent $agent
```

## Tests

The tests require Pester 5 on Windows and Linux. Install it, then load it explicitly so the Pester 3.4 that ships with Windows isn't used instead:

```powershell
Install-Module Pester -MinimumVersion 5.0.0 -Scope CurrentUser -SkipPublisherCheck
```

```powershell
Import-Module Pester -MinimumVersion 5.0.0
Invoke-Pester -Script .\tests\Network-Tools.Tests.ps1
```

## Notes

This module is focused on practical network workflows. If behavior needs to be stricter for production use, the tests are already set up so changes can be validated quickly.

OUI vendor mappings are stored in a separate file at data/oui-map.csv. You can provide your own map with Resolve-MacVendor -OuiMapPath.
