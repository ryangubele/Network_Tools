@{
    RootModule = 'Network-Tools.psm1'
    ModuleVersion = '1.0.0'
    GUID = 'f8fceb5b-c4b5-4702-b622-08561fcb6b39'
    Author = 'Network Engineering Tools'
    CompanyName = 'Community'
    Description = @'
Network Tools 1.0 is a PowerShell 7 toolkit for network engineers on Windows and Linux.

Monitor network devices with Invoke-BandwidthMonitor (Invoke-BwMon), a live SNMP interface dashboard with bandwidth meters, error and discard counters, alerts, and grid, errors, and list views. Get-SnmpInterface provides interface inventory, sampled traffic rates, and error deltas for scripts. Both support SNMP v1, v2c, and v3.

Discover hosts with Invoke-NetworkScan, a parallel ping sweep that streams results and can resolve DNS names and MAC vendors. Test TCP connectivity with Test-TcpPort, identify MAC vendors with Resolve-MacVendor, convert CIDR prefixes with Convert-FromCidr, and send UDP broadcast traffic with Send-Stimulus.
'@
    PowerShellVersion = '7.0'

    FunctionsToExport = @(
        'Send-Stimulus',
        'Test-TcpPort',
        'Resolve-MacVendor',
        'Convert-FromCidr',
        'Invoke-NetworkScan',
        'Get-SnmpInterface',
        'Invoke-BandwidthMonitor'
    )

    AliasesToExport = @(
        'Send-InterfaceStimulus',
        'Invoke-BwMon'
    )

    FormatsToProcess = @(
        'Network-Tools.Format.ps1xml'
    )

    CmdletsToExport = @()
    VariablesToExport = '*'
    PrivateData = @{
        PSData = @{
            Tags = @('Networking', 'NetworkEngineering', 'NetworkTools', 'CIDR', 'Ping', 'Discovery', 'TCP', 'MAC', 'OUI', 'SNMP', 'Bandwidth', 'PowerShell')
            LicenseUri = 'https://opensource.org/licenses/MIT'
        }
    }
}
