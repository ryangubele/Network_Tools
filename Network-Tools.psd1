@{
    RootModule = 'Network-Tools.psm1'
    ModuleVersion = '0.1.7'
    GUID = 'f8fceb5b-c4b5-4702-b622-08561fcb6b39'
    Author = 'Network Engineering Tools'
    CompanyName = 'Community'
    Description = 'Extended PowerShell toolkit for network engineers, including CIDR conversion, traffic stimulus, host discovery, TCP port testing, MAC vendor resolution, and SNMP (v1/v2c/v3) interface bandwidth and error-counter monitoring workflows.'
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
