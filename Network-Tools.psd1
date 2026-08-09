@{
    RootModule = 'Network-Tools.psm1'
    ModuleVersion = '0.1.6'
    GUID = 'f8fceb5b-c4b5-4702-b622-08561fcb6b39'
    Author = 'Network Engineering Tools'
    CompanyName = 'Community'
    Description = 'Extended PowerShell toolkit for network engineers, including CIDR conversion, traffic stimulus, host discovery, TCP port testing, and MAC vendor resolution workflows.'
    PowerShellVersion = '7.0'

    FunctionsToExport = @(
        'Send-Stimulus',
        'Test-TcpPort',
        'Resolve-MacVendor',
        'Convert-FromCidr',
        'Invoke-NetworkScan'
    )

    AliasesToExport = @(
        'Send-InterfaceStimulus'
    )

    FormatsToProcess = @(
        'Network-Tools.Format.ps1xml'
    )

    CmdletsToExport = @()
    VariablesToExport = '*'
    PrivateData = @{
        PSData = @{
            Tags = @('Networking', 'NetworkEngineering', 'NetworkTools', 'CIDR', 'Ping', 'Discovery', 'TCP', 'MAC', 'OUI', 'PowerShell')
            LicenseUri = 'https://opensource.org/licenses/MIT'
        }
    }
}
