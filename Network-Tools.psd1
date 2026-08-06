@{
    RootModule = 'Network-Tools.psm1'
    ModuleVersion = '0.1.0'
    GUID = 'f8fceb5b-c4b5-4702-b622-08561fcb6b39'
    Author = 'Network Engineering Tools'
    CompanyName = 'Community'
    Copyright = '(c) Network Engineering Tools. All rights reserved.'
    Description = 'PowerShell network engineering toolkit with CIDR conversion, traffic stimulus, and host discovery cmdlets.'
    PowerShellVersion = '7.0'

    FunctionsToExport = @(
        'Send-Stimulus',
        'Convert-FromCidr',
        'Invoke-NetworkScan'
    )

    AliasesToExport = @(
        'Send-InterfaceStimulus'
    )

    CmdletsToExport = @()
    VariablesToExport = '*'
    PrivateData = @{
        PSData = @{
            Tags = @('Networking', 'CIDR', 'Ping', 'Discovery', 'PowerShell')
        }
    }
}
