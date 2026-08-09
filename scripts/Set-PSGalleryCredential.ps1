param(
    [Parameter(Mandatory = $true)]
    [string]$ApiKey,

    [string]$CredentialPath = (Join-Path $HOME '.config/Network-Tools/psgallery-api.xml')
)

$ErrorActionPreference = 'Stop'

$credentialDirectory = Split-Path -Parent $CredentialPath
if (-not (Test-Path -LiteralPath $credentialDirectory)) {
    New-Item -ItemType Directory -Path $credentialDirectory -Force | Out-Null
}

$secureApiKey = ConvertTo-SecureString -String $ApiKey -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential('apikey', $secureApiKey)
$credential | Export-Clixml -Path $CredentialPath

Write-Host "Stored encrypted PowerShell Gallery API key at $CredentialPath"
