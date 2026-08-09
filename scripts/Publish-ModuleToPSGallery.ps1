param(
    [string]$Repository = 'PSGallery',
    [string]$CredentialPath = (Join-Path $HOME '.config/Network-Tools/psgallery-api.xml')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $CredentialPath)) {
    throw "No saved gallery credential found at $CredentialPath. Run scripts/Set-PSGalleryCredential.ps1 first."
}

$credential = Import-Clixml -Path $CredentialPath
$apiKey = [System.Net.NetworkCredential]::new(
    $credential.UserName,
    $credential.Password
).Password

$moduleRoot = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $moduleRoot 'Network-Tools.psd1'

$manifest = Test-ModuleManifest -Path $manifestPath
$moduleName = [string]$manifest.Name
$moduleVersion = [version]$manifest.Version

$published = Find-Module -Name $moduleName -Repository $Repository -ErrorAction SilentlyContinue
if ($null -ne $published) {
    $publishedVersion = [version]$published.Version
    if ($moduleVersion -le $publishedVersion) {
        throw "Manifest version $moduleVersion must be greater than published version $publishedVersion"
    }
}

Set-PSResourceRepository -Name $Repository -Trusted
Publish-PSResource -Path $moduleRoot -Repository $Repository -ApiKey $apiKey -Verbose
Write-Host "Published $moduleName $moduleVersion to $Repository"
