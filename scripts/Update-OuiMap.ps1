param(
    [string]$OutputPath = (Join-Path -Path $PSScriptRoot -ChildPath '..\data\oui-map.csv')
)

$ErrorActionPreference = 'Stop'

$registrySources = @(
    @{ Name = 'MA-L'; Uri = 'https://standards-oui.ieee.org/oui/oui.csv' },
    @{ Name = 'MA-M'; Uri = 'https://standards-oui.ieee.org/oui28/mam.csv' },
    @{ Name = 'MA-S'; Uri = 'https://standards-oui.ieee.org/oui36/oui36.csv' }
)

$entries = [System.Collections.Generic.List[object]]::new()

foreach ($source in $registrySources) {
    Write-Host "Downloading $($source.Name) registry from $($source.Uri)"
    $csvText = Invoke-RestMethod -Uri $source.Uri -Method Get -TimeoutSec 30
    $rows = $csvText | ConvertFrom-Csv

    foreach ($row in $rows) {
        $rawPrefix = $row.Assignment
        $rawVendor = $row.'Organization Name'
        if ([string]::IsNullOrWhiteSpace($rawPrefix) -or [string]::IsNullOrWhiteSpace($rawVendor)) {
            continue
        }

        $prefix = ($rawPrefix -replace '[^0-9A-Fa-f]', '').ToUpper()
        if ($prefix.Length -lt 6) {
            continue
        }

        $entries.Add([PSCustomObject]@{
            Prefix = $prefix
            Vendor = $rawVendor.Trim()
        })
    }
}

$dedup = $entries |
    Sort-Object Prefix, Vendor -Unique |
    Group-Object Prefix |
    ForEach-Object { $_.Group[0] } |
    Sort-Object Prefix

$resolvedOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$outDir = Split-Path -Parent $resolvedOutputPath
if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

$dedup | Export-Csv -Path $resolvedOutputPath -NoTypeInformation -Encoding utf8

Write-Host "Wrote $($dedup.Count) OUI entries to $resolvedOutputPath"
