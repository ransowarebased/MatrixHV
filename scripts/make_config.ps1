#requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('true', 'false')]
    [string]$CpuidPresence,

    [ValidateSet('true', 'false')]
    [string]$Logger,

    [ValidateSet('true', 'false')]
    [string]$VmxFlat,

    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $ProjectRoot 'config\MatrixConfig.bin'
}
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)

$CurrentCpuidPresence = $true
$CurrentLogger = $true
$CurrentVmxFlat = $false
if (Test-Path -LiteralPath $OutputPath -PathType Leaf) {
    foreach ($Line in Get-Content -LiteralPath $OutputPath) {
        if ($Line -match '^\s*cpuidpresence\s*=\s*(true|false)\s*$') {
            $CurrentCpuidPresence = [bool]::Parse($Matches[1])
        }
        elseif ($Line -match '^\s*logger\s*=\s*(true|false)\s*$') {
            $CurrentLogger = [bool]::Parse($Matches[1])
        }
        elseif ($Line -match '^\s*vmxflat\s*=\s*(true|false)\s*$') {
            $CurrentVmxFlat = [bool]::Parse($Matches[1])
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($CpuidPresence)) {
    $CurrentCpuidPresence = [bool]::Parse($CpuidPresence)
}
if (-not [string]::IsNullOrWhiteSpace($Logger)) {
    $CurrentLogger = [bool]::Parse($Logger)
}
if (-not [string]::IsNullOrWhiteSpace($VmxFlat)) {
    $CurrentVmxFlat = [bool]::Parse($VmxFlat)
}

$Parent = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Path $Parent -Force | Out-Null

$Contents = @(
    'MATRIXHV_CONFIG_V1'
    "cpuidpresence=$($CurrentCpuidPresence.ToString().ToLowerInvariant())"
    "logger=$($CurrentLogger.ToString().ToLowerInvariant())"
    "vmxflat=$($CurrentVmxFlat.ToString().ToLowerInvariant())"
) -join "`n"

[System.IO.File]::WriteAllText($OutputPath, $Contents + "`n", (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Generated MatrixHV configuration: $OutputPath"
Write-Output $OutputPath
