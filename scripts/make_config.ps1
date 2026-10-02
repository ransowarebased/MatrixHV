#requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('true', 'false')]
    [string]$CpuidPresence,

    [ValidateSet('true', 'false')]
    [string]$Logger,

    [ValidateSet('true', 'false')]
    [string]$VtNested,

    [ValidateSet('true', 'false')]
    [string]$VtEvmcs,

    [ValidateSet('true', 'false')]
    [string]$VmxTest,

    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $ProjectRoot 'builds\MatrixConfig.bin'
}
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
$BuildRoot = [System.IO.Path]::GetFullPath('D:\Projetos\MatrixHV\builds')
$BuildRootPrefix = $BuildRoot.TrimEnd('\') + '\'
if (-not $OutputPath.StartsWith($BuildRootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Configuration output must be under $BuildRoot"
}

$CurrentCpuidPresence = $false
$CurrentLogger = $true
$CurrentVtNested = $true
$CurrentVtEvmcs = $false
$CurrentVmxTest = $false
if (Test-Path -LiteralPath $OutputPath -PathType Leaf) {
    foreach ($Line in Get-Content -LiteralPath $OutputPath) {
        if ($Line -match '^\s*cpuidpresence\s*=\s*(true|false)\s*$') {
            $CurrentCpuidPresence = [bool]::Parse($Matches[1])
        }
        elseif ($Line -match '^\s*logger\s*=\s*(true|false)\s*$') {
            $CurrentLogger = [bool]::Parse($Matches[1])
        }
        elseif ($Line -match '^\s*VtNested\s*=\s*(true|false)\s*$') {
            $CurrentVtNested = [bool]::Parse($Matches[1])
        }
        elseif ($Line -match '^\s*VtEvmcs\s*=\s*(true|false)\s*$') {
            $CurrentVtEvmcs = [bool]::Parse($Matches[1])
        }
        elseif ($Line -match '^\s*VmxTest\s*=\s*(true|false)\s*$') {
            $CurrentVmxTest = [bool]::Parse($Matches[1])
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($CpuidPresence)) {
    $CurrentCpuidPresence = [bool]::Parse($CpuidPresence)
}
if (-not [string]::IsNullOrWhiteSpace($Logger)) {
    $CurrentLogger = [bool]::Parse($Logger)
}
if (-not [string]::IsNullOrWhiteSpace($VtNested)) {
    $CurrentVtNested = [bool]::Parse($VtNested)
}
if (-not [string]::IsNullOrWhiteSpace($VtEvmcs)) {
    $CurrentVtEvmcs = [bool]::Parse($VtEvmcs)
}
if (-not [string]::IsNullOrWhiteSpace($VmxTest)) {
    $CurrentVmxTest = [bool]::Parse($VmxTest)
}
if ($CurrentVtEvmcs) {
    $CurrentCpuidPresence = $true
    $CurrentVtNested = $true
}
if ($CurrentVmxTest -and -not $CurrentVtNested) {
    throw 'VmxTest requires VtNested=true.'
}

$Parent = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Path $Parent -Force | Out-Null

$Contents = @(
    'MATRIXHV_CONFIG_V2'
    "cpuidpresence=$($CurrentCpuidPresence.ToString().ToLowerInvariant())"
    "logger=$($CurrentLogger.ToString().ToLowerInvariant())"
    "VtNested=$($CurrentVtNested.ToString().ToLowerInvariant())"
    "VtEvmcs=$($CurrentVtEvmcs.ToString().ToLowerInvariant())"
    "VmxTest=$($CurrentVmxTest.ToString().ToLowerInvariant())"
) -join "`n"

[System.IO.File]::WriteAllText($OutputPath, $Contents + "`n", (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Generated MatrixHV configuration: $OutputPath"
Write-Output $OutputPath
