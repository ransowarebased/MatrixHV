#requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    [switch]$SkipImage,

    [switch]$SkipPackage,

    [string]$VeraCryptEfiSource
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$BuildRoot = 'D:\Projetos\MatrixHV\builds'
$TargetTriple = 'x86_64-unknown-uefi'
$BinaryName = 'MatrixHV'
$ManifestPath = Join-Path $ProjectRoot 'Cargo.toml'
$ConfigPath = Join-Path $ProjectRoot 'config\MatrixConfig.bin'
$CargoTargetRoot = Join-Path $BuildRoot '.cargo-target'
$ConfigurationName = $Configuration.ToLowerInvariant()
$CargoProfile = if ($Configuration -eq 'Release') { 'release' } else { 'debug' }
$OutputRoot = Join-Path $BuildRoot $ConfigurationName
$BootRoot = Join-Path $OutputRoot 'EFI\BOOT'

if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw "Cargo manifest not found: $ManifestPath"
}

if ((Get-Item -LiteralPath $ManifestPath).Length -eq 0) {
    throw "Cargo manifest is empty: $ManifestPath"
}

$CargoCommand = Get-Command cargo -ErrorAction SilentlyContinue
if ($null -eq $CargoCommand) {
    throw 'cargo was not found in PATH.'
}

New-Item -ItemType Directory -Path $CargoTargetRoot -Force | Out-Null
New-Item -ItemType Directory -Path $BootRoot -Force | Out-Null

$CargoArguments = @(
    'build',
    '--manifest-path', $ManifestPath,
    '--target', $TargetTriple,
    '--target-dir', $CargoTargetRoot,
    '--bin', $BinaryName
)

if ($Configuration -eq 'Release') {
    $CargoArguments += '--release'
}

Write-Host "Building $BinaryName ($Configuration) for $TargetTriple..."
& $CargoCommand.Source @CargoArguments
if ($LASTEXITCODE -ne 0) {
    throw "cargo build failed with exit code $LASTEXITCODE."
}

$BuiltBinary = Join-Path $CargoTargetRoot "$TargetTriple\$CargoProfile\$BinaryName.efi"
if (-not (Test-Path -LiteralPath $BuiltBinary -PathType Leaf)) {
    throw "Expected UEFI binary was not produced: $BuiltBinary"
}

$StagedBinary = Join-Path $OutputRoot "$BinaryName.efi"
$StagedConfig = Join-Path $OutputRoot 'MatrixConfig.bin'
$BootBinary = Join-Path $BootRoot 'BOOTX64.EFI'
Copy-Item -LiteralPath $BuiltBinary -Destination $StagedBinary -Force
Copy-Item -LiteralPath $BuiltBinary -Destination $BootBinary -Force
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "MatrixHV configuration was not generated: $ConfigPath"
}
Copy-Item -LiteralPath $ConfigPath -Destination $StagedConfig -Force

Write-Host "Staged UEFI binary: $StagedBinary"
Write-Host "Staged MatrixHV configuration: $StagedConfig"
Write-Host "Staged removable-media boot file: $BootBinary"

if (-not $SkipImage) {
    $MakeImageScript = Join-Path $PSScriptRoot 'make_image.ps1'
    $ImageArguments = @{
        Configuration = $Configuration
        BootBinary = $BootBinary
    }

    if (-not [string]::IsNullOrWhiteSpace($VeraCryptEfiSource)) {
        $ImageArguments.VeraCryptEfiSource = $VeraCryptEfiSource
    }

    & $MakeImageScript @ImageArguments
}

if (-not $SkipPackage) {
    $PackageScript = Join-Path $PSScriptRoot 'package.ps1'
    & $PackageScript -Configuration $Configuration
}

Write-Output $StagedBinary
