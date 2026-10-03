#requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    [switch]$SkipImage,

    [switch]$SkipPackage,

    [string]$VeraCryptEfiSource,

    [string]$VmxFlatEfiSource
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$BuildRoot = 'D:\Projetos\MatrixHV\builds'
$TargetTriple = 'x86_64-unknown-uefi'
$BinaryName = 'MatrixHV'
$ManifestPath = Join-Path $ProjectRoot 'Cargo.toml'
$RoadManifestPath = Join-Path $ProjectRoot 'src\neo\Cargo.toml'
$ConfigPath = Join-Path $BuildRoot 'MatrixConfig.bin'
$CargoTargetRoot = Join-Path $BuildRoot '.cargo-target'
$HostCargoTargetRoot = Join-Path $BuildRoot '.cargo-target-host'
$ConfigurationName = $Configuration.ToLowerInvariant()
$CargoProfile = if ($Configuration -eq 'Release') { 'release' } else { 'debug' }
$OutputRoot = Join-Path $BuildRoot $ConfigurationName
$BootRoot = Join-Path $OutputRoot 'EFI\BOOT'
$WindowsTargetTriple = 'x86_64-pc-windows-msvc'
$LinuxTargetTriple = 'x86_64-unknown-linux-musl'

if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw "Cargo manifest not found: $ManifestPath"
}

if ((Get-Item -LiteralPath $ManifestPath).Length -eq 0) {
    throw "Cargo manifest is empty: $ManifestPath"
}
if (-not (Test-Path -LiteralPath $RoadManifestPath -PathType Leaf)) {
    throw "ROAD Cargo manifest not found: $RoadManifestPath"
}

$CargoCommand = Get-Command cargo -ErrorAction SilentlyContinue
if ($null -eq $CargoCommand) {
    throw 'cargo was not found in PATH.'
}
$RustcCommand = Get-Command rustc -ErrorAction SilentlyContinue
if ($null -eq $RustcCommand) {
    throw 'rustc was not found in PATH.'
}

New-Item -ItemType Directory -Path $CargoTargetRoot -Force | Out-Null
New-Item -ItemType Directory -Path $HostCargoTargetRoot -Force | Out-Null
New-Item -ItemType Directory -Path $BootRoot -Force | Out-Null
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    & (Join-Path $PSScriptRoot 'make_config.ps1') -OutputPath $ConfigPath | Out-Null
}

$CargoArguments = @(
    'rustc',
    '--manifest-path', $ManifestPath,
    '--target', $TargetTriple,
    '--target-dir', $CargoTargetRoot,
    '--bin', $BinaryName
)

if ($Configuration -eq 'Release') {
    $CargoArguments += '--release'
}
$CargoArguments += @('--', '-Dwarnings', '--emit=obj,link')

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

$ResidentObject = Get-ChildItem -LiteralPath (Join-Path $CargoTargetRoot "$TargetTriple\$CargoProfile\deps") -Filter "$BinaryName-*.o" |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($null -eq $ResidentObject) {
    throw 'The embedded resident object was not produced.'
}
$PythonCommand = Get-Command python -ErrorAction Stop
$UpdatePackage = Join-Path $OutputRoot 'MatrixHV.mxcore'
& $PythonCommand.Source (Join-Path $PSScriptRoot 'build_update.py') package --object $ResidentObject.FullName --efi $StagedBinary --output $UpdatePackage
if ($LASTEXITCODE -ne 0) {
    throw "Resident package generation failed with exit code $LASTEXITCODE."
}

Write-Host "Staged UEFI binary: $StagedBinary"
Write-Host "Staged MatrixHV configuration: $StagedConfig"
Write-Host "Staged removable-media boot file: $BootBinary"

$RoadWindowsArguments = @(
    'build',
    '--manifest-path', $RoadManifestPath,
    '--target', $WindowsTargetTriple,
    '--target-dir', $HostCargoTargetRoot,
    '--bin', 'neo'
)
$RoadLinuxArguments = @(
    'build',
    '--manifest-path', $RoadManifestPath,
    '--target', $LinuxTargetTriple,
    '--target-dir', $HostCargoTargetRoot,
    '--bin', 'neo'
)
if ($Configuration -eq 'Release') {
    $RoadWindowsArguments += '--release'
    $RoadLinuxArguments += '--release'
}

Write-Host "Building ROAD Windows agent ($Configuration)..."
& $CargoCommand.Source @RoadWindowsArguments
if ($LASTEXITCODE -ne 0) {
    throw "ROAD Windows build failed with exit code $LASTEXITCODE."
}

Write-Host "Building ROAD Linux agent ($Configuration)..."
$LinuxLinkerVariable = 'CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER'
$PreviousLinuxLinker = [System.Environment]::GetEnvironmentVariable($LinuxLinkerVariable, 'Process')
if ([string]::IsNullOrWhiteSpace($PreviousLinuxLinker)) {
    $RustTargetLib = (& $RustcCommand.Source --print target-libdir).Trim()
    $RustLld = Join-Path (Split-Path -Parent $RustTargetLib) 'bin\rust-lld.exe'
    if (-not (Test-Path -LiteralPath $RustLld -PathType Leaf)) {
        throw "Rust LLD linker not found: $RustLld"
    }
    [System.Environment]::SetEnvironmentVariable($LinuxLinkerVariable, $RustLld, 'Process')
}
try {
    & $CargoCommand.Source @RoadLinuxArguments
    if ($LASTEXITCODE -ne 0) {
        throw "ROAD Linux build failed with exit code $LASTEXITCODE."
    }
}
finally {
    if ([string]::IsNullOrWhiteSpace($PreviousLinuxLinker)) {
        [System.Environment]::SetEnvironmentVariable($LinuxLinkerVariable, $null, 'Process')
    }
}

$BuiltWindowsNeo = Join-Path $HostCargoTargetRoot "$WindowsTargetTriple\$CargoProfile\neo.exe"
$BuiltLinuxNeo = Join-Path $HostCargoTargetRoot "$LinuxTargetTriple\$CargoProfile\neo"
$RoadArtifacts = @(
    @{ Source = $BuiltWindowsNeo; Destination = (Join-Path $OutputRoot 'neo.exe') },
    @{ Source = $BuiltLinuxNeo; Destination = (Join-Path $OutputRoot 'neo') }
)
foreach ($Artifact in $RoadArtifacts) {
    if (-not (Test-Path -LiteralPath $Artifact.Source -PathType Leaf)) {
        throw "Expected ROAD binary was not produced: $($Artifact.Source)"
    }
    Copy-Item -LiteralPath $Artifact.Source -Destination $Artifact.Destination -Force
    Write-Host "Staged ROAD binary: $($Artifact.Destination)"
}

if (-not $SkipImage) {
    $MakeImageScript = Join-Path $PSScriptRoot 'make_image.ps1'
    $ImageArguments = @{
        Configuration = $Configuration
        BootBinary = $BootBinary
        WindowsNeoSource = $BuiltWindowsNeo
    }

    if (-not [string]::IsNullOrWhiteSpace($VeraCryptEfiSource)) {
        $ImageArguments.VeraCryptEfiSource = $VeraCryptEfiSource
    }
    if (-not [string]::IsNullOrWhiteSpace($VmxFlatEfiSource)) {
        $ImageArguments.VmxFlatEfiSource = $VmxFlatEfiSource
    }

    & $MakeImageScript @ImageArguments
}

if (-not $SkipPackage) {
    $PackageScript = Join-Path $PSScriptRoot 'package.ps1'
    & $PackageScript -Configuration $Configuration
}

Write-Output $StagedBinary
