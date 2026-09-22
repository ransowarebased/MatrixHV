#requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$BuildRoot = [System.IO.Path]::GetFullPath('D:\Projetos\MatrixHV\builds')
$ConfigurationName = $Configuration.ToLowerInvariant()
$OutputRoot = Join-Path $BuildRoot $ConfigurationName
$BinaryPath = Join-Path $OutputRoot 'MatrixHV.efi'
$ConfigPath = Join-Path $OutputRoot 'MatrixConfig.bin'
$BootPath = Join-Path $OutputRoot 'EFI\BOOT\BOOTX64.EFI'
$ImagePath = Join-Path $OutputRoot 'MatrixHV.img'
$ControlPath = Join-Path $OutputRoot 'control.exe'
$WindowsNeoPath = Join-Path $OutputRoot 'neo.exe'
$LinuxNeoPath = Join-Path $OutputRoot 'neo'
$PackageRoot = Join-Path $BuildRoot 'packages'
$StagingRoot = Join-Path $BuildRoot ".package\$ConfigurationName"
$ArchivePath = Join-Path $PackageRoot "MatrixHV-$ConfigurationName.zip"
$HashPath = "$ArchivePath.sha256"

if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
    throw "Staged UEFI binary not found: $BinaryPath"
}

if (-not (Test-Path -LiteralPath $BootPath -PathType Leaf)) {
    throw "Staged removable-media boot file not found: $BootPath"
}
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "Staged MatrixHV configuration not found: $ConfigPath"
}
foreach ($RoadPath in @($ControlPath, $WindowsNeoPath, $LinuxNeoPath)) {
    if (-not (Test-Path -LiteralPath $RoadPath -PathType Leaf)) {
        throw "Staged ROAD binary not found: $RoadPath"
    }
}

if (Test-Path -LiteralPath $StagingRoot) {
    Remove-Item -LiteralPath $StagingRoot -Recurse -Force
}

New-Item -ItemType Directory -Path (Join-Path $StagingRoot 'EFI\BOOT') -Force | Out-Null
New-Item -ItemType Directory -Path $PackageRoot -Force | Out-Null

try {
    Copy-Item -LiteralPath $BinaryPath -Destination (Join-Path $StagingRoot 'MatrixHV.efi') -Force
    Copy-Item -LiteralPath $ConfigPath -Destination (Join-Path $StagingRoot 'MatrixConfig.bin') -Force
    Copy-Item -LiteralPath $BootPath -Destination (Join-Path $StagingRoot 'EFI\BOOT\BOOTX64.EFI') -Force
    Copy-Item -LiteralPath $ControlPath -Destination (Join-Path $StagingRoot 'control.exe') -Force
    Copy-Item -LiteralPath $WindowsNeoPath -Destination (Join-Path $StagingRoot 'neo.exe') -Force
    Copy-Item -LiteralPath $LinuxNeoPath -Destination (Join-Path $StagingRoot 'neo') -Force

    if (Test-Path -LiteralPath $ImagePath -PathType Leaf) {
        Copy-Item -LiteralPath $ImagePath -Destination (Join-Path $StagingRoot (Split-Path -Leaf $ImagePath)) -Force
    }

    if (Test-Path -LiteralPath $ArchivePath) {
        Remove-Item -LiteralPath $ArchivePath -Force
    }

    if (Test-Path -LiteralPath $HashPath) {
        Remove-Item -LiteralPath $HashPath -Force
    }

    $PackageEntries = Get-ChildItem -LiteralPath $StagingRoot -Force
    Compress-Archive -Path $PackageEntries.FullName -DestinationPath $ArchivePath -CompressionLevel Optimal

    $Hash = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    "$Hash  $(Split-Path -Leaf $ArchivePath)" | Set-Content -LiteralPath $HashPath -Encoding ASCII
}
finally {
    if (Test-Path -LiteralPath $StagingRoot) {
        Remove-Item -LiteralPath $StagingRoot -Recurse -Force
    }
}

Write-Host "Created package: $ArchivePath"
Write-Host "Created SHA-256 file: $HashPath"
Write-Output $ArchivePath
