#requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$buildRoot = [System.IO.Path]::GetFullPath('D:\Projetos\MatrixHV\builds')
$testRoot = Join-Path $buildRoot ('tests\build-scripts-' + [Guid]::NewGuid().ToString('N'))
$makeConfig = Join-Path $projectRoot 'scripts\make_config.ps1'
$makeImage = Join-Path $projectRoot 'scripts\make_image.ps1'
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null

try {
    $config = Join-Path $testRoot 'MatrixConfig.bin'
    & $makeConfig -OutputPath $config -Logger false -VtNested false | Out-Null
    & $makeConfig -OutputPath $config -VtEvmcs true | Out-Null
    $configText = [System.IO.File]::ReadAllText($config)
    foreach ($expected in @('logger=false', 'cpuidpresence=true', 'VtNested=true', 'VtEvmcs=true')) {
        if (-not $configText.Contains($expected)) {
            throw "Configuration did not preserve or normalize $expected"
        }
    }
    $outside = Join-Path $projectRoot ('builds-outside-' + [Guid]::NewGuid().ToString('N') + '.bin')
    $rejected = $false
    try {
        & $makeConfig -OutputPath $outside | Out-Null
    }
    catch {
        $rejected = $_.Exception.Message -like 'Configuration output must be under *'
    }
    if (-not $rejected -or (Test-Path -LiteralPath $outside)) {
        throw 'Configuration accepted an output path outside the build directory.'
    }

    $boot = Join-Path $testRoot 'BOOTX64.EFI'
    $linux = Join-Path $testRoot 'neo'
    $windows = Join-Path $testRoot 'neo.exe'
    [System.IO.File]::WriteAllBytes($boot, [byte[]](0..255))
    [System.IO.File]::WriteAllBytes($linux, [byte[]](0..255))
    [System.IO.File]::WriteAllBytes($windows, [byte[]](0..255))
    foreach ($source in @($boot, $config, $linux, $windows)) {
        $sourceBytes = [System.IO.File]::ReadAllBytes($source)
        $rejected = $false
        try {
            & $makeImage -BootBinary $boot -ConfigPath $config -NeoSource $linux -WindowsNeoSource $windows -ImagePath $source | Out-Null
        }
        catch {
            $rejected = $_.Exception.Message -like 'Image output cannot replace an input file:*'
        }
        if (-not $rejected -or [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($source)) -ne [Convert]::ToBase64String($sourceBytes)) {
            throw 'Image creation overwrote an input file.'
        }
    }
    foreach ($size in @(64, 65, 130)) {
        $image = Join-Path $testRoot "image-$size.img"
        [System.IO.File]::WriteAllText($image, 'previous image')
        & $makeImage -BootBinary $boot -ConfigPath $config -NeoSource $linux -WindowsNeoSource $windows -ImagePath $image -ImageSizeMiB $size | Out-Null
        $stream = [System.IO.File]::OpenRead($image)
        try {
            if ($stream.Length -ne [long]$size * 1MB) {
                throw "Image has an incorrect length at $size MiB."
            }
            $sector = New-Object byte[] 512
            $stream.Position = 2048 * 512
            if ($stream.Read($sector, 0, $sector.Length) -ne $sector.Length) {
                throw 'FAT32 boot sector is truncated.'
            }
            $bytesPerSector = [BitConverter]::ToUInt16($sector, 11)
            $sectorsPerCluster = $sector[13]
            $reserved = [BitConverter]::ToUInt16($sector, 14)
            $fatCount = $sector[16]
            $partitionSectors = [BitConverter]::ToUInt32($sector, 32)
            $fatSectors = [BitConverter]::ToUInt32($sector, 36)
            $clusters = [Math]::Floor(($partitionSectors - $reserved - $fatCount * $fatSectors) / $sectorsPerCluster)
            if ($clusters -lt 65525 -or ($clusters + 2) * 4 -gt $fatSectors * $bytesPerSector) {
                throw "FAT does not cover the image data area at $size MiB."
            }
            $rootOffset = (2048 + $reserved + $fatCount * $fatSectors) * [long]$bytesPerSector
            $stream.Position = $rootOffset
            if ($stream.Read($sector, 0, $sector.Length) -ne $sector.Length) {
                throw 'FAT32 root directory is truncated.'
            }
            $entry = 4 * 32
            if ([Text.Encoding]::ASCII.GetString($sector, $entry, 11) -ne 'MATRIX~1BIN') {
                throw 'Configuration directory entry is missing.'
            }
            $configCluster = ([uint32][BitConverter]::ToUInt16($sector, $entry + 20) -shl 16) -bor [BitConverter]::ToUInt16($sector, $entry + 26)
            $configSize = [BitConverter]::ToUInt32($sector, $entry + 28)
            $stream.Position = $rootOffset + ($configCluster - 2) * $sectorsPerCluster * [long]$bytesPerSector
            $configBytes = New-Object byte[] $configSize
            if ($stream.Read($configBytes, 0, $configBytes.Length) -ne $configBytes.Length -or [Text.Encoding]::UTF8.GetString($configBytes) -ne $configText) {
                throw 'Image configuration bytes do not match the source.'
            }
        }
        finally {
            $stream.Dispose()
        }
    }
    if (@(Get-ChildItem -LiteralPath $testRoot -Filter '*.tmp').Count -ne 0) {
        throw 'Image creation retained temporary output files.'
    }
    Write-Output 'Build script tests passed: configuration paths, preserved settings, input protection, image replacement, and FAT32 images at 64, 65, and 130 MiB.'
}
finally {
    $resolvedTestRoot = [System.IO.Path]::GetFullPath($testRoot)
    if (-not $resolvedTestRoot.StartsWith($buildRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove test artifacts outside the build directory: $resolvedTestRoot"
    }
    if (Test-Path -LiteralPath $resolvedTestRoot) {
        Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force
    }
}
