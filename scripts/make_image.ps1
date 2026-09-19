#requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    [string]$BootBinary,

    [string]$ImagePath,

    [ValidateRange(64, 2048)]
    [int]$ImageSizeMiB = 64,

    [string]$VeraCryptEfiSource
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Set-UInt16LittleEndian {
    param(
        [byte[]]$Buffer,
        [int]$Offset,
        [UInt16]$Value
    )

    $Bytes = [System.BitConverter]::GetBytes($Value)
    [System.Array]::Copy($Bytes, 0, $Buffer, $Offset, 2)
}

function Set-UInt32LittleEndian {
    param(
        [byte[]]$Buffer,
        [int]$Offset,
        [UInt32]$Value
    )

    $Bytes = [System.BitConverter]::GetBytes($Value)
    [System.Array]::Copy($Bytes, 0, $Buffer, $Offset, 4)
}

function Set-AsciiBytes {
    param(
        [byte[]]$Buffer,
        [int]$Offset,
        [string]$Value
    )

    $Bytes = [System.Text.Encoding]::ASCII.GetBytes($Value)
    [System.Array]::Copy($Bytes, 0, $Buffer, $Offset, $Bytes.Length)
}

function Set-FatEntry {
    param(
        [byte[]]$Fat,
        [UInt32]$Cluster,
        [UInt32]$Value
    )

    Set-UInt32LittleEndian -Buffer $Fat -Offset ([int]($Cluster * 4)) -Value $Value
}

function Get-ClusterOffset {
    param(
        [UInt32]$Cluster,
        [UInt32]$FirstDataSector,
        [UInt32]$SectorsPerCluster,
        [UInt32]$BytesPerSector
    )

    return [Int64](($FirstDataSector + (($Cluster - 2) * $SectorsPerCluster)) * $BytesPerSector)
}

function Get-FatLongNameChecksum {
    param([string]$ShortName)

    if ($ShortName.Length -ne 11) {
        throw "FAT short name must contain exactly 11 characters: '$ShortName'"
    }

    $Checksum = [byte]0
    foreach ($Byte in [System.Text.Encoding]::ASCII.GetBytes($ShortName)) {
        $Checksum = [byte]((((($Checksum -band 1) -shl 7) -bor ($Checksum -shr 1)) + $Byte) -band 0xFF)
    }

    return $Checksum
}

function Write-FatRawDirectoryEntry {
    param(
        [System.IO.FileStream]$Stream,
        [Int64]$DirectoryOffset,
        [int]$EntryIndex,
        [byte[]]$Entry
    )

    $Stream.Position = $DirectoryOffset + ($EntryIndex * 32)
    $Stream.Write($Entry, 0, $Entry.Length)
}

function Write-FatNamedDirectoryEntry {
    param(
        [System.IO.FileStream]$Stream,
        [Int64]$DirectoryOffset,
        [int]$EntryIndex,
        [string]$ShortName,
        [string]$LongName,
        [byte]$Attributes,
        [UInt32]$FirstCluster,
        [UInt32]$FileSize = 0
    )

    if ($ShortName.Length -ne 11) {
        throw "FAT short name must contain exactly 11 characters: '$ShortName'"
    }

    $CurrentIndex = $EntryIndex
    if (-not [string]::IsNullOrWhiteSpace($LongName)) {
        $NameUnits = New-Object 'System.Collections.Generic.List[UInt16]'
        foreach ($Character in $LongName.ToCharArray()) {
            $NameUnits.Add([UInt16][char]$Character)
        }
        $NameUnits.Add([UInt16]0)

        while (($NameUnits.Count % 13) -ne 0) {
            $NameUnits.Add([UInt16]0xFFFF)
        }

        $LongEntryCount = [int]($NameUnits.Count / 13)
        $Checksum = Get-FatLongNameChecksum -ShortName $ShortName
        $NameOffsets = @(1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30)

        for ($Sequence = $LongEntryCount; $Sequence -ge 1; $Sequence--) {
            $LongEntry = New-Object byte[] 32
            $Order = [byte]$Sequence
            if ($Sequence -eq $LongEntryCount) {
                $Order = [byte]($Order -bor 0x40)
            }

            $LongEntry[0] = $Order
            $LongEntry[11] = 0x0F
            $LongEntry[12] = 0
            $LongEntry[13] = $Checksum
            Set-UInt16LittleEndian -Buffer $LongEntry -Offset 26 -Value 0

            $UnitStart = ($Sequence - 1) * 13
            for ($UnitIndex = 0; $UnitIndex -lt 13; $UnitIndex++) {
                Set-UInt16LittleEndian -Buffer $LongEntry -Offset $NameOffsets[$UnitIndex] -Value $NameUnits[$UnitStart + $UnitIndex]
            }

            Write-FatRawDirectoryEntry -Stream $Stream -DirectoryOffset $DirectoryOffset -EntryIndex $CurrentIndex -Entry $LongEntry
            $CurrentIndex++
        }
    }

    $Entry = New-Object byte[] 32
    Set-AsciiBytes -Buffer $Entry -Offset 0 -Value $ShortName
    $Entry[11] = $Attributes
    Set-UInt16LittleEndian -Buffer $Entry -Offset 20 -Value ([UInt16](($FirstCluster -shr 16) -band 0xFFFF))
    Set-UInt16LittleEndian -Buffer $Entry -Offset 26 -Value ([UInt16]($FirstCluster -band 0xFFFF))
    Set-UInt32LittleEndian -Buffer $Entry -Offset 28 -Value $FileSize
    Write-FatRawDirectoryEntry -Stream $Stream -DirectoryOffset $DirectoryOffset -EntryIndex $CurrentIndex -Entry $Entry

    return ($CurrentIndex + 1)
}

function Resolve-VeraCryptPayload {
    param([string]$SourceRoot)

    $ResolvedRoot = [System.IO.Path]::GetFullPath($SourceRoot)
    if (-not (Test-Path -LiteralPath $ResolvedRoot -PathType Container)) {
        throw "VeraCrypt EFI source directory not found: $ResolvedRoot"
    }

    $AcceptedNames = @(
        'DcsBoot.efi', 'DcsBoot.dcs',
        'DcsInt.dcs', 'DcsInt.efi',
        'DcsInfo.dcs', 'DcsInfo.efi',
        'LegacySpeaker.dcs', 'LegacySpeaker.efi'
    )
    $CandidateFiles = @(Get-ChildItem -LiteralPath $ResolvedRoot -Recurse -File -ErrorAction Stop | Where-Object { $AcceptedNames -contains $_.Name })
    if ($CandidateFiles.Count -eq 0) {
        throw "No VeraCrypt EFI payload files were found under: $ResolvedRoot"
    }

    $PayloadSets = New-Object 'System.Collections.Generic.List[object]'
    foreach ($Group in ($CandidateFiles | Group-Object DirectoryName)) {
        $Files = @($Group.Group)

        $DcsBoot = @($Files | Where-Object { $_.BaseName -ieq 'DcsBoot' } | Sort-Object @{ Expression = { if ($_.Extension -ieq '.efi') { 0 } else { 1 } } }, Name | Select-Object -First 1)
        $DcsInt = @($Files | Where-Object { $_.BaseName -ieq 'DcsInt' } | Sort-Object @{ Expression = { if ($_.Extension -ieq '.dcs') { 0 } else { 1 } } }, Name | Select-Object -First 1)
        $DcsInfo = @($Files | Where-Object { $_.BaseName -ieq 'DcsInfo' } | Sort-Object @{ Expression = { if ($_.Extension -ieq '.dcs') { 0 } else { 1 } } }, Name | Select-Object -First 1)
        $LegacySpeaker = @($Files | Where-Object { $_.BaseName -ieq 'LegacySpeaker' } | Sort-Object @{ Expression = { if ($_.Extension -ieq '.dcs') { 0 } else { 1 } } }, Name | Select-Object -First 1)

        if ($DcsBoot.Count -eq 0 -or $DcsInt.Count -eq 0 -or $DcsInfo.Count -eq 0) {
            continue
        }

        $DirectoryPath = [string]$Group.Name
        $Score = 0
        if ($DirectoryPath -match '(?i)(^|[\\/])x64([\\/]|$)|amd64') { $Score += 20 }
        if ($DirectoryPath -match '(?i)[\\/]EFI[\\/]VeraCrypt([\\/]|$)') { $Score += 20 }
        if ($DcsBoot[0].Extension -ieq '.efi') { $Score += 4 }
        if ($DcsInt[0].Extension -ieq '.dcs') { $Score += 4 }
        if ($DcsInfo[0].Extension -ieq '.dcs') { $Score += 4 }
        if ($LegacySpeaker.Count -gt 0 -and $LegacySpeaker[0].Extension -ieq '.dcs') { $Score += 1 }

        $PayloadSets.Add([PSCustomObject]@{
            Directory = $DirectoryPath
            Score = $Score
            DcsBoot = $DcsBoot[0].FullName
            DcsInt = $DcsInt[0].FullName
            DcsInfo = $DcsInfo[0].FullName
            LegacySpeaker = if ($LegacySpeaker.Count -gt 0) { $LegacySpeaker[0].FullName } else { $null }
        })
    }

    if ($PayloadSets.Count -eq 0) {
        throw "No directory under '$ResolvedRoot' contains DcsBoot plus DcsInt and DcsInfo EFI payloads."
    }

    $Ranked = @($PayloadSets | Sort-Object @{ Expression = 'Score'; Descending = $true }, @{ Expression = { $_.Directory.Length }; Ascending = $true }, Directory)
    if ($Ranked.Count -gt 1 -and $Ranked[0].Score -eq $Ranked[1].Score -and $Ranked[0].Directory.Length -eq $Ranked[1].Directory.Length) {
        $Ambiguous = ($Ranked | Where-Object { $_.Score -eq $Ranked[0].Score -and $_.Directory.Length -eq $Ranked[0].Directory.Length } | ForEach-Object { $_.Directory }) -join '; '
        throw "Multiple equally suitable VeraCrypt EFI payload directories were found. Pass a more specific -VeraCryptEfiSource. Candidates: $Ambiguous"
    }

    return $Ranked[0]
}

function New-ImageFileDescriptor {
    param(
        [string]$Directory,
        [string]$Name,
        [string]$ShortName,
        [string]$LongName,
        [string]$SourcePath
    )

    $Bytes = [System.IO.File]::ReadAllBytes($SourcePath)
    if ($Bytes.Length -eq 0) {
        throw "EFI payload file is empty: $SourcePath"
    }
    if ($Bytes.LongLength -gt [UInt32]::MaxValue) {
        throw "EFI payload file is too large for a FAT32 directory entry: $SourcePath"
    }

    return [PSCustomObject]@{
        Directory = $Directory
        Name = $Name
        ShortName = $ShortName
        LongName = $LongName
        SourcePath = $SourcePath
        Bytes = $Bytes
        FirstCluster = [UInt32]0
        LastCluster = [UInt32]0
    }
}

$BuildRoot = [System.IO.Path]::GetFullPath('D:\Projetos\MatrixHV\builds')
$ConfigurationName = $Configuration.ToLowerInvariant()

if ([string]::IsNullOrWhiteSpace($BootBinary)) {
    $BootBinary = Join-Path $BuildRoot "$ConfigurationName\EFI\BOOT\BOOTX64.EFI"
}
if ([string]::IsNullOrWhiteSpace($ImagePath)) {
    $ImagePath = Join-Path $BuildRoot "images\MatrixHV-$ConfigurationName.img"
}

$BootBinary = [System.IO.Path]::GetFullPath($BootBinary)
$ImagePath = [System.IO.Path]::GetFullPath($ImagePath)
$BuildRootPrefix = $BuildRoot.TrimEnd('\') + '\'
if (-not $ImagePath.StartsWith($BuildRootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Image output must be under $BuildRoot"
}
if (-not (Test-Path -LiteralPath $BootBinary -PathType Leaf)) {
    throw "UEFI boot binary not found: $BootBinary"
}

$ImageFiles = New-Object 'System.Collections.Generic.List[object]'
$ImageFiles.Add((New-ImageFileDescriptor -Directory 'BOOT' -Name 'BOOTX64.EFI' -ShortName 'BOOTX64 EFI' -LongName $null -SourcePath $BootBinary))

$VeraCryptPayload = $null
if (-not [string]::IsNullOrWhiteSpace($VeraCryptEfiSource)) {
    $VeraCryptPayload = Resolve-VeraCryptPayload -SourceRoot $VeraCryptEfiSource
    $ImageFiles.Add((New-ImageFileDescriptor -Directory 'VeraCrypt' -Name 'DcsBoot.efi' -ShortName 'DCSBOOT EFI' -LongName $null -SourcePath $VeraCryptPayload.DcsBoot))
    $ImageFiles.Add((New-ImageFileDescriptor -Directory 'VeraCrypt' -Name 'DcsInt.dcs' -ShortName 'DCSINT  DCS' -LongName $null -SourcePath $VeraCryptPayload.DcsInt))
    $ImageFiles.Add((New-ImageFileDescriptor -Directory 'VeraCrypt' -Name 'DcsInfo.dcs' -ShortName 'DCSINFO DCS' -LongName $null -SourcePath $VeraCryptPayload.DcsInfo))
    if (-not [string]::IsNullOrWhiteSpace($VeraCryptPayload.LegacySpeaker)) {
        $ImageFiles.Add((New-ImageFileDescriptor -Directory 'VeraCrypt' -Name 'LegacySpeaker.dcs' -ShortName 'LEGACY~1DCS' -LongName 'LegacySpeaker.dcs' -SourcePath $VeraCryptPayload.LegacySpeaker))
    }
}

$BytesPerSector = [UInt32]512
$SectorsPerCluster = [UInt32]1
$ReservedSectors = [UInt32]32
$FatCount = [UInt32]2
$PartitionStart = [UInt32]2048
$TotalSectors = [UInt32](($ImageSizeMiB * 1MB) / $BytesPerSector)
$PartitionSectors = [UInt32]($TotalSectors - $PartitionStart)

$FatSectors = [UInt32]1
do {
    $DataSectors = [UInt32]($PartitionSectors - $ReservedSectors - ($FatCount * $FatSectors))
    $ClusterCount = [UInt32][Math]::Floor($DataSectors / [double]$SectorsPerCluster)
    $RequiredFatSectors = [UInt32][Math]::Ceiling((($ClusterCount + 2) * 4) / [double]$BytesPerSector)
    $Changed = $RequiredFatSectors -ne $FatSectors
    $FatSectors = $RequiredFatSectors
} while ($Changed)

$DataSectors = [UInt32]($PartitionSectors - $ReservedSectors - ($FatCount * $FatSectors))
$ClusterCount = [UInt32][Math]::Floor($DataSectors / [double]$SectorsPerCluster)
if ($ClusterCount -lt 65525) {
    throw "Image is too small for FAT32: $ImageSizeMiB MiB"
}

$ClusterSize = [UInt32]($BytesPerSector * $SectorsPerCluster)
$RootCluster = [UInt32]2
$EfiCluster = [UInt32]3
$BootDirectoryCluster = [UInt32]4
$VeraCryptDirectoryCluster = if ($null -ne $VeraCryptPayload) { [UInt32]5 } else { [UInt32]0 }
$NextCluster = if ($null -ne $VeraCryptPayload) { [UInt32]6 } else { [UInt32]5 }

foreach ($ImageFile in $ImageFiles) {
    $FileClusterCount = [UInt32][Math]::Ceiling($ImageFile.Bytes.Length / [double]$ClusterSize)
    $ImageFile.FirstCluster = $NextCluster
    $ImageFile.LastCluster = [UInt32]($NextCluster + $FileClusterCount - 1)
    $NextCluster = [UInt32]($ImageFile.LastCluster + 1)
}

if (($NextCluster - 1) -gt ($ClusterCount + 1)) {
    throw "EFI payloads do not fit in the $ImageSizeMiB MiB image."
}

$ImageDirectory = Split-Path -Parent $ImagePath
New-Item -ItemType Directory -Path $ImageDirectory -Force | Out-Null

$ImageLength = [Int64]$TotalSectors * $BytesPerSector
$Stream = [System.IO.File]::Open($ImagePath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
try {
    $Stream.SetLength($ImageLength)

    $Mbr = New-Object byte[] $BytesPerSector
    Set-UInt32LittleEndian -Buffer $Mbr -Offset 440 -Value 0x4D485631
    $Mbr[446] = 0x80
    $Mbr[447] = 0x20
    $Mbr[448] = 0x21
    $Mbr[449] = 0x00
    $Mbr[450] = 0x0C
    $Mbr[451] = 0xFE
    $Mbr[452] = 0xFF
    $Mbr[453] = 0xFF
    Set-UInt32LittleEndian -Buffer $Mbr -Offset 454 -Value $PartitionStart
    Set-UInt32LittleEndian -Buffer $Mbr -Offset 458 -Value $PartitionSectors
    $Mbr[510] = 0x55
    $Mbr[511] = 0xAA
    $Stream.Position = 0
    $Stream.Write($Mbr, 0, $Mbr.Length)

    $BootSector = New-Object byte[] $BytesPerSector
    $BootSector[0] = 0xEB
    $BootSector[1] = 0x58
    $BootSector[2] = 0x90
    Set-AsciiBytes -Buffer $BootSector -Offset 3 -Value 'MSWIN4.1'
    Set-UInt16LittleEndian -Buffer $BootSector -Offset 11 -Value ([UInt16]$BytesPerSector)
    $BootSector[13] = [byte]$SectorsPerCluster
    Set-UInt16LittleEndian -Buffer $BootSector -Offset 14 -Value ([UInt16]$ReservedSectors)
    $BootSector[16] = [byte]$FatCount
    Set-UInt16LittleEndian -Buffer $BootSector -Offset 17 -Value 0
    Set-UInt16LittleEndian -Buffer $BootSector -Offset 19 -Value 0
    $BootSector[21] = 0xF8
    Set-UInt16LittleEndian -Buffer $BootSector -Offset 22 -Value 0
    Set-UInt16LittleEndian -Buffer $BootSector -Offset 24 -Value 63
    Set-UInt16LittleEndian -Buffer $BootSector -Offset 26 -Value 255
    Set-UInt32LittleEndian -Buffer $BootSector -Offset 28 -Value $PartitionStart
    Set-UInt32LittleEndian -Buffer $BootSector -Offset 32 -Value $PartitionSectors
    Set-UInt32LittleEndian -Buffer $BootSector -Offset 36 -Value $FatSectors
    Set-UInt16LittleEndian -Buffer $BootSector -Offset 40 -Value 0
    Set-UInt16LittleEndian -Buffer $BootSector -Offset 42 -Value 0
    Set-UInt32LittleEndian -Buffer $BootSector -Offset 44 -Value $RootCluster
    Set-UInt16LittleEndian -Buffer $BootSector -Offset 48 -Value 1
    Set-UInt16LittleEndian -Buffer $BootSector -Offset 50 -Value 6
    $BootSector[64] = 0x80
    $BootSector[66] = 0x29
    Set-UInt32LittleEndian -Buffer $BootSector -Offset 67 -Value 0x4D485632
    Set-AsciiBytes -Buffer $BootSector -Offset 71 -Value 'MATRIXHV    '
    Set-AsciiBytes -Buffer $BootSector -Offset 82 -Value 'FAT32   '
    $BootSector[510] = 0x55
    $BootSector[511] = 0xAA

    $PartitionOffset = [Int64]$PartitionStart * $BytesPerSector
    $Stream.Position = $PartitionOffset
    $Stream.Write($BootSector, 0, $BootSector.Length)
    $Stream.Position = $PartitionOffset + (6 * $BytesPerSector)
    $Stream.Write($BootSector, 0, $BootSector.Length)

    $FsInfo = New-Object byte[] $BytesPerSector
    Set-UInt32LittleEndian -Buffer $FsInfo -Offset 0 -Value 0x41615252
    Set-UInt32LittleEndian -Buffer $FsInfo -Offset 484 -Value 0x61417272
    Set-UInt32LittleEndian -Buffer $FsInfo -Offset 488 -Value ([UInt32]::MaxValue)
    Set-UInt32LittleEndian -Buffer $FsInfo -Offset 492 -Value ([UInt32]::MaxValue)
    $FsInfo[510] = 0x55
    $FsInfo[511] = 0xAA
    $Stream.Position = $PartitionOffset + $BytesPerSector
    $Stream.Write($FsInfo, 0, $FsInfo.Length)
    $Stream.Position = $PartitionOffset + (7 * $BytesPerSector)
    $Stream.Write($FsInfo, 0, $FsInfo.Length)

    $Fat = New-Object byte[] ([int]($FatSectors * $BytesPerSector))
    Set-FatEntry -Fat $Fat -Cluster 0 -Value 0x0FFFFFF8
    Set-FatEntry -Fat $Fat -Cluster 1 -Value ([UInt32]::MaxValue)
    Set-FatEntry -Fat $Fat -Cluster $RootCluster -Value 0x0FFFFFFF
    Set-FatEntry -Fat $Fat -Cluster $EfiCluster -Value 0x0FFFFFFF
    Set-FatEntry -Fat $Fat -Cluster $BootDirectoryCluster -Value 0x0FFFFFFF
    if ($null -ne $VeraCryptPayload) {
        Set-FatEntry -Fat $Fat -Cluster $VeraCryptDirectoryCluster -Value 0x0FFFFFFF
    }

    foreach ($ImageFile in $ImageFiles) {
        for ($Cluster = $ImageFile.FirstCluster; $Cluster -le $ImageFile.LastCluster; $Cluster++) {
            $NextFileCluster = if ($Cluster -eq $ImageFile.LastCluster) { [UInt32]0x0FFFFFFF } else { [UInt32]($Cluster + 1) }
            Set-FatEntry -Fat $Fat -Cluster $Cluster -Value $NextFileCluster
        }
    }

    $FatStartSector = [UInt32]($PartitionStart + $ReservedSectors)
    for ($FatIndex = 0; $FatIndex -lt $FatCount; $FatIndex++) {
        $Stream.Position = [Int64]($FatStartSector + ($FatIndex * $FatSectors)) * $BytesPerSector
        $Stream.Write($Fat, 0, $Fat.Length)
    }

    $FirstDataSector = [UInt32]($PartitionStart + $ReservedSectors + ($FatCount * $FatSectors))
    $RootOffset = Get-ClusterOffset -Cluster $RootCluster -FirstDataSector $FirstDataSector -SectorsPerCluster $SectorsPerCluster -BytesPerSector $BytesPerSector
    $EfiOffset = Get-ClusterOffset -Cluster $EfiCluster -FirstDataSector $FirstDataSector -SectorsPerCluster $SectorsPerCluster -BytesPerSector $BytesPerSector
    $BootDirectoryOffset = Get-ClusterOffset -Cluster $BootDirectoryCluster -FirstDataSector $FirstDataSector -SectorsPerCluster $SectorsPerCluster -BytesPerSector $BytesPerSector

    $Index = 0
    $Index = Write-FatNamedDirectoryEntry -Stream $Stream -DirectoryOffset $RootOffset -EntryIndex $Index -ShortName 'EFI        ' -LongName $null -Attributes 0x10 -FirstCluster $EfiCluster

    $Index = 0
    $Index = Write-FatNamedDirectoryEntry -Stream $Stream -DirectoryOffset $EfiOffset -EntryIndex $Index -ShortName '.          ' -LongName $null -Attributes 0x10 -FirstCluster $EfiCluster
    $Index = Write-FatNamedDirectoryEntry -Stream $Stream -DirectoryOffset $EfiOffset -EntryIndex $Index -ShortName '..         ' -LongName $null -Attributes 0x10 -FirstCluster $RootCluster
    $Index = Write-FatNamedDirectoryEntry -Stream $Stream -DirectoryOffset $EfiOffset -EntryIndex $Index -ShortName 'BOOT       ' -LongName $null -Attributes 0x10 -FirstCluster $BootDirectoryCluster
    if ($null -ne $VeraCryptPayload) {
        $Index = Write-FatNamedDirectoryEntry -Stream $Stream -DirectoryOffset $EfiOffset -EntryIndex $Index -ShortName 'VERACR~1   ' -LongName 'VeraCrypt' -Attributes 0x10 -FirstCluster $VeraCryptDirectoryCluster
    }

    $Index = 0
    $Index = Write-FatNamedDirectoryEntry -Stream $Stream -DirectoryOffset $BootDirectoryOffset -EntryIndex $Index -ShortName '.          ' -LongName $null -Attributes 0x10 -FirstCluster $BootDirectoryCluster
    $Index = Write-FatNamedDirectoryEntry -Stream $Stream -DirectoryOffset $BootDirectoryOffset -EntryIndex $Index -ShortName '..         ' -LongName $null -Attributes 0x10 -FirstCluster $EfiCluster
    $BootFile = @($ImageFiles | Where-Object { $_.Directory -eq 'BOOT' })[0]
    $Index = Write-FatNamedDirectoryEntry -Stream $Stream -DirectoryOffset $BootDirectoryOffset -EntryIndex $Index -ShortName $BootFile.ShortName -LongName $BootFile.LongName -Attributes 0x20 -FirstCluster $BootFile.FirstCluster -FileSize ([UInt32]$BootFile.Bytes.Length)

    if ($null -ne $VeraCryptPayload) {
        $VeraCryptDirectoryOffset = Get-ClusterOffset -Cluster $VeraCryptDirectoryCluster -FirstDataSector $FirstDataSector -SectorsPerCluster $SectorsPerCluster -BytesPerSector $BytesPerSector
        $Index = 0
        $Index = Write-FatNamedDirectoryEntry -Stream $Stream -DirectoryOffset $VeraCryptDirectoryOffset -EntryIndex $Index -ShortName '.          ' -LongName $null -Attributes 0x10 -FirstCluster $VeraCryptDirectoryCluster
        $Index = Write-FatNamedDirectoryEntry -Stream $Stream -DirectoryOffset $VeraCryptDirectoryOffset -EntryIndex $Index -ShortName '..         ' -LongName $null -Attributes 0x10 -FirstCluster $EfiCluster
        foreach ($ImageFile in @($ImageFiles | Where-Object { $_.Directory -eq 'VeraCrypt' })) {
            $Index = Write-FatNamedDirectoryEntry -Stream $Stream -DirectoryOffset $VeraCryptDirectoryOffset -EntryIndex $Index -ShortName $ImageFile.ShortName -LongName $ImageFile.LongName -Attributes 0x20 -FirstCluster $ImageFile.FirstCluster -FileSize ([UInt32]$ImageFile.Bytes.Length)
        }
    }

    foreach ($ImageFile in $ImageFiles) {
        $FileOffset = Get-ClusterOffset -Cluster $ImageFile.FirstCluster -FirstDataSector $FirstDataSector -SectorsPerCluster $SectorsPerCluster -BytesPerSector $BytesPerSector
        $Stream.Position = $FileOffset
        $Stream.Write($ImageFile.Bytes, 0, $ImageFile.Bytes.Length)
    }
    $Stream.Flush()
}
finally {
    $Stream.Dispose()
}

Write-Host "Created UEFI FAT32 image: $ImagePath"
if ($null -ne $VeraCryptPayload) {
    Write-Host "Embedded VeraCrypt EFI payload from: $($VeraCryptPayload.Directory)"
    foreach ($ImageFile in @($ImageFiles | Where-Object { $_.Directory -eq 'VeraCrypt' })) {
        $Hash = (Get-FileHash -LiteralPath $ImageFile.SourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
        Write-Host "  EFI\VeraCrypt\$($ImageFile.Name) <= $($ImageFile.SourcePath) [$Hash]"
    }
}
Write-Output $ImagePath
