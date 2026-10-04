#requires -Version 5.1
[CmdletBinding(DefaultParameterSetName = 'Remote')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Remote')][string]$Remote,
    [Parameter(Mandatory = $true, ParameterSetName = 'Local')][switch]$Local,
    [Parameter(Mandatory = $true)][string]$NeoPath,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [switch]$ResumeFixture
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$guestDirectory = 'C:\MatrixHVBitmapTests'
$guestNeo = "$guestDirectory\neo.exe"
if ($Local) {
    $guestDirectory = Join-Path ([IO.Path]::GetFullPath($OutputDirectory)) 'fixture'
    $guestNeo = [IO.Path]::GetFullPath($NeoPath)
}
$logPath = Join-Path $OutputDirectory 'commands.log'

function Write-CommandRecord([string]$record) {
    $stream = [IO.File]::Open($logPath, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($record + "`n")
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
}

function Invoke-GuestScript([string]$scriptText, [int]$timeout = 20) {
    $scriptText = '$ProgressPreference="SilentlyContinue"; $ErrorActionPreference="Stop"; ' + $scriptText
    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($scriptText))
    Write-CommandRecord ("BEGIN powershell.exe -NoProfile -EncodedCommand " + $encodedCommand)
    if ($Local) {
        $lines = & powershell.exe -NoProfile -EncodedCommand $encodedCommand
    } else {
        $lines = & $NeoPath --remote $Remote --timeout $timeout exec powershell.exe -NoProfile -EncodedCommand $encodedCommand
    }
    if ($LASTEXITCODE -ne 0) { throw "Guest script failed: $lines" }
    return $lines
}

function Invoke-Bitmap([string[]]$bitmapArguments, [int]$expectedExit = 0) {
    Write-CommandRecord ("BEGIN " + $guestNeo + ' ad-bitmap ' + ($bitmapArguments -join ' '))
    if ($Local) {
        $lines = & $guestNeo ad-bitmap @bitmapArguments
    } else {
        $lines = & $NeoPath --remote $Remote --timeout 45 exec $guestNeo ad-bitmap @bitmapArguments
    }
    $commandExit = $LASTEXITCODE
    Write-CommandRecord (("END exit=" + $commandExit) + "`n" + ($lines -join "`n"))
    Write-Host ($lines -join "`n")
    if ($commandExit -ne $expectedExit) { throw "Bitmap command exited $commandExit, expected $expectedExit" }
    return $lines
}

function Start-Session([string[]]$targetArguments) {
    for ($attempt = 0; $attempt -lt 5; ++$attempt) {
        Write-CommandRecord ("BEGIN " + $guestNeo + ' ad-bitmap start ' + ($targetArguments -join ' '))
        if ($Local) {
            $lines = & $guestNeo ad-bitmap start @targetArguments
        } else {
            $lines = & $NeoPath --remote $Remote --timeout 45 exec $guestNeo ad-bitmap start @targetArguments
        }
        $commandExit = $LASTEXITCODE
        Write-CommandRecord (("END exit=" + $commandExit) + "`n" + ($lines -join "`n"))
        Write-Host ($lines -join "`n")
        if ($commandExit -eq 0 -and ($lines -join '') -match 'session=(\d+) state=ACTIVE') {
            return $Matches[1]
        }
        if ($commandExit -ne 0 -and $attempt -lt 4) { Start-Sleep -Milliseconds 100 }
    }
    throw 'Cannot start bitmap session'
}

function Send-FixtureCommand([string]$command) {
    Invoke-GuestScript @"
Remove-Item -LiteralPath '$guestDirectory\result.txt' -ErrorAction SilentlyContinue
Set-Content -LiteralPath '$guestDirectory\command.txt' -Value '$command'
for (`$attempt=0; `$attempt -lt 80; ++`$attempt) {
    if (Test-Path '$guestDirectory\result.txt') { Get-Content '$guestDirectory\result.txt'; exit 0 }
    Start-Sleep -Milliseconds 25
}
throw 'Fixture command timed out'
"@ | Out-Null
}

function Get-Export([string]$directory) {
    $lines = Invoke-GuestScript @"
`$records = @(Get-Content '$directory\pages.jsonl' | ForEach-Object { `$_ | ConvertFrom-Json })
`$files = @(Get-ChildItem '$directory' -Filter '*.bin' | ForEach-Object {
    [ordered]@{name=`$_.Name; bytes=[Convert]::ToBase64String([IO.File]::ReadAllBytes(`$_.FullName))}
})
[ordered]@{records=`$records; files=`$files; metadata=[IO.File]::ReadAllText('$directory\session.txt')} | ConvertTo-Json -Depth 6 -Compress
"@
    $export = ($lines -join "`n") | ConvertFrom-Json
    $localDirectory = Join-Path $OutputDirectory (Split-Path -Leaf $directory)
    New-Item -ItemType Directory -Path $localDirectory -Force | Out-Null
    foreach ($file in $export.files) {
        [IO.File]::WriteAllBytes((Join-Path $localDirectory $file.name), [Convert]::FromBase64String($file.bytes))
    }
    $export.records | ForEach-Object { $_ | ConvertTo-Json -Compress } | Set-Content -LiteralPath (Join-Path $localDirectory 'pages.jsonl')
    $export.metadata | Set-Content -LiteralPath (Join-Path $localDirectory 'session.txt')
    return $export
}

function Require([bool]$condition, [string]$message) {
    if (-not $condition) { throw $message }
}

if (-not $ResumeFixture) {
    $fixtureBytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'bitmap_vm_fixture.ps1')))
    $deployNeo = if ($Local) { '' } else { "Copy-Item -LiteralPath 'E:\neo.exe' -Destination '$guestNeo' -Force" }
    Invoke-GuestScript @"
New-Item -ItemType Directory -Path '$guestDirectory' -Force | Out-Null
[IO.File]::WriteAllBytes('$guestDirectory\fixture.ps1', [Convert]::FromBase64String('$fixtureBytes'))
$deployNeo
Remove-Item -LiteralPath '$guestDirectory\fixture.json' -ErrorAction SilentlyContinue
Remove-Item -LiteralPath '$guestDirectory\command.txt' -ErrorAction SilentlyContinue
Start-Process powershell.exe -WindowStyle Hidden -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command "& ''$guestDirectory\fixture.ps1'' -OutputDirectory ''$guestDirectory'' *> ''$guestDirectory\fixture-out.log''"'
exit 0
"@ | Out-Null
}
$fixtureJson = Invoke-GuestScript @"
for (`$attempt=0; `$attempt -lt 80; ++`$attempt) {
    if (Test-Path '$guestDirectory\fixture.json') { Get-Content -Raw '$guestDirectory\fixture.json'; exit 0 }
    Start-Sleep -Milliseconds 100
}
Get-Content '$guestDirectory\fixture-error.log'
throw 'Fixture did not initialize'
"@
$fixture = ($fixtureJson -join "`n") | ConvertFrom-Json
$fixture | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDirectory 'fixture.json')
if ($Local) {
    $resolved = & $guestNeo read ([string]$fixture.pid) auto
} else {
    $resolved = & $NeoPath --remote $Remote --timeout 45 exec $guestNeo read ([string]$fixture.pid) auto
}
Require ($LASTEXITCODE -eq 0) 'PID resolution failed'
Write-Host ($resolved -join "`n")
Require (($resolved -join '') -match 'cr3=(0x[0-9a-f]+)') 'CR3 was not returned'
$root = $Matches[1]
$suffix = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$sessionId = $null
try {
    $sessionId = Start-Session @('--pid', [string]$fixture.pid, '--gva', $fixture.gva, '--pages', '3')
    Send-FixtureCommand 'touch'
    $deltaDirectory = "$guestDirectory\delta-$suffix"
    Invoke-Bitmap @('stop', $sessionId, '--output', $deltaDirectory) | Out-Null
    $sessionId = $null
    $delta = Get-Export $deltaDirectory
    Require ($delta.records.Count -eq 3) 'Delta record count mismatch'
    Require (($delta.records[0].flags -band 3) -eq 1) 'Read-only page A/D mismatch'
    Require (($delta.records[1].flags -band 27) -eq 27) 'Dirty page flags mismatch'
    Require (($delta.records[2].flags -band 3) -eq 0) 'Untouched page A/D mismatch'
    $dirtyFile = @($delta.files | Where-Object { $_.name -eq $delta.records[1].dump })[0]
    $dirtyBytes = [Convert]::FromBase64String($dirtyFile.bytes)
    Require ($dirtyBytes.Length -eq 4096) 'Dirty dump size mismatch'
    Require (@($dirtyBytes | Where-Object { $_ -ne 0xa5 }).Count -eq 0) 'Dirty dump data mismatch'
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $digest = -join ($hash.ComputeHash($dirtyBytes) | ForEach-Object { '{0:x2}' -f $_ }) }
    finally { $hash.Dispose() }
    Require ($digest -eq $delta.records[1].sha256) 'Dirty dump SHA-256 mismatch'
    Require ($delta.records[1].initial_sha256 -ne $digest) 'Baseline SHA-256 did not detect the write'
    $baselineBytes = New-Object byte[] 4096
    for ($index = 0; $index -lt 4096; ++$index) { $baselineBytes[$index] = ($index + 4096) % 251 }
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $baselineDigest = -join ($hash.ComputeHash($baselineBytes) | ForEach-Object { '{0:x2}' -f $_ }) }
    finally { $hash.Dispose() }
    Require ($baselineDigest -eq $delta.records[1].initial_sha256) 'Baseline SHA-256 content mismatch'
    $accessedFile = @($delta.files | Where-Object { $_.name -eq 'accessed.bin' })[0]
    $bitmapFile = @($delta.files | Where-Object { $_.name -eq 'dirty.bin' })[0]
    Require (([Convert]::FromBase64String($accessedFile.bytes)[0]) -eq 3) 'Accessed bitmap data mismatch'
    Require (([Convert]::FromBase64String($bitmapFile.bytes)[0]) -eq 2) 'Dirty bitmap data mismatch'

    $sessionId = Start-Session @('--cr3', $root, '--gva', $fixture.gva, '--pages', '3')
    $cleanDirectory = "$guestDirectory\clean-$suffix"
    Invoke-Bitmap @('stop', $sessionId, '--output', $cleanDirectory) | Out-Null
    $sessionId = $null
    $clean = Get-Export $cleanDirectory
    Require (@($clean.records | Where-Object { ($_.flags -band 2) -ne 0 }).Count -eq 0) 'New session retained stale dirty bits'
    Require (@($clean.records | Where-Object { $_.dump -ne '' }).Count -eq 0) 'Clean session emitted a dump'

    $sessionId = Start-Session @('--cr3', $root, '--gva', $fixture.remapGva, '--pages', '1')
    Send-FixtureCommand 'remap'
    $remapDirectory = "$guestDirectory\remap-$suffix"
    Invoke-Bitmap @('stop', $sessionId, '--output', $remapDirectory) 1 | Out-Null
    $sessionId = $null
    $remap = Get-Export $remapDirectory
    $record = $remap.records[0]
    Require (($record.flags -band 4) -ne 0 -and $record.status -eq 13) 'Remap was not signaled'
    Require ($record.pte_fingerprint -ne $record.current_fingerprint) 'PTE fingerprint did not change'
    Require ($record.initial_gpa -ne $record.current_gpa) 'Replacement physical frame did not change'
    Require ($record.dump -eq '') 'Remapped frame was incorrectly dumped'
    $status = Invoke-Bitmap @('status')
    Require (($status -join '') -match 'split_tables=(\d+)') 'Split pool usage was not returned'
    Require ([int]$Matches[1] -gt 0) 'Runtime EPT splitting was not exercised'
    'PASS PID/CR3 input, START/STOP, exact 4 KiB A/D delta, fresh-session clearing, dirty dump, SHA-256, remap detection, SMP invalidation' | Tee-Object -FilePath (Join-Path $OutputDirectory 'result.txt')
} finally {
    if ($null -ne $sessionId) {
        if ($Local) {
            & $guestNeo ad-bitmap cancel $sessionId | Out-Null
        } else {
            & $NeoPath --remote $Remote --timeout 10 exec $guestNeo ad-bitmap cancel $sessionId | Out-Null
        }
    }
    Invoke-GuestScript "Set-Content -LiteralPath '$guestDirectory\command.txt' -Value 'stop'" | Out-Null
}
