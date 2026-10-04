#requires -Version 5.1
param(
    [Parameter(Mandatory = $true)][string]$Remote,
    [Parameter(Mandatory = $true)][string]$NeoPath,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [string]$GuestNeoPath = 'C:\Users\Matrix\AppData\Local\MatrixHV\neo.exe'
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$guestNeo = $GuestNeoPath
$guestDirectory = 'C:\MatrixHVMemoryTests'
$logPath = Join-Path $OutputDirectory 'neo-memory.log'

function Write-CommandRecord([string]$record) {
    $stream = [IO.File]::Open($logPath, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($record + "`n")
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
}

function Invoke-GuestScript([string]$scriptText) {
    $scriptText = "$" + "ProgressPreference = 'SilentlyContinue'; " + $scriptText
    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($scriptText))
    Write-CommandRecord ("BEGIN powershell.exe -NoProfile -EncodedCommand " + $encodedCommand)
    $commandOutput = & $NeoPath --remote $Remote --timeout 30 exec powershell.exe -NoProfile -EncodedCommand $encodedCommand
    if ($LASTEXITCODE -ne 0) { throw "Guest script failed: $commandOutput" }
    return $commandOutput
}

function Invoke-Memory([string[]]$memoryArguments, [int]$expectedExit = 0) {
    Write-CommandRecord ("BEGIN " + $guestNeo + ' ' + ($memoryArguments -join ' '))
    $commandOutput = & $NeoPath --remote $Remote --timeout 45 exec $guestNeo @memoryArguments
    $commandExit = $LASTEXITCODE
    Write-CommandRecord (("END exit=" + $commandExit) + "`n" + ($commandOutput -join "`n"))
    Write-Output $commandOutput
    if ($commandExit -ne $expectedExit) { throw "Memory command exit $commandExit, expected $expectedExit" }
}

function Require-Data([string[]]$lines, [string]$expectedHex) {
    if (-not ($lines | Where-Object { $_ -match ('transferred=\d+/\d+ data=' + $expectedHex + '$') })) {
        throw "Expected memory bytes were not returned: $expectedHex"
    }
}

function Get-Pattern([int]$start, [int]$count) {
    return -join (0..($count - 1) | ForEach-Object { '{0:x2}' -f (($start + $_) % 251) })
}

$fixtureBytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'memory_vm_fixture.ps1')))
Invoke-GuestScript @"
New-Item -ItemType Directory -Path '$guestDirectory' -Force | Out-Null
Remove-Item -LiteralPath '$guestDirectory\stop' -ErrorAction SilentlyContinue
Remove-Item -LiteralPath '$guestDirectory\fixture.json' -ErrorAction SilentlyContinue
[IO.File]::WriteAllBytes('$guestDirectory\fixture.ps1', [Convert]::FromBase64String('$fixtureBytes'))
Start-Process powershell.exe -WindowStyle Hidden -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File $guestDirectory\fixture.ps1 -OutputDirectory $guestDirectory'
"@ | Out-Null

try {
    $fixtureJson = Invoke-GuestScript @"
for (`$attempt = 0; `$attempt -lt 80; ++`$attempt) {
    if (Test-Path '$guestDirectory\fixture.json') { Get-Content -Raw '$guestDirectory\fixture.json'; exit 0 }
    Start-Sleep -Milliseconds 250
}
throw 'Memory fixture did not initialize'
"@
    $fixture = ($fixtureJson -join "`n") | ConvertFrom-Json
    $fixture | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDirectory 'fixture.json')
    $residentAddress = [Convert]::ToUInt64($fixture.resident.Substring(2), 16)
    $crossReadAddress = '0x{0:x}' -f ($residentAddress + 4080)
    $crossWriteAddress = '0x{0:x}' -f ($residentAddress + 4094)
    $processIdText = [string]$fixture.pid
    Invoke-Memory @('read', 'System', 'auto') | Out-Host
    $initial = Invoke-Memory @('read', $processIdText, 'auto', $fixture.resident, '32', $crossReadAddress, '64')
    Require-Data $initial (Get-Pattern 0 32)
    Require-Data $initial (Get-Pattern 4080 64)
    $zeroResult = Invoke-Memory @('read', $processIdText, 'auto', $fixture.demandZero, '64')
    Require-Data $zeroResult ('00' * 64)
    Invoke-Memory @('write', $processIdText, 'auto', $fixture.demandZero, 'aa') 1 | Out-Host
    Invoke-Memory @('write', $processIdText, 'auto', $fixture.resident, '1122334455667788', $crossWriteAddress, 'aabbccddeeff1020') | Out-Host
    $written = Invoke-Memory @('read', $processIdText, 'auto', $fixture.resident, '8', $crossWriteAddress, '8')
    Require-Data $written '1122334455667788'
    Require-Data $written 'aabbccddeeff1020'
    $observed = Invoke-GuestScript "Start-Sleep -Milliseconds 500; Get-Content '$guestDirectory\observed.txt'"
    $observedBytes = [Convert]::FromBase64String(($observed -join '').Trim())
    if ([BitConverter]::ToString($observedBytes, 0, 8) -ne '11-22-33-44-55-66-77-88') {
        throw 'The fixture did not observe the Neo write'
    }
    $mixed = Invoke-Memory @('read', $processIdText, 'auto', $fixture.resident, '8', '0', '8') 1
    Require-Data $mixed '1122334455667788'
    Invoke-Memory @('write', $processIdText, 'auto', $fixture.resident, (Get-Pattern 0 8), $crossWriteAddress, (Get-Pattern 4094 8)) | Out-Host
    'PASS process name, automatic CR3, batched cross-page reads and writes, demand-zero, independent failure, and target-side write observation' | Tee-Object -FilePath (Join-Path $OutputDirectory 'result.txt')
} finally {
    Invoke-GuestScript "Set-Content -LiteralPath '$guestDirectory\stop' -Value 'stop'" | Out-Null
}
