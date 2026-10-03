#requires -Version 5.1
param([Parameter(Mandatory = $true)][string]$OutputDirectory)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class MemoryVmFixture {
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint allocationType, uint protection);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualFree(IntPtr address, UIntPtr size, uint freeType);
    public static IntPtr residentBuffer;
    public static IntPtr demandZeroBuffer;
    public static void Initialize() {
        residentBuffer = VirtualAlloc(IntPtr.Zero, (UIntPtr)12288, 0x3000, 4);
        demandZeroBuffer = VirtualAlloc(IntPtr.Zero, (UIntPtr)4096, 0x3000, 4);
        if (residentBuffer == IntPtr.Zero || demandZeroBuffer == IntPtr.Zero)
            throw new InvalidOperationException("Cannot allocate memory test buffers");
        byte[] pattern = new byte[12288];
        for (int index = 0; index < pattern.Length; ++index) pattern[index] = (byte)(index % 251);
        Marshal.Copy(pattern, 0, residentBuffer, pattern.Length);
    }
    public static void Release() {
        if (residentBuffer != IntPtr.Zero) VirtualFree(residentBuffer, UIntPtr.Zero, 0x8000);
        if (demandZeroBuffer != IntPtr.Zero) VirtualFree(demandZeroBuffer, UIntPtr.Zero, 0x8000);
    }
}
'@

[MemoryVmFixture]::Initialize()
try {
    $fixtureState = [ordered]@{
        pid = $PID
        resident = '0x{0:x}' -f [MemoryVmFixture]::residentBuffer.ToInt64()
        demandZero = '0x{0:x}' -f [MemoryVmFixture]::demandZeroBuffer.ToInt64()
        size = 12288
    }
    $fixtureState | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDirectory 'fixture.json')
    $stopPath = Join-Path $OutputDirectory 'stop'
    while (-not (Test-Path -LiteralPath $stopPath)) {
        $observedBytes = New-Object byte[] 32
        [Runtime.InteropServices.Marshal]::Copy([MemoryVmFixture]::residentBuffer, $observedBytes, 0, 32)
        [Convert]::ToBase64String($observedBytes) | Set-Content -LiteralPath (Join-Path $OutputDirectory 'observed.txt')
        Start-Sleep -Milliseconds 250
    }
} finally {
    [MemoryVmFixture]::Release()
}
