#requires -Version 5.1
param([Parameter(Mandatory = $true)][string]$OutputDirectory)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class BitmapVmFixture {
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint type, uint protection);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool VirtualLock(IntPtr address, UIntPtr size);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool VirtualFree(IntPtr address, UIntPtr size, uint type);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr CreateFileMapping(IntPtr file, IntPtr attributes, uint protection,
                                         uint sizeHigh, uint sizeLow, string name);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr MapViewOfFileEx(IntPtr mapping, uint access, uint offsetHigh,
                                        uint offsetLow, UIntPtr bytes, IntPtr address);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool UnmapViewOfFile(IntPtr address);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    public static IntPtr buffer;
    public static IntPtr remapBuffer;
    static IntPtr firstMapping, secondMapping, replacementView;
    public static void Initialize() {
        buffer = VirtualAlloc(IntPtr.Zero, (UIntPtr)12288, 0x3000, 4);
        if (buffer == IntPtr.Zero) throw new Win32Exception();
        byte[] pattern = new byte[12288];
        for (int index = 0; index < pattern.Length; ++index) pattern[index] = (byte)(index % 251);
        Marshal.Copy(pattern, 0, buffer, pattern.Length);
        if (!VirtualLock(buffer, (UIntPtr)12288)) throw new Win32Exception();
        firstMapping = CreateFileMapping(new IntPtr(-1), IntPtr.Zero, 4, 0, 4096, null);
        secondMapping = CreateFileMapping(new IntPtr(-1), IntPtr.Zero, 4, 0, 4096, null);
        if (firstMapping == IntPtr.Zero || secondMapping == IntPtr.Zero) throw new Win32Exception();
        remapBuffer = MapViewOfFileEx(firstMapping, 2, 0, 0, (UIntPtr)4096, IntPtr.Zero);
        replacementView = MapViewOfFileEx(secondMapping, 2, 0, 0, (UIntPtr)4096, IntPtr.Zero);
        if (remapBuffer == IntPtr.Zero || replacementView == IntPtr.Zero) throw new Win32Exception();
        Marshal.WriteByte(remapBuffer, 0x11);
        Marshal.WriteByte(replacementView, 0x22);
        if (!VirtualLock(remapBuffer, (UIntPtr)4096) || !VirtualLock(replacementView, (UIntPtr)4096))
            throw new Win32Exception();
    }
    public static int AccessAndWrite() {
        int observed = Marshal.ReadByte(buffer);
        byte[] dirty = new byte[4096];
        for (int index = 0; index < dirty.Length; ++index) dirty[index] = 0xa5;
        Marshal.Copy(dirty, 0, IntPtr.Add(buffer, 4096), dirty.Length);
        return observed;
    }
    public static void Remap() {
        IntPtr address = remapBuffer;
        if (!UnmapViewOfFile(address)) throw new Win32Exception();
        remapBuffer = MapViewOfFileEx(secondMapping, 2, 0, 0, (UIntPtr)4096, address);
        if (remapBuffer != address) throw new InvalidOperationException("Replacement GVA changed");
        if (Marshal.ReadByte(remapBuffer) != 0x22) throw new InvalidOperationException("Wrong replacement frame");
        if (!VirtualLock(remapBuffer, (UIntPtr)4096)) throw new Win32Exception();
    }
    public static void Release() {
        if (buffer != IntPtr.Zero) VirtualFree(buffer, UIntPtr.Zero, 0x8000);
        if (remapBuffer != IntPtr.Zero) UnmapViewOfFile(remapBuffer);
        if (replacementView != IntPtr.Zero) UnmapViewOfFile(replacementView);
        if (firstMapping != IntPtr.Zero) CloseHandle(firstMapping);
        if (secondMapping != IntPtr.Zero) CloseHandle(secondMapping);
    }
}
'@

[BitmapVmFixture]::Initialize()
try {
    [ordered]@{
        pid = $PID
        gva = '0x{0:x}' -f [BitmapVmFixture]::buffer.ToInt64()
        remapGva = '0x{0:x}' -f [BitmapVmFixture]::remapBuffer.ToInt64()
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDirectory 'fixture.json')
    $commandPath = Join-Path $OutputDirectory 'command.txt'
    $resultPath = Join-Path $OutputDirectory 'result.txt'
    while ($true) {
        if (Test-Path -LiteralPath $commandPath) {
            $command = (Get-Content -LiteralPath $commandPath -Raw).Trim()
            Remove-Item -LiteralPath $commandPath
            switch ($command) {
                'touch' { $result = [BitmapVmFixture]::AccessAndWrite() }
                'remap' { [BitmapVmFixture]::Remap(); $result = 'remapped' }
                'stop' { break }
                default { throw "Unknown fixture command: $command" }
            }
            if ($command -eq 'stop') { break }
            Set-Content -LiteralPath $resultPath -Value $result
        }
        Start-Sleep -Milliseconds 20
    }
} finally {
    [BitmapVmFixture]::Release()
}
