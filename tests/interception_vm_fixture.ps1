#requires -Version 5.1
param(
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [string]$SharedName,
    [string]$ViewAddress = '0',
    [int]$StressMiB = 0
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;

public static class InterceptionVmFixture {
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate int Code();
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr CreateFileMapping(IntPtr file, IntPtr attributes, uint protection,
                                          uint sizeHigh, uint sizeLow, string name);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool VirtualLock(IntPtr address, UIntPtr size);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenFileMapping(uint access, bool inheritHandle, string name);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr MapViewOfFileEx(IntPtr mapping, uint access, uint offsetHigh,
                                        uint offsetLow, UIntPtr bytes, IntPtr address);
    [DllImport("kernel32.dll")] static extern bool UnmapViewOfFile(IntPtr address);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint allocation, uint protection);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool VirtualFree(IntPtr address, UIntPtr size, uint operation);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetProcessWorkingSetSize(IntPtr process, UIntPtr minimum, UIntPtr maximum);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern UIntPtr SetThreadAffinityMask(IntPtr thread, UIntPtr mask);
    public static IntPtr buffer;
    public static IntPtr stressBuffer;
    public static void InitializeStress(int mib) {
        if (mib == 0) return;
        long size = (long)mib * 1024 * 1024;
        if (!SetProcessWorkingSetSize(GetCurrentProcess(), (UIntPtr)(size + 64 * 1024 * 1024),
                                     (UIntPtr)(size + 128 * 1024 * 1024))) throw new Win32Exception();
        stressBuffer = VirtualAlloc(IntPtr.Zero, (UIntPtr)size, 0x3000, 0x40);
        if (stressBuffer == IntPtr.Zero) throw new Win32Exception();
        byte[] code = { 0xb8, 17, 0, 0, 0, 0xc3 };
        for (long offset = 0; offset < size; offset += 4096)
            Marshal.Copy(code, 0, new IntPtr(stressBuffer.ToInt64() + offset), code.Length);
        if (!VirtualLock(stressBuffer, (UIntPtr)size)) throw new Win32Exception();
    }
    public static int[] ExecuteAddress(long address) {
        Code target = (Code)Marshal.GetDelegateForFunctionPointer(new IntPtr(address), typeof(Code));
        int[] values = new int[Environment.ProcessorCount];
        for (int cpu = 0; cpu < values.Length; ++cpu) {
            UIntPtr previous = SetThreadAffinityMask(GetCurrentThread(), (UIntPtr)(1UL << cpu));
            if (previous == UIntPtr.Zero) throw new Win32Exception();
            try {
                for (int iteration = 0; iteration < 32; ++iteration) {
                    int value = target();
                    if (iteration != 0 && value != values[cpu]) throw new InvalidOperationException("Unstable stress execution");
                    values[cpu] = value;
                }
            } finally { SetThreadAffinityMask(GetCurrentThread(), previous); }
        }
        return values;
    }
    static IntPtr mapping;
    static Code first, second, mixed, cooperative;
    static Code[] targets;
    public static void Initialize(string sharedName, long desiredAddress, bool owner) {
        mapping = owner ? CreateFileMapping(new IntPtr(-1), IntPtr.Zero, 0x40, 0, 12288, sharedName)
                        : OpenFileMapping(0x26, false, sharedName);
        if (mapping == IntPtr.Zero) throw new Win32Exception();
        buffer = MapViewOfFileEx(mapping, 0x26, 0, 0, (UIntPtr)12288, new IntPtr(desiredAddress));
        if (buffer == IntPtr.Zero) throw new Win32Exception();
        if (desiredAddress != 0 && buffer.ToInt64() != desiredAddress)
            throw new InvalidOperationException("Shared view address changed");
        byte[] bytes = new byte[12288];
        bytes[0] = 0xb8; bytes[1] = 17; bytes[5] = 0xc3;
        bytes[4096] = 0xb8; bytes[4097] = 34; bytes[4101] = 0xc3;
        for (int index = 1; index < 4; ++index) {
            bytes[index * 16] = 0xb8; bytes[index * 16 + 1] = (byte)(17 + index);
            bytes[index * 16 + 5] = 0xc3;
            bytes[4096 + index * 16] = 0xb8; bytes[4097 + index * 16] = (byte)(34 + index);
            bytes[4101 + index * 16] = 0xc3;
        }
        // The third function reads original data from its own executable page.
        byte[] reader = { 0x0f, 0xb6, 0x05, 0xf9, 0, 0, 0, 0xc3 };
        Array.Copy(reader, 0, bytes, 512, reader.Length);
        bytes[768] = 91;
        // Switch to the original data slot, read the first byte, and switch back
        // from an unhooked page. R8 retains the observed byte across VMFUNC.
        byte[] vmfunc = { 0x49, 0xbb };
        Array.Copy(vmfunc, 0, bytes, 8192, vmfunc.Length);
        Array.Copy(BitConverter.GetBytes(buffer.ToInt64()), 0, bytes, 8194, 8);
        byte[] body = { 0x31, 0xc0, 0xb9, 1, 0, 0, 0, 0x0f, 0x01, 0xd4,
                        0x45, 0x0f, 0xb6, 0x03, 0x31, 0xc0, 0x31, 0xc9,
                        0x0f, 0x01, 0xd4, 0x44, 0x89, 0xc0, 0xc3 };
        Array.Copy(body, 0, bytes, 8202, body.Length);
        if (owner) Marshal.Copy(bytes, 0, buffer, bytes.Length);
        if (!VirtualLock(buffer, (UIntPtr)12288)) throw new Win32Exception();
        first = (Code)Marshal.GetDelegateForFunctionPointer(buffer, typeof(Code));
        second = (Code)Marshal.GetDelegateForFunctionPointer(IntPtr.Add(buffer, 4096), typeof(Code));
        mixed = (Code)Marshal.GetDelegateForFunctionPointer(IntPtr.Add(buffer, 512), typeof(Code));
        cooperative = (Code)Marshal.GetDelegateForFunctionPointer(IntPtr.Add(buffer, 8192), typeof(Code));
        targets = new Code[4];
        for (int index = 0; index < targets.Length; ++index)
            targets[index] = (Code)Marshal.GetDelegateForFunctionPointer(IntPtr.Add(buffer, index * 16), typeof(Code));
    }
    public static int Execute(int cpu, int function) {
        UIntPtr previous = SetThreadAffinityMask(GetCurrentThread(), (UIntPtr)(1UL << cpu));
        if (previous == UIntPtr.Zero) throw new Win32Exception();
        try { return (function == 0 ? first : function == 1 ? second : function == 2 ? mixed : cooperative)(); }
        finally { SetThreadAffinityMask(GetCurrentThread(), previous); }
    }
    public static string Read() {
        byte[] bytes = new byte[8];
        Marshal.Copy(buffer, bytes, 0, bytes.Length);
        return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
    }
    public static int[] ExecuteAll(int function, int iterations) {
        int[] values = new int[Environment.ProcessorCount];
        for (int cpu = 0; cpu < values.Length; ++cpu) {
            values[cpu] = Execute(cpu, function);
            for (int iteration = 1; iteration < iterations; ++iteration) {
                int value = Execute(cpu, function);
                if (value != values[cpu]) throw new InvalidOperationException("Unstable execution result");
            }
        }
        return values;
    }
    public static int[] Concurrent(int function, int iterations, bool writing) {
        int[] values = new int[Environment.ProcessorCount];
        Thread[] threads = new Thread[values.Length];
        Exception failure = null;
        for (int cpu = 0; cpu < threads.Length; ++cpu) {
            int processorId = cpu;
            threads[cpu] = new Thread(() => {
                try {
                    for (int iteration = 0; iteration < iterations; ++iteration) {
                        if (writing) Write(128 + processorId, (byte)iteration);
                        int value = Execute(processorId, function);
                        if (iteration != 0 && values[processorId] != value)
                            throw new InvalidOperationException("Concurrent execution changed");
                        values[processorId] = value;
                    }
                } catch (Exception error) { Interlocked.CompareExchange(ref failure, error, null); }
            });
            threads[cpu].Start();
        }
        foreach (Thread thread in threads) thread.Join();
        if (failure != null) throw failure;
        return values;
    }
    public static int[] ExecuteTargets() {
        int[] values = new int[Environment.ProcessorCount * 4];
        for (int cpu = 0; cpu < Environment.ProcessorCount; ++cpu) {
            UIntPtr previous = SetThreadAffinityMask(GetCurrentThread(), (UIntPtr)(1UL << cpu));
            if (previous == UIntPtr.Zero) throw new Win32Exception();
            try {
                for (int index = 0; index < targets.Length; ++index) values[cpu * 4 + index] = targets[index]();
            } finally { SetThreadAffinityMask(GetCurrentThread(), previous); }
        }
        return values;
    }
    public static void Write(int offset, byte value) { Marshal.WriteByte(buffer, offset, value); }
    public static void Release() {
        if (stressBuffer != IntPtr.Zero) VirtualFree(stressBuffer, UIntPtr.Zero, 0x8000);
        if (buffer != IntPtr.Zero) UnmapViewOfFile(buffer);
        if (mapping != IntPtr.Zero) CloseHandle(mapping);
    }
}
'@

$owner = -not $SharedName
if ($owner) { $SharedName = "Local\MatrixHVInterception_$PID" }
[InterceptionVmFixture]::Initialize($SharedName, [Convert]::ToInt64($ViewAddress.Replace('0x', ''), 16), $owner)
try {
    [InterceptionVmFixture]::InitializeStress($StressMiB)
    [ordered]@{
        pid = $PID
        first = '0x{0:x}' -f [InterceptionVmFixture]::buffer.ToInt64()
        second = '0x{0:x}' -f ([InterceptionVmFixture]::buffer.ToInt64() + 4096)
        mixed = '0x{0:x}' -f ([InterceptionVmFixture]::buffer.ToInt64() + 512)
        processors = [Environment]::ProcessorCount
        sharedName = $SharedName
        stressBuffer = '0x{0:x}' -f [InterceptionVmFixture]::stressBuffer.ToInt64()
        stressBytes = [long]$StressMiB * 1024 * 1024
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDirectory 'fixture.json')
    $commandPath = Join-Path $OutputDirectory 'command.json'
    $resultPath = Join-Path $OutputDirectory 'result.json'
    while ($true) {
        if (Test-Path -LiteralPath $commandPath) {
            $request = Get-Content -LiteralPath $commandPath -Raw | ConvertFrom-Json
            Remove-Item -LiteralPath $commandPath
            if ($request.operation -eq 'stop') { break }
            try {
                $value = switch ($request.operation) {
                    'execute' { [InterceptionVmFixture]::Execute($request.cpu, $request.function) }
                    'execute-all' { ,([InterceptionVmFixture]::ExecuteAll($request.function, $request.iterations)) }
                    'concurrent' { ,([InterceptionVmFixture]::Concurrent($request.function, $request.iterations, $request.writing)) }
                    'debug-all' { ,([InterceptionVmFixture]::ExecuteTargets()) }
                    'execute-address' { ,([InterceptionVmFixture]::ExecuteAddress([Convert]::ToInt64($request.address.Replace('0x', ''), 16))) }
                    'stress-cycle' {
                        $neo = [string]$request.neo
                        $installed = & $neo hook install $request.cr3 ('0x{0:x}' -f [InterceptionVmFixture]::buffer.ToInt64()) b833000000 --no-lease
                        if ($LASTEXITCODE -ne 0) { throw "Anchor installation failed: $installed" }
                        $token = [regex]::Match(($installed -join ' '), '\btoken=(\d+)').Groups[1].Value
                        try {
                            $completed = 0
                            foreach ($address in $request.addresses) {
                                $added = & $neo hook add $token $address b844000000
                                if ($LASTEXITCODE -ne 0) { throw "Stress add failed after ${completed} regions: $added" }
                                $patchId = [regex]::Match(($added -join ' '), '\bid=(\d+)').Groups[1].Value
                                $target = [Convert]::ToInt64($address.Replace('0x', ''), 16)
                                if (@([InterceptionVmFixture]::ExecuteAddress($target) | Where-Object { $_ -ne 68 }).Count) { throw 'Stress patch did not execute on every CPU' }
                                $removed = & $neo hook remove $token $patchId
                                if ($LASTEXITCODE -ne 0) { throw "Stress removal failed: $removed" }
                                if (@([InterceptionVmFixture]::ExecuteAddress($target) | Where-Object { $_ -ne 17 }).Count) { throw 'Removed stress patch is still executable' }
                                if (@([InterceptionVmFixture]::ExecuteAll(0, 32) | Where-Object { $_ -ne 51 }).Count) { throw 'Neighboring anchor patch changed' }
                                ++$completed
                            }
                            @{ completed = $completed; token = $token; processors = [Environment]::ProcessorCount }
                        } catch {
                            & $neo hook release $token | Out-Null
                            throw
                        }
                    }
                    'read' { [InterceptionVmFixture]::Read() }
                    'write' { [InterceptionVmFixture]::Write($request.offset, $request.value); 'written' }
                    default { throw "Unknown fixture command: $($request.operation)" }
                }
                @{ id = $request.id; value = $value } | ConvertTo-Json | Set-Content -LiteralPath ($resultPath + '.tmp')
            } catch {
                @{ id = $request.id; error = $_.Exception.ToString() } | ConvertTo-Json | Set-Content -LiteralPath ($resultPath + '.tmp')
            }
            Move-Item -LiteralPath ($resultPath + '.tmp') -Destination $resultPath -Force
        }
        Start-Sleep -Milliseconds 10
    }
} finally {
    [InterceptionVmFixture]::Release()
}
