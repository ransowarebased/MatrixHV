#requires -Version 5.1
param([Parameter(Mandatory = $true)][string]$PackagePath)

$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

public static class RuntimeUpdateVmTest {
    const string variableName = "MatrixHVControl";
    const string variableGuid = "{a830e824-19a4-42c4-9178-81ee63c135cc}";
    const int updateOffset = 616;
    static byte[] initialStatus;
    static uint processorCount;
    static ulong expectedMask;
    static ulong transaction;

    [StructLayout(LayoutKind.Sequential)]
    struct Luid { public uint lowPart; public int highPart; }
    [StructLayout(LayoutKind.Sequential)]
    struct Privileges { public uint privilegeCount; public Luid luid; public uint attributes; }
    [StructLayout(LayoutKind.Sequential)]
    struct GroupAffinity {
        public ulong mask;
        public ushort group, reserved0, reserved1, reserved2;
    }
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool LookupPrivilegeValue(string systemName, string name, out Luid luid);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref Privileges privileges,
                                            uint length, IntPtr previous, IntPtr returnedLength);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetThreadGroupAffinity(IntPtr thread, ref GroupAffinity affinity, out GroupAffinity previous);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern uint GetFirmwareEnvironmentVariableEx(string name, string guid, byte[] buffer, uint length, out uint attributes);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool SetFirmwareEnvironmentVariableEx(string name, string guid, byte[] buffer, uint length, uint attributes);

    static void Require(bool condition, string message) {
        if (!condition) throw new InvalidOperationException(message);
    }
    static ulong Quad(byte[] bytes, int offset) { return BitConverter.ToUInt64(bytes, offset); }
    static uint Word(byte[] bytes, int offset) { return BitConverter.ToUInt32(bytes, offset); }
    static void Put(byte[] bytes, int offset, byte[] value) { Array.Copy(value, 0, bytes, offset, value.Length); }
    static byte[] Status() {
        byte[] bytes = new byte[1056];
        uint attributes;
        uint length = GetFirmwareEnvironmentVariableEx(variableName, variableGuid, bytes, (uint)bytes.Length, out attributes);
        Require(length == bytes.Length && attributes == 7 && Word(bytes, 8) == 4, "Runtime bridge version or size mismatch");
        Require(Quad(bytes, 48) == 0 && Quad(bytes, 56) == 1 && Quad(bytes, 64) == 1 && Quad(bytes, 72) == 0, "Resident host is not ready");
        return bytes;
    }
    static void EnablePrivilege() {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), 0x28, out token)) throw new Win32Exception();
        try {
            Luid luid;
            if (!LookupPrivilegeValue(null, "SeSystemEnvironmentPrivilege", out luid)) throw new Win32Exception();
            Privileges privileges = new Privileges { privilegeCount = 1, luid = luid, attributes = 2 };
            if (!AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero) || Marshal.GetLastWin32Error() == 1300)
                throw new Win32Exception();
        } finally { CloseHandle(token); }
    }
    static byte[] Send(uint cpu, byte[] request, uint expectedError) {
        GroupAffinity affinity = new GroupAffinity { mask = 1UL << (int)cpu };
        GroupAffinity previous;
        if (!SetThreadGroupAffinity(GetCurrentThread(), ref affinity, out previous)) throw new Win32Exception();
        try {
            byte[] before = Status();
            Require(Word(before, 16) == Word(initialStatus, 88 + (int)cpu * 4), "CPU route changed");
            bool success = SetFirmwareEnvironmentVariableEx(variableName, variableGuid, request, (uint)request.Length, 7);
            int nativeError = Marshal.GetLastWin32Error();
            byte[] after = Status();
            if (expectedError == 0) Require(success, "Firmware request failed: " + nativeError);
            if (request.Length >= 48) {
                Require(Word(after, updateOffset + 12) == expectedError, "Unexpected runtime transaction error");
                if (expectedError != 0) Require(!success, "Rejected request unexpectedly succeeded");
            }
            return after;
        } finally {
            GroupAffinity ignored;
            SetThreadGroupAffinity(GetCurrentThread(), ref previous, out ignored);
        }
    }
    static byte[] Update(uint cpu, uint operation, byte[] payload = null, uint offset = 0, uint total = 0, uint expectedError = 0) {
        if (payload == null) payload = new byte[0];
        byte[] request = new byte[48 + payload.Length];
        Put(request, 0, BitConverter.GetBytes(0x4d41545249585550UL));
        Put(request, 8, BitConverter.GetBytes(1U));
        Put(request, 12, BitConverter.GetBytes(operation));
        Put(request, 16, BitConverter.GetBytes(transaction));
        Put(request, 24, BitConverter.GetBytes(Word(initialStatus, 88 + (int)cpu * 4)));
        Put(request, 32, BitConverter.GetBytes(offset));
        Put(request, 36, BitConverter.GetBytes((uint)payload.Length));
        Put(request, 40, BitConverter.GetBytes(total));
        Array.Copy(payload, 0, request, 48, payload.Length);
        return Send(cpu, request, expectedError);
    }
    static void Control(uint cpu, uint operation) {
        byte[] request = new byte[32];
        Put(request, 0, BitConverter.GetBytes(0x4d41545249584354UL));
        Put(request, 8, BitConverter.GetBytes(4U));
        Put(request, 12, BitConverter.GetBytes(operation));
        Put(request, 16, BitConverter.GetBytes(transaction));
        Put(request, 24, BitConverter.GetBytes(Word(initialStatus, 88 + (int)cpu * 4)));
        Send(cpu, request, 0);
    }
    static void Active() {
        byte[] status = Status();
        Require(Quad(status, 32) == expectedMask && Quad(status, 40) == 0, "CPU activation is incomplete");
    }
    static void Prepare(byte[] package) {
        ++transaction;
        Update(0, 4, total:(uint)package.Length);
        for (int offset = 0; offset < package.Length; offset += 1024) {
            byte[] block = new byte[Math.Min(1024, package.Length - offset)];
            Array.Copy(package, offset, block, 0, block.Length);
            Update(0, 5, block, (uint)offset);
        }
        Update(0, 6);
        for (uint cpu = 0; cpu < processorCount; ++cpu) Update(cpu, 7);
        Update(0, 8);
    }
    static void CompleteRecovery(ulong originalVersion) {
        byte[] status = Status();
        for (uint cpu = 0; cpu < processorCount; ++cpu) {
            if ((Quad(status, 40) & (1UL << (int)cpu)) != 0) Control(cpu, 1);
            Update(cpu, 10);
            Control(cpu, 3);
        }
        Update(0, 14);
        Active();
        status = Status();
        Require(Word(status, updateOffset + 8) == 7 && Quad(status, updateOffset + 48) == expectedMask
                && Quad(status, updateOffset + 24) == originalVersion, "Old core recovery was not verified");
    }
    public static string Run(string packagePath) {
        EnablePrivilege();
        string results = "";
        using (Mutex mutex = new Mutex(false, @"Global\MatrixHVRuntimeControl")) {
            Require(mutex.WaitOne(30000), "Runtime control mutex is busy");
            try {
                initialStatus = Status();
                processorCount = Word(initialStatus, 20);
                expectedMask = Quad(initialStatus, 24);
                Require(processorCount >= 2 && processorCount <= 64 && expectedMask == (processorCount == 64 ? ulong.MaxValue : (1UL << (int)processorCount) - 1),
                        "This VM test requires contiguous routes in processor group zero");
                Active();
                byte[] package = File.ReadAllBytes(packagePath);
                byte[] status = Status();
                ulong originalVersion = Word(status, updateOffset + 8) == 5 ? Quad(status, updateOffset + 32) : Quad(status, updateOffset + 24);
                Require(Quad(package, 32) > originalVersion, "VM recovery package must advance the current version");
                transaction = (ulong)DateTime.UtcNow.Ticks;
                ++transaction;
                Update(0, 4, total:(uint)package.Length);
                byte[] block = new byte[1024];
                Array.Copy(package, 1024, block, 0, block.Length);
                Update(0, 5, block, 1024);
                status = Update(0, 5, block, 1024);
                Require(Word(status, updateOffset + 20) == 1024, "Duplicate upload increased its byte count");
                block[0] ^= 1;
                Update(0, 5, block, 1024, expectedError:11);
                Update(0, 12);
                Active();
                results += "PASS cancellation, out-of-order duplicate upload, conflicting block rejection\n";

                ++transaction;
                Update(0, 4, total:(uint)package.Length);
                byte[] tampered = (byte[])package.Clone();
                tampered[tampered.Length - 1] ^= 1;
                for (int offset = 0; offset < tampered.Length; offset += 1024) {
                    byte[] chunk = new byte[Math.Min(1024, tampered.Length - offset)];
                    Array.Copy(tampered, offset, chunk, 0, chunk.Length);
                    Update(0, 5, chunk, (uint)offset);
                }
                Update(0, 6, expectedError:4);
                Update(0, 12);
                Active();
                results += "PASS runtime signature rejection before CPU deactivation\n";

                Prepare(package);
                Control(0, 2);
                status = Status();
                Require(Quad(status, 40) == 1 && Quad(status, 32) == (expectedMask & ~1UL), "Partial stop masks are wrong");
                Update(0, 13);
                CompleteRecovery(originalVersion);
                results += "PASS recovery after partial CPU deactivation\n";

                Prepare(package);
                for (uint cpu = 0; cpu < processorCount; ++cpu) Control(cpu, 2);
                Update(0, 9);
                Control(0, 1);
                Update(0, 13, expectedError:17);
                Require(Quad(Status(), updateOffset + 56) == 3, "Partial activation released a referenced bank");
                Control(0, 2);
                Update(0, 13);
                CompleteRecovery(originalVersion);
                results += "PASS recovery during partial activation and bank retention\n";
                return results;
            } finally { mutex.ReleaseMutex(); }
        }
    }
}
'@
[RuntimeUpdateVmTest]::Run($PackagePath)
