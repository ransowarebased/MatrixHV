param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class ProfileVmFixture {
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    delegate uint Transport(IntPtr packet, UIntPtr length, IntPtr status);
    [StructLayout(LayoutKind.Explicit, Size=1232)]
    struct Context {
        [FieldOffset(48)] public uint contextFlags;
        [FieldOffset(96)] public ulong dr3;
        [FieldOffset(112)] public ulong dr7;
    }
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint allocation, uint protection);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool VirtualFree(IntPtr address, UIntPtr size, uint operation);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr CreateThread(IntPtr attributes, UIntPtr stackSize, IntPtr start, IntPtr parameter, uint flags, out uint threadId);
    [DllImport("kernel32.dll", SetLastError=true)] static extern UIntPtr SetThreadAffinityMask(IntPtr thread, UIntPtr mask);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetThreadContext(IntPtr thread, IntPtr context);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetThreadContext(IntPtr thread, IntPtr context);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateThread(IntPtr thread, uint exitCode);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    static IntPtr code;
    static Transport transport;
    public static ulong callback { get { return (ulong)code.ToInt64() + 768; } }
    static void WriteCode(int offset, string hex) {
        byte[] bytes = new byte[hex.Length / 2];
        for (int index=0; index<bytes.Length; ++index) bytes[index]=Convert.ToByte(hex.Substring(index*2,2),16);
        Marshal.Copy(bytes,0,new IntPtr(code.ToInt64()+offset),bytes.Length);
    }
    public static void Initialize() {
        code=VirtualAlloc(IntPtr.Zero,(UIntPtr)4096,0x3000,0x40);
        if(code==IntPtr.Zero) throw new Win32Exception();
        // Windows x64: preserve RBX, submit pointer in RDX and size in R8,
        // and retain the transport status before returning the EAX signature.
        WriteCode(0,"534d89c34989d04889cab84d56484db9010000000fa24989135bc3");
        WriteCode(256,"5356574889ce8b7e088b068b4e040fa289460c895e10894e14895618ffcf75e95f5e5b33c0c3");
        WriteCode(512,"5356574889ce8b7e084c8bd6b8ff0f00000f0589460cffcf75ef5f5e5b33c0c3");
        // The routed call carries its native index in XMM4 and return PC in
        // RAX. Other syscalls use the owned XMM5 bypass before SWAPGS.
        WriteCode(768,"660f7ee181f9ff0f0000750e41ff42104889c1b878563412ffe1505248ba371337133713371366480f6eea5a660f7ee00f05c3");
        transport=(Transport)Marshal.GetDelegateForFunctionPointer(code,typeof(Transport));
    }
    public static byte[] Invoke(byte[] packet) {
        IntPtr buffer=Marshal.AllocHGlobal(packet.Length);
        IntPtr status=Marshal.AllocHGlobal(8);
        try {
            Marshal.Copy(packet,0,buffer,packet.Length);
            Marshal.WriteInt64(status,-1);
            uint signature=transport(buffer,(UIntPtr)packet.Length,status);
            if(signature!=0x4d454d31) throw new InvalidOperationException("Memory transport signature mismatch");
            Marshal.Copy(buffer,packet,0,packet.Length);
            uint transportStatus=(uint)Marshal.ReadInt64(status);
            if(transportStatus!=0) BitConverter.GetBytes(transportStatus).CopyTo(packet,40);
            return packet;
        } finally { Marshal.FreeHGlobal(status); Marshal.FreeHGlobal(buffer); }
    }
    public static uint[][] Sample(bool syscall, bool gated, int iterations) {
        uint[][] outputs=new uint[Environment.ProcessorCount][];
        for(int cpu=0;cpu<outputs.Length;++cpu) {
            IntPtr data=Marshal.AllocHGlobal(32);
            IntPtr allocation=Marshal.AllocHGlobal(1248);
            IntPtr context=new IntPtr((allocation.ToInt64()+15)&~15L);
            IntPtr thread=IntPtr.Zero;
            bool finished=false;
            try {
                Marshal.Copy(new byte[32],0,data,32);
                Marshal.WriteInt32(data,7); Marshal.WriteInt32(data,8,iterations);
                uint threadId;
                thread=CreateThread(IntPtr.Zero,UIntPtr.Zero,new IntPtr(code.ToInt64()+(syscall?512:256)),data,4,out threadId);
                if(thread==IntPtr.Zero || SetThreadAffinityMask(thread,(UIntPtr)(1UL<<cpu))==UIntPtr.Zero) throw new Win32Exception();
                Marshal.StructureToPtr(new Context { contextFlags=0x100010 },context,false);
                if(!GetThreadContext(thread,context)) throw new Win32Exception();
                Context state=(Context)Marshal.PtrToStructure(context,typeof(Context));
                state.dr3=gated?0x7ffe0ff0UL:0;
                state.dr7=(state.dr7&~0xffffffffffff00ffUL)|0x400UL|(gated?0x40UL:0);
                Marshal.StructureToPtr(state,context,false);
                if(!SetThreadContext(thread,context) || ResumeThread(thread)==uint.MaxValue) throw new Win32Exception();
                if(WaitForSingleObject(thread,15000)!=0) throw new InvalidOperationException("Native profile worker did not finish");
                finished=true;
                outputs[cpu]=new uint[4];
                for(int index=0;index<4;++index) outputs[cpu][index]=(uint)Marshal.ReadInt32(data,12+index*4);
            } finally {
                if(thread!=IntPtr.Zero && !finished) {
                    if(!TerminateThread(thread,1) || WaitForSingleObject(thread,5000)!=0)
                        Environment.FailFast("Cannot retire native profile worker before freeing its memory");
                }
                if(thread!=IntPtr.Zero) CloseHandle(thread);
                Marshal.FreeHGlobal(allocation); Marshal.FreeHGlobal(data);
            }
        }
        return outputs;
    }
    public static void Release() { if(code!=IntPtr.Zero) { VirtualFree(code,UIntPtr.Zero,0x8000); code=IntPtr.Zero; } }
}
'@
[ProfileVmFixture]::Initialize()
try {
    $fixturePath=Join-Path $OutputDirectory 'fixture.json'
    @{pid=$PID;processors=[Environment]::ProcessorCount;callback=('0x{0:x}' -f [ProfileVmFixture]::callback)} | ConvertTo-Json | Set-Content -LiteralPath ($fixturePath+'.tmp')
    Move-Item -LiteralPath ($fixturePath+'.tmp') -Destination $fixturePath -Force
    $commandPath=Join-Path $OutputDirectory 'command.json'
    $resultPath=Join-Path $OutputDirectory 'result.json'
    while($true) {
        if(Test-Path -LiteralPath $commandPath) {
            $request=Get-Content -Raw -LiteralPath $commandPath | ConvertFrom-Json
            Remove-Item -LiteralPath $commandPath
            if($request.operation -eq 'stop') { break }
            try {
                $value=switch($request.operation) {
                    'packet' { [Convert]::ToBase64String([ProfileVmFixture]::Invoke([Convert]::FromBase64String($request.packet))) }
                    'cpuid' { ,([ProfileVmFixture]::Sample($false,$request.gated,$request.iterations)) }
                    'syscall' { ,([ProfileVmFixture]::Sample($true,$request.gated,$request.iterations)) }
                    default { throw 'Unknown profile fixture command' }
                }
                @{id=$request.id;value=$value} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath ($resultPath+'.tmp')
            } catch {
                @{id=$request.id;error=$_.Exception.ToString()} | ConvertTo-Json | Set-Content -LiteralPath ($resultPath+'.tmp')
            }
            Move-Item -LiteralPath ($resultPath+'.tmp') -Destination $resultPath -Force
        }
        Start-Sleep -Milliseconds 10
    }
} finally { [ProfileVmFixture]::Release() }
