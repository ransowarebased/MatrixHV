#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$OutputDirectory, [int]$Seed=341049)
$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;
public static class MatrixVmFuzz {
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate long Code();
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint allocation, uint protection);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool VirtualLock(IntPtr address, UIntPtr size);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
    [DllImport("kernel32.dll", SetLastError=true)] static extern UIntPtr SetThreadAffinityMask(IntPtr thread, UIntPtr mask);
    public static IntPtr buffer;
    public static string[] descriptions;
    public static long[] expected;
    static Code first;
    static Code[] readers;
    public static void Initialize(int seed) {
        buffer=VirtualAlloc(IntPtr.Zero,(UIntPtr)8192,0x3000,0x40);
        if(buffer==IntPtr.Zero) throw new Win32Exception();
        byte[] image=new byte[8192];
        image[0]=0xb8; image[1]=17; image[5]=0xc3;
        Random random=new Random(seed);
        for(int index=3000;index<8192;++index) image[index]=(byte)random.Next(256);
        readers=new Code[96]; expected=new long[96]; descriptions=new string[96];
        string[] kinds={"movzx8","movzx16","movsx8","movsx16","movsxd32","mov32","mov64","mov8","mov16","add32","xor32","cmp32"};
        for(int index=0;index<readers.Length;++index) {
            int kind=index%kinds.Length;
            int width=kind==0||kind==2||kind==7?1:kind==1||kind==3||kind==8?2:kind==6?8:4;
            int alignment=index/kinds.Length;
            int dataOffset=alignment==0?3008:alignment==1?3009:alignment==2?4096-width:alignment==3?4095:alignment==4?0:alignment==5?1:alignment==6?3072:3081;
            int codeOffset=128+index*24;
            List<byte> code=new List<byte>();
            // Partial-register loads start from zero; all other instructions overwrite RAX.
            code.AddRange(new byte[]{0x31,0xc0});
            bool extended=(index&1)!=0 && kind<7;
            if(kind==8) code.Add(0x66);
            bool wide=kind==2||kind==3||kind==4||kind==6;
            if(wide||extended) code.Add((byte)(0x40|(wide?8:0)|(extended?4:0)));
            if(kind<=3) code.AddRange(new byte[]{0x0f,(byte)(kind==0?0xb6:kind==1?0xb7:kind==2?0xbe:0xbf)});
            else code.Add((byte)(kind==4?0x63:kind==7?0x8a:kind==9?0x03:kind==10?0x33:kind==11?0x3b:0x8b));
            code.Add((byte)(extended?0x15:0x05)); // R10 or RAX, RIP-relative memory.
            code.AddRange(BitConverter.GetBytes(dataOffset-(codeOffset+code.Count+4)));
            if(extended) code.AddRange(new byte[]{0x4c,0x89,0xd0});
            if(kind==11) code.AddRange(new byte[]{0x0f,0x94,0xc0});
            code.Add(0xc3);
            if(code.Count>24) throw new InvalidOperationException("Reader slot overflow");
            code.CopyTo(image,codeOffset);
            ulong value=0;
            for(int part=0;part<width;++part) value|=(ulong)image[dataOffset+part]<<(part*8);
            expected[index]=kind==2?(sbyte)value:kind==3?(short)value:kind==4?(int)value:kind==11?(value==0?1:0):unchecked((long)value);
            descriptions[index]=kinds[kind]+"/"+(extended?"r10":"rax")+"/offset="+dataOffset;
        }
        Marshal.Copy(image,0,buffer,image.Length);
        if(!VirtualLock(buffer,(UIntPtr)8192)) throw new Win32Exception();
        first=(Code)Marshal.GetDelegateForFunctionPointer(buffer,typeof(Code));
        for(int index=0;index<readers.Length;++index) readers[index]=(Code)Marshal.GetDelegateForFunctionPointer(IntPtr.Add(buffer,128+index*24),typeof(Code));
    }
    public static long Run(int seed,int iterations,int workers,int patchedValue,int startCase,int caseCount) {
        Exception failure=null;
        long completed=0;
        Thread[] threads=new Thread[workers];
        for(int worker=0;worker<workers;++worker) {
            int workerId=worker;
            threads[worker]=new Thread(()=>{
                UIntPtr previous=SetThreadAffinityMask(GetCurrentThread(),(UIntPtr)(1UL<<(workerId%Environment.ProcessorCount)));
                try {
                    if(previous==UIntPtr.Zero) throw new Win32Exception();
                    Random random=new Random(seed^((workerId+1)*7919));
                    for(int iteration=0;iteration<iterations;++iteration) {
                        int index=startCase+(iteration<caseCount?iteration:random.Next(caseCount));
                        long actual=readers[index]();
                        if(actual!=expected[index]) throw new InvalidOperationException("seed="+seed+" worker="+workerId+" iteration="+iteration+" case="+index+" "+descriptions[index]+" expected="+expected[index]+" actual="+actual);
                        long executed=first();
                        if(executed!=patchedValue) throw new InvalidOperationException("Patched execution changed: expected="+patchedValue+" actual="+executed+" seed="+seed+" iteration="+iteration);
                        Interlocked.Increment(ref completed);
                    }
                } catch(Exception error) { Interlocked.CompareExchange(ref failure,error,null); }
                finally { if(previous!=UIntPtr.Zero) SetThreadAffinityMask(GetCurrentThread(),previous); }
            });
            threads[worker].IsBackground=true;
            threads[worker].Start();
        }
        DateTime deadline=DateTime.UtcNow.AddSeconds(90);
        foreach(Thread thread in threads) {
            int remaining=(int)Math.Max(1,(deadline-DateTime.UtcNow).TotalMilliseconds);
            if(!thread.Join(remaining)) throw new TimeoutException("Fuzz worker failed to make progress");
        }
        if(failure!=null) throw failure;
        return completed;
    }
}
'@
[MatrixVmFuzz]::Initialize($Seed)
@{pid=$PID;first=('0x{0:x}' -f [MatrixVmFuzz]::buffer.ToInt64());processors=[Environment]::ProcessorCount;cases=[MatrixVmFuzz]::descriptions;seed=$Seed} | ConvertTo-Json -Depth 5 | Set-Content ($OutputDirectory+'\fixture.json')
while($true) {
    $path=$OutputDirectory+'\command.json'
    if(-not(Test-Path -LiteralPath $path)){Start-Sleep -Milliseconds 10;continue}
    $command=Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
    Remove-Item -LiteralPath $path
    if($command.operation -eq 'stop'){break}
    try {
        $count=[MatrixVmFuzz]::Run($command.seed,$command.iterations,$command.workers,$command.expected,$command.start_case,$command.case_count)
        $result=@{id=$command.id;completed=$count}
    } catch { $result=@{id=$command.id;error=$_.Exception.ToString()} }
    $result | ConvertTo-Json -Depth 6 | Set-Content ($OutputDirectory+'\result.tmp')
    Move-Item -LiteralPath ($OutputDirectory+'\result.tmp') -Destination ($OutputDirectory+'\result.json') -Force
}
