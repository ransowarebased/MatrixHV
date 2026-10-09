"""Exercise process-scoped CPUID and syscall profiles on every Windows vCPU."""
import argparse
import base64
import json
from pathlib import Path
import random
import struct
import subprocess
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--neo', type=Path, required=True)
    parser.add_argument('--remote', required=True)
    parser.add_argument('--guest-neo', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.relative_to(project / 'builds')
    output.mkdir(parents=True, exist_ok=True)
    guest = r'C:\MatrixHVProfiles-' + uuid.uuid4().hex[:12]
    peers = [guest, guest + r'\peer']
    sequence = 0
    token = None
    fixtures = []
    results = {'status': 'RUNNING', 'checks': [], 'cleanup_errors': [], 'guest_directory': guest}
    log = (output / 'commands.log').open('w', encoding='utf-8', buffering=1)

    def save():
        (output / 'results.json').write_text(json.dumps(results, indent=2))

    def remote(*operands):
        command = [str(args.neo.resolve()), '--remote', args.remote, '--timeout', '45', 'exec', *map(str, operands)]
        completed = subprocess.run(command, capture_output=True, timeout=55)
        text = completed.stdout.decode(errors='replace') + completed.stderr.decode(errors='replace')
        log.write(' '.join(map(str, operands)) + f'\nexit={completed.returncode}\n' + text + '\n')
        assert completed.returncode == 0, text
        return text

    def script(body):
        encoded = base64.b64encode(("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';" + body).encode('utf-16le')).decode()
        return remote('powershell.exe', '-NoProfile', '-EncodedCommand', encoded)

    def command(operation, directory=guest, **parameters):
        nonlocal sequence
        sequence += 1
        payload = json.dumps(dict(id=sequence, operation=operation, **parameters))
        text = script(f"Remove-Item -LiteralPath '{directory}\\result.json' -ErrorAction SilentlyContinue;[IO.File]::WriteAllText('{directory}\\command.tmp','{payload}');Move-Item -LiteralPath '{directory}\\command.tmp' -Destination '{directory}\\command.json' -Force;for($attempt=0;$attempt -lt 1600;++$attempt){{if(Test-Path '{directory}\\result.json'){{Get-Content -Raw '{directory}\\result.json';exit 0}};Start-Sleep -Milliseconds 25}};throw 'Profile fixture timed out'")
        response = json.loads(text)
        assert response['id'] == sequence and 'error' not in response, response
        return response['value']

    def packet(operation, length=160):
        data = bytearray(length)
        struct.pack_into('<QII', data, 0, 0x4d48564d454d3031, 1, operation)
        struct.pack_into('<I', data, 36, length)
        return data

    def invoke(data, expected=0):
        response = base64.b64decode(command('packet', packet=base64.b64encode(data).decode()))
        status = struct.unpack_from('<I', response, 40)[0]
        assert status == expected, (status, expected, data.hex(), response.hex())
        return response

    def mark(name):
        results['checks'].append(name)
        save()
        print('PASS ' + name, flush=True)

    try:
        assert 'state=disabled' in remote(args.guest_neo, 'hook', 'status')
        results['boot_before'] = script('(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString("o")')
        source = (project / 'tests/interception_profile_vm_fixture.ps1').read_bytes()
        for directory in peers:
            script(f"New-Item -ItemType Directory -Path '{directory}' -Force | Out-Null;[IO.File]::WriteAllBytes('{directory}\\fixture.ps1',[byte[]]@())")
            for offset in range(0, len(source), 4096):
                encoded = base64.b64encode(source[offset:offset + 4096]).decode()
                script(f"$s=[IO.File]::Open('{directory}\\fixture.ps1',[IO.FileMode]::Append);try{{$b=[Convert]::FromBase64String('{encoded}');$s.Write($b,0,$b.Length)}}finally{{$s.Dispose()}}")
            child = base64.b64encode(f"Start-Process powershell.exe -WindowStyle Hidden -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File {directory}\\fixture.ps1 -OutputDirectory {directory}' -RedirectStandardOutput '{directory}\\out.txt' -RedirectStandardError '{directory}\\error.txt' | Out-Null;exit 0".encode('utf-16le')).decode()
            script(f"$startup=([wmiclass]'Win32_ProcessStartup').CreateInstance();$startup.ShowWindow=0;$r=([wmiclass]'Win32_Process').Create('powershell.exe -NoProfile -EncodedCommand {child}',$null,$startup);if($r.ReturnValue -ne 0){{throw 'Detached profile launch failed'}}")
            fixtures.append(json.loads(script(f"for($attempt=0;$attempt -lt 400;++$attempt){{if(Test-Path '{directory}\\fixture.json'){{Get-Content -Raw '{directory}\\fixture.json';exit 0}};if(Test-Path '{directory}\\error.txt'){{$e=Get-Content -Raw '{directory}\\error.txt';if($e){{throw $e}}}};Start-Sleep -Milliseconds 25}};throw 'Profile initialization timed out'")))
        results['fixtures'] = fixtures
        info = invoke(packet(0, 288))
        root, lstar = struct.unpack_from('<2Q', info, 48)
        native = command('cpuid', gated=False, iterations=128)
        peer_native = command('cpuid', directory=peers[1], gated=True, iterations=128)
        values = [0x0badc0de, 0x10203040, 0x55667788, 0x87654321]
        request = packet(24, 208)
        struct.pack_into('<2Q', request, 16, root, 0x7ffe0ff0)
        struct.pack_into('<I', request, 32, 1)
        struct.pack_into('<I', request, 128, 16)
        struct.pack_into('<2Q', request, 144, 0xfffffffff0000040, 0x40)
        struct.pack_into('<I', request, 160, 7)
        struct.pack_into('<4I', request, 176, *values)
        response = invoke(request)
        token = struct.unpack_from('<Q', response, 80)[0]
        assert command('cpuid', gated=False, iterations=256) == native
        assert command('cpuid', directory=peers[1], gated=True, iterations=256) == peer_native
        assert command('cpuid', gated=True, iterations=256) == [values] * fixtures[0]['processors']
        mark('CPUID matches the DR gate on every CPU and preserves other threads and processes')
        clear = packet(25)
        struct.pack_into('<Q', clear, 80, token - 1)
        invoke(clear, 11)
        for seed in (341049, 0xab1015b, 0x5425cb8):
            rng = random.Random(seed)
            for _ in range(16):
                malformed = bytearray(request)
                struct.pack_into('<Q', malformed, 80, token)
                struct.pack_into('<I', malformed, 36, len(malformed) ^ (1 << rng.randrange(16)))
                invoke(malformed, 1)
        assert command('cpuid', gated=True, iterations=256) == [values] * fixtures[0]['processors']
        struct.pack_into('<Q', clear, 80, token)
        invoke(clear)
        token = None
        assert command('cpuid', gated=True, iterations=256) == native
        mark('Stale tokens and 48 seeded malformed packets preserve the profile; clear restores native CPUID')
        request = packet(26)
        struct.pack_into('<2Q', request, 16, root, int(fixtures[0]['callback'], 0))
        struct.pack_into('<Q', request, 48, lstar)
        struct.pack_into('<I', request, 128, 16)
        syscall_native = command('syscall', gated=False, iterations=16)
        response = base64.b64decode(command('packet', packet=base64.b64encode(request).decode()))
        status = struct.unpack_from('<I', response, 40)[0]
        if status == 5:
            results['syscall_hardware_contract'] = 'UNSUPPORTED: kernel entry, CET, or LA57 contract'
            assert 'state=disabled' in remote(args.guest_neo, 'hook', 'status')
            mark('Unsupported syscall entry contract rejects installation without changing the session')
        else:
            assert status == 0, (status, response.hex())
            token = struct.unpack_from('<Q', response, 80)[0]
            assert command('syscall', gated=False, iterations=16) == syscall_native
            routed = command('syscall', gated=True, iterations=128)
            assert all(row[:2] == [0x12345678, 128] for row in routed), routed
            clear = packet(27)
            struct.pack_into('<Q', clear, 80, token)
            invoke(clear)
            token = None
            assert command('syscall', gated=True, iterations=16) == syscall_native
            mark('Syscall callbacks, native bypass, DR gate and clear work on every CPU')
        results['boot_after'] = script('(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString("o")')
        assert results['boot_before'] == results['boot_after'], 'Guest rebooted during profile validation'
        assert 'failed=0x0' in remote(args.guest_neo, 'matrix', 'status')
        results['status'] = 'PASS'
    except Exception as error:
        results['status'] = 'FAIL'
        results['error'] = repr(error)
        raise
    finally:
        if token is not None:
            try:
                remote(args.guest_neo, 'hook', 'release', token)
            except Exception as error:
                results['cleanup_errors'].append(repr(error))
        for directory in peers:
            try:
                script(f"if(-not (Test-Path '{directory}')){{exit 0}};[IO.File]::WriteAllText('{directory}\\command.json','{{\"operation\":\"stop\"}}');for($attempt=0;$attempt -lt 100;++$attempt){{$p=@(Get-CimInstance Win32_Process -Filter \"name='powershell.exe'\" | Where-Object {{$_.CommandLine -like '*-File {directory}\\fixture.ps1 -OutputDirectory {directory}*'}});if(-not $p.Count){{exit 0}};Start-Sleep -Milliseconds 100}};foreach($process in $p){{Stop-Process -Id $process.ProcessId -ErrorAction Stop}}")
            except Exception as error:
                results['cleanup_errors'].append(repr(error))
        if results['cleanup_errors']:
            results['status'] = 'FAIL'
        save()
        log.close()
    assert results['status'] == 'PASS', results


if __name__ == '__main__':
    main()
