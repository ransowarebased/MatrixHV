"""Exercise interception profiles on every Windows CPU, locally or in a VM."""
import argparse
import base64
import json
import os
from pathlib import Path
import random
import re
import struct
import subprocess
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--neo', type=Path, required=True)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--remote')
    target.add_argument('--local', action='store_true')
    parser.add_argument('--guest-neo')
    parser.add_argument('--syscall-only', action='store_true',
                        help='Run CPUID setup/clear and standalone syscall regressions only')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.remote and not args.guest_neo:
        parser.error('--remote requires --guest-neo')
    if args.local:
        args.guest_neo = str(args.neo.resolve())
    project = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.relative_to(project / 'builds')
    output.mkdir(parents=True, exist_ok=True)
    guest = (str(output / ('fixture-' + uuid.uuid4().hex[:12])) if args.local
             else r'C:\MatrixHVProfiles-' + uuid.uuid4().hex[:12])
    peers = [guest, guest + r'\peer']
    sequence = 0
    token = None
    fixtures = []
    results = {'status': 'RUNNING', 'checks': [], 'cleanup_errors': [], 'guest_directory': guest}
    log = (output / 'commands.log').open('w', encoding='utf-8', buffering=1)

    def save_json(path, value):
        temporary = path.with_suffix('.tmp')
        with temporary.open('w', encoding='utf-8') as stream:
            json.dump(value, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)

    def save():
        save_json(output / 'results.json', results)

    def write_log(text):
        log.write(text)
        log.flush()
        os.fsync(log.fileno())

    def remote(*operands):
        command = ([*map(str, operands)] if args.local else
                   [str(args.neo.resolve()), '--remote', args.remote, '--timeout', '45', 'exec', *map(str, operands)])
        write_log(f'BEGIN {time.time():.6f} ' + ' '.join(map(str, operands)) + '\n')
        completed = subprocess.run(command, capture_output=True, timeout=55)
        text = completed.stdout.decode(errors='replace') + completed.stderr.decode(errors='replace')
        write_log(f'END {time.time():.6f} exit={completed.returncode}\n' + text + '\n')
        assert completed.returncode == 0, text
        return text

    def script(body):
        body = "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';" + body
        if args.local:
            script_path = output / ('command-' + uuid.uuid4().hex + '.ps1')
            script_path.write_text(body, encoding='utf-8-sig')
            return remote('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', script_path)
        encoded = base64.b64encode(body.encode('utf-16le')).decode()
        return remote('powershell.exe', '-NoProfile', '-EncodedCommand', encoded)

    def upload(path, data):
        if args.local:
            Path(path).write_bytes(data)
            return
        if not data:
            script(f"[IO.File]::WriteAllBytes('{path}',[byte[]]@())")
        for offset in range(0, len(data), 4096):
            encoded = base64.b64encode(data[offset:offset + 4096]).decode()
            mode = 'Append' if offset else 'Create'
            script(f"$s=[IO.File]::Open('{path}',[IO.FileMode]::{mode});try{{$b=[Convert]::FromBase64String('{encoded}');$s.Write($b,0,$b.Length)}}finally{{$s.Dispose()}}")

    def command(operation, directory=guest, **parameters):
        nonlocal sequence
        sequence += 1
        payload = json.dumps(dict(id=sequence, operation=operation, **parameters))
        save_json(output / 'last-command.json', json.loads(payload))
        prelude = ''
        if args.local:
            Path(directory, 'result.json').unlink(missing_ok=True)
            upload(directory + r'\command.tmp', payload.encode())
        elif len(payload.encode()) <= 4096:
            encoded = base64.b64encode(payload.encode()).decode()
            prelude = (f"if(Test-Path '{directory}\\result.json'){{Remove-Item -LiteralPath '{directory}\\result.json'}};"
                       f"[IO.File]::WriteAllBytes('{directory}\\command.tmp',[Convert]::FromBase64String('{encoded}'));")
        else:
            script(f"if(Test-Path '{directory}\\result.json'){{Remove-Item -LiteralPath '{directory}\\result.json'}}")
            upload(directory + r'\command.tmp', payload.encode())
        fixture = fixtures[peers.index(directory)]
        text = script(prelude + f"Move-Item -LiteralPath '{directory}\\command.tmp' -Destination '{directory}\\command.json' -Force;for($attempt=0;$attempt -lt 1600;++$attempt){{if(Test-Path '{directory}\\result.json'){{Get-Content -Raw '{directory}\\result.json';exit 0}};if(-not (Get-Process -Id {fixture['pid']} -ErrorAction SilentlyContinue)){{throw 'Profile fixture exited during {operation}'}};Start-Sleep -Milliseconds 25}};throw 'Profile fixture timed out'")
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
            script(f"New-Item -ItemType Directory -Path '{directory}' -Force | Out-Null")
            upload(directory + r'\fixture.ps1', source)
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
            protected = command('protect-native', gated=True)
            assert all(row[1] == 4 and row[3] == 0 for row in protected), protected
            mark('Native syscall bypass preserves the fifth stack argument on every CPU')
            clear = packet(27)
            struct.pack_into('<Q', clear, 80, token)
            invoke(clear)
            token = None
            assert command('syscall', gated=True, iterations=16) == syscall_native
            mark('Syscall callbacks, native bypass, DR gate and clear work on every CPU')
        if args.syscall_only:
            results['boot_after'] = script('(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString("o")')
            assert results['boot_before'] == results['boot_after'], 'Target rebooted during syscall validation'
            assert 'failed=0x0' in remote(args.guest_neo, 'matrix', 'status')
            results['status'] = 'PASS'
            return
        # Arbitrary read-only private data pages retain the original GPA bytes.
        data_address = int(fixtures[0]['data'], 0)
        debug_address = int(fixtures[0]['debugAddress'], 0)
        debug_redirect = int(fixtures[0]['debugRedirect'], 0)
        command('protect-data', readOnly=True)
        native_data = command('read-data')
        shadow_value = 0x8877665544332211
        hook = packet(11, 192)
        struct.pack_into('<Q', hook, 16, root)
        struct.pack_into('<I', hook, 32, 1)
        struct.pack_into('<I', hook, 128, 16)
        struct.pack_into('<QIIII', hook, 160, data_address, 184, 8, 0, 1)
        struct.pack_into('<Q', hook, 184, shadow_value)
        response = invoke(hook)
        token = struct.unpack_from('<Q', response, 80)[0]
        assert command('read-data') == shadow_value
        native_read = packet(1, 192)
        struct.pack_into('<Q', native_read, 16, root)
        struct.pack_into('<I', native_read, 32, 1)
        struct.pack_into('<QII', native_read, 160, data_address, 184, 8)
        original = invoke(native_read)
        assert struct.unpack_from('<Q', original, 184)[0] == native_data
        release = packet(20)
        struct.pack_into('<Q', release, 80, token)
        invoke(release)
        token = None
        assert command('read-data') == native_data
        command('protect-data', readOnly=False)
        mark('Arbitrary read-only data shadow changes scoped reads and preserves original RAM and protections')

        # Code hooks, debug redirects and CPUID remain installed while syscall routing is cleared.
        hook = packet(11, 190)
        struct.pack_into('<Q', hook, 16, root)
        struct.pack_into('<I', hook, 32, 1)
        struct.pack_into('<I', hook, 128, 1 | 4 | 16)
        struct.pack_into('<QII', hook, 160, debug_address, 184, 6)
        hook[184:] = bytes.fromhex('b822000000c3')
        response = invoke(hook)
        token = struct.unpack_from('<Q', response, 80)[0]
        assert all(row[0] == 34 for row in command('debug', gated=False, iterations=32))
        debug = packet(13, 176)
        struct.pack_into('<Q', debug, 16, root)
        struct.pack_into('<I', debug, 32, 1)
        struct.pack_into('<I', debug, 128, 16)
        struct.pack_into('<2Q', debug, 160, debug_address, debug_redirect)
        response = invoke(debug)
        token = struct.unpack_from('<Q', response, 80)[0]
        assert all(row[0] == 51 for row in command('debug', gated=False, iterations=32))
        struct.pack_into('<Q', request := packet(24, 208), 16, root)
        struct.pack_into('<Q', request, 24, 0x7ffe0ff0)
        struct.pack_into('<I', request, 32, 1)
        struct.pack_into('<Q', request, 80, token)
        struct.pack_into('<I', request, 128, 16)
        struct.pack_into('<2Q', request, 144, 0xfffffffff0000040, 0x40)
        struct.pack_into('<I', request, 160, 7)
        struct.pack_into('<4I', request, 176, *values)
        response = invoke(request)
        token = struct.unpack_from('<Q', response, 80)[0]
        syscall = packet(26)
        struct.pack_into('<2Q', syscall, 16, root, int(fixtures[0]['callback'], 0))
        struct.pack_into('<Q', syscall, 48, lstar)
        struct.pack_into('<Q', syscall, 80, token)
        struct.pack_into('<I', syscall, 128, 16)
        response = base64.b64decode(command('packet', packet=base64.b64encode(syscall).decode()))
        syscall_status = struct.unpack_from('<I', response, 40)[0]
        assert syscall_status in (0, 5), (syscall_status, response.hex())
        if syscall_status == 0:
            token = struct.unpack_from('<Q', response, 80)[0]
            assert all(row[:2] == [0x12345678, 64] for row in command('syscall', gated=True, iterations=64))
        results['combined_before_debug'] = remote(args.guest_neo, 'hook', 'status')
        save()
        assert all(row[0] == 51 for row in command('debug', gated=True, iterations=32))
        assert command('cpuid', gated=True, iterations=32) == [values] * fixtures[0]['processors']
        if syscall_status == 0:
            assert all(row[:2] == [0x12345678, 32] for row in command('syscall', gated=True, iterations=32))
        results['simultaneous_syscall_status'] = syscall_status
        mark('VMFUNC EPT hooks, debug redirects and CPUID coexist across every CPU')
        if syscall_status == 0:
            remote(args.guest_neo, 'syscall', 'clear', token)
            assert all(row[0] == 51 for row in command('debug', gated=True, iterations=16))
            mark('Clearing syscall interception preserves independently installed debug redirects')
        release = packet(20)
        struct.pack_into('<Q', release, 80, token)
        invoke(release)
        token = None
        assert all(row[0] == 17 for row in command('debug', gated=True, iterations=16))
        mark('Releasing the combined profile restores native code and guest debug state')
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
        if results['cleanup_errors']:
            raise AssertionError(results['cleanup_errors'])
    assert results['status'] == 'PASS', results


if __name__ == '__main__':
    main()
