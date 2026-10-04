"""Seeded instruction and hook lifecycle fuzzing against a live Windows VM."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import random
import re
import subprocess
import time
import uuid

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--neo', type=Path, required=True)
    parser.add_argument('--remote', required=True)
    parser.add_argument('--guest-neo', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seed', type=int, default=341049)
    parser.add_argument('--sessions', type=int, default=24)
    parser.add_argument('--iterations', type=int, default=256)
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.relative_to(project / 'builds')
    output.mkdir(parents=True, exist_ok=True)
    guest = r'C:\MatrixHVFuzz-' + str(args.seed) + '-' + uuid.uuid4().hex[:12]
    log = (output / 'commands.log').open('w', encoding='utf-8')
    results = {'seed': args.seed, 'sessions': [], 'status': 'RUNNING', 'coverage': '96 valid x64 readers: MOV/MOVZX/MOVSX/MOVSXD/ADD/XOR/CMP, RAX/R10, widths 1/2/4/8, aligned/unaligned/cross-page/patch-overlap; seeded hook modes, patch replacement, all-CPU execution, release restoration. Does not fuzz arbitrary VMCS state or kernel instructions.'}
    results['guest_directory'] = guest
    results['cleanup_errors'] = []
    token = None
    sequence = 0
    rng = random.Random(args.seed)

    def save():
        with (output / 'results.tmp').open('w', encoding='utf-8') as stream:
            json.dump(results, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(output / 'results.tmp', output / 'results.json')

    def remote(*operands):
        log.write(f'BEGIN {time.time():.6f} ' + ' '.join(map(str, operands)) + '\n')
        log.flush(); os.fsync(log.fileno())
        completed = subprocess.run([str(args.neo), '--remote', args.remote, '--timeout', '110', 'exec', *map(str, operands)], capture_output=True, timeout=120)
        text = (completed.stdout + completed.stderr).decode('utf-8', errors='replace')
        log.write(f'END {time.time():.6f} exit={completed.returncode}\n{text}\n')
        log.flush(); os.fsync(log.fileno())
        if completed.returncode:
            raise AssertionError(text)
        return text.strip()

    def script(body):
        encoded = base64.b64encode(("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';" + body).encode('utf-16le')).decode()
        return remote('powershell.exe', '-NoProfile', '-EncodedCommand', encoded)

    def neo(*operands):
        return remote(args.guest_neo, *operands)

    def detached(body):
        # The broker prevents PowerShell descendants from inheriting Neo's RPC pipes.
        encoded = base64.b64encode(body.encode('utf-16le')).decode()
        return script(f"$startup=([wmiclass]'Win32_ProcessStartup').CreateInstance();$startup.ShowWindow=0;$r=([wmiclass]'Win32_Process').Create('powershell.exe -NoProfile -EncodedCommand {encoded}',$null,$startup);if($r.ReturnValue -ne 0){{throw ('Detached launch failed: '+$r.ReturnValue)}};$r.ProcessId")

    def field(text, key):
        match = re.search(r'\b' + key + r'=([^\s]+)', text)
        assert match, (key, text)
        return match[1]

    def run(seed, iterations, workers, expected, start=0, count=96):
        nonlocal sequence
        sequence += 1
        payload = json.dumps(dict(id=sequence, operation='run', seed=seed, iterations=iterations, workers=workers, expected=expected, start_case=start, case_count=count))
        text = script(f"Remove-Item -LiteralPath '{guest}\\result.json' -ErrorAction SilentlyContinue; [IO.File]::WriteAllText('{guest}\\command.tmp','{payload}');Move-Item -LiteralPath '{guest}\\command.tmp' -Destination '{guest}\\command.json' -Force; for($attempt=0;$attempt -lt 4000;++$attempt){{if(Test-Path -LiteralPath '{guest}\\result.json'){{Get-Content -Raw '{guest}\\result.json';exit 0}};Start-Sleep -Milliseconds 25}};throw 'Fuzz fixture timed out'")
        result = json.loads(text)
        assert result['id'] == sequence and 'error' not in result, result
        assert result['completed'] == iterations * workers, result
        return result['completed']

    try:
        assert field(neo('hook', 'status'), 'state') == 'disabled'
        results['matrix_before'] = neo('matrix', 'status')
        results['last_boot_before'] = script('(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString("o")')
        expected_hash = hashlib.sha256(args.neo.read_bytes()).hexdigest()
        assert script(f"(Get-FileHash -LiteralPath '{args.guest_neo}').Hash").lower() == expected_hash
        script(f"New-Item -ItemType Directory -Path '{guest}' -Force | Out-Null;[IO.File]::WriteAllBytes('{guest}\\fixture.ps1',[byte[]]@())")
        data = (project / 'tests/interception_fuzz_vm_fixture.ps1').read_bytes()
        for offset in range(0, len(data), 4096):
            chunk = base64.b64encode(data[offset:offset+4096]).decode()
            script(f"$s=[IO.File]::Open('{guest}\\fixture.ps1',[IO.FileMode]::Append);try{{$b=[Convert]::FromBase64String('{chunk}');$s.Write($b,0,$b.Length)}}finally{{$s.Dispose()}}")
        detached(f"Start-Process powershell.exe -WindowStyle Hidden -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File {guest}\\fixture.ps1 -OutputDirectory {guest} -Seed {args.seed}' -RedirectStandardOutput '{guest}\\fixture-out.txt' -RedirectStandardError '{guest}\\fixture-error.txt' | Out-Null;exit 0")
        fixture = json.loads(script(f"for($attempt=0;$attempt -lt 400;++$attempt){{if(Test-Path '{guest}\\fixture.json'){{Get-Content -Raw '{guest}\\fixture.json';exit 0}};if(Test-Path '{guest}\\fixture-error.txt'){{$e=Get-Content -Raw '{guest}\\fixture-error.txt';if($e){{throw $e}}}};Start-Sleep -Milliseconds 25}};throw 'Fixture initialization failed'"))
        results['fixture'] = fixture
        root = field(neo('read', fixture['pid'], 'auto'), 'cr3')
        neo('telemetry', 'enable')
        detached(f"$ErrorActionPreference='Stop';$collectors=@();foreach($mode in @('general','watchdog','eptdiag')){{$path=Join-Path '{guest}' ($mode+'.txt');$a=@('telemetry');if($mode -ne 'general'){{$a+=$mode}};$a+=@('--seconds','1800','--interval-ms','500','--output',$path);$p=Start-Process '{args.guest_neo}' -WindowStyle Hidden -ArgumentList $a -PassThru -RedirectStandardOutput (Join-Path '{guest}' ($mode+'-out.txt')) -RedirectStandardError (Join-Path '{guest}' ($mode+'-error.txt'));$collectors+=@{{pid=$p.Id;mode=$mode;path=$path}}}};$collectors | ConvertTo-Json | Set-Content '{guest}\\collectors.json';exit 0")
        results['collectors'] = json.loads(script(f"for($attempt=0;$attempt -lt 200;++$attempt){{if(Test-Path '{guest}\\collectors.json'){{$collectors=(Get-Content -Raw '{guest}\\collectors.json' | ConvertFrom-Json);$ready=$true;foreach($collector in $collectors){{$p=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$collector.pid);if(-not $p -or $p.CommandLine -notlike '*{guest}*'){{throw ('Telemetry collector exited: '+$collector.mode)}};if(-not (Test-Path -LiteralPath $collector.path) -or (Get-Item -LiteralPath $collector.path).Length -eq 0){{$ready=$false}}}};if($ready -and $collectors.Count -eq 3){{$collectors | ConvertTo-Json;exit 0}}}};Start-Sleep -Milliseconds 100}};throw 'Telemetry collectors did not produce data'"))
        results['baseline_cases'] = run(args.seed, 96, fixture['processors'], 17)
        print('PASS baseline: all 96 readers on every CPU', flush=True)
        save()
        for session in range(args.sessions):
            mode = ['', '--persistent-data', '--concurrent-writes'][session % 3]
            workers = 1 if session < 3 else fixture['processors']
            patch_value = rng.randrange(32, 127)
            session_seed = rng.randrange(1, 0x7fffffff)
            entry = dict(session=session, mode=mode or 'default', workers=workers, seed=session_seed, patch_value=patch_value, status='RUNNING')
            results['sessions'].append(entry); save()
            print(f'BEGIN session={session} seed={session_seed} mode={mode or "default"} workers={workers}', flush=True)
            # A second unused patch keeps the session active during replacement.
            anchor = hex(int(fixture['first'], 0) + 64)
            installed = neo('hook', 'install', root, fixture['first'], 'b8'+patch_value.to_bytes(4,'little').hex(), anchor, '90', '--no-lease', *([mode] if mode else []))
            token = field(installed, 'token')
            assert field(installed, 'state') == 'active'
            entry['checks'] = run(session_seed, max(96, args.iterations), workers, patch_value)
            assert field(neo('hook', 'status'), 'state') == 'active'
            hook_id = field(neo('hook', 'list', token), 'id')
            replacement = rng.randrange(128, 240)
            neo('hook', 'remove', token, hook_id)
            entry['checks'] += run(session_seed, 96, workers, 17)
            neo('hook', 'add', token, fixture['first'], 'b8'+replacement.to_bytes(4,'little').hex())
            entry['replacement'] = replacement
            entry['checks'] += run(session_seed ^ 0x1234567, 96, workers, replacement)
            assert field(neo('hook', 'status'), 'state') == 'active'
            neo('hook', 'release', token); token = None
            entry['checks'] += run(session_seed, 96, workers, 17)
            assert field(neo('hook', 'status'), 'state') == 'disabled'
            entry['status'] = 'PASS'; save()
            print(f'PASS session={session} checks={entry["checks"]}', flush=True)
        results['last_boot_after'] = script('(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString("o")')
        assert results['last_boot_before'] == results['last_boot_after'], 'Guest rebooted during fuzzing'
        results['matrix_after'] = neo('matrix', 'status')
        results['telemetry_after'] = neo('telemetry')
        results['status'] = 'PASS'
    except Exception as error:
        results['status'] = 'FAIL'; results['error'] = repr(error)
        for name, operands in [('failure-status', ('hook', 'status')), ('failure-general', ('telemetry',)), ('failure-eptdiag', ('telemetry', 'eptdiag'))]:
            try:
                (output / (name + '.txt')).write_text(neo(*operands), encoding='utf-8')
            except Exception as snapshot_error:
                results.setdefault('snapshot_errors', []).append(repr(snapshot_error))
        raise
    finally:
        save()
        if token:
            try:
                neo('hook', 'release', token)
            except Exception as cleanup_error:
                results['cleanup_errors'].append('Hook release: ' + repr(cleanup_error))
        for name, body in [
            ('Collectors', f"$stopErrors=@();if(Test-Path '{guest}\\collectors.json'){{foreach($collector in (Get-Content -Raw '{guest}\\collectors.json' | ConvertFrom-Json)){{try{{$p=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$collector.pid);if($p -and $p.CommandLine -like '*{guest}*'){{Stop-Process -Id $collector.pid -ErrorAction Stop}}}}catch{{$stopErrors+=$_.Exception.Message}}}}}};if($stopErrors.Count){{throw ($stopErrors -join '; ')}}"),
            ('Fixture', f"[IO.File]::WriteAllText('{guest}\\command.json','{{\"operation\":\"stop\"}}');if(Test-Path '{guest}\\fixture.json'){{$fixture=Get-Content -Raw '{guest}\\fixture.json' | ConvertFrom-Json;for($attempt=0;$attempt -lt 50;++$attempt){{$p=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$fixture.pid);if(-not $p -or $p.CommandLine -notlike '*{guest}*'){{exit 0}};Start-Sleep -Milliseconds 100}};Stop-Process -Id $fixture.pid -ErrorAction Stop}}"),
        ]:
            try:
                script(body)
            except Exception as cleanup_error:
                results['cleanup_errors'].append(name + ': ' + repr(cleanup_error))
        if results['cleanup_errors'] and results['status'] == 'PASS':
            results['status'] = 'FAIL'
            results['error'] = 'Cleanup failed'
        save()
        log.close()
    assert results['status'] == 'PASS', results
    print('PASS VM fuzzing', flush=True)

if __name__ == '__main__':
    main()
