"""Run controlled NotMyFault cases against the current MatrixHV VMware image."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

CASES = {
    'on-dpc': ('hang', '0x02', True),
    'native-dpc': ('hang', '0x02', False),
    'on-irp': ('hang', '0x01', True),
    'on-deadlock': ('hang', '0x03', True),
    'on-high-irql': ('crash', '0x01', True),
    'native-high-irql': ('crash', '0x01', False),
    'on-double-free': ('crash', '0x08', True),
    'on-hal-watchdog': ('crash', '0x09', True),
    'on-hypervisor': ('crash', '0x0B', True),
}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--remote', required=True)
    parser.add_argument('--neo', type=Path, required=True)
    parser.add_argument('--ida', type=Path, required=True)
    parser.add_argument('--vmrun', type=Path, required=True)
    parser.add_argument('--vmx', type=Path, required=True)
    parser.add_argument('--serial', type=Path, required=True)
    parser.add_argument('--efi', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cases', nargs='+', choices=CASES, default=list(CASES))
    parser.add_argument('--cleanup-only', action='store_true')
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.relative_to(project / 'builds')
    output.mkdir(parents=True, exist_ok=True)
    guest_neo = r'C:\MatrixHVNotMyFault\neo.exe'
    expected_efi = hashlib.sha256(args.efi.read_bytes()).hexdigest()
    expected_neo = hashlib.sha256(args.neo.read_bytes()).hexdigest()
    summary = {'status': 'RUNNING', 'efi_sha256': expected_efi,
               'neo_sha256': expected_neo, 'cases': []}
    current_log = None
    guest = None
    sequence = 0
    recovered = False

    def save():
        temporary = output / 'results.tmp'
        temporary.write_text(json.dumps(summary, indent=2))
        os.replace(temporary, output / 'results.json')

    def remote(*operands, timeout=35, expected=0):
        completed = subprocess.run([str(args.neo.resolve()), '--remote', args.remote,
            '--timeout', str(timeout), 'exec', *map(str, operands)], capture_output=True, timeout=timeout + 8)
        text = (completed.stdout + completed.stderr).decode('utf-8', errors='replace').strip()
        if current_log:
            current_log.write(f'{time.time():.6f} exit={completed.returncode}\n{text}\n')
            current_log.flush()
        if expected is not None and completed.returncode != expected:
            raise AssertionError(f'Guest command exit={completed.returncode}: {text}')
        return text

    def script(body, admin=False, timeout=35):
        encoded = base64.b64encode(("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';" + body).encode('utf-16le')).decode()
        operands = ['powershell.exe', '-NoProfile', '-EncodedCommand', encoded]
        if admin:
            operands = [guest_neo, '--remote', '127.0.0.1:4041', '--timeout', str(timeout - 3), 'exec', *operands]
        return remote(*operands, timeout=timeout)

    def field(text, name):
        match = re.search(r'\b' + re.escape(name) + r'=([^\s]+)', text)
        assert match, (name, text)
        return match[1]

    def broker(body, admin=False):
        encoded = base64.b64encode(body.encode('utf-16le')).decode()
        return script("$startup=([wmiclass]'Win32_ProcessStartup').CreateInstance();$startup.ShowWindow=0;"
            f"$result=([wmiclass]'Win32_Process').Create('powershell.exe -NoProfile -EncodedCommand {encoded}',$null,$startup);"
            "if($result.ReturnValue -ne 0){throw ('Broker launch failed: '+$result.ReturnValue)};$result.ProcessId", admin=admin)

    def wait_ready():
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            completed = subprocess.run([str(args.neo.resolve()), '--remote', args.remote,
                '--timeout', '3', 'ping'], capture_output=True, timeout=6)
            if completed.returncode == 0:
                return
            time.sleep(2)
        raise AssertionError('Windows did not return after hard restart')

    def restart():
        nonlocal recovered
        prefix = [str(args.vmrun.resolve()), '-T', 'ws', '-vp', os.environ['MATRIXHV_VM_PASSWORD']]
        for operands in [('stop', str(args.vmx.resolve()), 'hard'), ('start', str(args.vmx.resolve()), 'nogui')]:
            completed = subprocess.run([*prefix, *operands], capture_output=True, text=True, timeout=45)
            assert completed.returncode == 0, completed.stdout + completed.stderr
        wait_ready()
        recovered = True

    def prepare_admin():
        try:
            if script("([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)", admin=True, timeout=7).strip() == 'True':
                return
        except (AssertionError, subprocess.TimeoutExpired):
            pass
        script(f"$p=Start-Process -FilePath '{guest_neo}' -WindowStyle Hidden -Verb RunAs "
               "-ArgumentList 'serve','--listen','127.0.0.1:4041' -PassThru;"
               "$p.Id | Set-Content 'C:\\MatrixHVNotMyFault\\admin-server.pid';$p.Id")
        for _ in range(20):
            try:
                assert script("([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)", admin=True).strip() == 'True'
                return
            except (AssertionError, subprocess.TimeoutExpired):
                time.sleep(1)
        raise AssertionError('Administrator helper unavailable')

    def fixture_command(operation, **values):
        nonlocal sequence
        sequence += 1
        payload = json.dumps(dict(id=sequence, operation=operation, **values))
        text = script(f"Remove-Item -LiteralPath '{guest}\\result.json' -ErrorAction SilentlyContinue;"
            f"[IO.File]::WriteAllText('{guest}\\command.tmp','{payload}');"
            f"Move-Item -LiteralPath '{guest}\\command.tmp' -Destination '{guest}\\command.json' -Force;"
            f"for($attempt=0;$attempt -lt 400;++$attempt){{if(Test-Path '{guest}\\result.json'){{Get-Content -Raw '{guest}\\result.json';exit 0}};Start-Sleep -Milliseconds 25}};throw 'Fixture command timed out'")
        value = json.loads(text)
        assert value['id'] == sequence and 'error' not in value, value
        return value['value']

    def capture(directory, name):
        shutil.copy2(args.serial, directory / 'serial.log')
        environment = os.environ.copy()
        environment.update(MATRIXHV_EVIDENCE_ROOT=str(directory), MATRIXHV_EVIDENCE_SAMPLE=name)
        ida = str(args.ida.resolve()).replace("'", "''")
        source = str(project / 'tests/collect_boot_state.py').replace("'", "''")
        log = str(directory / f'{name}-idat.log').replace("'", "''")
        command = f"$p=Start-Process -FilePath '{ida}' -WindowStyle Hidden -ArgumentList '-A','-t','-S\"{source}\"','-L\"{log}\"' -PassThru; $p.WaitForExit(); exit $p.ExitCode"
        completed = subprocess.run(['powershell.exe', '-NoProfile', '-Command', command], env=environment, capture_output=True, text=True, timeout=50)
        state = json.loads((directory / f'{name}-state.json').read_text())
        assert completed.returncode == 0 and not state.get('error'), state.get('error') or completed.stderr
        assert len(state['cpus']) == len(state['contexts']) == 8
        return state

    def resident_health(state):
        return [{'cpu': context['values']['processor_number'],
            'host_fault_vector': context['values']['event.host_fault_vector'],
            'resume_failures': context['values']['watchdog_resume_failures'],
            'entry_failure_state': context['values']['entry_failure_state'],
            'refresh_owned': context['values']['interception.refresh_owned'],
            'last_reason': context['values']['last_reason'],
            'last_guest_rip': hex(context['values']['last_guest_rip'])} for context in state['contexts']]

    def cleanup():
        prepare_admin()
        summary['cleanup'] = script(
            "$path='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl';"
            "$backup='C:\\MatrixHVNotMyFault\\crash-control-before.json';"
            "if(Test-Path $backup){$before=Get-Content -Raw $backup|ConvertFrom-Json;"
            "foreach($property in $before.PSObject.Properties){"
            "if($null -eq $property.Value){if((Get-ItemProperty $path).PSObject.Properties.Name -contains $property.Name){"
            "Remove-ItemProperty $path -Name $property.Name}}else{"
            "New-ItemProperty $path -Name $property.Name -PropertyType DWord -Value $property.Value -Force|Out-Null}}};"
            "Get-ItemProperty $path|Select-Object CrashDumpEnabled,AutoReboot,LogEvent,AlwaysKeepMemoryDump|ConvertTo-Json -Compress",
            admin=True)
        broker("Start-Sleep -Seconds 2;$path='C:\\MatrixHVNotMyFault\\admin-server.pid';"
            "if(Test-Path $path){$id=[int](Get-Content $path);"
            "$process=Get-Process -Id $id -ErrorAction SilentlyContinue;"
            "if($process -and $process.Path -eq 'C:\\MatrixHVNotMyFault\\neo.exe'){Stop-Process -Id $id -Force}}", admin=True)
        summary['final_status'] = remote(guest_neo, 'matrix', 'status')
        assert field(summary['final_status'], 'active') == '0xff' and field(summary['final_status'], 'failed') == '0x0'

    save()
    try:
        wait_ready()
        if args.cleanup_only:
            recovered = True
        for name in ([] if args.cleanup_only else args.cases):
            kind, fault_type, active = CASES[name]
            directory = output / name
            directory.mkdir(exist_ok=True)
            current_log = (directory / 'commands.log').open('w', encoding='utf-8', buffering=1)
            record = {'case': name, 'kind': kind, 'fault_type': fault_type,
                      'matrix_active': active, 'status': 'RUNNING'}
            summary['cases'].append(record)
            recovered = False
            save()
            print('BEGIN', name, flush=True)
            prepare_admin()
            metadata = json.loads(script("[ordered]@{efi=(Get-FileHash E:\\EFI\\BOOT\\BOOTX64.EFI).Hash;"
                f"neo=(Get-FileHash '{guest_neo}').Hash;boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('o')}} | ConvertTo-Json -Compress"))
            assert metadata['efi'].lower() == expected_efi and metadata['neo'].lower() == expected_neo, metadata
            record['before'] = metadata
            # The original crash-control values are retained once and restored after the suite.
            script("$path='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CrashControl';"
                "if(-not(Test-Path C:\\MatrixHVNotMyFault\\crash-control-before.json)){"
                "$before=@{};foreach($key in @('CrashDumpEnabled','AutoReboot','LogEvent','AlwaysKeepMemoryDump')){"
                "$before[$key]=(Get-ItemProperty $path).$key};$before|ConvertTo-Json|Set-Content C:\\MatrixHVNotMyFault\\crash-control-before.json};"
                "New-ItemProperty $path -Name CrashDumpEnabled -PropertyType DWord -Value 3 -Force | Out-Null;"
                "New-ItemProperty $path -Name AutoReboot -PropertyType DWord -Value 0 -Force | Out-Null;"
                "New-ItemProperty $path -Name LogEvent -PropertyType DWord -Value 1 -Force | Out-Null;"
                "New-ItemProperty $path -Name AlwaysKeepMemoryDump -PropertyType DWord -Value 1 -Force | Out-Null;"
                "Get-CimInstance Win32_PageFileUsage | Select-Object Name,AllocatedBaseSize | ConvertTo-Json -Compress", admin=True)
            guest = 'C:\\MatrixHVNotMyFault\\' + name
            script(f"New-Item -ItemType Directory -Path '{guest}' -Force | Out-Null")
            if active:
                fixture_data = (project / 'tests/interception_vm_fixture.ps1').read_bytes()
                script(f"[IO.File]::WriteAllBytes('{guest}\\fixture.ps1',[byte[]]@())")
                for offset in range(0, len(fixture_data), 4096):
                    encoded = base64.b64encode(fixture_data[offset:offset + 4096]).decode()
                    script(f"$stream=[IO.File]::Open('{guest}\\fixture.ps1',[IO.FileMode]::Append);try{{$bytes=[Convert]::FromBase64String('{encoded}');$stream.Write($bytes,0,$bytes.Length)}}finally{{$stream.Dispose()}}")
                broker(f"Start-Process powershell.exe -WindowStyle Hidden -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File {guest}\\fixture.ps1 -OutputDirectory {guest}' -RedirectStandardOutput '{guest}\\fixture-out.txt' -RedirectStandardError '{guest}\\fixture-error.txt' | Out-Null")
                fixture = json.loads(script(f"for($attempt=0;$attempt -lt 400;++$attempt){{if(Test-Path '{guest}\\fixture.json'){{Get-Content -Raw '{guest}\\fixture.json';exit 0}};Start-Sleep -Milliseconds 25}};throw 'Fixture initialization failed'"))
                root = field(remote(guest_neo, 'read', fixture['pid'], 'auto'), 'cr3')
                installed = remote(guest_neo, 'hook', 'install', root, fixture['first'], 'b833000000', '--no-lease', '--concurrent-writes')
                assert field(installed, 'state') == 'active'
                record['hook'] = installed
                fixture_command('start-stress', expected=51, interval_ms=10)
                time.sleep(1)
                writers = fixture_command('stress-status')
                assert writers['running'] and not writers['error'] and all(value > 0 for value in writers['counts']), writers
                record['writers_before'] = writers
            else:
                stopped = script(f"& '{guest_neo}' matrix off;if($LASTEXITCODE -ne 0){{throw 'MatrixHV stop failed'}};& '{guest_neo}' matrix status", admin=True)
                assert field(stopped, 'active') == '0x0' and field(stopped, 'stopped') == '0xff', stopped
                record['native_status'] = stopped
            before = capture(directory, 'before')
            assert all(item['host_fault_vector'] == (1 << 64) - 1 and not item['resume_failures'] and not item['entry_failure_state'] for item in resident_health(before))
            body = (f"$ErrorActionPreference='Stop';[ordered]@{{utc=[DateTime]::UtcNow.ToString('o');kind='{kind}';type='{fault_type}';admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}} | ConvertTo-Json -Compress | Set-Content '{guest}\\launch.json';"
                f"$stream=[IO.File]::Open('{guest}\\launch.json',[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read);try{{$stream.Flush($true)}}finally{{$stream.Dispose()}};"
                f"$p=Start-Process 'C:\\MatrixHVNotMyFault\\tools\\notmyfaultc64.exe' -WindowStyle Hidden -ArgumentList '-accepteula','/{kind}','{fault_type}' -PassThru -RedirectStandardOutput '{guest}\\notmyfault-out.txt' -RedirectStandardError '{guest}\\notmyfault-error.txt';"
                f"$p.Id | Set-Content '{guest}\\notmyfault.pid';$p.WaitForExit();$p.ExitCode | Set-Content '{guest}\\exit-code.txt'")
            record['launcher_pid'] = broker(body, admin=True)
            record['launch_host_time'] = time.time()
            save()
            time.sleep(12)
            for sample in ('fault-1', 'fault-2'):
                state = capture(directory, sample)
                record[sample] = resident_health(state)
                save()
                if sample == 'fault-1':
                    time.sleep(5)
            try:
                record['guest_observation'] = script(f"Get-Content -Raw '{guest}\\launch.json';Get-Content -Raw '{guest}\\notmyfault-out.txt';if(Test-Path '{guest}\\exit-code.txt'){{'EXIT='+(Get-Content '{guest}\\exit-code.txt')}};Get-CimInstance Win32_SystemDriver | Where-Object {{$_.Name -match 'myfault'}} | Select-Object Name,State,PathName | ConvertTo-Json -Compress", timeout=7)
                if active:
                    record['writers_after'] = fixture_command('stress-status')
            except Exception as error:
                record['guest_observation_error'] = repr(error)
            host_failed = any(item['host_fault_vector'] != (1 << 64) - 1 or item['resume_failures'] or item['entry_failure_state'] for sample in ('fault-1', 'fault-2') for item in record[sample])
            fixture_failed = bool(record.get('writers_after', {}).get('error'))
            record['status'] = 'HYPERVISOR_FAILURE' if host_failed else 'INTERCEPTION_FAILURE' if fixture_failed else 'CAPTURED'
            save()
            restart()
            record['recovered'] = True
            record['recovery_status'] = remote(guest_neo, 'matrix', 'status')
            assert field(record['recovery_status'], 'active') == '0xff' and field(record['recovery_status'], 'failed') == '0x0'
            record['after_boot'] = script("(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('o')").strip()
            assert record['after_boot'] != metadata['boot']
            prepare_admin()
            record['dumps'] = script("if(Test-Path C:\\Windows\\Minidump){@(Get-ChildItem C:\\Windows\\Minidump -File | Select-Object Name,Length,LastWriteTime) | ConvertTo-Json -Compress}else{'[]'}", admin=True)
            record['durable_observation'] = json.loads(script(
                f"$files=@{{}};foreach($name in @('launch.json','notmyfault-out.txt','notmyfault-error.txt','exit-code.txt')){{"
                f"$path=Join-Path '{guest}' $name;if(Test-Path $path){{$files[$name]=[IO.File]::ReadAllText($path)}}}};"
                "$files | ConvertTo-Json -Compress"))
            save()
            current_log.close()
            current_log = None
            print('CAPTURED', name, 'host_failed=' + str(host_failed), flush=True)
            if host_failed or fixture_failed:
                raise AssertionError('MatrixHV failure captured; preserve evidence before another case')
        summary['status'] = 'CLEANED' if args.cleanup_only else 'CAPTURED'
    except Exception as error:
        summary['status'] = 'FAIL'
        summary['error'] = repr(error)
        save()
        if not recovered:
            try:
                restart()
                summary['recovered_after_failure'] = True
            except Exception as recovery_error:
                summary['recovery_error'] = repr(recovery_error)
        raise
    finally:
        if recovered:
            try:
                cleanup()
            except Exception as error:
                summary['cleanup_error'] = repr(error)
                if summary['status'] in ('CAPTURED', 'CLEANED'):
                    summary['status'] = 'CLEANUP_FAILURE'
        if current_log:
            current_log.close()
        save()
    if summary.get('cleanup_error'):
        raise AssertionError(summary['cleanup_error'])

if __name__ == '__main__':
    main()
