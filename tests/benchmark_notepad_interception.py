"""Measure idle Notepad interception overhead with three paired conditions."""

import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--entry', required=True)
    parser.add_argument('--redirect', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seconds', type=float, default=10)
    parser.add_argument('--rounds', type=int, default=3)
    args = parser.parse_args()
    if args.seconds <= 0 or args.rounds <= 0:
        parser.error('Seconds and rounds must be positive')
    project = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.relative_to(project / 'builds')
    output.mkdir(parents=True, exist_ok=False)
    neo_path = project / 'builds/release/neo.exe'
    log = (output / 'commands.log').open('w', encoding='utf-8', buffering=1)

    def neo(*operands):
        result = subprocess.run([str(neo_path), *map(str, operands)],
                                capture_output=True, text=True, timeout=30)
        log.write('COMMAND ' + ' '.join(map(str, operands)) + '\n' + result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        return result.stdout

    def field(text, name):
        match = re.search(r'\b' + re.escape(name) + r'=([^\s]+)', text)
        if not match:
            raise RuntimeError('Missing field: ' + name)
        return match[1]

    initial = neo('hook', 'status')
    (output / 'initial-profile.txt').write_text(initial)
    if field(initial, 'state') != 'disabled':
        raise RuntimeError('An existing interception profile must be released before measurement')
    process_info = neo('read', args.pid, 'auto')
    if field(process_info, 'name').lower() != 'notepad.exe':
        raise RuntimeError('The selected process must be notepad.exe')
    root = field(process_info, 'cr3')
    identity = field(neo('read', args.pid, 'auto', args.entry, 4), 'data')
    redirect_bytes = field(neo('read', args.pid, 'auto', args.redirect, 18), 'data')
    expected_redirect = identity + 'ff2500000000' + (int(args.entry, 0) + 4).to_bytes(8, 'little').hex()
    if identity != '4883ec28' or redirect_bytes != expected_redirect:
        raise RuntimeError('The provided trampoline does not replay the validated entry instruction')

    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.QueryProcessCycleTime.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_ulonglong)]
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel.GetSystemTimes.argtypes = [ctypes.POINTER(wintypes.FILETIME)] * 3
    handle = kernel.OpenProcess(0x1000, False, args.pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())

    def ticks(value):
        return (value.dwHighDateTime << 32) | value.dwLowDateTime

    def cpu_snapshot():
        creation, exited, process_kernel, process_user = [wintypes.FILETIME() for _ in range(4)]
        idle, system_kernel, system_user = [wintypes.FILETIME() for _ in range(3)]
        cycles = ctypes.c_ulonglong()
        if not kernel.GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exited),
                                      ctypes.byref(process_kernel), ctypes.byref(process_user)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel.GetSystemTimes(ctypes.byref(idle), ctypes.byref(system_kernel), ctypes.byref(system_user)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel.QueryProcessCycleTime(handle, ctypes.byref(cycles)):
            raise ctypes.WinError(ctypes.get_last_error())
        return dict(time=time.perf_counter(), process=ticks(process_kernel) + ticks(process_user),
                    cycles=cycles.value, idle=ticks(idle), system=ticks(system_kernel) + ticks(system_user))

    def telemetry(name):
        path = output / (name + '.txt')
        neo('telemetry', '--output', path)
        text = path.read_text()
        values = {key: int(value, 0) for key, value in
                  re.findall(r'^(cpu\.\d+\.[\w.]+)=(0x[0-9a-fA-F]+|\d+)$', text, re.MULTILINE)}
        if not values or any(value != 1 for key, value in values.items() if key.endswith('.telemetry_enabled')):
            raise RuntimeError('Enabled telemetry is required on all measured CPUs')
        return values, int(field(text, 'sample_unix_ms'))

    counters = {'exits': 'exits', 'ept': 'exit_reason.48', 'mtf': 'exit_reason.37',
                'cr3': 'cr3_exits', 'exception': 'exit_reason.0',
                'timer': 'preemption_timer_exits', 'handler_cycles': 'handler_cycles.other'}
    token = None
    runs = []
    manifest = dict(pid=args.pid, cr3=root, entry=args.entry, redirect=args.redirect,
                    workload='Notepad idle; identity entrypoint patch; no target invocation',
                    exit_scope='All registered vCPUs, including background activity and observers',
                    clock_unit='Handler TSC ticks; process cycles from QueryProcessCycleTime',
                    cpu_unit='Percent of total logical CPU capacity; Windows accounting',
                    logical_processors=os.cpu_count(), warmup_seconds=2,
                    seconds=args.seconds, rounds=args.rounds, runs=runs)

    def save(status):
        manifest['status'] = status
        (output / 'results.json').write_text(json.dumps(manifest, indent=2))

    def release():
        nonlocal token
        if token is not None:
            neo('hook', 'release', token)
            token = None

    try:
        telemetry('preflight')
        for repetition in range(1, args.rounds + 1):
            order = ['none', 'split_mtf', 'debug_registers']
            order = order[repetition - 1:] + order[:repetition - 1]
            for condition in order:
                release()
                if condition == 'split_mtf':
                    token = field(neo('hook', 'install', root, args.entry, identity,
                                      '--lease-ms', '120000'), 'token')
                elif condition == 'debug_registers':
                    token = field(neo('debug-registers', 'set', root, args.entry, args.redirect), 'token')
                name = f'{condition}-{repetition}'
                print('BEGIN ' + name, flush=True)
                time.sleep(2)
                profile_before = neo('hook', 'status')
                before, before_ms = telemetry(name + '-before')
                cpu_before = cpu_snapshot()
                time.sleep(args.seconds)
                cpu_after = cpu_snapshot()
                after, after_ms = telemetry(name + '-after')
                profile_after = neo('hook', 'status')
                (output / (name + '-profile-before.txt')).write_text(profile_before)
                (output / (name + '-profile-after.txt')).write_text(profile_after)
                if condition != 'none' and (field(profile_after, 'state') != 'active'
                                             or field(profile_after, 'token') != token):
                    raise RuntimeError('Interception profile expired or changed during measurement')
                elapsed = cpu_after['time'] - cpu_before['time']
                counter_seconds = (after_ms - before_ms) / 1000
                deltas = {}
                for label, suffix in counters.items():
                    keys = [key for key in before if re.fullmatch(r'cpu\.\d+\.' + re.escape(suffix), key)]
                    if not keys or any(after[key] < before[key] for key in keys):
                        raise RuntimeError('Missing or reset counter: ' + suffix)
                    deltas[label] = sum(after[key] - before[key] for key in keys)
                cycle_keys = [key for key in before if re.fullmatch(
                    r'cpu\.\d+\.handler_cycles\.(vmcs|nested_entry|other|invept)', key)]
                if any(after[key] < before[key] for key in cycle_keys):
                    raise RuntimeError('Handler cycle counters reset during measurement')
                deltas['handler_cycles'] = sum(after[key] - before[key] for key in cycle_keys)
                system_delta = cpu_after['system'] - cpu_before['system']
                process_seconds = (cpu_after['process'] - cpu_before['process']) / 1e7
                run = dict(condition=condition, repetition=repetition, seconds=elapsed,
                           counter_seconds=counter_seconds,
                           deltas=deltas, exits_per_second=deltas['exits'] / counter_seconds,
                           handler_tsc_ticks_per_exit=deltas['handler_cycles'] / deltas['exits'] if deltas['exits'] else None,
                           notepad_cycles=cpu_after['cycles'] - cpu_before['cycles'],
                           notepad_cpu_percent=100 * process_seconds / elapsed / os.cpu_count(),
                           system_cpu_percent=100 * (1 - (cpu_after['idle'] - cpu_before['idle']) / system_delta),
                           hit_delta=int(field(profile_after, 'hits')) - int(field(profile_before, 'hits')))
                runs.append(run)
                save('RUNNING')
                print(json.dumps(run), flush=True)
                release()
        metrics = ['exits_per_second', 'handler_tsc_ticks_per_exit', 'notepad_cycles',
                   'notepad_cpu_percent', 'system_cpu_percent']
        manifest['medians'] = {condition: {metric: statistics.median(
            run[metric] for run in runs if run['condition'] == condition) for metric in metrics}
            for condition in ['none', 'split_mtf', 'debug_registers']}
        save('PASS')
        print(json.dumps(manifest['medians'], indent=2), flush=True)
    except BaseException as error:
        manifest['error'] = str(error)
        save('FAILED')
        raise
    finally:
        try:
            release()
            (output / 'final-profile.txt').write_text(neo('hook', 'status'))
        finally:
            kernel.CloseHandle(handle)
            log.close()


if __name__ == '__main__':
    main()
