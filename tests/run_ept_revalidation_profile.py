"""Profile uncached reference EPT walks, validate their data layout and restore sources."""

from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess
import sys

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'builds/validation/ept-revalidation-profile'
PATHS = ['src/vmx/asm/nested.S', 'src/asm/diagnostics.S',
         None, 'tests/nested_tests.rs', 'src/vmx/asm/island.S']


def replace_once(text, old, new):
    assert text.count(old) == 1, (old[:90], text.count(old))
    return text.replace(old, new, 1)


def prepare():
    OUT.mkdir(parents=True, exist_ok=True)
    sources = {name: (ROOT / name).read_bytes() for name in PATHS}
    for name, data in sources.items():
        backup = OUT / (Path(name).name + '.original')
        if backup.exists():
            assert backup.read_bytes() == data, f'Existing backup differs: {name}'
        else:
            backup.write_bytes(data)
    text = sources[PATHS[0]].decode()
    cached_call = 'lea rdi, [rdx + 16]\ncall .Lresident_nested_translate_ept02_revalidate'
    if cached_call in text:
        # Measure repeated reference walks rather than silently profiling cache hits.
        text = replace_once(text, cached_call, 'xor edi, edi\ncall .Lresident_nested_translate_ept02')
        text = replace_once(text, 'mov qword ptr [rsp], 256\nmov qword ptr [rsp + 16], 0',
                            'mov qword ptr [rsp], 256')
    start = text.index('.Lresident_nested_translate_ept02:')
    end = text.index('.Lresident_nested_track_ept12_access:', start)
    translation = text[start:end]
    labels = re.findall(r'^(\.L\w+):', translation, re.M)
    for label in sorted(labels, key=len, reverse=True):
        translation = re.sub(re.escape(label) + r'\b', label + '_profile', translation)
    assert translation.count('mov r10, qword ptr [rsi]') == 4
    for level in (4, 3, 2, 1):
        translation = translation.replace('mov r10, qword ptr [rsi]\nresident_nested_ept12_permissions ' + str(level),
            'mov r10, qword ptr [rsi]\npush rcx\nmov ecx, ' + str(level) +
            '\ncall .Lresident_ept_profile_entry\npop rcx\nresident_nested_ept12_permissions ' + str(level), 1)
    helpers = r'''
// Experimental, sampled diagnostic state. No translations are reused here.
.Lresident_ept_profile_begin:
xor eax, eax
cmp qword ptr [r12 + {b_telemetry_active}], 0
je .Lresident_ept_profile_begin_done
mov rcx, qword ptr [r12 + {b_processor_number}]
cmp rcx, 64
jae .Lresident_ept_profile_begin_done
shl rcx, 9
lea r11, [rip + .Lresident_ept_profile_slots]
add r11, rcx
inc qword ptr [r11]
test byte ptr [r11], 63
jnz .Lresident_ept_profile_begin_done
inc qword ptr [r11 + 8]
mov qword ptr [r11 + 176], 0
xor edx, edx
mov qword ptr [r11 + 200], rdx
mov qword ptr [r11 + 208], rdx
mov qword ptr [r11 + 216], rdx
mov qword ptr [r11 + 224], rdx
mov qword ptr [r11 + 232], rdx
mov qword ptr [r11 + 240], rdx
mov qword ptr [r11 + 248], rdx
mov qword ptr [r11 + 256], rdx
lfence
rdtsc
shl rdx, 32
or rax, rdx
mov qword ptr [r11 + 184], rax
mov rax, r11
.Lresident_ept_profile_begin_done:
ret
.Lresident_ept_profile_entry:
pushfq
push rax
push rdx
push r9
mov rax, qword ptr [r12 + {b_processor_number}]
shl rax, 9
lea rdx, [rip + .Lresident_ept_profile_slots]
add rax, rdx
mov edx, 4
sub edx, ecx
lea r9, [rdx + rdx * 2]
inc qword ptr [rax + r9 * 8 + 64]
cmp qword ptr [rax + rdx * 8 + 200], rsi
jne .Lresident_ept_profile_entry_first
inc qword ptr [rax + r9 * 8 + 72]
cmp qword ptr [rax + rdx * 8 + 232], r10
jne .Lresident_ept_profile_entry_first
inc qword ptr [rax + r9 * 8 + 80]
.Lresident_ept_profile_entry_first:
mov qword ptr [rax + rdx * 8 + 200], rsi
mov qword ptr [rax + rdx * 8 + 232], r10
pop r9
pop rdx
pop rax
popfq
ret
'''
    text = replace_once(text, '.Lresident_nested_guest_msr_list_is_mapped:',
                        helpers + translation + '\n.Lresident_nested_guest_msr_list_is_mapped:')
    text = replace_once(text, 'mov qword ptr [rsp], 256\nmov rdx, rsp',
                        'mov qword ptr [rsp], 256\ncall .Lresident_ept_profile_begin\nmov qword ptr [rsp + 8], rax\nmov rdx, rsp')
    finish = r'''
push rax
push rdx
push rcx
mov r11, qword ptr [rsp + 32]
test r11, r11
jz .Lresident_ept_profile_finished
lfence
rdtsc
shl rdx, 32
or rax, rdx
sub rax, qword ptr [r11 + 184]
add qword ptr [r11 + 160], rax
cmp qword ptr [rsp + 16], 0
je .Lresident_ept_profile_discarded
inc qword ptr [r11 + 16]
jmp .Lresident_ept_profile_finished
.Lresident_ept_profile_discarded:
inc qword ptr [r11 + 24]
mov rax, qword ptr [r11 + 176]
add qword ptr [r11 + 168], rax
.Lresident_ept_profile_finished:
pop rcx
pop rdx
pop rax
'''
    text = replace_once(text, 'mov ecx, 39\ncall .Lresident_nested_revalidate_ept02_table\ntest eax, eax',
                        'mov ecx, 39\ncall .Lresident_nested_revalidate_ept02_table\n' + finish + '\ntest eax, eax')
    text = replace_once(text,
        'mov r9, qword ptr [r12 + {b_nested_ept12_pointer}]\nxor edi, edi\ncall .Lresident_nested_translate_ept02\ncmp eax, 1',
        '''mov rdx, qword ptr [rsp + 40]
mov rax, qword ptr [rdx + 8]
test rax, rax
jz .Lresident_ept_profile_normal_leaf
inc qword ptr [rax + 32]
inc qword ptr [rax + 176]
mov r9, qword ptr [r12 + {b_nested_ept12_pointer}]
xor edi, edi
call .Lresident_nested_translate_ept02_profile
jmp .Lresident_ept_profile_leaf_result
.Lresident_ept_profile_normal_leaf:
mov r9, qword ptr [r12 + {b_nested_ept12_pointer}]
xor edi, edi
call .Lresident_nested_translate_ept02
.Lresident_ept_profile_leaf_result:
cmp eax, 1''')
    text = replace_once(text, '''cmp qword ptr [rdi], r13
je .Lresident_nested_revalidate_ept02_next
mov qword ptr [rdi], r13''', '''mov rdx, qword ptr [rsp + 40]
mov rdx, qword ptr [rdx + 8]
cmp qword ptr [rdi], r13
je .Lresident_ept_profile_unchanged
test rdx, rdx
jz .Lresident_ept_profile_write_leaf
inc qword ptr [rdx + 48]
.Lresident_ept_profile_write_leaf:
mov qword ptr [rdi], r13''')
    text = replace_once(text, '.Lresident_nested_revalidate_ept02_remove:\n', '''.Lresident_ept_profile_unchanged:
test rdx, rdx
jz .Lresident_nested_revalidate_ept02_next
inc qword ptr [rdx + 40]
jmp .Lresident_nested_revalidate_ept02_next
.Lresident_nested_revalidate_ept02_remove:
mov rdx, qword ptr [rsp + 40]
mov rdx, qword ptr [rdx + 8]
test rdx, rdx
jz .Lresident_ept_profile_remove_leaf
inc qword ptr [rdx + 56]
.Lresident_ept_profile_remove_leaf:
''')
    diagnostics = sources[PATHS[1]].decode()
    diagnostics = replace_once(diagnostics, 'cmp ecx, {ept_diagnostic_subleaf}\n', '''cmp ecx, 0x380
jb .Lresident_ept_profile_query_done
cmp ecx, 0x38c
jb .Lresident_ept_profile_query
.Lresident_ept_profile_query_done:
cmp ecx, {ept_diagnostic_subleaf}
''')
    diagnostics = replace_once(diagnostics, '.Lresident_dispatch_cpuid_ept_sync_diagnostics:', '''.Lresident_ept_profile_query:
cmp ecx, 0x380
jne .Lresident_ept_profile_query_data
mov eax, 1
xor ebx, ebx
mov ecx, 64
xor edx, edx
jmp .Lresident_dispatch_cpuid_diagnostic_store
.Lresident_ept_profile_query_data:
sub ecx, 0x381
mov r10, qword ptr [r8 + {b_processor_number}]
cmp r10, 64
jae .Lresident_dispatch_cpuid_diagnostic_zero
shl r10, 9
lea r9, [rip + .Lresident_ept_profile_slots]
add r10, r9
jmp .Lresident_dispatch_cpuid_ept_diagnostic_pair
.Lresident_dispatch_cpuid_ept_sync_diagnostics:''')
    neo = sources[PATHS[2]].decode()
    names = ['calls', 'samples', 'completed', 'discarded', 'leaves', 'unchanged', 'changed', 'removed']
    for level in (4, 3, 2, 1):
        names += [f'l{level}_reads', f'l{level}_repeat_address', f'l{level}_repeat_value']
    names += ['sampled_walk_cycles', 'discarded_leaves']
    neo = replace_once(neo, '            if caps.eax & EPT_RECYCLING_CAPABILITY != 0 && mode != Mode::Watchdog {', '''            let (profile_version, sample_period) = pair(diagnostic_cpu(0x380, cpu));
            if profile_version == 1 && mode != Mode::Watchdog {
                writeln!(sample, "{prefix}.ept_revalidation.sample_period={sample_period}").unwrap();
                let names = ''' + json.dumps(names) + ''';
                for (index, names) in names.chunks_exact(2).enumerate() {
                    let (first, second) = pair(diagnostic_cpu(0x381 + index as u32, cpu));
                    writeln!(sample, "{prefix}.ept_revalidation.{}={first}", names[0]).unwrap();
                    writeln!(sample, "{prefix}.ept_revalidation.{}={second}", names[1]).unwrap();
                }
            }
            if caps.eax & EPT_RECYCLING_CAPABILITY != 0 && mode != Mode::Watchdog {''')
    tests = sources[PATHS[3]].decode()
    tests = replace_once(tests, '        lists_live: u64,\n', '        lists_live: u64,\n        processor_number: u64,\n')
    tests = replace_once(tests, '        test_lists_live = const std::mem::offset_of!(Context, lists_live),',
                        '        test_lists_live = const std::mem::offset_of!(Context, lists_live),\n        b_processor_number = const std::mem::offset_of!(Context, processor_number),')
    marker = '    #[test]\n    fn revalidation_updates_remaps_permissions_and_memory_type() {'
    tests = replace_once(tests, marker, '    include!("ept_revalidation_profile_tests.rs");\n\n' + marker)
    island = sources[PATHS[4]].decode()
    island = replace_once(island, 'matrixhv_resident_eptp_switch_state\n', '''matrixhv_resident_eptp_switch_state
.balign 64
.globl matrixhv_ept_profile_slots
matrixhv_ept_profile_slots:
.Lresident_ept_profile_slots:
.zero 32768
''')
    manifest = {}
    for name, patched in zip(PATHS, (text, diagnostics, neo, tests, island)):
        encoded = patched.encode()
        (ROOT / name).write_bytes(encoded)
        (OUT / (Path(name).name + '.instrumented')).write_bytes(encoded)
        manifest[name] = {'original_sha256': hashlib.sha256(sources[name]).hexdigest(),
                          'instrumented_sha256': hashlib.sha256(encoded).hexdigest()}
    (OUT / 'instrumentation-manifest.json').write_text(json.dumps(manifest, indent=2))


def restore():
    manifest = json.loads((OUT / 'instrumentation-manifest.json').read_text())
    for name in PATHS:
        target = ROOT / name
        current = hashlib.sha256(target.read_bytes()).hexdigest()
        assert current in manifest[name].values(), f'Source changed independently: {name}'
    for name in PATHS:
        target = ROOT / name
        target.write_bytes((OUT / (Path(name).name + '.original')).read_bytes())


def test():
    from harness import prepare_nested_ept

    for period in (1, 64):
        prepare_nested_ept(ROOT)
        if period == 1:
            assembly = ROOT / 'builds/nested-ept-tests/resident-ept.S'
            assembly.write_bytes(assembly.read_bytes().replace(
                b'test byte ptr [r11], 63', b'test byte ptr [r11], 0'))
        binary = OUT / f'profile-tests-{period}.exe'
        subprocess.run(['rustc', '--edition=2024', '-Dwarnings', '--test',
                        '--cfg', 'test_harness="ept"', str(ROOT / 'tests/nested_tests.rs'),
                        '-o', str(binary)], check=True, cwd=ROOT)
        result = subprocess.run([str(binary), '--test-threads=1'], cwd=ROOT,
                                capture_output=True, text=True)
        (OUT / f'profile-tests-{period}.txt').write_text(result.stdout + result.stderr)
        print(result.stdout.splitlines()[-2])
        result.check_returncode()


def layout():
    from resident_image import validate_image

    object_path = max((ROOT / 'builds/.cargo-target/x86_64-unknown-uefi/release/deps').glob('MatrixHV-*.o'),
                      key=lambda path: path.stat().st_mtime_ns)
    image, symbols = validate_image(object_path)
    start = symbols['matrixhv_ept_profile_slots']
    code_end = symbols['matrixhv_resident_code_end']
    assert start >= code_end, 'Profiling counters must be in the writable data region'
    assert start % 64 == 0 and start + 32768 <= len(image)
    assert not any(image[start:start + 32768])
    result = {'object': str(object_path), 'image_bytes': len(image),
              'code_end': code_end, 'profile_data_start': start,
              'profile_data_bytes': 32768, 'writable_layout_verified': True}
    (OUT / 'profile-layout.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['prepare', 'test', 'layout', 'restore'])
    parser.add_argument('--output', type=Path, default=OUT)
    parser.add_argument('--neo-source', type=Path,
                        help='Path to src/telemetry.rs in a separate Neo checkout (modified by prepare and restore)')
    arguments = parser.parse_args()
    if arguments.mode in ('prepare', 'restore'):
        if arguments.neo_source is None or not arguments.neo_source.is_file():
            parser.error('prepare and restore require --neo-source from a separate Neo checkout')
        PATHS[2] = str(arguments.neo_source.resolve())
    OUT = arguments.output.resolve()
    OUT.relative_to((ROOT / 'builds').resolve())
    {'prepare': prepare, 'test': test, 'layout': layout, 'restore': restore}[arguments.mode]()
