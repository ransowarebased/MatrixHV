"""Run the real recorder assembly with VMREAD replaced by a deterministic model."""
from pathlib import Path
import re
import subprocess

project = Path(__file__).resolve().parents[1]
output = project / 'builds/flight-recorder-tests'
output.mkdir(parents=True, exist_ok=True)
source = (project / 'src/asm/diagnostics.S').read_text()
assembly = source.split('.macro matrixhv_island_flight_recorder', 1)[1].split('.endm', 1)[0]
offsets = dict(b_flight_sequence=0, b_flight_frozen=8, b_last_reason=16,
               b_last_guest_rip=24, b_last_qualification=32, b_processor_number=40,
               b_nested_active=48, b_nested_l2_active=56, b_nested_current_vmcs=64,
               b_telemetry_active=96, b_flight_records=104, flight_capacity_mask=2047, flight_record_bytes=80,
               ept_violation_reason=48, ept_misconfiguration_reason=49,
               guest_physical_address=0x2400, vm_instruction_error=0x4400)
assembly = re.sub(r'\{(\w+)\}', lambda match: str(offsets[match[1]]), assembly)
assembly = assembly.replace('vmread r11, rax', 'call .Ltest_vmread')
assembly += '''
.balign 8
matrixhv_resident_island_log_backend:
.quad 0
.Ltest_vmread:
cmp qword ptr [r12 + 88], 0
jne .Ltest_vmread_failed
cmp eax, 0x2400
jne .Ltest_vmread_error
mov r11, qword ptr [r12 + 72]
jmp .Ltest_vmread_success
.Ltest_vmread_error:
mov r11, qword ptr [r12 + 80]
.Ltest_vmread_success:
cmp r12, 0
ret
.Ltest_vmread_failed:
stc
ret
.globl test_record_exit
test_record_exit:
push r12
mov r12, rcx
sub rsp, 16
mov qword ptr [rsp + 8], r8
push rdx
popfq
call .Lresident_flight_record_exit
pushfq
pop rax
add rsp, 16
pop r12
ret
.globl test_record_failure
test_record_failure:
push r12
mov r12, rcx
push rdx
popfq
call .Lresident_flight_record_entry_failure
pushfq
pop rax
pop r12
ret
'''
(output / 'recorder.S').write_text('.text\n' + assembly)
binary = output / 'flight_recorder_tests.exe'
subprocess.run(['rustc', '--edition=2024', '-Dwarnings', '--test',
                str(project / 'tests/flight_recorder_tests.rs'), '-o', str(binary)], cwd=project, check=True)
subprocess.run([str(binary)], cwd=project, check=True)
