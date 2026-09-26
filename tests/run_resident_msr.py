from pathlib import Path
import re
import subprocess


project = Path(__file__).resolve().parents[1]
output = project / "builds" / "resident-msr-tests"
output.mkdir(parents=True, exist_ok=True)
source = (project / "src/core/vt_resident.rs").read_text(encoding="utf-8")
assembly_source = (project / "src/asm/resident_island.S").read_text(encoding="utf-8")
start = assembly_source.index('.Lresident_nested_complete_vmcs02_msr_exit:')
end = assembly_source.index('.Lresident_nested_activate_vmcs01_msr_entry:', start)
assembly = assembly_source[start:end].strip()
start = assembly_source.index('.Lresident_validate_efer:')
end = assembly_source.index('.Lresident_guarded_rdmsr:', start)
assembly += "\n" + assembly_source[start:end].strip()
wrapper = """
.text
.globl test_validate_efer
test_validate_efer:
    push rbx
    mov rbx, rcx
    mov r11, [rcx]
    mov r8, rdx
    mov rdx, r9
    mov r9, [rsp + 48]
    call .Lresident_validate_efer
    setnc al
    movzx eax, al
    mov [rbx], r11
    pop rbx
    ret
.globl test_validate_canonical
test_validate_canonical:
    mov r11, rcx
    mov r9, rdx
    call .Lresident_validate_canonical_msr
    setnc al
    movzx eax, al
    ret
.globl test_complete_msr_exit
test_complete_msr_exit:
    push r12
    push rsi
    push rdi
    mov r12, rcx
    mov qword ptr [rip + matrixhv_resident_island_msr_switch_count], rdx
    mov r10d, r8d
    call .Lresident_nested_complete_vmcs02_msr_exit
    pop rdi
    pop rsi
    pop r12
    ret
.Lresident_nested_host_msr_list_is_mapped:
    mov eax, 1
    ret
.data
.balign 8
matrixhv_resident_island_msr_switch_count:
    .quad 0
.text
"""
(output / "resident-msr.S").write_text(wrapper + assembly, encoding="utf-8")
start = assembly_source.index('.Lresident_deliver_pending_nmi:')
end = assembly_source.index('.Lresident_validate_efer:', start)
nmi = assembly_source[start:end].strip()
nmi = nmi.replace("vmread r11, rax", "mov r11, [r12 + {test_vmcs} + rax * 8]\ncmp r12, 0")
nmi = nmi.replace("vmwrite rax, r11", "mov [r12 + {test_vmcs} + rax * 8], r11\ncmp r12, 0")
nmi += "\n.Lresident_dispatch_vmread_failed:\n.Lresident_dispatch_vmwrite_failed:\nud2\n"
nmi += """
.globl test_deliver_nmi
test_deliver_nmi:
    push r12
    mov r12, rcx
    call .Lresident_deliver_pending_nmi
    pop r12
    ret
"""
(output / "resident-nmi.S").write_text(nmi, encoding="utf-8")
start = assembly_source.index('.Lresident_dispatch_cache_flush:')
end = assembly_source.index('.Lresident_nested_l2_reflect:', start)
cache_flush = assembly_source[start:end].strip()
cache_flush = cache_flush.replace("wbinvd", "inc qword ptr [r12 + 8]")
cache_flush += """
.Lresident_msr_privilege:
    bt qword ptr [r12], 0
    ret
.Lresident_dispatch_inject_gp:
    mov qword ptr [r12 + 24], 1
    ret
.Lresident_advance_guest_rip:
    add qword ptr [r12 + 16], 2
    ret
.Lresident_dispatch_resume:
    ret
.globl test_cache_flush
test_cache_flush:
    push r12
    mov r12, rcx
    call .Lresident_dispatch_cache_flush
    pop r12
    ret
"""
(output / "resident-cache-flush.S").write_text(".text\n" + cache_flush, encoding="utf-8")
start = source.index("    allow_low_msr_passthrough(&msr_bitmap, IA32_ARCH_CAPABILITIES_MSR);")
end = source.index("    // L1 owns the local APIC", start)
bitmap_policy = "fn clock_bitmap() -> ResidentPages {\nlet msr_bitmap = ResidentPages::new();\n"
bitmap_policy += source[start:end] + "\nmsr_bitmap\n}\n"
start = source.index("fn allow_low_msr_passthrough(")
end = source.index("fn allow_high_msr_passthrough(", start)
bitmap_policy += source[start:end]
for name in set(re.findall(r"\b(?:IA32_[A-Z0-9_]+|MSR_BITMAP_WRITE_LOW_OFFSET)\b", bitmap_policy)):
    bitmap_policy += re.search(rf"const {name}:[^;]+;", source)[0] + "\n"
start = source.index("fn spec_ctrl_available(")
end = source.index("\n}", start) + 2
cases = (project / "tests/resident_msr.rs").read_text(encoding="utf-8")
harness = output / "harness.rs"
harness.write_text(source[start:end] + "\n" + bitmap_policy + cases, encoding="utf-8")
binary = output / "resident-msr-tests.exe"
subprocess.run(["rustc", "--edition=2024", "--test", str(harness), "-o", str(binary)], check=True)
subprocess.run([str(binary)], check=True)
