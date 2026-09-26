from pathlib import Path
import re
import subprocess


project = Path(__file__).resolve().parents[1]
output = project / "builds" / "ept-cache-tests"
output.mkdir(parents=True, exist_ok=True)
source = (project / "src/core/vt_ept.rs").read_text(encoding="utf-8")


def item(declaration):
    start = source.index(declaration)
    opening = source.index("{", start)
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


policy = "#[repr(u64)]\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n" + item("enum EptMemoryType")
policy += "\n#[repr(C)]\n" + item("struct MtrrState")
policy += "\nimpl MtrrState {\n" + item("fn memory_type(") + "\n}\n"
policy += "\n" + item("fn decode_memory_type(") + "\n" + item("fn combine_memory_types(")
policy += "\n" + item("fn next_mapped_chunk(")
policy += "\n" + item("fn align_up(") + "\n" + item("fn high_address_mapping_end(")
policy += "\n" + "\n".join(re.findall(
    r"const (?:EPT_GUEST_PHYSICAL_LIMIT|EPT_MINIMUM_MAPPED_END|EPT_2MB_PAGE_SIZE|EPT_1GB_PAGE_SIZE|EPT_512GB_PAGE_SIZE):[^;]+;", source
))
assembly = (project / "src/asm/ept_cache.S").read_text(encoding="utf-8")
transaction = assembly[assembly.index(".Lresident_update_dirty_mtrrs:"):assembly.index(".Lresident_rebuild_ept_cache:")]
transaction = transaction.replace("{guest_cr0}", "0").replace("{cr0_read_shadow}", "1")
transaction = transaction.replace("{b_mtrr_dirty}", "0")
transaction = transaction.replace(
    "vmread r11, rax", "mov r11, [r12 + 8 + rax * 8]\ncmp r12, 0"
)
transaction += """
.Lresident_rebuild_ept_cache:
    inc qword ptr [r12 + 24]
    ret
.Lresident_dispatch_vmread_failed:
    ud2
.globl test_cache_transaction
test_cache_transaction:
    push r12
    mov r12, rcx
    call .Lresident_update_dirty_mtrrs
    pop r12
    ret
"""
(output / "ept-transaction.S").write_text(".text\n" + transaction, encoding="utf-8")
start = assembly.index(".Lresident_cache_update_table:")
end = assembly.index("// Each CPU retires", start)
assembly = assembly[start:end].replace("{host_page_address_mask}", "0x000ffffffffff000")
wrapper = """
.text
.globl test_cache_type
test_cache_type:
    push rdi
    push r15
    mov r15, rcx
    mov rdi, rdx
    lea r10, [rdx + r8]
    call .Lresident_cache_range_type
    pop r15
    pop rdi
    ret
.globl test_cache_update
test_cache_update:
    push rdi
    push r15
    mov r15, rcx
    mov rdi, rdx
    mov edx, r8d
    call .Lresident_cache_update_table
    pop r15
    pop rdi
    ret
"""
(output / "ept-cache.S").write_text(wrapper + assembly, encoding="utf-8")
cases = (project / "tests/ept_cache.rs").read_text(encoding="utf-8")
harness = output / "harness.rs"
harness.write_text(policy + "\n" + cases, encoding="utf-8")
binary = output / "ept-cache-tests.exe"
subprocess.run(["rustc", "--edition=2024", "--test", str(harness), "-o", str(binary)], check=True)
subprocess.run([str(binary)], check=True)

high_policy = "use core::ptr::NonNull;\n"
high_policy += "#[repr(u64)]\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n" + item("enum EptMemoryType")
high_policy += "\nimpl IdentityEpt {\n" + item("pub fn map_high_address_gaps(") + "\n}\n"
for declaration in [
    "fn high_address_mapping_end(",
    "fn align_up(",
    "fn write_entry(",
    "fn read_entry(",
    "fn table_from_entry(",
    "fn table_entry(",
    "fn leaf_entry(",
]:
    high_policy += "\n" + item(declaration)
high_policy += "\n" + "\n".join(re.findall(
    r"const (?:EPT_READ|EPT_WRITE|EPT_EXECUTE|EPT_PERMISSIONS|EPT_LARGE_PAGE|EPT_MEMORY_TYPE_SHIFT|EPT_FIRMWARE_TYPE_SHIFT|EPT_ADDRESS_MASK|EPT_MINIMUM_MAPPED_END|EPT_2MB_PAGE_SIZE|EPT_1GB_PAGE_SIZE|EPT_512GB_PAGE_SIZE|EPT_ENTRY_COUNT|EPT_CAP_1GB_PAGE):[^;]+;",
    source,
))
high_cases = (project / "tests/ept_high.rs").read_text(encoding="utf-8")
high_harness = output / "high-harness.rs"
high_harness.write_text(high_policy + "\n" + high_cases, encoding="utf-8")
high_binary = output / "ept-high-tests.exe"
subprocess.run(["rustc", "--edition=2024", "--test", str(high_harness), "-o", str(high_binary)], check=True)
subprocess.run([str(high_binary)], check=True)
