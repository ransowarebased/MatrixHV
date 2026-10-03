"""Prepare host harnesses for the component suites executed by run_alltests.py."""

import ast
from pathlib import Path
import re
import struct
import subprocess
import textwrap


def read_resident_rust(project: Path) -> str:
    return (project / "src/protocol.rs").read_text(encoding="utf-8") + "\n" + "\n".join((project / "src/core" / name).read_text(encoding="utf-8")
                     for name in ("resident/mod.rs", "resident/abi.rs", "resident/boot.rs", "state.rs", "msr.rs", "nested.rs", "bridge.rs", "entry.rs", "exits.rs"))


def read_resident_assembly(project: Path) -> str:
    assembly = project / "src" / "asm"
    island = (assembly / "island.S").read_text(encoding="utf-8")
    macros = "\n".join(
        (assembly / name).read_text(encoding="utf-8")
        for name in ("nested.S", "hyperv.S", "exits.S", "msr.S", "control.S", "diagnostics.S", "ept_cache.S", "eptp_switch.S", "ap_startup.S")
    )
    lines = macros.splitlines(keepends=True)
    definitions = {}
    expansions = {}
    helpers = []
    index = 0
    while index < len(lines):
        declaration = re.fullmatch(
            r"\.macro ((?:matrixhv_|resident_hyperv_|resident_diagnostic_)\w+)(?:[ \t]+([^\n]*))?[ \t]*\n?", lines[index]
        )
        helper = re.fullmatch(r"\.macro resident_\w+[^\n]*\s*", lines[index])
        if declaration is None and helper is None:
            index += 1
            continue
        name = declaration[1] if declaration else None
        declaration_index = index
        start = index + 1
        index = start
        depth = 1
        while index < len(lines):
            directive = lines[index].strip()
            if directive.startswith(".macro "):
                depth += 1
            elif directive == ".endm":
                depth -= 1
                if depth == 0:
                    break
            index += 1
        if depth:
            raise ValueError(f"Unterminated resident assembly macro: {name}")
        if name is None:
            helpers.append("".join(lines[declaration_index:index + 1]))
        else:
            definitions[name] = ("".join(lines[start:index]),
                                 [argument.strip() for argument in (declaration[2] or "").split(",") if argument.strip()])
            expansions[name] = 0
        index += 1
    for _ in range(len(definitions) + 1):
        changed = False
        for name, (body, parameters) in definitions.items():
            invocation = re.compile(rf"^{re.escape(name)}(?:[ \t]+([^\n]*))?\n", re.MULTILINE)
            def expand(match, body=body, parameters=parameters):
                arguments = [argument.strip() for argument in (match[1] or "").split(",") if argument.strip()]
                if len(arguments) != len(parameters):
                    raise ValueError(f"Invalid arguments for resident macro {name}: {arguments}")
                result = body
                for parameter, argument in zip(parameters, arguments):
                    result = re.sub(rf"\\{re.escape(parameter)}\b", lambda match, argument=argument: argument, result)
                return result
            island, count = invocation.subn(expand, island)
            expansions[name] += count
            changed |= count != 0
        if not changed:
            for name, count in expansions.items():
                if count < 1 or (name.startswith("matrixhv_") and count != 1):
                    expected = "one" if name.startswith("matrixhv_") else "at least one"
                    raise ValueError(f"Expected {expected} resident expansion for {name}, found {count}")
            result = "\n".join(helpers) + island
            hyperv = (project / "src/hyperv.rs").read_text(encoding="utf-8")
            values = {name: int(value.replace("_", ""), 0) for name, value in re.findall(
                r"pub const (HYPERV\w*): u32 = (0x[0-9a-fA-F_]+|[0-9_]+);", hyperv)}
            aliases = {"vendor_leaf": "HYPERVISOR_LEAF_START", "msr_base": "HYPERV_GUEST_OS_ID_MSR"}
            return re.sub(r"\{hv_(\w+)\}", lambda match: str(values[
                aliases.get(match[1], "HYPERV_" + match[1].upper())]), result)
    raise ValueError("Cyclic resident assembly macro composition")


def prepare_boot_order(project: Path):
    output = project / "builds/boot-order-tests"
    output.mkdir(parents=True, exist_ok=True)
    source = (project / "src" / "firmware.rs").read_text(encoding="utf-8")
    start = source.index("mod boot_order {")
    end = source.index("\npub(crate) mod memory_map {", start)
    parser = source[start:end]
    start = source.index("fn same_hd_partition(")
    end = source.index("\npub fn initialize_boot_environment(", start)
    parser += "\n" + source[start:end]
    (output / "definitions.rs").write_text(parser, encoding="utf-8")




def prepare_ept_cache(project: Path):
    output = project / "builds" / "ept-cache-tests"
    output.mkdir(parents=True, exist_ok=True)
    source = (project / "src/core/ept.rs").read_text(encoding="utf-8")
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
    (output / "definitions.rs").write_text(policy, encoding="utf-8")
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
    (output / "high-definitions.rs").write_text(high_policy, encoding="utf-8")


def prepare_eptp_sync(project: Path):
    output = project / "builds" / "eptp-sync-tests"
    output.mkdir(parents=True, exist_ok=True)
    source = (project / "src/asm/eptp_switch.S").read_text()
    start = source.index(".Lresident_nested_eptp_sync_acquire:")
    end = source.index(".endm", start)
    assembly = source[start:end]
    state_start = source.index(".macro matrixhv_resident_eptp_switch_state")
    state_start = source.index("\n", state_start) + 1
    assembly += source[state_start:source.index(".endm", state_start)]
    assert assembly.count("invept rax, xmmword ptr [rsp]") == 1
    assembly = assembly.replace(
        "invept rax, xmmword ptr [rsp]",
        "inc qword ptr [r12 + {test_flushes}]\nmov eax, 1\ntest eax, eax",
    )
    assert assembly.count("vmread r11, rax") == 1
    assembly = assembly.replace(
        "vmread r11, rax",
        "mov r11, qword ptr [r12 + {test_exit_info}]\n"
        "push rax\nmov eax, 1\ntest eax, eax\npop rax",
    )
    assembly = assembly.replace(".balign 8\n.Lresident_eptp_sync_owner:",
                                ".data\n.balign 8\n.Lresident_eptp_sync_owner:")
    (output / "eptp-sync.S").write_text(assembly + "\n.text\n")


def prepare_logger(project: Path):
    output = project / "builds" / "logger-tests"
    output.mkdir(parents=True, exist_ok=True)
    runtime = (project / "src/runtime.rs").read_text(encoding="utf-8")
    screen = (project / "src/diagnostics.rs").read_text(encoding="utf-8")
    def item(source, declaration):
        start = source.index(declaration)
        opening = source.index("{", start)
        depth = 1
        end = opening + 1
        while depth:
            depth += (source[end] == "{") - (source[end] == "}")
            end += 1
        return source[start:end]
    backend = "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n" + item(runtime, "pub(crate) enum LogBackend")
    selector = item(runtime, "fn select_backend(")
    toggle = item(runtime, "pub fn set_enabled(")
    active_backend = item(runtime, "pub(crate) fn backend(")
    probe = item(runtime, "fn probe_com1(")
    firmware_guard = item(screen, "fn firmware_calls_allowed(")
    constants = "\n".join(
        re.findall(r"(?:pub\(crate\) )?const (?:COM1|TRANSMIT_EMPTY|TX_WAIT_LIMIT):[^;]+;", runtime)
        + re.findall(r"pub\(crate\) const (?:SERIAL_SINK|FRAMEBUFFER_SINK):[^;]+;", runtime)
    )
    backend_state = "\n".join(re.findall(
        r"static (?:BACKEND|SERIAL_PRESENT):[^;]+;", runtime
    ))
    (output / "definitions.rs").write_text("\n".join([
        "use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};",
        backend, backend_state, selector, toggle, active_backend, probe, firmware_guard, constants,
    ]), encoding="utf-8")


def prepare_evmcs(project: Path):
    output = project / "builds" / "evmcs-tests"
    output.mkdir(parents=True, exist_ok=True)
    source = read_resident_assembly(project)
    nested_rust = (project / 'src/nested.rs').read_text(encoding='utf-8')
    width_start = nested_rust.index('        let physical_address_bits =')
    width_end = nested_rust.index('        Self {', width_start)
    width = nested_rust[width_start:width_end].replace('__cpuid', 'cpuid')
    (output / 'physical-width.rs').write_text(
        'fn test_physical_width(cpuid: impl Fn(u32) -> core::arch::x86_64::CpuidResult) -> u32 {\n'
        + width + '\nphysical_address_bits\n}\n', encoding='utf-8')
    event = source[source.index('.Lresident_nested_entry_event_is_valid:'):
                   source.index('.Lresident_nested_value_is_canonical:')]
    tsc_start = source.index('mov rax, {tsc_offset}\nmov r11, qword ptr [r12 + {b_nested_inherited_l1_tsc_offset}]')
    tsc = source[tsc_start:source.index('call .Lresident_nested_write_vmcs02_control', tsc_start)]
    validation = '''
    .text
    .globl test_entry_event
    test_entry_event:
        push r12
        mov r12, rcx
        call .Lresident_nested_entry_event_is_valid
        pop r12
        ret
    .globl test_tsc_composition
    test_tsc_composition:
        push r12
        mov r12, rcx
    ''' + tsc + '\nmov rax, r11\npop r12\nret\n' + event
    completion = source.split('call .Lresident_nested_complete_vmcs02_msr_exit\n', 1)[1].split(
        'mov qword ptr [r12 + {b_nested_l2_active}], 0', 1)[0]
    completion = '.Ltest_complete_evmcs_exit:\n' + completion + 'ret\n'
    routing = source[source.index('.Lresident_nested_l2_route:'):
                     source.index('.Lresident_nested_l2_reflect:')]
    routing = routing.replace('{b_last_reason}', '{b_nested_vmcs12_exit_reason}')
    handlers = source[
        source.index(".Lresident_hyperv_evmcs_select:"):
        source.index(".Lresident_dispatch_vmclear:")
    ]
    vmclear = source[source.index('.Lresident_dispatch_vmclear:'):
                     source.index('.Lresident_dispatch_vmlaunch:')]
    vmclear = vmclear.replace('vmread r11, rax', 'xor r11d, r11d\ncmp r12, 0')
    vmclear = re.sub(r'^vmclear .*$', 'cmp r12, 0', vmclear, flags=re.MULTILINE)
    vmptrld = source[source.index('.Lresident_dispatch_vmptrld:'):
                     source.index('.Lresident_dispatch_vmptrst:')]
    vmptrld = vmptrld.replace('vmread r11, rax', 'xor r11d, r11d\ncmp r12, 0')
    vmptrld = re.sub(r'^resident_telemetry_counter .*$', '', vmptrld, flags=re.MULTILINE)
    vmptrld = vmptrld.replace('call .Lresident_nested_load_vmcs12_backing', 'call .Ltest_load_backing')
    vmptrld += source[source.index('.Lresident_nested_load_vmcs12_backing:'):
                      source.index('.Lresident_hyperv_evmcs_select:')].replace(
                          '.Lresident_nested_load_vmcs12_backing:', '.Ltest_load_backing:')
    vmptrld += '\n.Lresident_nested_shadow_sync:\nret\n'
    backing = source[source.index('.Lresident_nested_initialize_vmcs12_backing:'):
                     source.index('.Lresident_nested_load_vmcs12_backing:')]
    entry_mode = source[source.index('.Lresident_nested_capture_vmcs02_guest_state:'):
                        source.index('.Lresident_nested_capture_vmcs02_entry_mode_done:')]
    entry_mode = entry_mode.replace('vmread r11, rax', 'call .Ltest_entry_mode_vmread')
    entry_mode += '.Lresident_nested_capture_vmcs02_entry_mode_done:\nret\n'
    shadow_intercept = source[
        source.index(".Lresident_nested_shadow_intercept_reads:"):
        source.index(".Lresident_nested_shadow_sync:")
    ]
    field_map = source[
        source.index(".Lresident_evmcs_field_map:"):
        source.index(".Lresident_vmcs12_field_index_table:")
    ]
    island = read_resident_assembly(project)
    translation = island[island.index('.Lresident_ept01_page_is_readable:'):
                         island.index('.Lresident_dispatch_xsetbv:')]
    assist_write = island[island.index('.Lresident_dispatch_wrmsr_vp_assist:'):
                          island.index('.Lresident_dispatch_wrmsr_hyperv_apic:')]
    cpuid = island[island.index('.Lresident_dispatch_cpuid_evmcs:'):
                   island.index('.Lresident_dispatch_cpuid_matrixhv:')]
    cpuid = cpuid.replace('{hyperv_features_leaf}', '0x40000003')
    cpuid = cpuid.replace('{b_nested_evmcs_enabled}', '8').replace('{b_hyperv_timing_supported}', '0')
    cpuid = cpuid.replace('{b_event_context}', '16').replace('{event_hyperv_tsc_invariant_supported}', '0')
    cpuid_wrapper = """
    .text
    .globl test_evmcs_cpuid
    test_evmcs_cpuid:
        push rsi
        push r12
        sub rsp, 64
        lea r12, [rsp + 32]
        mov qword ptr [r12], 0
        mov qword ptr [r12 + 8], 1
        lea rax, [rsp + 56]
        mov [r12 + 16], rax
        mov qword ptr [rax], 0
        mov rsi, rdx
        mov r8d, ecx
        jmp .Lresident_dispatch_cpuid_evmcs
    .Lresident_dispatch_cpuid_advance:
        mov rax, [rsp]
        mov [rsi], eax
        mov rax, [rsp + 24]
        mov [rsi + 4], eax
        mov rax, [rsp + 8]
        mov [rsi + 8], eax
        mov rax, [rsp + 16]
        mov [rsi + 12], eax
        add rsp, 64
        pop r12
        pop rsi
        ret
    """
    wrapper = """
    .text
    .globl test_select_evmcs
    test_select_evmcs:
        push rbx
        push r12
        push r13
        push rsi
        push rdi
        mov r12, rcx
        call .Lresident_hyperv_evmcs_select
        pop rdi
        pop rsi
        pop r13
        pop r12
        pop rbx
        ret
    .globl test_route_l2_cpuid
    test_route_l2_cpuid:
        push r12
        sub rsp, 8
        mov r12, rcx
        mov [rsp], rdx
        jmp .Lresident_nested_l2_route
    .Lresident_dispatch_cpuid:
        mov eax, 1
        jmp .Ltest_route_l2_done
    .Lresident_nested_l2_reflect:
        xor eax, eax
    .Ltest_route_l2_done:
        add rsp, 8
        pop r12
        ret
    .globl test_store_evmcs
    test_store_evmcs:
        push rbx
        push r12
        push r13
        push rsi
        push rdi
        mov r12, rcx
        mov qword ptr [r12 + {b_nested_failure_count}], 0
        call .Lresident_hyperv_evmcs_store
        pop rdi
        pop rsi
        pop r13
        pop r12
        pop rbx
        ret
    .globl test_complete_evmcs_exit
    test_complete_evmcs_exit:
        push rbx
        push r12
        push r13
        push rsi
        push rdi
        mov r12, rcx
        call .Ltest_complete_evmcs_exit
        pop rdi
        pop rsi
        pop r13
        pop r12
        pop rbx
        ret
    .Lresident_nested_physical_address_is_valid:
        mov eax, 1
        ret
    .Lresident_ept01_host_page_is_mapped:
        xor eax, eax
        cmp r11, [r12 + {b_nested_host_mapping_cache}]
        setne al
        ret
    .globl test_write_vp_assist
    test_write_vp_assist:
        push rbx
        push r12
        push r13
        push r14
        push r15
        push rsi
        push rdi
        sub rsp, 32
        mov r12, rcx
        mov eax, edx
        mov [rsp], rax
        shr rdx, 32
        mov [rsp + 16], rdx
        jmp .Lresident_dispatch_wrmsr_vp_assist
    .globl test_clear_evmcs
    test_clear_evmcs:
        push rbx
        push r12
        push r13
        push r14
        push r15
        push rsi
        push rdi
        sub rsp, 32
        mov r12, rcx
        mov [rsp], rdx
        jmp .Lresident_dispatch_vmclear
    .globl test_load_vmcs
    test_load_vmcs:
        push rbx
        push r12
        push r13
        push r14
        push r15
        push rsi
        push rdi
        sub rsp, 32
        mov r12, rcx
        mov [rsp], rdx
        jmp .Lresident_dispatch_vmptrld
    .Lresident_nested_decode_memory_operand:
        lea r10, [rsp + 8]
        mov [r12 + {b_nested_operand_linear_address}], r10
        clc
        ret
    .Lresident_nested_read_operand_range:
        mov r10, [r12 + {b_nested_operand_linear_address}]
        clc
        ret
    .Lresident_nested_succeed:
    .Lresident_dispatch_resume:
        mov eax, 1
        jmp .Ltest_page_handler_done
    .Lresident_dispatch_wrmsr_passthrough:
        mov eax, 2
        jmp .Ltest_page_handler_done
    .Lresident_nested_vmfail_with_error:
    .Lresident_nested_inject_ud:
    .Lresident_nested_inject_gp:
    .Lresident_nested_inject_pf_read:
    .Lresident_dispatch_inject_gp:
        xor eax, eax
    .Ltest_page_handler_done:
        add rsp, 32
        pop rdi
        pop rsi
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbx
        ret
    .Lresident_dispatch_halt:
    .Lresident_dispatch_vmread_failed:
        ud2
    .Ltest_evmcs_store_failed:
        inc qword ptr [r12 + {b_nested_failure_count}]
        ret
    .globl test_capture_evmcs_entry_mode
    test_capture_evmcs_entry_mode:
        push r12
        push r13
        mov r12, rcx
        mov r13, rdx
        call .Lresident_nested_capture_vmcs02_guest_state
        pop r13
        pop r12
        ret
    .Ltest_entry_mode_vmread:
        xor r11d, r11d
        cmp rax, {guest_efer}
        cmove r11, r13
        cmp r12, 0
        ret
    .Lresident_advance_guest_rip:
    .Lresident_nested_store_current_vmcs12:
    .Lresident_nested_materialize_vmcs02_rare_state:
    .Lresident_nested_eptp_before_root_write:
        ret
    """
    (output / "handlers.S").write_text(
        wrapper + validation + routing + completion + handlers.replace('jz .Lresident_dispatch_halt', 'jz .Ltest_evmcs_store_failed') + vmclear + vmptrld + backing + entry_mode + assist_write
        + translation + shadow_intercept + cpuid_wrapper + cpuid + ".balign 8\n" + field_map,
        encoding="utf-8",
    )


def prepare_vmcs_shadow(project: Path):
    output = project / "builds/vmcs-shadow-tests"
    output.mkdir(parents=True, exist_ok=True)
    source = read_resident_assembly(project)
    handlers = source[
        source.index(".Lresident_nested_shadow_intercept_reads:"):
        source.index(".Lresident_nested_translate_current_vmcs:")
    ]
    handlers = handlers.replace(
        "vmptrld [r12 + {b_nested_shadow_vmcs_region}]",
        "mov qword ptr [r12 + {test_current_vmcs}], 1\ntest r12, r12",
    ).replace(
        "vmptrld [r12 + {b_nested_vmcs01_region}]",
        "mov qword ptr [r12 + {test_current_vmcs}], 0\ntest r12, r12",
    ).replace("vmwrite rax, r11", "call .Ltest_vmwrite").replace(
        "vmclear [r12 + {b_nested_shadow_vmcs_region}]", "test r12, r12"
    )
    wrapper = """
    .text
    .globl test_shadow_sync
    test_shadow_sync:
        push rdi
        push r12
        mov r12, rcx
        call .Lresident_nested_shadow_sync
        pop r12
        pop rdi
        ret
    .globl test_shadow_write
    test_shadow_write:
        push rdi
        push r12
        mov r12, rcx
        mov rax, rdx
        mov r11, r8
        call .Lresident_nested_shadow_write
        pop r12
        pop rdi
        ret
    .globl test_shadow_intercept
    test_shadow_intercept:
        push rdi
        push r12
        mov r12, rcx
        call .Lresident_nested_shadow_intercept_reads
        pop r12
        pop rdi
        ret
    .Ltest_vmwrite:
        cmp qword ptr [r12 + {test_current_vmcs}], 1
        jne .Lresident_dispatch_halt
        cmp rax, {host_rsp}
        je .Ltest_write_rsp
        cmp rax, {host_rip}
        jne .Lresident_dispatch_halt
        mov qword ptr [r12 + {test_shadow_rip}], r11
        jmp .Ltest_write_done
    .Ltest_write_rsp:
        mov qword ptr [r12 + {test_shadow_rsp}], r11
    .Ltest_write_done:
        mov eax, 1
        test eax, eax
        ret
    .Lresident_dispatch_halt:
        ud2
    """
    (output / "handlers.S").write_text(wrapper + handlers, encoding="utf-8")


def prepare_native_shadow(project: Path):
    output = project / "builds/native-shadow-tests"
    output.mkdir(parents=True, exist_ok=True)
    source = read_resident_assembly(project)
    def block(start, end):
        begin = source.index(start)
        return source[begin:source.index(end, begin)]
    assembly = block(".Lresident_nested_translate_current_vmcs:", ".Lresident_dispatch_vmread:")
    assembly += block(".Lresident_nested_validate_entry:", ".Lresident_vmcs12_field_index:")
    switch_source = (project / "src/asm/eptp_switch.S").read_text()
    start = switch_source.index(".Lresident_nested_validate_vm_functions:")
    assembly += switch_source[start:switch_source.index(".Lresident_nested_prepare_ept02:", start)]
    assembly += "\n.Lresident_nested_vmfunc_failed:\nxor eax, eax\nret\n"
    assembly += block(".Lresident_nested_physical_address_is_valid:", ".Lresident_nested_resolve_ept02_violation:")
    assembly += block(".Lresident_dispatch_vmptrld:", ".Lresident_dispatch_vmptrst:")
    assembly += block(".Lresident_nested_vmclear_ordinary:", ".Lresident_nested_vmclear_software:")
    assembly += block(".Lresident_nested_shadow_intercept_reads:", ".Lresident_nested_shadow_sync:")
    assembly += block(".Lresident_nested_vmwrite_operands_ready:", ".Lresident_nested_shadow_intercept_reads:")
    assembly += block(".Lresident_vmcs12_field_index:", "// Cache controls")
    assembly += block(".Lresident_vmcs12_field_index_table:", ".balign 8")
    assembly += block(".Lresident_nested_sync_vmcs02_guest_state:", "mov rax, {guest_pat}") + "ret\n"
    for name in ("vmlaunch", "vmresume"):
        start = f".Lresident_nested_{name}_vmcs_ready:"
        part = source[source.index(start):]
        assembly += part[:part.index("mov rax, {guest_interruptibility_info}")] + "xor eax, eax\nret\n"
    assembly = re.sub(r"^resident_telemetry_counter .*\n", "", assembly, flags=re.MULTILINE)
    assembly = assembly.replace("vmwrite r10, r11", "call .Ltest_write_shadow")
    assembly = assembly.replace("vmread r11, r10", "call .Ltest_read_shadow")
    assembly = assembly.replace("vmread r11, rax", "call .Ltest_read_vmcs01")
    assembly = assembly.replace("vmwrite rax, r11", "mov [r12 + {test_rflags}], r11\ntest r12, r12")
    for field in ("b_nested_current_vmcs_hpa", "b_nested_vmcs01_region"):
        assembly = assembly.replace(
            "vmptrld [r12 + {" + field + "}]",
            "push rax\nmov rax, [r12 + {" + field + "}]\n"
            "mov [r12 + {test_selected}], rax\npop rax\ntest r12, r12",
        )
    assembly = re.sub(r"vmclear (\[[^\n]+\])", r"push rax\nmov rax, \1\n"
                      r"mov [r12 + {test_cleared}], rax\n"
                      r"inc qword ptr [r12 + {test_clear_count}]\npop rax\ntest r12, r12", assembly)
    # The pushed scratch register shifts only the stack-based VMCLEAR operand.
    assembly = assembly.replace("mov rax, [rsp]\nmov [r12 + {test_cleared}]", "mov rax, [rsp + 8]\nmov [r12 + {test_cleared}]")
    wrappers = ".text\n"
    entries = {
        "write": "native_shadow_vmwrite", "read": "native_shadow_vmread",
        "validate": "validate_shadow_controls", "flush": "flush_l1_shadow",
        "load": "dispatch_vmptrld", "clear": "vmclear_ordinary",
        "link": "sync_vmcs02_guest_state", "launch": "vmlaunch_vmcs_ready",
        "resume": "vmresume_vmcs_ready",
        "field": "shadow_field_available",
        "software_write": "vmwrite_operands_ready",
        "entry": "validate_entry",
    }
    for name, label in entries.items():
        target = ".Lresident_" + label if name == "load" else ".Lresident_nested_" + label
        wrappers += f"""
        .globl test_native_shadow_{name}
        test_native_shadow_{name}:
            push rbx
            push rsi
            push rdi
            push r12
            push r13
            push r14
            mov r12, rcx
            mov r10, rdx
            mov r11, r8
            call {target}
            {"mov eax, r10d" if name == "entry" else ""}
            pop r14
            pop r13
            pop r12
            pop rdi
            pop rsi
            pop rbx
            ret
        """
    wrappers += """
    .Ltest_write_shadow:
        mov [r12 + {test_shadow_value}], r11
        push qword ptr [r12 + {test_native_flags}]
        popfq
        ret
    .Ltest_read_shadow:
        mov r11, [r12 + {test_shadow_value}]
        push qword ptr [r12 + {test_native_flags}]
        popfq
        ret
    .Ltest_read_vmcs01:
        xor r11d, r11d
        cmp eax, {guest_cs_selector}
        je .Ltest_read_vmcs01_done
        mov r11, [r12 + {test_rflags}]
    .Ltest_read_vmcs01_done:
        test r12, r12
        ret
    .Lresident_ept01_page_is_readable:
    .Lresident_ept01_page_is_writable:
        add r11, [r12 + {test_translation_delta}]
    .Lresident_ept01_host_page_is_mapped:
        mov rax, [r12 + {test_mapped}]
        ret
    .Lresident_nested_eptp_before_root_write:
        inc qword ptr [r12 + {test_root_writes}]
        ret
    .Lresident_nested_decode_memory_operand:
        lea r10, [r12 + {test_operand}]
        mov [r12 + {b_nested_operand_linear_address}], r10
        clc
        ret
    .Lresident_nested_read_operand_range:
        mov r10, [r12 + {b_nested_operand_linear_address}]
        clc
        ret
    .Lresident_nested_store_current_vmcs12:
        inc qword ptr [r12 + {test_stores}]
        ret
    .Lresident_nested_initialize_vmcs12_backing:
    .Lresident_nested_load_vmcs12_backing:
    .Lresident_nested_shadow_sync:
    .Lresident_nested_shadow_write:
    .Lresident_nested_materialize_guest_field:
        ret
    .Lresident_nested_write_vmcs02_control:
        mov [r12 + {test_link}], r11
        ret
    .Lresident_nested_vmread_value:
        mov [r12 + {test_read_value}], r11
    .Lresident_nested_succeed:
        xor eax, eax
        ret
    .Lresident_advance_guest_rip:
        inc qword ptr [r12 + {test_advances}]
        ret
    .Lresident_dispatch_resume:
        xor eax, eax
        ret
    .Lresident_nested_vmfail_with_error:
        mov rax, r10
        ret
    .Lresident_nested_vmfail_invalid_no_current_vmcs:
        mov rax, -1
        ret
    .Lresident_nested_vmclear_software:
        mov eax, 100
        ret
    .Lresident_nested_vmclear_invalid_address:
        mov eax, 2
        ret
    .Lresident_nested_inject_gp:
    .Lresident_nested_inject_ud:
    .Lresident_nested_inject_pf_read:
    .Lresident_dispatch_vmread_failed:
    .Lresident_dispatch_vmwrite_failed:
    .Lresident_dispatch_halt:
        ud2
    """
    assembly = wrappers + assembly
    constants = {
        "guest_rflags": 0x6820, "guest_cs_selector": 0x802, "vmread_reason": 23,
        "vmx_status_flags_clear_mask": -2262, "vmcs_link_pointer": 0x2800,
        "vmptrld_invalid_physical_address_error": 9, "vmptrld_vmxon_pointer_error": 10,
        "vmptrld_incorrect_revision_error": 11,
        "vmcs_unsupported_component_error": 12,
        "vmwrite_read_only_component_error": 13, "vmcs12_extended_field_count": 122,
        "vmcs_field_guest_rip": 0x681e, "vmcs_field_guest_rsp": 0x681c,
        "vmcs_field_guest_rflags": 0x6820, "vmcs_field_host_rsp": 0x6c14,
        "vmcs_field_host_rip": 0x6c16, "vmcs_field_instruction_error": 0x4400,
        "vmcs_field_exit_reason": 0x4402, "vmcs_field_exit_instruction_len": 0x440c,
        "vmcs_field_exit_qualification": 0x6400,
        "vmcs_shadow_read_byte_offset": 0xd82, "vmcs_shadow_read_bypass_mask": 0x50,
        "nested_guest_msr_list_capacity": 512,
        "vm_entry_invalid_control_fields_error": 7,
        "vm_entry_invalid_host_state_field_error": 8,
    }
    fields = sorted(set(re.findall(r"\{((?:b_|test_)\w+)\}", assembly)))
    offsets = {}
    cursor = 0
    for name in fields:
        offsets[name] = cursor
        cursor += 122 * 8 if name == "b_nested_vmcs12_extended_fields" else 8
    values = constants | offsets
    assembly = re.sub(r"\{(\w+)\}", lambda match: str(values[match[1]]), assembly)
    (output / "handlers.S").write_text(assembly, encoding="utf-8")
    mapping = f"const CONTEXT_QWORDS: usize = {cursor // 8};\nfn offset(name: &str) -> usize {{ match name {{\n"
    mapping += "\n".join(f'"{name}" => {value // 8},' for name, value in offsets.items())
    mapping += '\n_ => panic!("unknown shadow field {name}"),\n} }\n'
    (output / "offsets.rs").write_text(mapping, encoding="utf-8")


def prepare_nested_ept(project: Path):
    output = project / "builds" / "nested-ept-tests"
    output.mkdir(parents=True, exist_ok=True)
    source = read_resident_assembly(project)
    switch_source = (project / "src/asm/eptp_switch.S").read_text()
    exit_msr_start = source.index('.Lresident_nested_capture_vmcs02_guest_state:')
    exit_msr_end = source.index('lea rsi, [rip + .Lresident_nested_guest_state_table]', exit_msr_start)
    exit_msr_assembly = source[exit_msr_start:exit_msr_end].replace(
        "vmread r11, rax",
        "mov r11, qword ptr [r12 + {test_hardware} + rax * 8]\n"
        "push rax\nmov eax, 1\ntest eax, eax\npop rax",
    )
    (output / "resident-exit-msrs.S").write_text(exit_msr_assembly + "ret\n")
    start = source.index('.Lresident_nested_resolve_ept02_violation:')
    end = source.index('.Lresident_nested_guest_msr_list_is_mapped:')
    prepare_start = switch_source.index('.Lresident_nested_prepare_ept02:')
    prepare_end = switch_source.index('.Lresident_nested_activate_vmcs02_ept:')
    invept_start = source.index('.Lresident_nested_invalidate_ept12_context:')
    invept_end = source.index('.Lresident_dispatch_invvpid:', invept_start)
    assembly = (switch_source[prepare_start:prepare_end] + source[start:end] + source[invept_start:invept_end]).strip()
    vmfunc_start = switch_source.index('.Lresident_nested_switch_eptp:')
    vmfunc_end = switch_source.index('.Lresident_nested_prepare_ept02:', vmfunc_start)
    address_start = source.index('.Lresident_nested_physical_address_is_valid:')
    address_end = source.index('.Lresident_nested_resolve_ept02_violation:', address_start)
    vmfunc_assembly = (switch_source[vmfunc_start:vmfunc_end] + source[address_start:address_end]).replace(
        '.Lresident_nested_physical_address_is_valid', '.Ltest_vmfunc_physical_address_is_valid'
    ).replace('.Lresident_nested_address_width_is_valid', '.Ltest_vmfunc_address_width_is_valid')
    for suffix in ('invalid', 'valid'):
        vmfunc_assembly = vmfunc_assembly.replace(
            '.Lresident_nested_physical_address_' + suffix,
            '.Ltest_vmfunc_physical_address_' + suffix,
        )
    assembly += '\n' + vmfunc_assembly
    native_start = switch_source.index('.Lresident_nested_refresh_eptp_list:')
    native_end = switch_source.index('.Lresident_nested_vmfunc:')
    native = switch_source[native_start:native_end]
    native = native.replace('.Lresident_dispatch_vmwrite_failed', '.Lresident_dispatch_vmread_failed')
    native = native.replace(
        'vmwrite rax, r11',
        'mov qword ptr [r12 + {test_native_vmcs} + rax * 8], r11\n'
        'push rax\nmov eax, 1\ntest eax, eax\npop rax',
    ).replace(
        'vmread r10, rax',
        'mov r10, qword ptr [r12 + {test_native_vmcs} + rax * 8]\n'
        'push rax\nmov eax, 1\ntest eax, eax\npop rax',
    )
    assembly += '\n' + native
    assembly = assembly.replace(
        '[rip + .Lresident_eptp_lists_live]', '[r12 + {test_lists_live}]'
    )
    flush_start = switch_source.index('.Lresident_nested_eptp_sync_flush_local:')
    flush_end = switch_source.index('.Lresident_nested_eptp_sync_enter:', flush_start)
    assembly += '\n' + switch_source[flush_start:flush_end]
    assembly += (
        '\n.Lresident_nested_eptp_sync_acquire:\n'
        'inc qword ptr [r12 + {test_sync_requests}]\n'
        'mov rax, qword ptr [r12 + {test_sync_result}]\nret\n'
        '.Lresident_nested_eptp_sync_end:\n'
        'inc qword ptr [r12 + {test_sync_releases}]\nret\n'
        '.Lresident_nested_eptp_sync_poll:\nret\n'
    )
    macro_start = source.index('.macro resident_telemetry_counter ')
    macro_end = source.index('.endm', macro_start) + len('.endm')
    assembly = source[macro_start:macro_end] + "\n" + assembly
    assert assembly.count("vmread r8, rax") == 1
    assert assembly.count("invept rax, xmmword ptr [rsp]") == 2
    assembly = assembly.replace(
        "vmread r8, rax",
        "mov r8, qword ptr [r12 + {b_last_guest_physical_address}]\n"
        "mov eax, 1\ntest eax, eax",
    ).replace("invept rax, xmmword ptr [rsp]", "mov eax, 1\ntest eax, eax")
    assembly += "\n.Lresident_dispatch_vmread_failed:\n.Lresident_dispatch_halt:\nud2\n"
    (output / "resident-ept.S").write_text(assembly)
    guest_start = source.index('.Lresident_nested_sync_vmcs02_guest_fields:')
    guest_end = source.index('.Lresident_nested_capture_vmcs02_guest_state:')
    table_start = source.index('.Lresident_nested_guest_state_table:')
    table_end = source.index('.Lresident_nested_host_state_table:')
    guest_assembly = (source[guest_start:guest_end] + source[table_start:table_end]).strip()
    assert guest_assembly.count("vmwrite rax, r11") == 1
    guest_assembly = guest_assembly.replace(
        "vmwrite rax, r11",
        "mov qword ptr [r12 + {test_hardware} + rdx * 8], r11\n"
        "inc qword ptr [r12 + {test_writes}]\nmov eax, 1\ntest eax, eax",
    )
    guest_assembly += "\n.Lresident_dispatch_vmwrite_failed:\nud2\n"
    capture_start = source.index('.Lresident_nested_capture_vmcs02_guest_state_loop:')
    capture_end = source.index('mov rax, {guest_gs_base}', capture_start)
    rare_start = source.index('.Lresident_nested_materialize_guest_field:')
    rare_end = source.index('.Lresident_nested_complete_vmcs02_msr_exit:', rare_start)
    guest_assembly += "\n" + source[capture_start:capture_end].strip() + (
        "\nmov rax, qword ptr [rip + .Lresident_nested_rare_guest_fields]\n"
        "mov qword ptr [r12 + {b_nested_vmcs02_rare_state_pending}], rax\n"
        "mov rax, qword ptr [rip + .Lresident_nested_rare_guest_fields + 8]\n"
        "mov qword ptr [r12 + {b_nested_vmcs02_rare_state_pending} + 8], rax\nret\n"
    )
    guest_assembly += source[rare_start:rare_end].strip()
    assert guest_assembly.count("vmread r11, rax") == 3
    guest_assembly = guest_assembly.replace(
        "vmread r11, rax",
        "cmp qword ptr [r12 + {test_selected_vmcs}], 2\n"
        "jne .Lresident_dispatch_halt\n"
        "mov r11, qword ptr [r12 + {test_hardware} + rdx * 8]\n"
        "inc qword ptr [r12 + {test_reads}]\n"
        "push rax\nmov eax, 1\ntest eax, eax\npop rax",
    )
    for region in ("01", "02"):
        guest_assembly = guest_assembly.replace(
            "vmptrld [r12 + {b_nested_vmcs" + region + "_region}]",
            "mov rax, qword ptr [r12 + {b_nested_vmcs" + region + "_region}]\n"
            "mov qword ptr [r12 + {test_selected_vmcs}], rax\n"
            "inc qword ptr [r12 + {test_switches}]\n"
            "mov eax, 1\ntest eax, eax",
        )
    (output / "resident-guest.S").write_text(guest_assembly)
    control_start = source.index('.Lresident_vmcs12_field_index:')
    control_end = source.index('.Lresident_nested_merge_vmcs02_controls:')
    lookup_start = source.index('.Lresident_vmcs12_field_index_table:')
    lookup_end = source.index('.balign', lookup_start)
    control_assembly = (source[control_start:control_end] + source[lookup_start:lookup_end]).strip()
    assert control_assembly.count("vmwrite rax, r11") == 1
    control_assembly = control_assembly.replace(
        "vmwrite rax, r11",
        "mov qword ptr [r12 + {test_hardware} + rdx * 8], r11\n"
        "inc qword ptr [r12 + {test_writes}]\n"
        "push rax\nmov eax, 1\ntest eax, eax\npop rax",
    )
    (output / "resident-controls.S").write_text(control_assembly)
    vpid_start = source.index('.Lresident_nested_prepare_vpid02:')
    vpid_end = source.index('.Lresident_nested_select_msr_entry_list:')
    invalidation_start = source.index('.Lresident_nested_invvpid_validate:')
    invalidation_end = source.index('.Lresident_nested_invalid_invalidation_operand:')
    vpid_assembly = (source[vpid_start:vpid_end] + source[invalidation_start:invalidation_end]).strip()
    assert vpid_assembly.count("invvpid rax, xmmword ptr [rsp]") == 1
    vpid_assembly = vpid_assembly.replace(
        "invvpid rax, xmmword ptr [rsp]",
        "inc qword ptr [r12 + {test_flushes}]\n"
        "mov qword ptr [r12 + {test_kind}], rax\n"
        "mov rax, qword ptr [rsp]\nmov qword ptr [r12 + {test_tag}], rax\n"
        "mov eax, 1\ntest eax, eax",
    ).replace(
        "call .Lresident_nested_write_vmcs02_control",
        "mov qword ptr [r12 + {test_selected_tag}], r11",
    )
    vpid_assembly += (
        "\n.Lresident_nested_succeed:\nxor eax, eax\nret\n"
        ".Lresident_nested_invalid_invalidation_operand:\nmov eax, 1\nret\n"
    )
    (output / "resident-vpid.S").write_text(vpid_assembly)
    msr_start = source.index('.Lresident_nested_complete_vmcs02_msr_exit:')
    msr_end = source.index('.Lresident_nested_restore_l1_host_state:')
    mapped_start = source.index('.Lresident_nested_guest_msr_list_is_mapped:')
    mapped_end = source.index('.Lresident_nested_msr_requires_hardware_store:')
    msr_assembly = (source[msr_start:msr_end] + source[mapped_start:mapped_end]).strip()
    select_start = source.index(".Lresident_nested_select_msr_entry_list:")
    select_end = source.index(".Lresident_nested_prepare_full_msr_entry:", select_start)
    msr_assembly += "\n" + source[select_start:select_end] + '\n.Lresident_nested_read_saved_msr:\nud2\n.Lresident_ept01_page_is_writable:\nmov eax, 1\nret\n'
    msr_assembly = msr_assembly.replace(
        'call .Lresident_nested_eptp_before_root_write',
        'call .Ltest_msr_root_write',
    )
    msr_assembly += '\n.Ltest_msr_root_write:\nret\n.Lresident_ept01_page_translate:\njmp .Lresident_ept01_host_page_is_mapped\n'
    msr_assembly = msr_assembly.replace(
        "vmwrite rax, r11",
        "inc qword ptr [r12 + {test_writes}]\n"
        "mov qword ptr [r12 + {test_hardware} + rax * 8], r11\n"
        "push rax\nmov eax, 1\ntest eax, eax\npop rax",
    )
    msr_assembly += "\n.data\n.balign 8\nmatrixhv_resident_island_msr_switch_count:\n.quad 1\n.text\n"
    (output / "resident-msr-exit.S").write_text(msr_assembly)
    address_start = source.index('.Lresident_nested_physical_address_is_valid:')
    address_end = source.index('.Lresident_nested_resolve_ept02_violation:', address_start)
    address_assembly = source[address_start:address_end].strip()
    (output / "resident-address.S").write_text(address_assembly)
    snapshot_start = source.index('.Lresident_nested_snapshot_vmcs01_effective_state:')
    snapshot_end = source.index('.Lresident_nested_sync_vmcs02_guest_state:')
    snapshot_assembly = source[snapshot_start:snapshot_end].strip()
    snapshot_assembly = snapshot_assembly.replace(
        "vmread r11, rax",
        "inc qword ptr [r12 + {test_reads}]\n"
        "mov r11, qword ptr [r12 + {test_hardware} + rax * 8]\n"
        "mov eax, 1\ntest eax, eax",
    )
    (output / "resident-snapshot.S").write_text(snapshot_assembly)
    success_start = source.index('.Lresident_nested_succeed:')
    success_end = source.index('.Lresident_nested_inject_pf_write:', success_start)
    success_assembly = source[success_start:success_end].strip()
    success_assembly = success_assembly.replace(
        ".Lresident_nested_succeed:", ".Ltest_nested_success:"
    ).replace(
        "vmread r11, rax",
        "mov r11, qword ptr [r12 + {test_rflags}]\nmov eax, 1\ntest eax, eax",
    ).replace(
        "vmwrite rax, r11",
        "mov qword ptr [r12 + {test_rflags}], r11\n"
        "inc qword ptr [r12 + {test_writes}]\nmov eax, 1\ntest eax, eax",
    ).replace(
        "call .Lresident_advance_guest_rip", "inc qword ptr [r12 + {test_advances}]"
    ).replace("jmp .Lresident_dispatch_resume", "ret")
    (output / "resident-success.S").write_text(success_assembly)
    bitmap_start = source.index('.Lresident_nested_merge_msr_bitmap_loop:')
    bitmap_end = source.index('jmp .Lresident_nested_use_composed_msr_bitmap', bitmap_start)
    bitmap_assembly = source[bitmap_start:bitmap_end].strip()
    (output / "resident-msr-bitmap.S").write_text(bitmap_assembly + "\nret\n")
    merge_start = source.index('.Lresident_nested_merge_vmcs02_controls:')
    primary_start = source.index('mov rax, {cpu_based_vm_exec_control}', merge_start)
    primary_end = source.index('bt r11, 21', primary_start)
    secondary_start = source.index('mov rax, {secondary_vm_exec_control}', primary_end)
    secondary_end = source.index('mov rax, {vm_exit_controls}', secondary_start)
    merge_assembly = (source[primary_start:primary_end] + source[secondary_start:secondary_end]).strip()
    merge_assembly = merge_assembly.replace(
        ".Lresident_nested_write_vmcs02_control", ".Ltest_capture_vmcs02_control"
    )
    merge_assembly = merge_assembly.replace("mov rax, 0x2026", "mov rax, 3").replace("mov rax, 0x2028", "mov rax, 4")
    merge_assembly = merge_assembly.replace(".Lresident_nested_eptp_before_root_write", ".Ltest_shadow_root_write").replace(".Lresident_ept01_page_is_readable", ".Ltest_shadow_translate")
    merge_assembly += (
        "\nret\n.Ltest_capture_vmcs02_control:\n"
        "mov qword ptr [r12 + {test_hardware} + rax * 8], r11\nret\n"
        ".Ltest_shadow_root_write:\nret\n.Ltest_shadow_translate:\nmov eax, 1\nret\n"
    )
    (output / "resident-intercepts.S").write_text(merge_assembly)
    policy_start = source.index('bt dword ptr [r12 + {b_nested_vmcs12_primary_control}], 28', merge_start)
    policy_end = source.index('.Lresident_nested_merge_msr_bitmap_done:', policy_start)
    policy_assembly = source[policy_start:policy_end].replace(
        '.Lresident_ept01_page_is_readable', '.Ltest_msr_policy_host_page_is_mapped'
    ).replace(
        '.Lresident_nested_', '.Ltest_msr_policy_'
    )
    policy_assembly += (
        '\nret\n.Ltest_msr_policy_host_page_is_mapped:\n'
        'mov r11, qword ptr [r12 + {test_translated}]\n'
        'mov eax, dword ptr [r12 + {test_mapped}]\nret\n'
        '.Ltest_msr_policy_write_vmcs02_control:\n'
        'mov qword ptr [r12 + {test_selected}], r11\nret\n'
    )
    (output / "resident-msr-policy.S").write_text(policy_assembly)
    io_start = source.index("bt r11, 21", merge_start)
    io_end = source.index(".Lresident_nested_merge_io_bitmaps_done:", io_start)
    io = source[io_start:io_end].replace(".Lresident_nested_merge_io_bitmaps_done", ".Ltest_io_done")
    io = io.replace(".Lresident_nested_write_vmcs02_control", ".Ltest_io_write")
    translation_start = switch_source.index(".Lresident_ept01_page_is_readable:")
    translation_end = switch_source.index(".endm", translation_start)
    io += "\n.Ltest_io_done:\nret\n" + switch_source[translation_start:translation_end]
    io += "\n.Ltest_io_write:\nmov [r12 + {review_hardware} + rax * 8], r11\nret\n"
    io += ".Lresident_ept01_host_page_is_mapped:\nmov eax, 1\nret\n"
    io += ".Lresident_nested_eptp_before_root_write:\nret\n.Lresident_dispatch_halt:\nud2\n"
    wrapper = ".text\n.globl review_edge_merge_io\nreview_edge_merge_io:\npush r12\nmov r12, rcx\nmov r11, [r12 + {b_nested_vmcs12_primary_control}]\ncall .Ltest_io_merge\npop r12\nret\n.Ltest_io_merge:\n"
    (output / "resident-io.S").write_text((wrapper + io).replace(".Lresident_", ".Ltest_io_"))


def prepare_nested_regressions(project: Path):
    output = project / "builds/nested-regression-tests"
    output.mkdir(parents=True, exist_ok=True)
    source = read_resident_assembly(project)
    def block(start, end):
        begin = source.index(start)
        return source[begin:source.index(end, begin)]
    assembly = "\n".join([
        block('.Lresident_nested_msr_exit_requested:', '.Lresident_nested_read_gpr:'),
        block('.Lresident_nested_operand_width:', '.Lresident_nested_physical_address_is_valid:'),
        block('.Lresident_ept01_page_is_readable:', '.Lresident_dispatch_xsetbv:'),
        block('.Lresident_nested_guest_msr_list_is_mapped:', '.Lresident_nested_store_current_vmcs12:'),
        block('.Lresident_nested_select_msr_entry_list:', '.Lresident_nested_compose_vmcs02_msr_lists:'),
        block('.Lresident_nested_restore_internal_msr_entry:', '.Lresident_nested_l2_resume_ept:'),
        block('.Lresident_nested_l2_probe_reflection:', '.Lresident_nested_l2_probe_non_msr:'),
        block('.Lresident_dispatch_inject_gp_event:', '.Lresident_advance_guest_rip:'),
        '.Ltest_regression_capture_exception:\n' + block(
            'cmp qword ptr [r12 + {b_nested_l2_msr_gp_pending}], 0',
            '.Lresident_nested_l2_exit_interrupt_ready:',
        ) + '.Lresident_nested_l2_exit_interrupt_ready:\nret\n',
        block('.Lresident_dispatch_rdmsr_vmcs_value:', '.Lresident_dispatch_rdmsr_gs_base:'),
        block('.Lresident_dispatch_wrmsr_not_vmx:', '.Lresident_dispatch_wrmsr_fs_base:'),
        block('.Lresident_nested_compose_vmcs02_msr_lists:', '.Lresident_nested_snapshot_vmcs01_effective_state:'),
        block('.Lresident_nested_complete_vmcs02_msr_exit:', '.Lresident_nested_restore_l1_host_state:'),
        block('.Lresident_nested_msr_list_is_valid:', '.Lresident_nested_entry_event_is_valid:'),
        block('.Lresident_nested_physical_address_is_valid:', '.Lresident_nested_resolve_ept02_violation:'),
    ])
    fault = block('.Lresident_nested_inject_pf_write:', '.Lresident_nested_inject_ud:')
    fault = re.sub(r'^resident_telemetry_counter .*\n', '', fault, flags=re.MULTILINE)
    fault = fault.replace('mov cr2, r10', 'mov [r12 + {test_fault_address}], r10')
    fault = fault.replace('jmp .Lresident_dispatch_resume', 'xor eax, eax\njmp .Ltest_regression_return')
    assembly += fault + '\n.Lresident_diagnostic_nested_record_failure:\nret\n'
    assembly = assembly.replace('vmread r11, rax', 'call .Ltest_regression_vmread')
    assembly = assembly.replace('vmread r13, rax', 'call .Ltest_regression_vmread\nmov r13, r11')
    assembly = assembly.replace('vmwrite rax, r11', 'call .Lresident_nested_write_vmcs02_control')
    assembly = assembly.replace('vmwrite rax, r10', 'mov [r12 + {test_controls} + rax * 8], r10\ncmp r12, 0')
    for register in ['r8', 'r9', 'r10']:
        assembly = assembly.replace(f'vmread {register}, rax', f'mov {register}, [r12 + {{test_vmcs}} + rax * 8]\ncmp r12, 0')
    constants = {
        'host_page_address_mask': 0x000ffffffffff000,
        'guest_cr0': 0, 'guest_cr4': 1, 'guest_cr3': 2, 'vm_entry_controls': 3,
        'guest_cs_ar_bytes': 4, 'guest_pat': 5, 'guest_efer': 6,
        'guest_ia32_debugctl': 7, 'guest_fs_base': 8, 'guest_gs_base': 9,
        'guest_sysenter_cs': 10, 'guest_sysenter_esp': 11, 'guest_sysenter_eip': 12,
        'vm_entry_msr_load_addr': 0, 'vm_entry_msr_load_count': 1,
        'vm_exit_msr_store_addr': 2, 'vm_exit_msr_store_count': 3,
        'vm_exit_msr_load_addr': 4, 'vm_exit_msr_load_count': 5,
        'vm_entry_intr_info_field': 13, 'vm_entry_exception_error_code': 14,
        'exit_intr_info': 13, 'exit_intr_error_code': 14,
        'rdmsr_reason': 31, 'wrmsr_reason': 32,
        'nested_guest_msr_list_capacity': 512,
        'spec_ctrl_msr': 0x48, 'kernel_gs_base_msr': 0xc0000102,
        'tsc_aux_msr': 0xc0000103, 'star_msr': 0xc0000081,
        'lstar_msr': 0xc0000082, 'cstar_msr': 0xc0000083,
        'fmask_msr': 0xc0000084, 'tsc_msr': 0x10,
        'efer_msr': 0xc0000080, 'fs_base_msr': 0xc0000100, 'gs_base_msr': 0xc0000101,
        'sysenter_cs_msr': 0x174, 'sysenter_esp_msr': 0x175, 'sysenter_eip_msr': 0x176,
    }
    wrapper = r"""
    .text
    .globl test_nested_regression
    test_nested_regression:
        push rbx
        push rbp
        push rsi
        push rdi
        push r12
        push r13
        push r14
        push r15
        mov r12, rcx
        mov qword ptr [rip + matrixhv_resident_island_msr_switch_count], r9
        cmp edx, 0
        je .Ltest_regression_read
        cmp edx, 1
        je .Ltest_regression_write
        cmp edx, 2
        je .Ltest_regression_requested
        cmp edx, 3
        je .Ltest_regression_compose
        cmp edx, 4
        je .Ltest_regression_complete
        cmp edx, 5
        je .Ltest_regression_activate
        cmp edx, 6
        je .Ltest_regression_validate_list
        cmp edx, 7
        je .Ltest_regression_prepare_full
        cmp edx, 8
        je .Ltest_regression_restore_root
        cmp edx, 9
        je .Ltest_regression_route_msr
        cmp edx, 10
        je .Ltest_regression_internal
        ud2
    .Ltest_regression_read:
        mov ecx, r8d
        call .Lresident_nested_read_operand_range
        jc .Lresident_nested_inject_pf_read
        jmp .Ltest_regression_carry_result
    .Ltest_regression_write:
        mov ecx, r8d
        call .Lresident_nested_write_operand_range
        jc .Lresident_nested_inject_pf_write
    .Ltest_regression_carry_result:
        setnc al
        movzx eax, al
        mov [r12 + {test_fault_address}], r10
        jmp .Ltest_regression_return
    .Ltest_regression_requested:
        mov ecx, r8d
        mov edx, dword ptr [r12 + {test_write}]
        call .Lresident_nested_msr_exit_requested
        jmp .Ltest_regression_return
    .Ltest_regression_compose:
        call .Lresident_nested_compose_vmcs02_msr_lists
        mov eax, 1
        jmp .Ltest_regression_return
    .Ltest_regression_complete:
        mov r10d, r8d
        call .Lresident_nested_complete_vmcs02_msr_exit
        mov eax, 1
        jmp .Ltest_regression_return
    .Ltest_regression_activate:
        call .Lresident_nested_activate_vmcs01_msr_entry
        mov eax, 1
        jmp .Ltest_regression_return
    .Ltest_regression_validate_list:
        mov r11, [r12 + {test_list_address}]
        mov r10d, r8d
        call .Lresident_nested_msr_list_is_valid
        jmp .Ltest_regression_return
    .Ltest_regression_prepare_full:
        call .Lresident_nested_prepare_full_msr_entry
        mov eax, 1
        jmp .Ltest_regression_return
    .Ltest_regression_restore_root:
        call .Lresident_nested_restore_root_spec_ctrl
        mov eax, 1
        jmp .Ltest_regression_return
    .Ltest_regression_internal:
        call .Lresident_nested_restore_internal_msr_entry
        mov eax, 1
        jmp .Ltest_regression_return
    .Ltest_regression_route_msr:
        sub rsp, 128
        mov rax, [r12 + {test_guest_rax}]
        mov [rsp], rax
        mov rax, [r12 + {test_guest_rcx}]
        mov [rsp + 8], rax
        mov rax, [r12 + {test_guest_rdx}]
        mov [rsp + 16], rax
        mov eax, [r12 + {b_last_reason}]
        jmp .Lresident_nested_l2_probe_reflection
    .Lresident_dispatch_rdmsr:
        cmp dword ptr [rsp + 8], 0x1d9
        je .Lresident_dispatch_rdmsr_debugctl
        jmp .Lresident_dispatch_rdmsr_efer
    .Lresident_dispatch_wrmsr:
        mov ecx, [rsp + 8]
        jmp .Lresident_dispatch_wrmsr_not_vmx
    .Lresident_dispatch_inject_gp:
        jmp .Lresident_dispatch_inject_gp_event
    .Lresident_dispatch_resume:
        call .Lresident_nested_restore_internal_msr_entry
        jmp .Ltest_regression_route_done
    .Lresident_nested_l2_reflect_generic:
        mov qword ptr [r12 + {test_reflected}], 1
        call .Ltest_regression_capture_exception
    .Ltest_regression_route_done:
        mov rax, [rsp]
        mov [r12 + {test_guest_rax}], rax
        mov rax, [rsp + 16]
        mov [r12 + {test_guest_rdx}], rax
        add rsp, 128
        mov eax, 1
        jmp .Ltest_regression_return
    .Lresident_advance_guest_rip:
        inc qword ptr [r12 + {test_advances}]
        ret
    .Lresident_validate_efer:
        cmp qword ptr [r12 + {test_msr_fault}], 1
        cmc
        ret
    .Lresident_dispatch_wrmsr_passthrough:
    .Lresident_nested_l2_probe_non_msr:
        ud2
    .Ltest_regression_return:
        pop r15
        pop r14
        pop r13
        pop r12
        pop rdi
        pop rsi
        pop rbp
        pop rbx
        ret
    .Ltest_regression_vmread:
        mov r11, [r12 + {test_vmcs} + rax * 8]
        cmp r12, 0
        ret
    .Lresident_nested_write_vmcs02_control:
        mov [r12 + {test_controls} + rax * 8], r11
        cmp r12, 0
        ret
    .Lresident_ept01_host_page_is_mapped:
        mov eax, 1
        ret
    .Lresident_nested_eptp_before_root_write:
        ret
    .Lresident_guarded_wrmsr:
        cmp ecx, 0x1d9
        jne .Ltest_regression_spec_ctrl_write
        cmp qword ptr [r12 + {test_msr_fault}], 1
        je .Ltest_regression_bad_msr
        shl rdx, 32
        or rax, rdx
        mov [r12 + {test_host_debugctl}], rax
        clc
        ret
    .Ltest_regression_spec_ctrl_write:
        shl rdx, 32
        or rax, rdx
        mov [r12 + {test_spec_ctrl}], rax
        inc qword ptr [r12 + {test_spec_ctrl_writes}]
        clc
        ret
    .Lresident_guarded_rdmsr:
        cmp ecx, 0x1d9
        jne .Ltest_regression_software_msr_read
        mov rax, [r12 + {test_host_debugctl}]
        jmp .Ltest_regression_software_msr_ready
    .Ltest_regression_software_msr_read:
        cmp ecx, 0x123
        jne .Ltest_regression_bad_msr
        mov rax, [r12 + {test_software_msr}]
    .Ltest_regression_software_msr_ready:
        mov rdx, rax
        shr rdx, 32
        mov eax, eax
        clc
        ret
    .Ltest_regression_bad_msr:
        stc
        ret
    .Lresident_dispatch_halt:
        mov qword ptr [r12 + {test_aborted}], 1
        add rsp, 8
        xor eax, eax
        jmp .Ltest_regression_return
    .Lresident_dispatch_vmread_failed:
    .Lresident_dispatch_vmwrite_failed:
        ud2
    .data
    .balign 8
    matrixhv_resident_island_msr_switch_count:
        .quad 0
    .text
    """
    assembly = wrapper + assembly
    sizes = {'test_vmcs': 15, 'test_controls': 15, 'b_nested_operand_data': 2}
    offsets = {}
    cursor = 0
    for name in sorted(set(re.findall(r'\{((?:b_|test_)\w+)\}', assembly))):
        offsets[name] = cursor
        cursor += sizes.get(name, 1) * 8
    assembly = re.sub(r'\{(\w+)\}', lambda match: str((constants | offsets)[match[1]]), assembly)
    (output / 'handlers.S').write_text(assembly, encoding='utf-8')
    mapping = f'const CONTEXT_QWORDS: usize = {cursor // 8};\nfn offset(name: &str) -> usize {{ match name {{\n'
    mapping += '\n'.join(f'"{name}" => {value // 8},' for name, value in offsets.items())
    mapping += '\n_ => panic!("unknown regression field {name}"),\n} }\n'
    (output / 'offsets.rs').write_text(mapping, encoding='utf-8')


def prepare_nested_logging(project: Path):
    output = project / "builds" / "nested-logging-tests"
    output.mkdir(parents=True, exist_ok=True)
    source = read_resident_assembly(project)
    start = source.index(".Lresident_dispatch_vmxon:")
    end = source.index(".Lresident_nested_vmfail_with_error:", start)
    success = source.index(".Lresident_nested_vmfail_invalid_flags:", end)
    success_end = source.index(".Lresident_nested_inject_pf_write:", success)
    macro = source.index(".macro resident_telemetry_counter ")
    macro_end = source.index(".endm", macro) + len(".endm")
    gate = source.index(".Lresident_nested_update_gate:")
    gate_end = source.index(".Lresident_dispatch_control_probe:", gate)
    assembly = source[macro:macro_end] + "\n" + source[start:end] + source[success:success_end]
    assembly += source[gate:gate_end].replace(
        "[rip + matrixhv_resident_update_context]", "[r12 + {b_test_update_context}]")
    retire = source.index(".Lresident_update_retire_nested:")
    assembly += source[retire:gate].replace(
        "vmclear qword ptr [r12 + {b_nested_vmcs02_region}]", "mov rax, [r12 + {b_nested_vmcs02_region}]\ncall .Ltest_retire_vmclear").replace(
        "vmclear qword ptr [r12 + {b_nested_shadow_vmcs_region}]", "mov rax, [r12 + {b_nested_shadow_vmcs_region}]\ncall .Ltest_retire_vmclear")
    shadow_start = source.index(".Lresident_nested_shadow_intercept_reads:")
    shadow_end = source.index(".Lresident_nested_shadow_sync:", shadow_start)
    assembly += source[shadow_start:shadow_end]
    assembly = assembly.replace("vmread r11, rax", "call .Ltest_vmread")
    assembly = assembly.replace("vmwrite rax, r11", "call .Ltest_vmwrite")
    constants = {"guest_cs_selector": 0, "guest_rflags": 1, "exception_bitmap": 2,
                 "guest_cr0": 3, "cr0_read_shadow": 4, "cr0_guest_host_mask": 5,
                 "guest_cr4": 6,
                 "vmxon_in_vmx_root_error": 15, "vmx_status_flags_clear_mask": ~0x8d5,
                 "vmcs_shadow_read_byte_offset": 0xd82,
                 "vmcs_shadow_read_bypass_mask": 0x50,
                 "vmfail_invalid_status": 1, "update_context_phase": 0,
                 "cr4_read_shadow": 7, "cr4_vmxe": 1 << 13}
    for name in ("nested_vmxon_message", "nested_vmxoff_message", "nested_pointer_message",
                 "state_rip", "state_newline"):
        label = ".L" + name
        literal = re.search(re.escape(label) + r':\s*\.ascii ("[^\n]+")', source)[1]
        constants[name + "_len"] = len(ast.literal_eval(literal))
        assembly += f"\n{label}:\n.ascii {literal}\n"
    assembly += textwrap.dedent("""
    .text
    .globl test_update_retire_nested
    test_update_retire_nested:
        push rdi
        push r12
        mov r12, rcx
        mov rdi, rcx
        call .Lresident_update_retire_nested
        setnc al
        movzx eax, al
        pop r12
        pop rdi
        ret
    .Ltest_retire_vmclear:
        cmp qword ptr [r12 + {b_test_clear_count}], 0
        jne .Ltest_retire_vmclear_second
        mov [r12 + {b_test_clear_first}], rax
        jmp .Ltest_retire_vmclear_recorded
    .Ltest_retire_vmclear_second:
        mov [r12 + {b_test_clear_second}], rax
    .Ltest_retire_vmclear_recorded:
        inc qword ptr [r12 + {b_test_clear_count}]
        mov rax, [r12 + {b_test_clear_count}]
        cmp rax, [r12 + {b_test_clear_failure}]
        je .Ltest_retire_vmclear_failed
        mov eax, 1
        test eax, eax
        ret
    .Ltest_retire_vmclear_failed:
        stc
        ret
    .Lresident_ept01_page_is_writable:
        mov eax, [r12 + {b_test_page_writable}]
        ret
    .globl test_vmx_lifecycle
    test_vmx_lifecycle:
        push rbx
        push rbp
        push rsi
        push rdi
        push r12
        push r13
        push r14
        push r15
        mov r12, rcx
        test edx, edx
        jnz .Ltest_vmxoff
        call .Lresident_dispatch_vmxon
        jmp .Ltest_return
    .Ltest_vmxoff:
        call .Lresident_dispatch_vmxoff
    .Ltest_return:
        pop r15
        pop r14
        pop r13
        pop r12
        pop rdi
        pop rsi
        pop rbp
        pop rbx
        ret
    .Ltest_vmread:
        cmp eax, 7
        jne .Ltest_vmread_guest_cr4
        mov r11, [r12 + {b_test_cr4_shadow}]
        jmp .Ltest_vmread_ready
    .Ltest_vmread_guest_cr4:
        mov r11, [r12 + {b_test_cr4}]
        cmp eax, 6
        je .Ltest_vmread_ready
        mov r11, [r12 + {b_test_cr0}]
        cmp eax, 3
        je .Ltest_vmread_ready
        mov r11, [r12 + {b_test_cr0_shadow}]
        cmp eax, 4
        je .Ltest_vmread_ready
        mov r11, [r12 + {b_test_cr0_mask}]
        cmp eax, 5
        je .Ltest_vmread_ready
        xor r11d, r11d
        cmp eax, 1
        jne .Ltest_vmread_ready
        mov r11, [r12 + {b_test_rflags}]
    .Ltest_vmread_ready:
        push rax
        mov eax, 1
        test eax, eax
        pop rax
        ret
    .Ltest_vmwrite:
        cmp eax, 7
        jne .Ltest_vmwrite_flags
        mov [r12 + {b_test_cr4_shadow}], r11
        jmp .Ltest_vmwrite_ready
    .Ltest_vmwrite_flags:
        cmp eax, 1
        jne .Ltest_vmwrite_ready
        mov [r12 + {b_test_rflags}], r11
    .Ltest_vmwrite_ready:
        push rax
        mov eax, 1
        test eax, eax
        pop rax
        ret
    .Lresident_nested_decode_memory_operand:
        lea r10, [r12 + {b_test_operand}]
        mov [r12 + {b_nested_operand_linear_address}], r10
        clc
        ret
    .Lresident_nested_read_operand_range:
        mov r10, [r12 + {b_nested_operand_linear_address}]
        clc
        ret
    .Lresident_ept01_page_is_readable:
    .Lresident_nested_physical_address_is_valid:
        mov eax, 1
        ret
    .Lresident_nested_store_current_vmcs12:
        inc qword ptr [r12 + {b_test_stores}]
        ret
    .Lresident_advance_guest_rip:
        add qword ptr [r12 + {b_test_rip}], 3
        ret
    .Lresident_serial_write:
        add qword ptr [r12 + {b_test_serial_bytes}], r9
        ret
    .Lresident_serial_hex64:
        add qword ptr [r12 + {b_test_serial_bytes}], 16
        ret
    .Lresident_dispatch_resume:
        xor eax, eax
        ret
    .Lresident_nested_inject_ud:
        mov qword ptr [r12 + {b_test_exception}], 6
        mov eax, 1
        ret
    .Lresident_nested_inject_gp:
        mov qword ptr [r12 + {b_test_exception}], 13
        mov eax, 1
        ret
    .Lresident_nested_inject_pf_read:
    .Lresident_nested_vmfail_invalid_vmxon_address:
    .Lresident_nested_vmfail_invalid_vmxon_revision:
    .Lresident_nested_vmfail_with_error:
        mov [r12 + {b_test_vmx_error}], r10
    .Lresident_dispatch_vmread_failed:
    .Lresident_dispatch_vmwrite_failed:
        mov eax, 1
        ret
    """)
    names = sorted(set(re.findall(r"\{(b_[a-z0-9_]+)\}", assembly)) | {"b_telemetry_probe_active", "b_test_guest_os_id"})
    offsets, cursor = {}, 0
    for name in names:
        offsets[name] = cursor
        cursor += 16 if name in {"b_nested_vmcs02_rare_state_pending", "b_nested_vmcs02_control_cache_valid"} else 8
    assert cursor <= 64 * 8
    constants["event_hyperv_guest_os_id"] = offsets["b_test_guest_os_id"]
    assembly = re.sub(r"\{([a-z0-9_]+)\}", lambda match: str(
        offsets[match[1]] if match[1] in offsets else constants[match[1]]
    ), assembly)
    (output / "lifecycle.S").write_text(".text\n" + assembly, encoding="utf-8")
    mapping = "fn offset(name: &str) -> usize { match name {\n"
    mapping += "\n".join(f'"{name}" => {value // 8},' for name, value in offsets.items())
    mapping += '\n_ => panic!("unknown lifecycle field {name}"),\n} }\n'
    (output / "offsets.rs").write_text(mapping, encoding="utf-8")
    display_start = source.index(".Lresident_framebuffer_active:")
    display_end = source.index(".Lresident_paint_byte:", display_start)
    hex_start = source.index(".Lresident_paint_hex:")
    hex_end = source.index(".Lresident_diagnostic_name_offsets:", hex_start)
    display = source[display_start:display_end] + source[hex_start:hex_end]
    display = display.replace("rdtsc", "mov eax, 1000\nxor edx, edx")
    display_constants = {
        "log_framebuffer_sink": 2, "event_ebs_seen": 0,
        "event_visual_base": 8, "event_visual_stride_bytes": 16,
        "event_visual_deadline": 24,
        "visual_marker_row_step": 16, "visual_marker_step_bytes": 64,
        "visual_marker_side": 8, "visual_hex_last_row": 35,
        "visual_hex_column_step_bytes": 640, "visual_hex_row_step": 12,
        "visual_hex_y": 64,
    }
    display = re.sub(r"\{([a-z0-9_]+)\}", lambda match: str(display_constants[match[1]]), display)
    display += textwrap.dedent("""
    .text
    .globl test_resident_display
    test_resident_display:
        mov byte ptr [rip + matrixhv_resident_island_log_backend], 2
        mov r8, rcx
        mov ecx, 1
        test edx, edx
        jz .Lresident_paint_stage
        mov rax, 0x123456789abcdef0
        jmp .Lresident_paint_hex
    .data
    matrixhv_resident_island_log_backend:
        .byte 2
    """)
    (output / "display.S").write_text(display, encoding="utf-8")


def prepare_pci_bar(project: Path):
    output = project / "builds/pci-bar-tests"
    output.mkdir(parents=True, exist_ok=True)
    source = (project / "src" / "firmware.rs").read_text(encoding="utf-8")
    start = source.index("fn read_pci_bar_range(")
    opening = source.index("{", start)
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    parser = source[start:end].replace("PciDiscoveryError", "EptError").replace("FIRMWARE_PHYSICAL_LIMIT", "EPT_GUEST_PHYSICAL_LIMIT")
    stubs = """
    const PCI_BAR_DESCRIPTOR_SIZE: usize = 46;
    const EPT_GUEST_PHYSICAL_LIMIT: u64 = 1 << 48;
    #[derive(Debug, PartialEq)]
    enum EptError {
        AddressOverflow,
        GuestPhysicalAddressTooWide(u64),
    }
    """
    (output / "definitions.rs").write_text(stubs + parser, encoding="utf-8")


def prepare_resident_control(project: Path):
    output = project / "builds" / "resident-control-tests"
    output.mkdir(parents=True, exist_ok=True)
    source = read_resident_assembly(project)
    def section(start, end):
        first = source.index(start)
        return source[first:source.index(end, first)]
    entry = section("matrixhv_resident_dispatch_entry:", ".Lresident_control_rearm_done:")
    reason = section(".Lresident_dispatch_reason_ready:", "and eax, 0xffff")
    assembly = "\n".join([
        section(".macro resident_control_on_restore_msr ", ".macro resident_control_native_checkpoint "),
        entry,
        ".Lresident_control_rearm_done:",
        reason,
        "xor eax, eax\njmp .Ltest_dispatch_return",
        section(".Lresident_control_off_native:", ".Lresident_set_variable_on:"),
        section(".Lresident_control_on_root_cleanup:", ".Lresident_control_capture_native:"),
    ])
    offsets = {}
    sizes = {}
    for prefix in ("control_cpu_", "probe_", "b_", "event_"):
        cursor = 0
        names = set(re.findall(r"\{(" + prefix + r"[a-z0-9_]+)\}", assembly))
        if prefix == "control_cpu_":
            names.add("control_cpu_native_snapshot_count")
        for name in sorted(names):
            if name in {"control_cpu_state_size", "probe_state_size"}:
                continue
            offsets[name] = cursor
            size = 72 if name == "control_cpu_on_native_msrs" else 8
            if name == "event_control_cpu_states":
                size = sizes["control_cpu_"] * 64
            elif name == "event_control_probe_states":
                size = sizes["probe_"] * 64
            elif name == "event_control_completion_sequences":
                size = 64 * 8
            cursor += size
        sizes[prefix] = cursor
    constants = {
        "control_cpu_state_size": sizes["control_cpu_"],
        "probe_state_size": sizes["probe_"],
        "native_stack_bytes": 4096, "native_recovery_pml4": 4096,
        "boot_canary_start": 0x12345678, "boot_canary_end": 0x87654321,
        "host_page_address_mask": 0x000FFFFFFFFFF000,
        "exit_reason": 0, "exit_qualification": 1, "vm_entry_msr_load_count": 2,
        "spec_ctrl_msr": 0x48,
    }
    assembly = re.sub(r"\{([a-z0-9_]+)\}", lambda match: str(
        offsets[match[1]] if match[1] in offsets else constants[match[1]]
    ), assembly)
    model_fields = {
        "clear_fail": 1, "clear_count": 1, "off_count": 1,
        "vmcs_active": 1, "dirty_vmcs": 1, "backing_vmcs": 1,
        "history": 1, "reason": 1, "qualification": 1,
        "msr_rearm_count": 1, "entry_msr_count": 1,
        "cr0": 1, "cr4": 1, "dr7": 1, "cr3_count": 1, "cr3_values": 2,
        "gdt_base": 1, "gdt_limit": 1, "idt_base": 1, "idt_limit": 1,
        "selectors": 8, "msr_mask": 1, "msrs": 9,
    }
    model_offsets = {}
    cursor = 0
    for name, count in model_fields.items():
        model_offsets[name] = cursor
        cursor += count * 8
    helpers = r"""
    .text
    .macro test_note field, value
        pushfq
        push rsi
        mov rsi, qword ptr [rip + test_model]
        mov qword ptr [rsi + \field], \value
        pop rsi
        popfq
    .endm
    .macro test_vmclear
        push rax
        push rdx
        mov rax, qword ptr [rip + test_model]
        inc qword ptr [rax + $clear_count]
        shl qword ptr [rax + $history], 4
        or qword ptr [rax + $history], 1
        cmp qword ptr [rax + $clear_fail], 0
        jne .Ltest_clear_failure\@
        mov rdx, qword ptr [rax + $dirty_vmcs]
        mov qword ptr [rax + $backing_vmcs], rdx
        mov qword ptr [rax + $vmcs_active], 0
        cmp rax, 0
        jmp .Ltest_clear_done\@
    .Ltest_clear_failure\@:
        cmp qword ptr [rax + $clear_fail], 1
        jne .Ltest_clear_valid\@
        cmp rax, 0
        stc
        jmp .Ltest_clear_done\@
    .Ltest_clear_valid\@:
        cmp rax, rax
    .Ltest_clear_done\@:
        pop rdx
        pop rax
    .endm
    .macro test_vmxoff
        push rax
        mov rax, qword ptr [rip + test_model]
        inc qword ptr [rax + $off_count]
        shl qword ptr [rax + $history], 4
        or qword ptr [rax + $history], 2
        cmp qword ptr [rax + $vmcs_active], 0
        je .Ltest_off_preserved\@
        mov qword ptr [rax + $backing_vmcs], 0
    .Ltest_off_preserved\@:
        mov qword ptr [rax + $vmcs_active], 0
        cmp rax, 0
        pop rax
    .endm
    .macro test_vmread
        push rsi
        mov rsi, qword ptr [rip + test_model]
        cmp eax, 0
        jne .Ltest_read_qualification\@
        mov r11, qword ptr [rsi + $reason]
        jmp .Ltest_read_done\@
    .Ltest_read_qualification\@:
        mov r11, qword ptr [rsi + $qualification]
    .Ltest_read_done\@:
        cmp rsi, 0
        pop rsi
    .endm
    .macro test_vmwrite
        push rax
        mov rax, qword ptr [rip + test_model]
        inc qword ptr [rax + $msr_rearm_count]
        mov qword ptr [rax + $entry_msr_count], r11
        cmp rax, 0
        pop rax
    .endm
    .macro test_write_cr3 value
        pushfq
        push rax
        push rsi
        mov rsi, qword ptr [rip + test_model]
        mov rax, qword ptr [rsi + $cr3_count]
        mov qword ptr [rsi + $cr3_values + rax * 8], \value
        inc qword ptr [rsi + $cr3_count]
        shl qword ptr [rsi + $history], 4
        add rax, 3
        or qword ptr [rsi + $history], rax
        pop rsi
        pop rax
        popfq
    .endm
    .macro test_load_table displacement, base_field, limit_field
        pushfq
        push rax
        push rsi
        mov rsi, qword ptr [rip + test_model]
        mov rax, qword ptr [rsp + 24 + \displacement + 2]
        mov qword ptr [rsi + \base_field], rax
        movzx eax, word ptr [rsp + 24 + \displacement]
        mov qword ptr [rsi + \limit_field], rax
        pop rsi
        pop rax
        popfq
    .endm
    .macro test_segment index
        pushfq
        push rax
        push rsi
        mov rsi, qword ptr [rip + test_model]
        movzx eax, ax
        mov qword ptr [rsi + $selectors + (\index * 8)], rax
        pop rsi
        pop rax
        popfq
    .endm
    .macro test_far_return
        pushfq
        push rax
        push rsi
        mov rsi, qword ptr [rip + test_model]
        mov rax, qword ptr [rsp + 32]
        mov qword ptr [rsi + $selectors], rax
        pop rsi
        pop rax
        popfq
        lea rsp, [rsp + 16]
    .endm
    .macro test_wrmsr
        pushfq
        push rsi
        push rdi
        push r11
        mov rsi, qword ptr [rip + test_model]
        lea rdi, [rip + test_msr_indices]
        xor r11d, r11d
    .Ltest_msr_find\@:
        cmp ecx, dword ptr [rdi + r11 * 4]
        je .Ltest_msr_found\@
        inc r11d
        cmp r11d, 9
        jb .Ltest_msr_find\@
        ud2
    .Ltest_msr_found\@:
        mov qword ptr [rsi + $msrs + r11 * 8], rax
        bts qword ptr [rsi + $msr_mask], r11
        pop r11
        pop rdi
        pop rsi
        popfq
    .endm
    """
    helpers = re.sub(r"\$([a-z0-9_]+)", lambda match: str(model_offsets[match[1]]), helpers)
    replacements = {
        "vmread r11, rax": "test_vmread",
        "vmwrite rax, r11": "test_vmwrite", "vmxoff": "test_vmxoff",
        "mov cr0, r11": f'test_note {model_offsets["cr0"]}, r11',
        "mov cr4, r11": f'test_note {model_offsets["cr4"]}, r11',
        "mov dr7, rax": f'test_note {model_offsets["dr7"]}, rax',
        "mov cr3, r11": "test_write_cr3 r11", "mov cr3, rdx": "test_write_cr3 rdx",
        "lgdt [rsp]": f'test_load_table 0, {model_offsets["gdt_base"]}, {model_offsets["gdt_limit"]}',
        "lidt [rsp + 16]": f'test_load_table 16, {model_offsets["idt_base"]}, {model_offsets["idt_limit"]}',
        "retfq": "test_far_return", "wrmsr": "test_wrmsr", "lldt ax": "test_segment 6",
        "ltr ax": "test_segment 7\nor byte ptr [rdx + rax + 5], 2",
    }
    for index, name in enumerate(("ss", "es", "ds", "fs", "gs"), start=1):
        replacements[f"mov {name}, ax"] = f"test_segment {index}"
    assembly = "\n".join(
        "test_vmclear" if line.startswith("vmclear ") else replacements.get(line, line)
        for line in assembly.splitlines()
    )
    wrappers = r"""
    .text
    .globl test_control_restore_address
    test_control_restore_address:
        lea rax, [rip + .Lresident_control_on_native_restore]
        ret
    .macro test_setup
        mov qword ptr [rip + test_model], rdx
        mov qword ptr [rip + matrixhv_resident_bridge_context], rcx
        mov r10, rcx
        mov r9, r8
        imul r9, @state_size
        lea r9, [r10 + r9 + @states]
    .endm
    .globl test_control_off
    test_control_off:
        test_setup
        pushfq
        jmp .Lresident_control_off_native
    .globl test_control_cleanup
    test_control_cleanup:
        test_setup
        push r12
        pushfq
        mov qword ptr [r9 + @caller_rsp], rsp
        jmp .Lresident_control_on_root_cleanup
    .globl test_control_dispatch
    test_control_dispatch:
        mov qword ptr [rip + test_model], r8
        mov qword ptr [rip + matrixhv_resident_bridge_context], rdx
        mov r8, r9
        imul r9, @state_size
        lea r9, [rdx + r9 + @states]
        mov r10, rdx
        push r12
        pushfq
        mov qword ptr [r9 + @caller_rsp], rsp
        mov r12, qword ptr [r9 + @sequence]
        sub rsp, 8
        mov qword ptr [rsp], rcx
        jmp matrixhv_resident_dispatch_entry
    .Lresident_control_capture_native:
        pushfq
        inc qword ptr [r9 + @snapshot_count]
        popfq
        ret
    .Lresident_dispatch_unsupported:
        movabs rax, 0x8000000000000003
    .Ltest_dispatch_return:
        mov qword ptr [rsp], rax
        pop rax
        pop rcx
        pop rdx
        pop rbx
        pop rbp
        pop rsi
        pop rdi
        pop r8
        pop r9
        pop r10
        pop r11
        pop r12
        pop r13
        pop r14
        pop r15
        add rsp, 8
        popfq
        pop r12
        ret
    .Lresident_dispatch_vmread_failed:
    .Lresident_dispatch_vmwrite_failed:
    matrixhv_resident_island_fatal:
        ud2
    matrixhv_resident_set_variable:
        ud2
    .data
    .balign 8
    test_model:
        .quad 0
    matrixhv_resident_bridge_context:
        .quad 0
    matrixhv_resident_island_msr_switch_count:
        .quad 1
    test_msr_indices:
        .long 0x1d9, 0x277, 0xc0000080, 0xc0000100, 0xc0000101, 0x174, 0x175, 0x176, 0x48
    """
    wrapper_offsets = {
        "state_size": sizes["control_cpu_"], "states": offsets["event_control_cpu_states"],
        "caller_rsp": offsets["control_cpu_native_caller_rsp"],
        "sequence": offsets["control_cpu_sequence"],
        "snapshot_count": offsets["control_cpu_native_snapshot_count"],
    }
    wrappers = re.sub(r"@([a-z0-9_]+)", lambda match: str(wrapper_offsets[match[1]]), wrappers)
    (output / "resident-control.S").write_text(helpers + assembly + "\n" + wrappers, encoding="utf-8")
    mapping = "fn offset(name: &str) -> usize { match name {\n"
    mapping += "\n".join(f'    "{name}" => {value // 8},' for name, value in offsets.items())
    mapping += '\n    _ => panic!("unknown control field {name}"),\n} }\n'
    for name, prefix in (("BOOT_WORDS", "b_"), ("EVENT_WORDS", "event_"),
                         ("STATE_WORDS", "control_cpu_"), ("PROBE_WORDS", "probe_")):
        mapping += f"const {name}: usize = {sizes[prefix] // 8};\n"
    mapping += "#[repr(C)]\n#[derive(Default)]\nstruct Model {\n"
    mapping += "\n".join(
        f"    {name}: " + ("u64," if count == 1 else f"[u64; {count}],")
        for name, count in model_fields.items()
    )
    mapping += "\n}\n"
    (output / "offsets.rs").write_text(mapping, encoding="utf-8")


def prepare_hyperv_time(project: Path):
    output = project / 'builds/hyperv-time-tests'
    output.mkdir(parents=True, exist_ok=True)
    source = (project / 'src/hyperv.rs').read_text(encoding='utf-8')
    scale = source[source.index('pub fn hyperv_reference_tsc_scale('):source.index('pub fn native_hyperv_reference_tsc(')]
    native = source[source.index('pub fn native_hyperv_reference_tsc('):source.index('pub fn restrict_evmcs_secondary_capability(')]
    native = native.replace('pub fn native_hyperv_reference_tsc(calibrate: impl FnOnce() -> u64)',
                            'fn native_hyperv_reference_tsc(cpuid: impl Fn(u32) -> core::arch::x86_64::CpuidResult, epoch: u64, calibrate: impl FnOnce() -> u64)')
    native = native.replace('pub fn native_hyperv_invariant_tsc()',
                            'fn native_hyperv_invariant_tsc(cpuid: impl Fn(u32) -> core::arch::x86_64::CpuidResult)')
    native = native.replace('    let cpuid = core::arch::x86_64::__cpuid;\n', '')
    native = native.replace('native_hyperv_invariant_tsc()', 'native_hyperv_invariant_tsc(&cpuid)')
    native = native.replace('    let epoch = unsafe { core::arch::x86_64::_rdtsc() };\n', '')
    scale += '\n' + re.search(r'pub const CPUID_HYPERVISOR_PRESENT_BIT: u32 = [^;]+;', source)[0] + '\n' + native
    firmware = (project / 'src/firmware.rs').read_text(encoding='utf-8')
    scale += '\n' + firmware[firmware.index('unsafe fn acpi_pm_timer('):]
    (output / 'definitions.rs').write_text(scale, encoding='utf-8')
    source = read_resident_assembly(project)
    read = source[source.index('.Lresident_dispatch_rdmsr_reference_count:'):source.index('.Lresident_dispatch_rdmsr_zero:')]
    write = source[source.index('.Lresident_dispatch_wrmsr_reference_count:'):source.index('.Lresident_dispatch_xsetbv:')]
    read += source[source.index('.Lresident_dispatch_rdmsr_guest_os_id:'):source.index('.Lresident_dispatch_rdmsr_vp_index:')]
    write += source[source.index('.Lresident_dispatch_wrmsr_guest_os_id:'):source.index('.Lresident_dispatch_wrmsr_reference_count:')]
    cpuid = source[source.index('.Lresident_dispatch_cpuid_hypervisor_present:'):source.index('.Lresident_dispatch_cpuid_matrixhv:')]
    route_start = source.index('cmp ecx, {hyperv_tsc_invariant_control_msr}')
    read_route = source[route_start:source.index('cmp ecx, {hyperv_reference_count_msr}', route_start)]
    route_start = source.index('cmp ecx, {hyperv_tsc_invariant_control_msr}', route_start + len(read_route))
    write_route = source[route_start:source.index('cmp ecx, {hyperv_reference_count_msr}', route_start)]
    routes = '.Ltest_time_rdmsr_route:\n' + read_route + 'jmp .Lresident_dispatch_rdmsr_passthrough\n'
    routes += '.Ltest_time_wrmsr_route:\n' + write_route + 'jmp .Lresident_dispatch_wrmsr_passthrough\n'
    assembly = read + write + cpuid + routes
    offsets = {'hyperv_features_leaf': 0x40000003, 'b_nested_expose_vmx': 64,
               'b_telemetry_active': 72, 'b_cpuid_hypervisor_eax': 80,
               'hyperv_guest_idle_access_mask': 0xfffffbff,
               'hyperv_guest_idle_feature_mask': 0xffffffdf,
               'b_event_context': 0, 'b_hyperv_timing_supported': 8, 'b_cache_ept_pointer': 24,
               'b_nested_evmcs_enabled': 32, 'event_hyperv_tsc_scale': 0,
               'event_hyperv_tsc_offset': 8, 'event_hyperv_reference_tsc_msr': 16,
               'event_hyperv_reference_tsc_lock': 24, 'event_hyperv_guest_os_id': 32,
               'event_hyperv_hypercall_msr': 40, 'event_hyperv_hypercall_lock': 48,
               'event_hyperv_reference_tsc_sequence': 56,
               'event_hyperv_tsc_invariant_supported': 64,
               'event_hyperv_tsc_invariant_control': 72,
               'hyperv_tsc_invariant_control_msr': 0x40000118,
               'host_page_address_mask': 0x000ffffffffff000}
    assembly = re.sub(r'\{(\w+)\}', lambda match: str(offsets[match[1]]), assembly)
    assembly = re.sub(r'^rdtsc$', 'mov rax, [r12 + 16]\nmov rdx, rax\nshr rdx, 32\nmov eax, eax', assembly, flags=re.MULTILINE)
    assembly = assembly.replace(
        'rep stosq', 'rep stosq\nmov rax, [r11 + 8]\nmov [r12 + 48], rax\n'
        'mov rax, [r11 + 16]\nmov [r12 + 56], rax'
    )
    wrappers = """
    .text
    .globl test_time_msr
    test_time_msr:
        push r12
        push r13
        push rdi
        sub rsp, 32
        mov r12, rcx
        mov r13, rdx
        mov rax, [rdx]
        mov [rsp], rax
        mov rax, [rdx + 8]
        mov [rsp + 16], rax
        cmp r8d, 0
        je .Lresident_dispatch_rdmsr_reference_count
        cmp r8d, 1
        je .Lresident_dispatch_rdmsr_reference_tsc
        cmp r8d, 2
        je .Lresident_dispatch_wrmsr_reference_tsc
        cmp r8d, 3
        je .Lresident_dispatch_wrmsr_reference_count
        cmp r8d, 4
        je .Lresident_dispatch_rdmsr_guest_os_id
        cmp r8d, 5
        je .Lresident_dispatch_rdmsr_hypercall
        cmp r8d, 6
        je .Lresident_dispatch_wrmsr_guest_os_id
        mov ecx, 0x40000118
        cmp r8d, 8
        je .Ltest_time_rdmsr_route
        cmp r8d, 9
        je .Ltest_time_wrmsr_route
        jmp .Lresident_dispatch_wrmsr_hypercall
    .Lresident_dispatch_rdmsr_nested_value:
        mov eax, r11d
        mov [rsp], rax
        shr r11, 32
        mov [rsp + 16], r11
        jmp .Lresident_dispatch_resume
    .Lresident_dispatch_resume:
        mov eax, 1
        jmp .Ltest_time_done
    .Lresident_dispatch_inject_gp:
        xor eax, eax
        jmp .Ltest_time_done
    .Lresident_dispatch_rdmsr_passthrough:
    .Lresident_dispatch_wrmsr_passthrough:
        mov eax, 2
    .Ltest_time_done:
        mov rdx, [rsp]
        mov [r13], edx
        mov rdx, [rsp + 16]
        mov [r13 + 8], edx
        add rsp, 32
        pop rdi
        pop r13
        pop r12
        ret
    .Lresident_advance_guest_rip:
    .Lresident_nested_eptp_before_root_write:
        ret
    .Lresident_nested_physical_address_is_valid:
        xor eax, eax
        test r11, 0xfff
        setz al
        ret
    .Lresident_ept01_host_page_is_mapped:
        xor eax, eax
        cmp r11, [r12 + 40]
        setne al
        ret
    .globl test_time_cpuid
    test_time_cpuid:
        push r12
        push r13
        sub rsp, 32
        mov r12, rcx
        mov r13, rdx
        mov eax, [rdx]
        mov [rsp], rax
        mov eax, [rdx + 4]
        mov [rsp + 24], rax
        mov eax, [rdx + 8]
        mov [rsp + 8], rax
        mov eax, [rdx + 12]
        mov [rsp + 16], rax
        jmp .Lresident_dispatch_cpuid_hypervisor_present
    .Lresident_dispatch_cpuid_advance:
        mov rax, [rsp]
        mov [r13], eax
        mov rax, [rsp + 24]
        mov [r13 + 4], eax
        mov rax, [rsp + 8]
        mov [r13 + 8], eax
        mov rax, [rsp + 16]
        mov [r13 + 12], eax
        add rsp, 32
        pop r13
        pop r12
        ret
    """
    (output / 'handlers.S').write_text(wrappers + assembly, encoding='utf-8')
    hypercall = source[source.index('.Lresident_dispatch_hyperv_hypercall:'):
                       source.index('.Lresident_dispatch_vmware_hypercall:', source.index('.Lresident_dispatch_hyperv_hypercall:'))]
    hypercall += source[source.index('.Lresident_ept01_page_is_readable:'):
                        source.index('.Lresident_dispatch_xsetbv:')]
    hypercall_offsets = dict(offsets, guest_cr0=0x6800, guest_cs_ar_bytes=0x4816, guest_efer=0x2806)
    hypercall = re.sub(r'\{(\w+)\}', lambda match: str(hypercall_offsets[match[1]]), hypercall)
    hypercall = hypercall.replace('vmread r11, rax', 'call .Ltest_hypercall_vmread')
    hypercall_wrapper = """
    .text
    .globl test_hypercall
    test_hypercall:
        push r12
        push r13
        push r14
        sub rsp, 32
        mov r12, rcx
        mov r14, rdx
        mov rax, [rdx]
        mov [rsp], rax
        mov rax, [rdx + 8]
        mov [rsp + 8], rax
        mov rax, [rdx + 16]
        mov [rsp + 16], rax
        mov rax, [rdx + 24]
        mov [rsp + 24], rax
        jmp .Lresident_dispatch_hyperv_hypercall
    .Ltest_hypercall_vmread:
        mov r11, [r12 + 64]
        cmp eax, 0x6800
        je .Ltest_hypercall_vmread_done
        mov r11, [r12 + 72]
        cmp eax, 0x4816
        je .Ltest_hypercall_vmread_done
        mov r11, [r12 + 80]
    .Ltest_hypercall_vmread_done:
        cmp r12, 0
        ret
    .Lresident_guest_privilege:
        cmp qword ptr [r12 + 88], 1
        cmc
        ret
    .Lresident_dispatch_resume:
        mov eax, 1
        jmp .Ltest_hypercall_done
    .Lresident_dispatch_inject_ud:
        xor eax, eax
        jmp .Ltest_hypercall_done
    .Lresident_dispatch_unsupported:
        mov eax, 2
    .Ltest_hypercall_done:
        mov rdx, [rsp]
        mov [r14], rdx
        mov rdx, [rsp + 8]
        mov [r14 + 8], rdx
        mov rdx, [rsp + 16]
        mov [r14 + 16], rdx
        mov rdx, [rsp + 24]
        mov [r14 + 24], rdx
        add rsp, 32
        pop r14
        pop r13
        pop r12
        ret
    .Lresident_dispatch_vmread_failed:
        ud2
    .Lresident_advance_guest_rip:
    .Lresident_nested_eptp_before_root_write:
        ret
    .Lresident_ept01_host_page_is_mapped:
        xor eax, eax
        cmp r11, [r12 + 40]
        setne al
        ret
    """
    (output / 'hypercall.S').write_text((hypercall_wrapper + hypercall).replace('.Lresident_', '.Lhypercall_'), encoding='utf-8')


def prepare_resident_msr(project: Path):
    output = project / "builds" / "resident-msr-tests"
    output.mkdir(parents=True, exist_ok=True)
    source = read_resident_rust(project)
    assembly_source = read_resident_assembly(project)
    cr_source = (project / 'src/asm/exits.S').read_text(encoding='utf-8')
    cr_start = cr_source.index('.Lresident_ap_cr_access:')
    cr_end = cr_source.index('.endm', cr_start)
    cr_access = cr_source[cr_start:cr_end].strip()
    cr_constants = {
        'b_last_qualification': 0, 'b_nested_l1_cr4': 8,
        'b_nested_vmx_cr0_fixed0': 16, 'b_nested_vmx_cr0_fixed1': 24,
        'b_nested_vmx_cr4_fixed0': 32, 'b_nested_vmx_cr4_fixed1': 40,
        'b_nested_active': 48,
        'guest_rsp': 0, 'cr0_read_shadow': 1, 'guest_cr0': 2,
        'guest_cr4': 3, 'cr4_read_shadow': 4, 'cr0_guest_host_mask': 5,
        'cr4_guest_host_mask': 6, 'guest_efer': 7, 'vm_entry_controls': 8,
        'secondary_vm_exec_control': 9, 'virtual_processor_id': 10,
        'guest_cs_ar_bytes': 11, 'guest_cr3': 12, 'guest_tr_ar_bytes': 13,
        'guest_pdptr0': 14, 'b_nested_physical_address_bits': 104,
    }
    cr_access = re.sub(r'\{(\w+)\}', lambda match: str(cr_constants[match[1]]), cr_access)
    cr_access = re.sub(r'vmread (r\w+), rax',
        r'mov \1, [r12 + 128 + rax * 8]\ncmp r12, 0', cr_access)
    cr_access = re.sub(r'vmwrite rax, (r\w+)',
        r'mov [r12 + 128 + rax * 8], \1\ninc qword ptr [r12 + 56]\ncmp r12, 0', cr_access)
    cr_access = cr_access.replace('invvpid rax, xmmword ptr [rsp]', '''
        inc qword ptr [r12 + 64]
        mov rax, [rsp]
        mov [r12 + 88], rax
        mov rax, [rsp + 8]
        mov [r12 + 96], rax
        cmp r12, 0
    ''')
    cr_wrapper = """
    .text
    .globl test_write_cr
    test_write_cr:
        push rbx
        push rbp
        push rsi
        push rdi
        push r12
        push r13
        push r14
        push r15
        sub rsp, 128
        mov r12, rcx
        mov rsi, rdx
        mov rdi, rsp
        mov ecx, 15
        rep movsq
        jmp .Lresident_ap_cr_access
    .Lresident_update_dirty_mtrrs:
        inc qword ptr [r12 + 80]
        ret
    .Lresident_advance_guest_rip:
        inc qword ptr [r12 + 72]
        ret
    .Lresident_ept01_page_is_readable:
        xor eax, eax
        cmp r11, 0x4000
        jne .Ltest_cr_pdpte_unmapped
        mov r11, [r12 + 312]
        test r11, r11
        jz .Ltest_cr_pdpte_unmapped
        mov eax, 1
    .Ltest_cr_pdpte_unmapped:
        ret
    .Lresident_dispatch_resume:
        mov eax, 1
        jmp .Ltest_write_cr_done
    .Lresident_dispatch_inject_gp:
        xor eax, eax
        jmp .Ltest_write_cr_done
    .Lresident_dispatch_unsupported:
        mov eax, 2
        jmp .Ltest_write_cr_done
    .Lresident_dispatch_vmread_failed:
    .Lresident_dispatch_vmwrite_failed:
    .Lresident_dispatch_halt:
        mov eax, 3
    .Ltest_write_cr_done:
        add rsp, 128
        pop r15
        pop r14
        pop r13
        pop r12
        pop rdi
        pop rsi
        pop rbp
        pop rbx
        ret
    """
    (output / 'resident-cr.S').write_text(
        (cr_wrapper + cr_access).replace('.Lresident_', '.Ltest_cr_'), encoding='utf-8')
    apic = assembly_source[assembly_source.index('.Lresident_dispatch_rdmsr_hyperv_apic:'):
                           assembly_source.index('.Lresident_dispatch_rdmsr_guest_os_id:')]
    apic += assembly_source[assembly_source.index('.Lresident_dispatch_wrmsr_hyperv_apic:'):
                            assembly_source.index('.Lresident_dispatch_wrmsr_guest_os_id:')]
    apic = apic.replace('{b_nested_evmcs_enabled}', '0').replace('{apic_base_msr}', '27')
    apic = re.sub(r'^rdmsr$', 'mov rax, [r12 + 8]\nmov rdx, rax\nshr rdx, 32', apic, flags=re.MULTILINE)
    apic_wrapper = """
    .text
    .globl test_hyperv_apic
    test_hyperv_apic:
        push r12
        push r13
        sub rsp, 32
        mov r12, rcx
        mov r13, rdx
        mov rax, [rdx]
        mov [rsp], rax
        mov rax, [rdx + 8]
        mov [rsp + 8], rax
        mov rax, [rdx + 16]
        mov [rsp + 16], rax
        mov ecx, [rsp + 8]
        test r8d, r8d
        jnz .Lresident_dispatch_wrmsr_hyperv_apic
        jmp .Lresident_dispatch_rdmsr_hyperv_apic
    .Lresident_dispatch_rdmsr_passthrough:
        mov [r12 + 16], rcx
        mov r11, [r12 + 24]
        jmp .Lresident_dispatch_rdmsr_nested_value
    .Lresident_guarded_rdmsr:
        mov [r12 + 16], rcx
        mov rax, [r12 + 24]
        mov rdx, rax
        shr rdx, 32
        mov eax, eax
        clc
        ret
    .Lresident_ept01_host_page_is_mapped:
        xor eax, eax
        cmp r11, [r12 + 32]
        setne al
        ret
    .Lresident_guarded_wrmsr:
        mov [r12 + 16], rcx
        shl rdx, 32
        or rax, rdx
        mov [r12 + 24], rax
        clc
        ret
    .Lresident_dispatch_wrmsr_passthrough:
        mov [r12 + 16], rcx
        mov eax, [rsp + 16]
        shl rax, 32
        mov edx, [rsp]
        or rax, rdx
        mov [r12 + 24], rax
        jmp .Lresident_dispatch_resume
    .Lresident_dispatch_rdmsr_nested_value:
        mov eax, r11d
        mov [rsp], rax
        shr r11, 32
        mov [rsp + 16], r11
        jmp .Lresident_dispatch_resume
    .Lresident_advance_guest_rip:
        ret
    .Lresident_dispatch_resume:
        mov eax, 1
        jmp .Ltest_hyperv_apic_done
    .Lresident_dispatch_inject_gp:
        xor eax, eax
    .Ltest_hyperv_apic_done:
        mov rdx, [rsp]
        mov [r13], rdx
        mov rdx, [rsp + 16]
        mov [r13 + 16], rdx
        add rsp, 32
        pop r13
        pop r12
        ret
    """
    (output / 'resident-hyperv-apic.S').write_text(
        (apic_wrapper + apic).replace('.Lresident_', '.Ltest_apic_'), encoding='utf-8')
    parent_start = assembly_source.index('.Lresident_hyperv_require_parent_msr:')
    parent_end = assembly_source.index('.Lresident_dispatch_rdmsr_zero:', parent_start)
    parent_policy = assembly_source[parent_start:parent_end]
    parent_policy = parent_policy.replace('{b_hyperv_timing_supported}', '0')
    parent_policy = parent_policy.replace('{b_nested_evmcs_enabled}', '8')
    parent_wrapper = """
    .text
    .globl test_parent_msr_access
    test_parent_msr_access:
        push r12
        mov r12, rcx
        mov ecx, edx
        call .Lresident_hyperv_require_parent_msr
        setnc al
        movzx eax, al
        pop r12
        ret
    """
    (output / 'resident-hyperv-parent.S').write_text(parent_wrapper + parent_policy, encoding='utf-8')
    vmcall_start = assembly_source.index('.Lresident_dispatch_vmcall:')
    vmcall_end = assembly_source.index('.Lresident_dispatch_hyperv_hypercall:', vmcall_start)
    vmcall = assembly_source[vmcall_start:vmcall_end]
    vmcall = re.sub(r'^resident_telemetry_counter[^\n]*\n', '', vmcall, flags=re.MULTILINE)
    private_start = assembly_source.index('.macro resident_private_vmcall ')
    private_end = assembly_source.index('.endm', private_start) + len('.endm')
    vmcall = assembly_source[private_start:private_end] + '\n' + vmcall
    vmcall_constants = {
        'start_checkpoint_magic': 'RESIDENT_VMCALL_START_CHECKPOINT',
        'stop_magic': 'RESIDENT_VMCALL_STOP',
        'nested_probe_failed_magic': 'RESIDENT_VMCALL_NESTED_PROBE_FAILED',
        'bridge_probe_vmcall': 'CONTROL_PROBE_VMCALL',
        'bridge_off_prepare_vmcall': 'CONTROL_OFF_PREPARE_VMCALL',
        'bridge_off_commit_vmcall': 'CONTROL_OFF_COMMIT_VMCALL',
        'vmware_hypervisor_magic': 'VMWARE_HYPERVISOR_MAGIC',
    }
    vmcall_values = {
        name: int(re.search(rf'const {constant}: u(?:32|64) = (0x[0-9a-fA-F_]+);', source)[1].replace('_', ''), 0)
        for name, constant in vmcall_constants.items()
    }
    vmcall_values['b_telemetry_probe_active'] = 8
    vmcall_values['update_vmcall'] = 0x4d41545249585556
    vmcall = re.sub(r'\{(\w+)\}', lambda match: str(vmcall_values[match[1]]), vmcall)
    vmcall_wrapper = """
    .text
    .globl test_private_vmcall
    test_private_vmcall:
        push r12
        sub rsp, 32
        mov r12, rcx
        mov [rsp], rdx
        jmp .Lresident_dispatch_vmcall
    .Lresident_guest_privilege:
        bt qword ptr [r12], 0
        ret
    .Lresident_ap_ready:
    .Lresident_dispatch_start_checkpoint:
    .Lresident_dispatch_control_probe:
    .Lresident_dispatch_control_off_prepare:
    .Lresident_dispatch_control_off_unexpected:
    .Lresident_dispatch_update:
    .Lresident_dispatch_stop:
    .Lresident_dispatch_nested_probe_failed:
        mov eax, 1
        jmp .Ltest_private_vmcall_done
    .Lresident_dispatch_inject_gp:
        xor eax, eax
        jmp .Ltest_private_vmcall_done
    .Lresident_dispatch_hyperv_hypercall:
        mov eax, 2
        jmp .Ltest_private_vmcall_done
    .Lresident_dispatch_vmware_hypercall:
        mov eax, 3
    .Ltest_private_vmcall_done:
        add rsp, 32
        pop r12
        ret
    """
    (output / 'resident-private-vmcall.S').write_text(
        (vmcall_wrapper + vmcall).replace('.Lresident_', '.Ltest_private_'), encoding='utf-8')
    start = assembly_source.index('.Lresident_nested_complete_vmcs02_msr_exit:')
    end = assembly_source.index('.Lresident_nested_activate_vmcs01_msr_entry:', start)
    assembly = assembly_source[start:end].strip()
    assembly += '\n.Lresident_nested_read_saved_msr:\nud2\n.Lresident_ept01_page_is_writable:\nmov eax, 1\nret\n\n.Lresident_dispatch_halt:\nud2\n'
    assembly += '\n.Lresident_nested_eptp_before_root_write:\nret\n'
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
        push rbx
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
        pop rbx
        ret
    .Lresident_nested_msr_entry_is_writable:
    .Lresident_nested_guest_msr_list_is_mapped:
        mov eax, 1
        ret
    .Lresident_nested_copy_guest_msr_list:
        mov ecx, r10d
        shl ecx, 1
        rep movsq
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
    end = assembly_source.index('.Lresident_nested_l2_route:', start)
    cache_flush = assembly_source[start:end].strip()
    cache_flush = cache_flush.replace("wbinvd", "inc qword ptr [r12 + 8]")
    cache_flush += """
    .Lresident_guest_privilege:
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
    start = assembly_source.index('.Lresident_nested_merge_msr_bitmap_loop:')
    end = assembly_source.index('.Lresident_nested_intercept_unmapped_msr_bitmap:', start)
    bitmap_merge = assembly_source[start:end]
    bitmap_merge += """
    .Lresident_nested_use_composed_msr_bitmap:
        ret
    .globl test_merge_msr_bitmaps
    test_merge_msr_bitmaps:
        push rsi
        push rdi
        mov rsi, rcx
        mov rdi, rdx
        mov rdx, r8
        mov ecx, 512
        call .Lresident_nested_merge_msr_bitmap_loop
        pop rdi
        pop rsi
        ret
    """
    policy_start = assembly_source.index('.Lresident_update_apply_msr_policy:')
    policy_end = assembly_source.index('.Lresident_update_retire_nested:', policy_start)
    policy = assembly_source[policy_start:policy_end]
    hwp_index = int(re.search(r'const IA32_HWP_REQUEST_MSR: u32 = (0x[0-9a-f]+);', source)[1], 0)
    policy_constants = {"update_context_phase": 0, "b_nested_l0_msr_bitmap": 0,
                        "hwp_request_write_byte": 2048 + (hwp_index >> 3),
                        "hwp_request_write_mask": 255 ^ (1 << (hwp_index & 7))}
    policy = re.sub(r'\{(\w+)\}', lambda match: str(policy_constants[match[1]]), policy)
    policy += """
    .globl test_update_msr_policy
    test_update_msr_policy:
        push r12
        push r13
        mov r12, rcx
        mov r13, rdx
        mov eax, 0x1234
        call .Lresident_update_apply_msr_policy
        pop r13
        pop r12
        ret
    """
    (output / "resident-msr-bitmap.S").write_text(".text\n" + bitmap_merge + policy, encoding="utf-8")
    start = source.index("            allow_native_msr_reads(bitmap);")
    end = source.index("    // L1 owns the local APIC", start)
    bitmap_policy = "fn clock_bitmap() -> ResidentPages {\nlet mut msr_bitmap = ResidentPages::new();\nlet bitmap = &mut msr_bitmap.bytes;\n"
    bitmap_policy += source[start:end] + "\nmsr_bitmap\n}\n"
    start = source.index("fn allow_low_msr_passthrough(")
    end = source.index("fn spec_ctrl_available(", start)
    bitmap_policy += source[start:end]
    for name in set(re.findall(r"\b(?:IA32_[A-Z0-9_]+|MSR_BITMAP_(?:WRITE_LOW|READ_HIGH|WRITE_HIGH)_OFFSET)\b", bitmap_policy)):
        bitmap_policy += re.search(rf"const {name}:[^;]+;", source)[0] + "\n"
    start = source.index("fn spec_ctrl_available(")
    end = source.index("\n}", start) + 2
    (output / "definitions.rs").write_text(source[start:end] + "\n" + bitmap_policy, encoding="utf-8")


def prepare_resident_pages(project: Path):
    output = project / "builds" / "resident-pages-tests"
    output.mkdir(parents=True, exist_ok=True)
    source = (project / "src/memory.rs").read_text(encoding="utf-8")
    def item(declaration):
        start = source.index(declaration)
        opening = source.index("{", start)
        depth, end = 1, opening + 1
        while depth:
            depth += (source[end] == "{") - (source[end] == "}")
            end += 1
        return source[start:end]
    definitions = "\n".join(item(declaration) for declaration in [
        "pub enum AddressConstraint",
        "pub struct ResidentPages",
        "impl ResidentPages",
        "impl Drop for ResidentPages",
    ])
    definitions = definitions.replace("crate::hv_core::", "hv_core::")
    (output / "definitions.rs").write_text(definitions, encoding="utf-8")


def prepare_resident_telemetry(project: Path):
    output = project / "builds" / "resident-telemetry-tests"
    output.mkdir(parents=True, exist_ok=True)
    source = read_resident_assembly(project)
    start = source.index('.Lresident_dispatch_cpuid_diagnostic:')
    end = source.index('.Lresident_dispatch_cpuid_standard:', start)
    trace_start = source.index('.Lresident_diagnostic_nested_record_failure:')
    trace_end = source.index('.Lresident_dispatch_cpuid:', trace_start)
    assembly = source[trace_start:trace_end] + "\n" + source[start:end]
    profile_start = source.index('.Lresident_profile_exit_handler:')
    profile_end = source.index('.Lresident_dispatch_halt:', profile_start)
    assembly += "\n" + source[profile_start:profile_end]
    macro_start = source.index('.macro resident_telemetry_counter ')
    macro_end = source.index('.endm', macro_start) + len('.endm')
    assembly = source[macro_start:macro_end] + "\n" + assembly
    names = sorted(set(re.findall(r"\{((?:b_|event_)[a-z0-9_]+)\}", assembly)))
    offsets = {}
    cursor = 0
    for name in names:
        offsets[name] = cursor
        cursor += 4096 if name == "event_control_cpu_states" else 1024 if name == "b_nested_exit_reason_counts" else 512 if name == "event_cpu_contexts" else (
            192 * 8 if name == "b_nested_failure_trace" else (
            56 if name in {"b_watchdog_before", "b_watchdog_after", "b_watchdog_resume", "b_entry_failure_guest"}
            else 32 if name == "b_nested_exit_handler_cycles" else 8
            )
        )
    constants = {
        "cpuid_reason": 10, "matrixhv_status_leaf": 0x4D485652,
        "guest_contract_subleaf": 54, "guest_contract_unsupported": 3,
        "ept_violation_reason": 48, "invept_reason": 50, "preemption_timer_reason": 52,
        "vmread_reason": 23, "vmwrite_reason": 25, "vmlaunch_reason": 20, "vmresume_reason": 24,
        "log_serial_sink": 1,
        "nested_failure_trace_capacity": 32,
        "nested_failure_trace_limit": 0x161,
        "guest_rip": 0, "guest_rsp": 1, "guest_rflags": 2,
        "guest_cr0": 3, "guest_cr3": 4, "guest_cr4": 5, "guest_efer": 6,
        "control_cpu_state_size": 64, "control_cpu_stage": 0, "control_cpu_phase": 8,
        "control_cpu_on_failure_reason": 16, "control_cpu_on_failure_qualification": 24,
        "control_cpu_native_snapshot_count": 32, "control_cpu_sequence": 40,
        "control_cpu_native_storage_physical": 48,
        "native_snapshot_size": 80, "native_snapshot_stack": 16,
        "native_stack_bytes": 64, "native_snapshot_capacity": 24,
        "native_snapshot_pairs": 5, "native_snapshot_leaf_limit": 0x4000 + 24 * 5,
        "native_snapshots_offset": 64,
    }
    assembly = re.sub(r"\{([a-z0-9_]+)\}", lambda match: str(
        (offsets if match[1] in offsets else constants)[match[1]]
    ), assembly)
    assembly = assembly.replace("rdtsc", "mov eax, 100\nxor edx, edx")
    assembly = assembly.replace("vmread r11, rax",
        "lea r11, [rip + test_guest_state]\nmov r11, [r11 + rax * 8]\ncmp r12, 0")
    wrappers = """
    .text
    .globl test_watchdog_begin
    test_watchdog_begin:
        push r12
        mov r12, rcx
        mov r10d, [r12 + LAST_RAX_OFFSET]
        call .Lresident_telemetry_begin
        call .Lresident_watchdog_begin
        pop r12
        ret
    .globl test_watchdog_complete
    test_watchdog_complete:
        push r12
        mov r12, rcx
        call .Lresident_watchdog_handler_returned
        call .Lresident_watchdog_resuming
        pop r12
        ret
    .globl test_counter
    test_counter:
        push r12
        mov r12, rcx
        stc
        resident_telemetry_counter inc, EXIT_COUNT_OFFSET, ACTIVE_OFFSET
        pushfq
        pop rax
        pop r12
        ret
    .globl test_profile_exit
    test_profile_exit:
        push r12
        mov r12, rcx
        call .Lresident_profile_exit_handler
        pop r12
        ret
    .globl test_nested_failure_record
    test_nested_failure_record:
        push r12
        mov r12, rcx
        mov r10, r8
        mov r8, rdx
        call .Lresident_diagnostic_nested_record_failure
        pop r12
        ret
    .globl test_diagnostic
    test_diagnostic:
        push rbx
        push r12
        push r13
        mov r12, rcx
        mov [r12 + EVENT_OFFSET], rdx
        mov ecx, r8d
        mov r13, r9
        sub rsp, 32
        jmp .Lresident_dispatch_cpuid_diagnostic
    .Lresident_dispatch_cpuid_advance:
        mov eax, [rsp]
        mov [r13], eax
        mov eax, [rsp + 24]
        mov [r13 + 4], eax
        mov eax, [rsp + 8]
        mov [r13 + 8], eax
        mov eax, [rsp + 16]
        mov [r13 + 12], eax
        add rsp, 32
        pop r13
        pop r12
        pop rbx
        ret
    .Lresident_dispatch_vmread_failed:
        ud2
    .data
    .balign 8
    test_guest_state:
        .quad 0x123456789abcdef0, 0xabcdef0123456780, 0x202, 0x80000011, 0x1000, 0x2000, 0x500
    matrixhv_resident_island_log_backend:
        .byte 0
    .text
    """
    wrappers = wrappers.replace("EVENT_OFFSET", str(offsets["b_event_context"]))
    wrappers = wrappers.replace("LAST_RAX_OFFSET", str(offsets["b_last_rax"]))
    wrappers = wrappers.replace("EXIT_COUNT_OFFSET", str(offsets["b_exit_count"]))
    wrappers = wrappers.replace("ACTIVE_OFFSET", str(offsets["b_telemetry_active"]))
    counter_macro, assembly = assembly.split('.endm', 1)
    (output / "resident-telemetry.S").write_text(
        counter_macro + '.endm\n' + wrappers + "\n" + assembly, encoding="utf-8"
    )
    mapping = "fn offset(name: &str) -> usize { match name {\n"
    mapping += "\n".join(f'    "{name}" => {value // 8},' for name, value in offsets.items())
    mapping += '\n    _ => panic!("unknown telemetry field {name}"),\n} }\n'
    (output / "offsets.rs").write_text(mapping, encoding="utf-8")


def prepare_resident_visual(project: Path):
    output = project / "builds" / "resident-visual-tests"
    output.mkdir(parents=True, exist_ok=True)
    source = read_resident_assembly(project)
    start = source.index('.globl matrixhv_resident_ebs_callback')
    callback_end = source.index('.globl matrixhv_resident_get_variable', start)
    paint_start = source.index('.Lresident_claim_diagnostic:', callback_end)
    end = source.index('.Lresident_serial_state:', paint_start)
    hex_start = source.index('.Lresident_paint_hex:', end)
    hex_end = source.index('.Lresident_serial_write:', hex_start)
    emit_start = source.index('.Lresident_diagnostic_emit_value:', end)
    serial_char_start = source.index('.Lresident_serial_char:', hex_end)
    serial_hex_start = source.index('.Lresident_serial_hex64:', serial_char_start)
    serial_hex_end = source.index('.Lresident_vmcs12_field_index_table:', serial_hex_start)
    msr_start = source.index('.Lresident_guarded_rdmsr:')
    msr_end = source.index('.globl matrixhv_resident_island_gp', msr_start)
    gp_end = source.index('.Lresident_host_gp_fatal:', msr_end)
    exception_start = source.index('.globl matrixhv_resident_exception_stubs', gp_end)
    exception_end = source.index('.globl matrixhv_resident_island_fatal', exception_start)
    timer_start = source.index('.Lresident_reload_diagnostic_timer:')
    timer_end = source.index('.Lresident_sample_framebuffer_on_exit:', timer_start)
    timer_assembly = source[timer_start:timer_end].strip()
    timer_assembly = timer_assembly.replace("rdtsc", "mov rax, rdi\nmov rdx, rdi\nshr rdx, 32")
    timer_assembly = timer_assembly.replace(
        "vmwrite rax, r11", "mov [rbx], r11\nmov [rbx + 8], rax\ncmp r11, 0"
    )
    timer_assembly += "\n.Lresident_dispatch_vmwrite_failed:\nud2"
    sample_end = source.index('.Lresident_dispatch_resume:', timer_end)
    sample_assembly = source[timer_end:sample_end].replace(
        "rdtsc", "mov rax, qword ptr [rip + test_visual_tsc]\nmov rdx, rax\nshr rdx, 32"
    )
    timer_assembly += "\n" + sample_assembly
    boot_timer_start = source.index('.Lresident_dispatch_boot_timer:')
    boot_timer_end = source.index('.Lresident_boot_timer_retry_event:', boot_timer_start)
    boot_timer = source[boot_timer_start:boot_timer_end]
    boot_timer = boot_timer.replace("rdtsc", "mov rax, qword ptr [rip + test_visual_tsc]\nmov rdx, rax\nshr rdx, 32")
    boot_timer = boot_timer.replace("vmread r11, rax", "mov r11, [r12 + {test_pin_controls}]\ncmp r12, 0")
    boot_timer = boot_timer.replace("vmwrite rax, r11", "mov [r12 + {test_pin_controls}], r11\ncmp r12, 0")
    timer_assembly += "\n" + boot_timer + """
    .Lresident_boot_timer_retry_event:
        ret
    .Lresident_diagnostic_snapshot:
        inc qword ptr [r12 + {test_snapshot_count}]
        ret
    .Lresident_dispatch_unsupported:
    .Lresident_dispatch_vmread_failed:
        ud2
    """
    assembly = (
        source[start:callback_end]
        + source[paint_start:end]
        + source[emit_start:hex_start]
        + source[hex_start:hex_end]
        + source[hex_end:serial_char_start]
        + source[serial_hex_start:serial_hex_end]
        + source[msr_start:gp_end]
        + ".balign 16\n"
        + source[exception_start:exception_end]
    ).strip()
    assembly = assembly.replace(
        ".Lresident_host_nmi_return:\npop rax\niretq",
        ".Lresident_host_nmi_return:\npop rax\njmp .Ltest_nmi_return",
    ).replace("mov rax, qword ptr gs:[112]", "mov rax, qword ptr [rip + matrixhv_resident_island_event_context]")
    assembly = assembly.replace(
        "jz .Lresident_host_gp_fatal", "jz .Ltest_gp_unhandled"
    ).replace("iretq", "jmp .Ltest_gp_return")
    assembly = (
        assembly.replace("cli", "nop")
        .replace("mov rdx, cr2", "mov edx, 0x12345678")
        .replace("matrixhv_resident_island_fatal", ".Ltest_exception_return")
        .replace(".Lresident_island_fatal_owned", ".Ltest_exception_return")
        .replace(".Lresident_island_fatal_serial", ".Ltest_exception_return")
    )
    assembly += "\njmp .Ltest_exception_return"
    assembly = assembly.replace("rdtsc", "mov rax, qword ptr [rip + test_visual_tsc]\nmov rdx, rax\nshr rdx, 32")
    assembly = assembly.replace(
        "vmread rdx, rax",
        "mov rdx, qword ptr [rcx + {test_primary_controls}]\ncmp rcx, 0",
    ).replace(
        "vmwrite rax, rdx",
        "mov qword ptr [rcx + {test_primary_controls}], rdx\ncmp rcx, 0",
    )
    screen = (project / "src/diagnostics.rs").read_text(encoding="utf-8")
    def marker_constant(name):
        return int(re.search(rf"const {name}: usize = (\d+);", screen).group(1))
    wrappers = """
    .data
    .balign 8
    .globl test_visual_tsc
    test_visual_tsc:
        .quad 1000
    .text
    .Lresident_nested_eptp_sync_host_nmi:
        xor eax, eax
        ret
    .Ltest_convert_pointer:
        xor eax, eax
        ret
    .globl test_claim_diagnostic
    test_claim_diagnostic:
        mov r8, rcx
        call .Lresident_claim_diagnostic
        sete al
        movzx eax, al
        ret
    .globl test_set_backend
    test_set_backend:
        mov byte ptr [rip + matrixhv_resident_island_log_backend], cl
        mov qword ptr [rip + .Ltest_serial_length], 0
        ret
    .globl test_copy_serial
    test_copy_serial:
        push rsi
        push rdi
        mov rdi, rcx
        mov rax, qword ptr [rip + .Ltest_serial_length]
        cmp rax, rdx
        cmova rax, rdx
        mov rcx, rax
        lea rsi, [rip + .Ltest_serial_bytes]
        rep movsb
        pop rdi
        pop rsi
        ret
    .globl test_emit_value
    test_emit_value:
        mov rax, rdx
        mov edx, r8d
        mov r8, rcx
        mov ecx, edx
        jmp .Lresident_diagnostic_emit_value
    .Lresident_serial_char:
        push rcx
        push rdx
        mov rcx, qword ptr [rip + .Ltest_serial_length]
        cmp rcx, 4096
        jae .Ltest_serial_char_done
        lea rdx, [rip + .Ltest_serial_bytes]
        mov byte ptr [rdx + rcx], al
        inc rcx
        mov qword ptr [rip + .Ltest_serial_length], rcx
    .Ltest_serial_char_done:
        pop rdx
        pop rcx
        ret
    .globl test_paint_stage
    test_paint_stage:
        mov r8, rcx
        mov ecx, edx
        jmp .Lresident_paint_stage
    .globl test_paint_byte
    test_paint_byte:
        mov eax, edx
        mov edx, r8d
        mov r8, rcx
        mov ecx, edx
        jmp .Lresident_paint_byte
    .globl test_paint_hex
    test_paint_hex:
        mov rax, rdx
        mov edx, r8d
        mov r8, rcx
        mov ecx, edx
        jmp .Lresident_paint_hex
    .globl test_msr_fault_fixup
    test_msr_fault_fixup:
        mov rax, rcx
        jmp .Lresident_access_fault_fixup
    .globl test_read_fault_rip
    test_read_fault_rip:
        lea rax, [rip + .Lresident_rdmsr_instruction]
        ret
    .globl test_write_fault_rip
    test_write_fault_rip:
        lea rax, [rip + .Lresident_wrmsr_instruction]
        ret
    .globl test_xsetbv_fault_rip
    test_xsetbv_fault_rip:
        lea rax, [rip + .Lresident_xsetbv_instruction]
        ret
    .globl test_fault_resume_rip
    test_fault_resume_rip:
        lea rax, [rip + .Lresident_access_fault_return]
        ret
    .globl test_gp_frame
    test_gp_frame:
        push rbx
        mov rbx, rcx
        sub rsp, 48
        mov r10, qword ptr [rbx + 8]
        mov qword ptr [rsp], r10
        mov r10, qword ptr [rbx]
        mov qword ptr [rsp + 8], r10
        mov qword ptr [rsp + 16], 8
        mov qword ptr [rsp + 24], 2
        mov qword ptr [rsp + 32], 0
        mov qword ptr [rsp + 40], 0
        mov rax, qword ptr [rbx + 16]
        mov rdx, qword ptr [rbx + 24]
        jmp matrixhv_resident_island_gp
    .Ltest_gp_unhandled:
        mov qword ptr [rbx + 56], 1
        pop rdx
        pop rax
        add rsp, 8
    .Ltest_gp_return:
        mov r10, qword ptr [rsp]
        mov qword ptr [rbx + 32], r10
        mov qword ptr [rbx + 40], rax
        mov qword ptr [rbx + 48], rdx
        add rsp, 40
        pop rbx
        ret
    .globl test_exception_frame
    test_exception_frame:
        push rbx
        mov rbx, rdx
        mov qword ptr [rip + matrixhv_resident_island_event_context], rbx
        mov r10d, ecx
        push 0
        push 0
        push 2
        push 8
        push r9
        mov eax, 0x60227d00
        bt eax, ecx
        jnc .Ltest_exception_enter
        push r8
    .Ltest_exception_enter:
        lea r11, [rip + matrixhv_resident_exception_stubs]
        shl r10, 4
        add r11, r10
        jmp r11
    .Ltest_exception_return:
        add rsp, 56
        pop rbx
        ret
    .Ltest_nmi_return:
        add rsp, 40
        pop rbx
        ret
    .data
    .balign 8
    matrixhv_resident_island_event_context:
        .quad 0
    matrixhv_resident_original_get_variable:
        .quad 0
    matrixhv_resident_original_set_variable:
        .quad 0
    matrixhv_resident_runtime_get_variable:
        .quad 0
    matrixhv_resident_runtime_set_variable:
        .quad 0
    matrixhv_resident_bridge_context:
        .quad 0
    matrixhv_resident_convert_pointer:
        .quad .Ltest_convert_pointer
    matrixhv_resident_island_log_backend:
        .byte 2
    .balign 8
    .Ltest_serial_length:
        .quad 0
    .Ltest_serial_bytes:
        .zero 4096
    .text
    """
    (output / "resident-visual.S").write_text(wrappers + assembly, encoding="utf-8")
    timer_wrapper = """
    .text
    .globl test_sample_framebuffer
    test_sample_framebuffer:
        push r12
        mov r12, rcx
        call .Lresident_sample_framebuffer_on_exit
        pop r12
        ret
    .globl test_dispatch_timer
    test_dispatch_timer:
        push r12
        mov r12, rcx
        call .Lresident_dispatch_boot_timer
        pop r12
        ret
    .globl test_reload_timer
    test_reload_timer:
        push rbx
        push rdi
        push r12
        mov r12, rcx
        mov rdi, rdx
        mov rbx, r8
        call .Lresident_reload_diagnostic_timer
        pop r12
        pop rdi
        pop rbx
        ret
    """
    (output / "resident-timer.S").write_text(timer_wrapper + timer_assembly, encoding="utf-8")
    constants = f"""
    const MARKER_SIDE: usize = {marker_constant('RESIDENT_MARKER_SIZE')};
    const MARKER_STEP: usize = {marker_constant('RESIDENT_MARKER_STEP')};
    const MARKER_ROW_STEP: usize = {marker_constant('RESIDENT_MARKER_ROW_STEP')};
    const HEX_Y: usize = {marker_constant('RESIDENT_HEX_Y')};
    const HEX_ROW_STEP: usize = {marker_constant('RESIDENT_HEX_ROW_STEP')};
    const HEX_ROWS: usize = {marker_constant('RESIDENT_HEX_ROWS')};
    const HEX_COLUMN_STEP: usize = {marker_constant('RESIDENT_HEX_COLUMN_STEP')};
    """
    (output / "definitions.rs").write_text(constants, encoding="utf-8")


def prepare_boot_state(project: Path):
    resident = read_resident_rust(project)
    nested = (project / "src/nested.rs").read_text()
    collector = ast.parse((project / "tests/collect_boot_state.py").read_text())
    functions = [node for node in collector.body if isinstance(node, ast.FunctionDef)
                 and node.name in ("structure", "append_u64_fields")]
    namespace = {"resident": resident, "nested": nested, "re": re,
                 "fields": {}, "formats": {}, "offset": 0}
    exec(compile(ast.Module(body=functions, type_ignores=[]), "collect_boot_state.py", "exec"), namespace)
    namespace["append_u64_fields"](namespace["structure"](resident, "ResidentBootContext"), "")
    output = project / "builds/boot-state-tests"
    output.mkdir(parents=True, exist_ok=True)
    harness = "use std::mem::{offset_of, size_of};\n"
    harness += 'pub mod protocol { include!("../../src/protocol.rs"); }\n'
    harness += 'pub mod nested { include!("../../src/nested.rs"); }\n'
    harness += 'pub mod memory { pub const PAGE_SIZE: usize = 4096; }\n'
    harness += 'pub mod hv_core { pub mod bridge { include!("../../src/core/bridge.rs"); } }\n'
    harness += 'pub mod abi { include!("../../src/core/resident/abi.rs"); }\n'
    harness += "use abi::ResidentBootContext;\n"
    harness += "fn main() {\n"
    for name, format_code in namespace["formats"].items():
        path = name
        displacement = ""
        if name.rsplit(".", 1)[-1].isdecimal():
            path, index = name.rsplit(".", 1)
            element = "u64" if format_code == "<Q" else "u32"
            displacement = f" + {index} * size_of::<{element}>()"
        harness += f'println!("{name}={{}}", offset_of!(ResidentBootContext, {path}){displacement});\n'
    harness += "}\n"
    source_path = output / "layout.rs"
    executable = output / "layout.exe"
    source_path.write_text(harness)
    subprocess.run(["rustc", "--edition=2024", "-Dwarnings", str(source_path),
                    "-o", str(executable)], check=True, cwd=project)
    result = subprocess.run([str(executable)], check=True, capture_output=True, text=True)
    actual = dict(line.split("=", 1) for line in result.stdout.splitlines())
    expected = namespace["fields"]
    assert set(actual) == set(expected)
    for name, offset in expected.items():
        assert int(actual[name]) == offset, (name, offset, actual[name])
        assert struct.calcsize(namespace["formats"][name]) in (4, 8)
    print(f"Verified {len(expected)} resident fields, including nested structs and mixed-width arrays.")


def prepare_smp(project: Path):
    output = project / "builds/smp-tests"
    output.mkdir(parents=True, exist_ok=True)
    source = (project / "src/smp.rs").read_text(encoding="utf-8")
    opening = source[source.index("fn open_mp_services("):source.index("pub(crate) fn enumerate(")]
    batch = source[source.index("struct ApBatchEntry {"):]
    vcpu = (project / "src/core/vcpu.rs").read_text(encoding="utf-8")
    start = vcpu.rindex("#[unsafe(no_mangle)]", 0, vcpu.index("unsafe extern \"efiapi\" fn matrixhv_ap_prepare("))
    end = vcpu.index("#[unsafe(no_mangle)]", vcpu.index("pub(crate) fn matrixhv_ap_launch_asm(", start))
    definitions = """use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use uefi::{Status, boot};
use uefi::proto::pi::mp::MpServices;
""" + opening + batch + vcpu[start:end]
    (output / "definitions.rs").write_text(definitions, encoding="utf-8")
    assembly = (project / "src/asm/ap_launch.S").read_text(encoding="utf-8")
    # Execute the production save/prepare/restore paths with only privileged
    # instructions and the resident guest probe replaced by host equivalents.
    assembly = assembly.replace("    cli\n", "    nop\n")
    assembly = assembly.replace("    vmlaunch\n", "    jmp .Lap_guest_return\n")
    guest = """.macro matrixhv_ap_guest_probe
.Lap_guest_return:
    mov rax, 0x123456789abcdef0
    jmp .Lap_restore
.endm
"""
    (output / "ap-launch.S").write_text(guest + assembly, encoding="utf-8")


COMPONENTS = {
    "boot": {
        "order": prepare_boot_order,
        "config": None,
    },
    "smp": {
        "batch": prepare_smp,
    },
    "ept": {
        "core_audit": None,
        "cache": prepare_ept_cache,
        "high": prepare_ept_cache,
        "pci_bar": prepare_pci_bar,
        "sync": prepare_eptp_sync,
    },
    "nested": {
        "policy": prepare_evmcs,
        "shadow": prepare_vmcs_shadow,
        "native_shadow": prepare_native_shadow,
        "ept": prepare_nested_ept,
        "logging": prepare_nested_logging,
        "regressions": prepare_nested_regressions,
    },
    "resident": {
        "control": prepare_resident_control,
        "msr": prepare_resident_msr,
        "hyperv_time": prepare_hyperv_time,
        "pages": prepare_resident_pages,
        "telemetry": prepare_resident_telemetry,
        "visual": prepare_resident_visual,
    },
    "runtime": {
        "logger": prepare_logger,
    },
    "hardware": {
        "cpu_state": None,
        "vmexit_timing": None,
    },
}
