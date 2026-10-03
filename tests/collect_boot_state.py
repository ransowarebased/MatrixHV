"""Collect read-only boot evidence with IDA's VMware GDB backend."""

import json
import os
from pathlib import Path
import re
import struct
import sys
import traceback

import ida_dbg
import ida_bytes
import ida_ida
import ida_idd
import ida_idp
import ida_pro
import ida_segment
import ida_ua
import idc


project = Path(__file__).resolve().parents[1]
output = Path(os.environ["MATRIXHV_EVIDENCE_ROOT"]).resolve()
output.relative_to(project / "builds")
sample = os.environ["MATRIXHV_EVIDENCE_SAMPLE"]
sys.stdout = (output / f"{sample}-ida.txt").open("w", buffering=1)
sys.stderr = sys.stdout


def structure(source, name):
    return source.split(f"struct {name} {{", 1)[1].split("\n}", 1)[0]


resident = "\n".join((project / "src/vmx" / name).read_text()
                     for name in ("resident/abi.rs",))
nested = (project / "src/vmx/nested.rs").read_text() + "\n" + (
    project / "src/vmx/vmcs12.rs").read_text()
fields = {}
formats = {}
offset = 0


def append_u64_fields(source, prefix):
    global offset
    for name, kind in re.findall(r"(?:pub )?(\w+): ([^,\n]+),", source):
        if kind in ("u64", "u32"):
            size = 8 if kind == "u64" else 4
            offset = (offset + size - 1) // size * size
            fields[prefix + name] = offset
            formats[prefix + name] = "<Q" if kind == "u64" else "<I"
            offset += size
        elif kind == "WatchdogGuestState":
            append_u64_fields(structure(resident, kind), prefix + name + ".")
        elif kind == "NestedVmxState":
            append_u64_fields(structure(nested, kind), prefix + name + ".")
        elif kind == "NestedVmcs12State":
            append_u64_fields(structure(nested, kind), prefix + name + ".")
        elif (array := re.fullmatch(r"\[(u64|u32); (\w+)\]", kind)):
            element, length = array.groups()
            size = 8 if element == "u64" else 4
            offset = (offset + size - 1) // size * size
            count = int(length) if length.isdecimal() else int(
                re.search(r"const " + re.escape(length) + r": usize = (\d+)", resident + nested)[1]
            )
            for index in range(count):
                if name == "flight_recorder_records" and index not in (0, count - 1):
                    offset += size
                    continue
                fields[f"{prefix}{name}.{index}"] = offset
                formats[f"{prefix}{name}.{index}"] = "<Q" if element == "u64" else "<I"
                offset += size
        elif name == "original_gdtr":
            return
        else:
            raise RuntimeError(f"Unsupported resident layout field: {prefix}{name}: {kind}")


append_u64_fields(structure(resident, "ResidentBootContext"), "")
reference_serial = os.environ.get("MATRIXHV_REFERENCE_SERIAL")
serial_path = Path(reference_serial) if reference_serial else output / "serial.log"
result = {"cpus": [], "contexts": []}
exit_code = 1
attached = False


def plain_layout(source, name, stop=None):
    sizes = {"u8": (1, 1), "u16": (2, 2), "u32": (4, 4),
             "u64": (8, 8), "usize": (8, 8), "AtomicU64": (8, 8)}
    constants = {"BANK_PAGES": 64}
    constants.update({name: int(value) for name, value in re.findall(
        r"(?:pub )?const (\w+): usize = (\d+);", source)})

    def size_of(kind):
        if kind in sizes:
            return sizes[kind]
        array = re.fullmatch(r"\[(.*); ([\w:]+)\]", kind)
        if array:
            size, alignment = size_of(array[1])
            count = int(array[2]) if array[2].isdecimal() else constants[array[2].split("::")[-1]]
            return size * count, alignment
        _, size, alignment = plain_layout(source, kind)
        return size, alignment

    members, cursor, alignment = {}, 0, 1
    for field, kind in re.findall(r"(?:pub )?(\w+): ([^,\n]+),", structure(source, name)):
        if field == stop:
            members[field] = (cursor + 7) & ~7
            break
        size, field_alignment = size_of(kind)
        alignment = max(alignment, field_alignment)
        cursor = (cursor + field_alignment - 1) // field_alignment * field_alignment
        members[field] = cursor
        cursor += size
    return members, (cursor + alignment - 1) // alignment * alignment, alignment


try:
    if not ida_idp.set_processor_type("metapc", ida_idp.SETPROC_LOADER):
        raise RuntimeError("Intel x86 processor module unavailable")
    ida_ida.inf_set_app_bitness(64)
    if not ida_dbg.load_debugger("gdb", True):
        raise RuntimeError("GDB debugger unavailable")
    ida_dbg.set_remote_debugger("127.0.0.1", "", 8864)
    print("START", ida_dbg.start_process("", "", ""))
    event = ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 10)
    print("EVENT", event)
    attached = ida_dbg.get_process_state() != ida_dbg.DSTATE_NOTASK
    if event <= 0 or ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
        raise RuntimeError("Debugger did not suspend the VM")
    if ida_dbg.get_thread_qty() == 0:
        raise RuntimeError("Debugger returned no CPUs")
    names = [descriptor[0].upper() for descriptor in ida_idd.dbg_get_registers()]
    for index in range(ida_dbg.get_thread_qty()):
        thread = ida_dbg.getn_thread(index)
        ida_dbg.select_thread(thread)
        registers = dict(zip(names, (value.ival for value in ida_dbg.get_reg_vals(thread))))
        rip = registers["RIP"]
        instructions = idc.get_bytes(rip, 32, True)
        if instructions is None or len(instructions) != 32:
            raise RuntimeError(f"Cannot read instruction bytes for CPU {thread}")
        cpu = {"thread": thread, "registers": registers,
               "cr3": idc.send_dbg_command("r cr3"),
               "rip_bytes": instructions.hex() if instructions else None}
        result["cpus"].append(cpu)
        print("CPU", json.dumps(cpu))
    print("PHYSICAL", idc.send_dbg_command("phys"))
    # Read after suspension so a guest reboot during IDA startup cannot leave
    # stale allocation addresses from an earlier boot in the same serial file.
    serial = serial_path.read_text(errors="replace")
    boot_marker = "[MATRIXHV][PHASE] boot.entry"
    if boot_marker in serial:
        serial = serial[serial.rfind(boot_marker):]
    contexts = re.findall(r"smp resident (?:BSP|processor=\d+).*?context=(0x[0-9a-fA-F]+)", serial)
    if not contexts:
        # Early probe failures can precede the SMP residency log. R12 still
        # identifies each halted CPU's root context; verify its canaries below.
        candidates = [cpu["registers"]["R12"] for cpu in result["cpus"]]
        candidates.extend(int(address, 16) for address in re.findall(
            r"(?:residency_context|context)=(0x[0-9a-fA-F]+)", serial))
        contexts = []
        signature = struct.pack("<QQ", 0x4856424F4F544331, 0x4856424F4F544332)
        for address in dict.fromkeys(candidates):
            if address & 0xFFF:
                continue
            canary_address = address + fields["canary_start"]
            ida_dbg.invalidate_dbgmem_contents(canary_address, len(signature))
            if idc.get_bytes(canary_address, len(signature), True) == signature:
                contexts.append(hex(address))
        if not contexts:
            raise RuntimeError("No valid resident contexts in registers or serial log")
    if reference_serial:
        # A UART-free run has no serial addresses. Scan only the nearby physical
        # allocation neighborhood from an earlier boot. Canaries, CPU count,
        # current layout, and runtime fields validate every discovered context.
        addresses = [int(address, 16) for address in contexts]
        start = (min(addresses) & ~0xFFFFF) - 0x100000
        end = (max(addresses) & ~0xFFFFF) + 0x200000
        ida_dbg.invalidate_dbgmem_contents(start, end - start)
        memory = idc.get_bytes(start, end - start, True)
        if memory is None or len(memory) != end - start:
            raise RuntimeError("Cannot read bounded resident allocation range")
        signature = struct.pack("<QQ", 0x4856424F4F544331, 0x4856424F4F544332)
        contexts = []
        cursor = 0
        while (cursor := memory.find(signature, cursor)) >= 0:
            candidate = start + cursor - fields["canary_start"]
            if candidate & 0xFFF == 0:
                contexts.append(hex(candidate))
            cursor += len(signature)
        if len(contexts) != len(result["cpus"]):
            raise RuntimeError("Resident context count differs from debugger CPU count")
        result["context_discovery"] = {"start": start, "end": end,
                                       "reference_serial": str(serial_path)}
    for address_text in dict.fromkeys(contexts):
        address = int(address_text, 16)
        size = max(field_offset + struct.calcsize(formats[name])
                   for name, field_offset in fields.items())
        ida_dbg.invalidate_dbgmem_contents(address, size)
        data = idc.get_bytes(address, size, True)
        if data is None or len(data) != size:
            raise RuntimeError(f"Cannot read resident context at {address_text}")
        values = {name: struct.unpack_from(formats[name], data, field_offset)[0]
                  for name, field_offset in fields.items()}
        (output / f"{sample}-context-{address:x}.bin").write_bytes(data)
        recorder_offset = fields["flight_recorder_records.0"]
        sequence = values["flight_recorder_sequence"]
        records = []
        for index in range(2048):
            record = struct.unpack_from("<10Q", data, recorder_offset + index * 80)
            if max(0, sequence - 2048) < record[0] <= sequence:
                entry = dict(zip(("sequence", "tsc", "reason", "rip", "qualification", "gpa", "vcpu", "flags", "vmcs", "detail"), record))
                entry["instruction_error"] = entry["detail"] if entry["flags"] & (1 << 32) else None
                entry["msr"] = entry["detail"] if entry["flags"] & (1 << 33) else None
                records.append(entry)
        records.sort(key=lambda record: record["sequence"])
        (output / f"{sample}-flight-{address:x}.json").write_text(json.dumps({
            "context": address, "sequence": sequence,
            "frozen": values["flight_recorder_frozen"], "records": records,
        }, indent=2))
        if values["canary_start"] != 0x4856424F4F544331 or values["canary_end"] != 0x4856424F4F544332:
            raise RuntimeError("Resident context layout or canaries are invalid")
        event_address = values["event_context"]
        ida_dbg.invalidate_dbgmem_contents(event_address, 104)
        event_data = idc.get_bytes(event_address, 104, True)
        event = struct.unpack("<13Q", event_data)
        values["event.ebs_seen"] = event[1]
        values["event.va_seen"] = event[2]
        values["event.cpu_mask"] = event[7]
        values["event.halted"] = event[8]
        values["event.host_fault_vector"] = event[9]
        values["event.host_fault_rip"] = event[10]
        values["event.host_fault_error_code"] = event[11]
        values["event.host_fault_address"] = event[12]
        values["event.visual_base"] = event[5]
        values["event.visual_stride_bytes"] = event[6]
        if "update" not in result:
            layout_source = resident + (project / "src/vmx/bridge.rs").read_text() + (project / "src/protocol.rs").read_text()
            event_fields, event_size, _ = plain_layout(layout_source, "ResidentEventContext")
            cpu_fields, cpu_size, _ = plain_layout(layout_source, "ControlCpuState")
            update_source = (project / "src/update.rs").read_text()
            update_fields, update_prefix_size, _ = plain_layout(update_source, "RuntimeContext", "transaction")
            event_data = idc.get_bytes(event_address, event_size, True)
            if event_data is None or len(event_data) != event_size:
                raise RuntimeError("Cannot read resident runtime update state")
            read_quad = lambda data, offset: struct.unpack_from("<Q", data, offset)[0]
            update_address = read_quad(event_data, event_fields["update_context_physical"])
            update_data = idc.get_bytes(update_address, update_prefix_size + 384, True)
            if update_data is None:
                raise RuntimeError("Cannot read hidden runtime update context")
            banks = struct.unpack_from("<2Q", update_data, update_fields["banks"])
            status_offset = update_fields["transaction"]
            cpu_states = []
            for cpu_index in range(read_quad(event_data, event_fields["control_processor_count"])):
                cpu_offset = event_fields["control_cpu_states"] + cpu_index * cpu_size
                host = cpu_offset + cpu_fields["host_fields"]
                host_rip = read_quad(event_data, host + 21 * 8)
                bank = next((index for index, base in enumerate(banks) if base <= host_rip < base + 256 * 1024), None)
                cpu_states.append({"cpu": cpu_index, "host_rip": host_rip,
                                   "host_idt": read_quad(event_data, host + 16 * 8), "bank": bank})
            ptes = struct.unpack_from("<128Q", update_data, update_fields["bank_ptes"])
            result["update"] = {
                "context": update_address, "banks": banks,
                "transaction": read_quad(update_data, status_offset),
                "phase": struct.unpack_from("<I", update_data, status_offset + 8)[0],
                "previous_version": read_quad(update_data, status_offset + 24),
                "next_version": read_quad(update_data, status_offset + 32),
                "verified_mask": read_quad(update_data, status_offset + 48),
                "retained_banks": read_quad(update_data, status_offset + 56),
                "previous_identity": update_data[status_offset + 64:status_offset + 96].hex(),
                "next_identity": update_data[status_offset + 96:status_offset + 128].hex(),
                "cpu_states": cpu_states,
                "bank_page_permissions": [[read_quad(idc.get_bytes(pointer, 8, True), 0) & ~0x000FFFFFFFFFF000
                                           for pointer in ptes[index * 64:(index + 1) * 64]] for index in range(2)],
            }
        if os.environ.get("MATRIXHV_VMFUNC_PROBE") == "1" and values["processor_number"] == 0:
            probe_address = values["nested.vmxon_operand"] + 136
            ida_dbg.invalidate_dbgmem_contents(probe_address, 24)
            probe_data = idc.get_bytes(probe_address, 24, True)
            if probe_data is None or len(probe_data) != 24:
                raise RuntimeError("Cannot read VMFUNC probe results")
            result["vmfunc_probe"] = {
                "baseline_exits": struct.unpack_from("<I", probe_data, 0)[0],
                "switch_loop_exits": struct.unpack_from("<I", probe_data, 8)[0],
                "completed": struct.unpack_from("<Q", probe_data, 16)[0],
                "valid_vmfunc_instructions": 2049,
            }
            list_address = values["nested.vmcs12.extended_fields.119"]
            ida_dbg.invalidate_dbgmem_contents(list_address, 4096)
            list_data = idc.get_bytes(list_address, 4096, True)
            if list_data is None or len(list_data) != 4096:
                raise RuntimeError("Cannot read VMFUNC probe EPTP list")
            result["vmfunc_probe"]["eptp_slots"] = {
                str(index): struct.unpack_from("<Q", list_data, index * 8)[0]
                for index in (0, 2, 511)
            }
        result["contexts"].append({"address": address, "values": values})
        print("CONTEXT", address_text, json.dumps(values))
    (output / f"{sample}-state.json").write_text(json.dumps(result, indent=2))
    exit_code = 0
except Exception:
    result["error"] = traceback.format_exc()
    (output / f"{sample}-state.json").write_text(json.dumps(result, indent=2))
    traceback.print_exc()
finally:
    try:
        if attached:
            print("VIRTUAL", idc.send_dbg_command("virt"))
            print("DETACH", ida_dbg.detach_process())
            ida_dbg.wait_for_next_event(ida_dbg.WFNE_ANY, 10)
        if exit_code == 0:
            if ida_dbg.get_process_state() != ida_dbg.DSTATE_NOTASK:
                raise RuntimeError("Debugger remained attached after capture")
            # Decode only after detaching; copied bytes belong to this empty IDB.
            for cpu in result["cpus"]:
                rip = cpu["registers"]["RIP"]
                code = bytes.fromhex(cpu["rip_bytes"])
                start = rip & ~0xFFF
                end = (rip + len(code) + 0xFFF) & ~0xFFF
                if not ida_segment.get_segment_info(None, rip):
                    if not ida_segment.add_segm(0, start, end, "VM_SNAPSHOT", "CODE"):
                        raise RuntimeError(f"Cannot create snapshot segment at {start:#x}")
                if not ida_segment.set_segment_addressing(rip, 2):
                    raise RuntimeError("Cannot select 64-bit snapshot addressing")
                ida_bytes.put_bytes(rip, code)
                cpu["disassembly"] = []
                cursor = rip
                while cursor < rip + len(code) and len(cpu["disassembly"]) < 8:
                    instruction = ida_ua.insn_t()
                    size = ida_ua.decode_insn(instruction, cursor)
                    if size == 0 or cursor + size > rip + len(code):
                        break
                    idc.create_insn(cursor)
                    cpu["disassembly"].append({"address": cursor, "size": size,
                                               "text": idc.generate_disasm_line(cursor, 0)})
                    cursor += size
                if not cpu["disassembly"]:
                    raise RuntimeError(f"Cannot decode CPU {cpu['thread']} instruction bytes")
            (output / f"{sample}-state.json").write_text(json.dumps(result, indent=2))
    except Exception:
        result["error"] = traceback.format_exc()
        (output / f"{sample}-state.json").write_text(json.dumps(result, indent=2))
        traceback.print_exc()
        exit_code = 1
    finally:
        ida_pro.qexit(exit_code)
