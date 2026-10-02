"""Collect read-only boot evidence with IDA's VMware GDB backend."""

import json
import os
from pathlib import Path
import re
import struct
import sys
import traceback

import ida_dbg
import ida_idd
import ida_pro
import idc


project = Path(__file__).resolve().parents[1]
output = Path(os.environ["MATRIXHV_EVIDENCE_ROOT"]).resolve()
output.relative_to(project / "builds")
sample = os.environ["MATRIXHV_EVIDENCE_SAMPLE"]
sys.stdout = (output / f"{sample}-ida.txt").open("w", buffering=1)
sys.stderr = sys.stdout


def structure(source, name):
    return source.split(f"struct {name} {{", 1)[1].split("\n}", 1)[0]


resident = "\n".join((project / "src/core" / name).read_text()
                     for name in ("resident/abi.rs",))
nested = (project / "src/nested.rs").read_text()
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
                re.search(r"const " + re.escape(length) + r": usize = (\d+)", nested)[1]
            )
            for index in range(count):
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
try:
    if not ida_dbg.load_debugger("gdb", True):
        raise RuntimeError("GDB debugger unavailable")
    ida_dbg.set_remote_debugger("127.0.0.1", "", 8864)
    print("START", ida_dbg.start_process("", "", ""))
    print("EVENT", ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 10))
    names = [descriptor[0].upper() for descriptor in ida_idd.dbg_get_registers()]
    for index in range(ida_dbg.get_thread_qty()):
        thread = ida_dbg.getn_thread(index)
        ida_dbg.select_thread(thread)
        registers = dict(zip(names, (value.ival for value in ida_dbg.get_reg_vals(thread))))
        rip = registers["RIP"]
        instructions = idc.get_bytes(rip, 32, True)
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
        values["event.visual_base"] = event[5]
        values["event.visual_stride_bytes"] = event[6]
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
    (output / f"{sample}-state.json").write_text(json.dumps(result, indent=2))
    traceback.print_exc()
finally:
    try:
        print("VIRTUAL", idc.send_dbg_command("virt"))
        print("RESUME", ida_dbg.continue_process())
        print("DETACH", ida_dbg.detach_process())
    finally:
        ida_pro.qexit(exit_code)
