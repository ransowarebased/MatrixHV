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


resident = (project / "src/core/vt_resident.rs").read_text()
nested = (project / "src/nested/state.rs").read_text()
vmcs = (project / "src/nested/vmcs.rs").read_text()
fields = {}
offset = 0


def append_u64_fields(source, prefix):
    global offset
    for name, kind in re.findall(r"(?:pub )?(\w+): ([^,\n]+),", source):
        if kind != "u64":
            break
        fields[prefix + name] = offset
        offset += 8


append_u64_fields(structure(resident, "ResidentBootContext"), "")
append_u64_fields(structure(nested, "NestedVmxState"), "nested.")
append_u64_fields(structure(vmcs, "NestedVmcs12State"), "nested.vmcs12.")
extended_count = int(re.search(r"const VMCS12_EXTENDED_FIELD_COUNT: usize = (\d+)", vmcs)[1])
offset += extended_count * 8 + 8
append_u64_fields(structure(nested, "NestedVmxState").split("pub vmcs12: NestedVmcs12State,", 1)[1], "nested.")
reference_serial = os.environ.get("MATRIXHV_REFERENCE_SERIAL")
serial_path = Path(reference_serial) if reference_serial else output / "serial.log"
serial = serial_path.read_text(errors="replace")
contexts = re.findall(r"smp resident (?:BSP|processor=\d+).*?context=(0x[0-9a-fA-F]+)", serial)
if not contexts:
    raise RuntimeError("No resident contexts in this run's serial log")

result = {"cpus": [], "contexts": []}
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
        size = max(fields.values()) + 8
        ida_dbg.invalidate_dbgmem_contents(address, size)
        data = idc.get_bytes(address, size, True)
        if data is None or len(data) != size:
            raise RuntimeError(f"Cannot read resident context at {address_text}")
        values = {name: struct.unpack_from("<Q", data, field_offset)[0]
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
        result["contexts"].append({"address": address, "values": values})
        print("CONTEXT", address_text, json.dumps(values))
    (output / f"{sample}-state.json").write_text(json.dumps(result, indent=2))
except Exception:
    traceback.print_exc()
finally:
    try:
        print("VIRTUAL", idc.send_dbg_command("virt"))
        print("RESUME", ida_dbg.continue_process())
        print("DETACH", ida_dbg.detach_process())
    finally:
        ida_pro.qexit(0)
