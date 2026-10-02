"""Recover IDA functions reached from Hyper-V's data-referenced exception stubs."""

import json
import os
from pathlib import Path

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_pro
import idautils
import idc


output = Path(os.environ["MATRIXHV_TSC_REVIEW_OUTPUT"])
base = ida_nalt.get_imagebase()
targets = [0x3abdc0, 0x2327e0, 0x21f21c, 0x2240bc, 0x2241b8, 0x25916c,
           0x31ba3c, 0x31bdf0, 0x255ce0, 0x324f1c, 0x3249ac, 0x21f65c,
           0x224750]
data_misclassified_ranges = {0x2327e0: 0x2328b4, 0x21f65c: 0x21fab9}
try:
    ida_auto.auto_wait()
    for rva in targets:
        address = base + rva
        if ida_funcs.get_func(address) is None:
            if rva in data_misclassified_ranges:
                ida_bytes.del_items(address, ida_bytes.DELIT_EXPAND,
                                    data_misclassified_ranges[rva] - rva)
            idc.create_insn(address)
            ida_funcs.add_func(address)
    ida_auto.auto_wait()
    records = []
    with (output / "tsc-exception-decompiled.txt").open("w", encoding="utf-8") as decompiled, (
        output / "tsc-exception-disassembly.txt"
    ).open("w", encoding="utf-8") as listing:
        hexrays = ida_hexrays.init_hexrays_plugin()
        for rva in targets:
            address = base + rva
            function = ida_funcs.get_func(address)
            header = f"\nFUNCTION RVA={rva:#x} {idc.get_func_name(address)}\n"
            listing.write(header)
            decompiled.write(header)
            if function is None:
                decompiled.write("Function creation failed\n")
                continue
            record = {"rva": hex(rva), "name": idc.get_func_name(address), "calls": []}
            for item in idautils.FuncItems(address):
                if not ida_bytes.is_code(ida_bytes.get_full_flags(item)):
                    continue
                line = idc.generate_disasm_line(item, 0) or ""
                listing.write(f"{item - base:#x} {line}\n")
                if idc.print_insn_mnem(item) == "call":
                    record["calls"].append({"rva": hex(item - base), "instruction": line})
            if hexrays:
                try:
                    decompiled.write(str(ida_hexrays.decompile(address)) + "\n")
                except Exception as error:
                    decompiled.write(f"Decompilation failed: {error}\n")
            records.append(record)
    (output / "tsc-exception-index.json").write_text(json.dumps(records, indent=2) + "\n")
    ida_pro.qexit(0)
except Exception:
    import traceback
    (output / "tsc-exception-error.txt").write_text(traceback.format_exc())
    ida_pro.qexit(1)
