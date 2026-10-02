"""Check the captured physical USB EFI's synthetic-MSR fallback in emulation."""

import hashlib
import json
from pathlib import Path
import struct
import sys

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "builds/hv-review-deps"))

import capstone
import pefile
import unicorn
from unicorn import x86_const

EXPECTED_SHA256 = "79135403939f6003aae2134b38fcf2df8ca74b11449762e3d20b6fc029ecfeb7"
BASE = 0x20000000
STACK = 0x1000000
CONTEXT = 0x2000000
GUEST_RIP = 0xfffff8000031bf76


def run_case(image, hardware_fault):
    machine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    mapped = image.get_memory_mapped_image()
    machine.mem_map(BASE, (len(mapped) + 4095) & ~4095)
    machine.mem_write(BASE, mapped)
    machine.mem_map(STACK, 0x10000)
    machine.mem_map(CONTEXT, 0x20000)
    stack_pointer = STACK + 0x8000
    machine.mem_write(stack_pointer, struct.pack("<QQQ", 1, 0x40000118, 0))
    machine.mem_write(CONTEXT + 0xf8, struct.pack("<Q", 32))
    machine.mem_write(CONTEXT + 0x100, struct.pack("<Q", 2))
    machine.mem_write(CONTEXT + 0x130, struct.pack("<Q", GUEST_RIP))
    machine.reg_write(x86_const.UC_X86_REG_RSP, stack_pointer)
    machine.reg_write(x86_const.UC_X86_REG_R12, CONTEXT)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    vmcs = {0x681e: GUEST_RIP}
    writes = []
    visited = []

    def read_register(name):
        return machine.reg_read(getattr(x86_const, "UC_X86_REG_" + name.upper()))

    def hook_code(emulator, address, _size, _data):
        rva = address - BASE
        if rva in [0x43d57, 0x4602c, 0x46035, 0x455f5, 0x4567b, 0x45923]:
            visited.append(hex(rva))
        if rva == 0x45923:
            emulator.emu_stop()
            return
        instruction = next(decoder.disasm(bytes(emulator.mem_read(address, 15)), address))
        if instruction.mnemonic == "rdmsr":
            msr = read_register("ecx")
            assert msr == 0xfe, hex(msr)
            emulator.reg_write(x86_const.UC_X86_REG_RAX, 0x108)
            emulator.reg_write(x86_const.UC_X86_REG_RDX, 0)
        elif instruction.mnemonic == "wrmsr":
            writes.append({"rva": hex(rva), "msr": hex(read_register("ecx")),
                           "value": hex(read_register("eax") | (read_register("edx") << 32))})
            assert rva == 0x4602c
            if hardware_fault:
                # The image's GP fixup maps the guarded instruction to STC/RET.
                emulator.reg_write(x86_const.UC_X86_REG_RIP, BASE + 0x46035)
                return
        elif instruction.mnemonic == "vmwrite":
            field_register, value_register = instruction.op_str.split(", ")
            vmcs[read_register(field_register)] = read_register(value_register)
            emulator.reg_write(x86_const.UC_X86_REG_EFLAGS, read_register("eflags") & ~0x41)
        else:
            return
        emulator.reg_write(x86_const.UC_X86_REG_RIP, address + instruction.size)

    machine.hook_add(unicorn.UC_HOOK_CODE, hook_code)
    machine.emu_start(BASE + 0x439df, BASE + image.OPTIONAL_HEADER.SizeOfImage, count=2000)
    assert machine.reg_read(x86_const.UC_X86_REG_RIP) == BASE + 0x45923
    assert writes == [{"rva": "0x4602c", "msr": "0x40000118", "value": "0x1"}]
    if hardware_fault:
        assert vmcs[0x4016] == 0x80000b0d and vmcs[0x4018] == 0
        assert vmcs[0x681e] == GUEST_RIP
        assert "0x4567b" not in visited
    else:
        assert 0x4016 not in vmcs and vmcs[0x681e] == GUEST_RIP + 2, (vmcs, visited)
    return {"modeled_hardware_fault": hardware_fault, "native_writes_attempted": writes,
            "visited_rvas": visited, "resulting_vmcs": {hex(k): hex(v) for k, v in vmcs.items()}}


def main():
    capture = json.loads((PROJECT / "tools/hv-review/physical-windows/elevated-efi.json").read_text(encoding="utf-8-sig"))
    record = next(item for item in capture["files"] if item["source"] == "K:\\MatrixHV.efi")
    binary = Path(record["destination"])
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError("The USB image no longer matches the reviewed instruction RVAs")
    image = pefile.PE(str(binary))
    image.relocate_image(BASE)
    cases = [run_case(image, hardware_fault) for hardware_fault in [False, True]]
    output = PROJECT / "tools/hv-review/usb-msr-emulation.json"
    report = {
        "binary": str(binary), "sha256": digest, "passed": len(cases), "cases": cases,
        "scope": "Actual captured USB EFI instruction bytes with modeled hardware/VMCS; no VM logs or physical boot execution",
        "assumptions": [
            "CPL validation has succeeded and the L1 WRMSR dispatch reaches RVA 0x439df.",
            "Native MTRRCAP is modeled as 0x108; L2 and telemetry flags are clear.",
            "The fault case redirects the guarded WRMSR to its decoded GP fixup at RVA 0x46035.",
            "The nonfault case is a control demonstrating the success branch; it is not a claim that bare hardware implements this synthetic MSR.",
            "Privileged instructions never execute on the physical host.",
        ],
        "physical_reset_causality_proven": False,
    }
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Passed {len(cases)} captured-EFI MSR dispatch cases; evidence: {output}")


if __name__ == "__main__":
    main()
