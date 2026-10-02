"""Emulate the identified Hyper-V invariant-TSC gates without executing kernel code."""

import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys

import pefile


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "builds/hv-review-deps"))
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RSI,
    UC_X86_REG_R14, UC_X86_REG_RIP, UC_X86_REG_RSP,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_GS_BASE,
)


EXPECTED_SHA256 = "cf5af317f300b7da25f37d5dc6ca75bff91b6b868d89f337d23ec1773340ce8a"
STACK = 0x10000000
BOOT = 0x10100000
STOP = 0x10200000
HYPERCALL_PAGE = 0x10300000
PROCESSOR = 0x10400000
TRAP = 0x10500000


def run_case(image, native_invariant, suppress_native_tsc, access_control, interface, locked):
    base = image.OPTIONAL_HEADER.ImageBase
    machine = Uc(UC_ARCH_X86, UC_MODE_64)
    machine.mem_map(base, image.OPTIONAL_HEADER.SizeOfImage)
    machine.mem_write(base, image.get_memory_mapped_image())
    for address in [STACK, BOOT, STOP, HYPERCALL_PAGE]:
        machine.mem_map(address, 0x10000)
    writes = []
    modeled_calls = set()

    def write64(address, value):
        machine.mem_write(address, struct.pack("<Q", value))

    def read64(address):
        return struct.unpack("<Q", machine.mem_read(address, 8))[0]

    def return_from_call(value=None):
        if value is not None:
            machine.reg_write(UC_X86_REG_RAX, value)
        stack = machine.reg_read(UC_X86_REG_RSP)
        machine.reg_write(UC_X86_REG_RIP, read64(stack))
        machine.reg_write(UC_X86_REG_RSP, stack + 8)

    def hook_code(emulator, address, size, user_data):
        rva = address - base
        if rva == 0x262680:
            modeled_calls.add(hex(rva))
            return_from_call(emulator.reg_read(UC_X86_REG_RCX) >> 12)
        elif rva == 0x31cc84:
            modeled_calls.add(hex(rva))
            return_from_call(0x40000002)
        elif rva in [0x236090, 0x3a5810]:
            modeled_calls.add(hex(rva))
            return_from_call()
        elif rva == 0x31dde4:
            modeled_calls.add(hex(rva))
            emulator.mem_write(emulator.reg_read(UC_X86_REG_RCX), bytes(16))
            return_from_call()
        elif bytes(emulator.mem_read(address, size)) == b"\x0f\x32":
            msr = emulator.reg_read(UC_X86_REG_RCX) & 0xffffffff
            value = 2 if msr == 0x40000001 and locked else 0
            emulator.reg_write(UC_X86_REG_RAX, value)
            emulator.reg_write(UC_X86_REG_RDX, 0)
            emulator.reg_write(UC_X86_REG_RIP, address + size)
        elif bytes(emulator.mem_read(address, size)) == b"\x0f\x30":
            msr = emulator.reg_read(UC_X86_REG_RCX) & 0xffffffff
            value = ((emulator.reg_read(UC_X86_REG_RDX) & 0xffffffff) << 32) | (
                emulator.reg_read(UC_X86_REG_RAX) & 0xffffffff
            )
            writes.append({"rva": hex(rva), "msr": hex(msr), "value": hex(value)})
            emulator.reg_write(UC_X86_REG_RIP, address + size)

    machine.hook_add(UC_HOOK_CODE, hook_code)
    cache = base + 0xa2540
    machine.mem_write(cache + 4, struct.pack("<II", 0x16, 0x80000008))
    for leaf, registers in [
        (0x80000000, [0x80000008, 0, 0, 0]),
        (0x80000007, [0, 0, 0, 0x100 if native_invariant else 0]),
    ]:
        offset = (leaf - 0x7fffffdb) * 16 + 12
        machine.mem_write(cache + offset, struct.pack("<4I", *registers))
    write64(base + 0xaf158, 0)
    write64(base + 0xb1d80, int(interface) | (int(access_control) << 31))
    write64(base + 0xb1d58, HYPERCALL_PAGE)
    write64(BOOT + 0x118, int(suppress_native_tsc))
    stack = STACK + 0x8008
    write64(stack, STOP)
    machine.reg_write(UC_X86_REG_RSP, stack)
    machine.reg_write(UC_X86_REG_RSI, BOOT)
    machine.reg_write(UC_X86_REG_R14, 1)
    machine.emu_start(base + 0x25925f, base + 0x2592c3, count=10000)
    if machine.reg_read(UC_X86_REG_RIP) != base + 0x2592c3:
        raise AssertionError("The timing gate did not reach its expected continuation")
    flags = read64(base + 0xaf158)
    machine.reg_write(UC_X86_REG_RSP, stack)
    machine.emu_start(base + 0x31bdf0, STOP, count=10000)
    if machine.reg_read(UC_X86_REG_RIP) != STOP:
        raise AssertionError("Nested initialization did not return")
    expected = native_invariant and not suppress_native_tsc and not access_control and interface and not locked
    observed = any(item["msr"] == "0x40000118" and item["value"] == "0x1" for item in writes)
    if observed != expected:
        raise AssertionError((native_invariant, suppress_native_tsc, access_control, interface, locked, writes))
    return {
        "native_cpuid_invariant_tsc": native_invariant,
        "boot_flags_0x118_bit0": suppress_native_tsc,
        "cpuid_access_tsc_invariant_bit15": access_control,
        "nested_interface": interface,
        "hypercall_msr_locked": locked,
        "timing_flags": hex(flags),
        "writes": writes,
        "writes_invariant_control": observed,
        "modeled_calls": sorted(modeled_calls),
    }


def run_fault_path(image, recovery_registered):
    base = image.OPTIONAL_HEADER.ImageBase
    machine = Uc(UC_ARCH_X86, UC_MODE_64)
    machine.mem_map(base, image.OPTIONAL_HEADER.SizeOfImage)
    machine.mem_write(base, image.get_memory_mapped_image())
    for address in [STACK, STOP, PROCESSOR, TRAP]:
        machine.mem_map(address, 0x10000)
    modeled_calls = set()
    fatal = []
    resets = []

    def write64(address, value):
        machine.mem_write(address, struct.pack("<Q", value))

    def read64(address):
        return struct.unpack("<Q", machine.mem_read(address, 8))[0]

    def return_from_call(value=None):
        if value is not None:
            machine.reg_write(UC_X86_REG_RAX, value)
        stack = machine.reg_read(UC_X86_REG_RSP)
        machine.reg_write(UC_X86_REG_RIP, read64(stack))
        machine.reg_write(UC_X86_REG_RSP, stack + 8)

    def hook_code(emulator, address, size, user_data):
        rva = address - base
        if rva == 0x21f21c:
            fatal.append({"code": hex(emulator.reg_read(UC_X86_REG_RCX)),
                          "fault_rva": hex(emulator.reg_read(UC_X86_REG_RDX)),
                          "exception": hex(emulator.reg_read(UC_X86_REG_R8))})
        elif rva == 0x3b3640:
            modeled_calls.add(hex(rva))
            target = emulator.reg_read(UC_X86_REG_RCX)
            value = emulator.reg_read(UC_X86_REG_RDX) & 255
            length = emulator.reg_read(UC_X86_REG_R8)
            emulator.mem_write(target, bytes([value]) * length)
            return_from_call(target)
        elif rva == 0x3b3380:
            modeled_calls.add(hex(rva))
            target = emulator.reg_read(UC_X86_REG_RCX)
            source = emulator.reg_read(UC_X86_REG_RDX)
            length = emulator.reg_read(UC_X86_REG_R8)
            emulator.mem_write(target, bytes(emulator.mem_read(source, length)))
            return_from_call(target)
        elif rva in [0x2256d8, 0x224750, 0x24f4a8, 0x237a8c, 0x22400c, 0x2241b8]:
            modeled_calls.add(hex(rva))
            return_from_call(0)
        elif bytes(emulator.mem_read(address, size)) == b"\x0f\x31":
            emulator.reg_write(UC_X86_REG_RAX, 0x100000)
            emulator.reg_write(UC_X86_REG_RDX, 0)
            emulator.reg_write(UC_X86_REG_RIP, address + size)
        elif bytes(emulator.mem_read(address, size)) == b"\xee":
            resets.append({"rva": hex(rva), "port": hex(emulator.reg_read(UC_X86_REG_RDX) & 65535),
                           "value": hex(emulator.reg_read(UC_X86_REG_RAX) & 255)})
            emulator.emu_stop()

    machine.hook_add(UC_HOOK_CODE, hook_code)
    write64(PROCESSOR, PROCESSOR)
    write64(PROCESSOR + 0x28, 1 << 63)
    write64(PROCESSOR + 0x300, TRAP + 0x1000 if recovery_registered else 0)
    write64(TRAP + 0xb8, base + 0x31bf76)
    write64(base + 0xdddf8, base)
    write64(base + 0xb1d80, 1)
    write64(base + 0xaf158, 8)
    write64(base + 0xa8500, 0x100000020)
    write64(base + 0xa8508, 1)
    write64(base + 0xa8620, 0x20)
    machine.mem_write(base + 0x235e8, struct.pack("<I", 0xffffffff))
    machine.mem_write(base + 0x9c040, struct.pack("<I", 18))
    machine.mem_write(base + 0xd4280, struct.pack("<I", 1))
    stack = STACK + 0x8008
    write64(stack, STOP)
    machine.reg_write(UC_X86_REG_GS_BASE, PROCESSOR)
    machine.reg_write(UC_X86_REG_RSP, stack)
    machine.reg_write(UC_X86_REG_RCX, 0x1004)
    machine.reg_write(UC_X86_REG_RDX, TRAP)
    machine.reg_write(UC_X86_REG_R8, TRAP + 0x2000)
    machine.emu_start(base + 0x2327e0, STOP, count=20000)
    if recovery_registered:
        assert not fatal and not resets
        assert machine.reg_read(UC_X86_REG_RIP) == STOP
    else:
        assert fatal == [{"code": "0x11", "fault_rva": "0x31bf76", "exception": "0x1004"}], fatal
        assert resets == [{"rva": "0x2241a2", "port": "0x64", "value": "0xfe"}], resets
    return {"recovery_registered": recovery_registered, "fatal": fatal, "reset_writes": resets,
            "modeled_calls": sorted(modeled_calls)}


def main():
    binary = PROJECT / "tools/hv-review/hvix64/hvix64.exe"
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError("The Hyper-V image does not match the reviewed build")
    image = pefile.PE(str(binary))
    image.relocate_image(0x20000000)
    cases = [run_case(image, *values) for values in itertools.product([False, True], repeat=5)]
    fault_cases = [run_fault_path(image, registered) for registered in [False, True]]
    report = {
        "binary_sha256": digest,
        "scope": "Emulation of actual instruction bytes using synthetic inputs; no VM logs or failed physical boot capture",
        "executed_ranges": ["0x25925f..0x2592c3", "0x255ce0..0x255d32", "0x32c504..0x32c757", "0x31bdf0..0x31c026"],
        "assumptions": [
            "The image is relocated to 0x20000000 inside the emulator; instruction RVAs are unchanged.",
            "CPUID cache and nested feature state are supplied as synthetic inputs.",
            "All preceding boot phases succeed; boot-mode phase dispatch reaches the selected blocks.",
            "A hypercall page already exists and its GPA translation succeeds.",
            "Memory allocation, cookie checking, optional nested-feature querying and reenlightenment follow-up are modeled.",
            "RDMSR/WRMSR are intercepted by the emulator; no physical MSR or firmware state is accessed.",
        ],
        "passed": len(cases),
        "cases": cases,
        "fault_dispatch_cases": fault_cases,
        "fault_dispatch_scope": "Synthetic #GP record at RVA 0x31bf76, one processor, boot stage 18, no debugger and no ACPI reset register. Memory helpers and platform notification/cleanup calls are modeled. Actual fatal-dispatch and reset-selection instructions are emulated; this is not a physical boot trace.",
        "physical_causality_proven": False,
    }
    output = PROJECT / "tools/hv-review/invariant-tsc-emulation.json"
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Passed {len(cases)} binary gate cases; evidence: {output}")


if __name__ == "__main__":
    main()
