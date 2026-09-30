"""Export PE-backed loader disassembly and matching symbol identity."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import urllib.error
import urllib.request
import uuid

import capstone
import pefile


def analyze(binary, output, fetch_symbols):
    data = binary.read_bytes()
    image = pefile.PE(data=data)
    metadata = {"binary": str(binary), "sha256": hashlib.sha256(data).hexdigest(),
                "image_base": image.OPTIONAL_HEADER.ImageBase, "symbols": []}
    for entry in getattr(image, "DIRECTORY_ENTRY_DEBUG", []):
        if entry.struct.Type != 2:
            continue
        record = image.get_data(entry.struct.AddressOfRawData, entry.struct.SizeOfData)
        if record[:4] != b"RSDS":
            continue
        guid = uuid.UUID(bytes_le=record[4:20]).hex.upper()
        age = struct.unpack_from("<I", record, 20)[0]
        name = record[24:].split(b"\0", 1)[0].decode().replace("\\", "/").split("/")[-1]
        url = f"https://msdl.microsoft.com/download/symbols/{name}/{guid}{age:X}/{name}"
        identity = {"name": name, "guid": guid, "age": age, "url": url}
        if fetch_symbols:
            try:
                with urllib.request.urlopen(url, timeout=30) as response:
                    (output / name).write_bytes(response.read())
                identity["download"] = "available"
            except (urllib.error.URLError, TimeoutError) as error:
                identity["download"] = str(error)
        metadata["symbols"].append(identity)
    exports = {entry.address: entry.name.decode() for entry in
               getattr(getattr(image, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])
               if entry.name}
    imports = {entry.address - image.OPTIONAL_HEADER.ImageBase: entry.name.decode()
               for library in getattr(image, "DIRECTORY_ENTRY_IMPORT", [])
               for entry in library.imports if entry.name}
    metadata["imports"] = imports
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    functions = []
    with (output / "hvloader-disassembly.txt").open("w", encoding="utf-8") as listing:
        for entry in image.DIRECTORY_ENTRY_EXCEPTION:
            start, end = entry.struct.BeginAddress, entry.struct.EndAddress
            function = {"start": start, "end": end, "name": exports.get(start),
                        "privileged": [], "calls": []}
            listing.write(f"\nFUNCTION {start:#x}..{end:#x} {exports.get(start, '')}\n")
            for instruction in decoder.disasm(image.get_data(start, end - start), start):
                annotation = ""
                if instruction.mnemonic == "call":
                    operand = instruction.operands[0]
                    if operand.type == capstone.CS_OP_IMM:
                        target = operand.imm
                        annotation = exports.get(target, "")
                    elif operand.type == capstone.CS_OP_MEM and operand.mem.base == capstone.x86.X86_REG_RIP:
                        target = instruction.address + instruction.size + operand.mem.disp
                        annotation = imports.get(target, "indirect")
                    else:
                        target = None
                    function["calls"].append({"rva": instruction.address, "target": target,
                                              "annotation": annotation})
                if instruction.mnemonic in {"cpuid", "rdmsr", "wrmsr", "vmcall", "vmlaunch",
                                            "vmresume", "vmxon", "vmxoff", "vmread", "vmwrite"}:
                    function["privileged"].append({"rva": instruction.address,
                                                   "instruction": instruction.mnemonic})
                listing.write(f"{instruction.address:#010x} {instruction.bytes.hex():24s} "
                              f"{instruction.mnemonic:8s} {instruction.op_str} {annotation}\n")
            functions.append(function)
    metadata["functions"] = functions
    (output / "hvloader-analysis.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(json.dumps({key: metadata[key] for key in ("binary", "sha256", "symbols")}, indent=2))
    print("Privileged functions:", [hex(function["start"]) for function in functions if function["privileged"]])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--fetch-symbols", action="store_true")
    arguments = parser.parse_args()
    arguments.output.resolve().relative_to(Path(__file__).resolve().parents[1] / "builds")
    arguments.output.mkdir(parents=True, exist_ok=True)
    analyze(arguments.binary.resolve(), arguments.output.resolve(), arguments.fetch_symbols)
