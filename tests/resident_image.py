"""Validate the copied resident image in an x86-64 COFF object."""

import argparse
from dataclasses import dataclass, replace
import hashlib
from pathlib import Path
import struct


ISLAND_SECTION = ".text.matrixhv_resident_island"
ISLAND_START = "matrixhv_resident_island_start"
ISLAND_END = "matrixhv_resident_island_end"


@dataclass(frozen=True)
class Section:
    name: str
    data: bytes
    relocations: int
    characteristics: int
    fixups: tuple


@dataclass(frozen=True)
class Symbol:
    name: str
    value: int
    section: int
    storage: int


@dataclass(frozen=True)
class Fixup:
    offset: int
    symbol: Symbol
    kind: int


def read_coff(path: Path):
    data = path.read_bytes()
    machine, section_count, _, symbol_offset, symbol_count, optional_size, _ = (
        struct.unpack_from("<HHIIIHH", data)
    )
    if machine != 0x8664 or optional_size != 0:
        raise ValueError(f"Expected an x86-64 COFF object: {path}")
    strings_offset = symbol_offset + symbol_count * 18
    strings_size, = struct.unpack_from("<I", data, strings_offset)
    if strings_offset + strings_size > len(data):
        raise ValueError("Truncated COFF string table")
    strings = data[strings_offset:strings_offset + strings_size]

    def string(offset):
        if not 4 <= offset < len(strings):
            raise ValueError(f"Invalid COFF string offset: {offset}")
        return strings[offset:strings.index(b"\0", offset)].decode("ascii")

    sections = []
    relocation_offsets = []
    for index in range(section_count):
        raw_name, _, _, size, offset, relocation_offset, _, relocations, _, flags = (
            struct.unpack_from("<8sIIIIIIHHI", data, 20 + index * 40)
        )
        name = raw_name.rstrip(b"\0").decode("ascii")
        if name.startswith("/"):
            name = string(int(name[1:]))
        if offset + size > len(data):
            raise ValueError(f"Truncated COFF section: {name}")
        sections.append(Section(name, data[offset:offset + size], relocations, flags, ()))
        relocation_offsets.append(relocation_offset)
    symbols = []
    symbol_indices = {}
    index = 0
    while index < symbol_count:
        name, value, section, _, storage, auxiliary = struct.unpack_from(
            "<8sIhHBB", data, symbol_offset + index * 18
        )
        if name[:4] == b"\0" * 4:
            name = string(struct.unpack_from("<I", name, 4)[0])
        else:
            name = name.rstrip(b"\0").decode("ascii")
        symbol = Symbol(name, value, section, storage)
        symbols.append(symbol)
        symbol_indices[index] = symbol
        index += 1 + auxiliary
    for index, (section, offset) in enumerate(zip(sections, relocation_offsets)):
        fixups = []
        for relocation_index in range(section.relocations):
            address, symbol_index, kind = struct.unpack_from(
                "<IIH", data, offset + relocation_index * 10
            )
            fixups.append(Fixup(address, symbol_indices[symbol_index], kind))
        sections[index] = replace(section, fixups=tuple(fixups))
    return sections, symbols


def validate_image(path: Path):
    sections, symbols = read_coff(path)
    matches = [(index + 1, section) for index, section in enumerate(sections)
               if section.name == ISLAND_SECTION]
    if len(matches) != 1:
        raise ValueError("The resident island must occupy exactly one section")
    section_index, island = matches[0]
    if island.relocations:
        raise ValueError("The copied resident image contains unresolved relocations")
    if not island.characteristics & 0x20 or not island.characteristics & 0x20000000:
        raise ValueError("The resident island must be executable code")
    alignment = (island.characteristics >> 20) & 0xf
    if not 5 <= alignment <= 14:
        raise ValueError("The resident island requires at least 16-byte alignment")
    exported = {symbol.name: symbol.value for symbol in symbols
                if symbol.section == section_index and symbol.storage == 2}
    if exported.get(ISLAND_START) != 0 or exported.get(ISLAND_END) != len(island.data):
        raise ValueError("Resident copy boundaries must span the complete section")
    if not all(0 <= offset < len(island.data) for name, offset in exported.items()
               if name != ISLAND_END):
        raise ValueError("A resident entry or patch slot lies outside the copied image")
    for name in ("matrixhv_resident_island_entry", "matrixhv_resident_island_gp",
                 "matrixhv_resident_island_fatal", "matrixhv_resident_island_log_backend",
                 "matrixhv_resident_island_event_context"):
        if name not in exported:
            raise ValueError(f"Missing resident entry or patch slot: {name}")
    for name, offset in exported.items():
        if name.endswith(("_log_backend", "_event_context", "_visual_callback",
                          "_msr_switch_count")) and (offset % 8 or offset + 8 > len(island.data)):
            raise ValueError(f"Misaligned resident patch slot: {name}")
    return island.data, exported


def entry_blocks(path: Path):
    sections, symbols = read_coff(path)
    # global_asm entries share the first .text section; Rust bodies have their
    # own sections. Compare individual blocks because owner moves reorder them.
    section_index, section = next((index + 1, section)
                                 for index, section in enumerate(sections)
                                 if section.name == ".text")
    exported = {symbol.name: symbol.value for symbol in symbols
                if symbol.section == section_index and symbol.storage == 2}
    if not exported or not all(name.startswith("matrixhv_") for name in exported):
        raise ValueError("Expected MatrixHV assembly entries in the first .text section")
    offsets = sorted({*exported.values(), len(section.data)})
    blocks = {}
    for name, start in exported.items():
        end = next(offset for offset in offsets if offset > start)
        fixups = tuple((fixup.offset - start, fixup.kind, fixup.symbol.name)
                       for fixup in section.fixups if start <= fixup.offset < end)
        blocks[name] = section.data[start:end], fixups
    return blocks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("object", type=Path)
    parser.add_argument("--baseline", type=Path)
    arguments = parser.parse_args()
    image, symbols = validate_image(arguments.object)
    if arguments.baseline:
        previous_image, previous_symbols = validate_image(arguments.baseline)
        if image != previous_image:
            first_difference = next((index for index, (old, new) in
                                     enumerate(zip(previous_image, image)) if old != new),
                                    min(len(previous_image), len(image)))
            raise ValueError(f"Resident instructions/data changed at offset {first_difference:#x}")
        if symbols != previous_symbols:
            raise ValueError("Resident exported symbols or patch offsets changed")
        print("Resident instructions, data and exported symbol offsets match the baseline")
        if entry_blocks(arguments.object) != entry_blocks(arguments.baseline):
            raise ValueError("Guest/root/AP assembly instructions or call relocation targets changed")
        print("Guest/root/AP assembly blocks and symbolic call targets match the baseline")
    print(f"Resident image: {len(image)} bytes, {len(symbols)} exported symbols, no relocations")
    print(f"SHA-256: {hashlib.sha256(image).hexdigest()}")


if __name__ == "__main__":
    main()
