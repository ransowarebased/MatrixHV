"""Read resident assembly with nested blocks at their production expansion sites."""

from pathlib import Path
import re


def read_resident_assembly(project: Path) -> str:
    assembly = project / "src" / "asm"
    island = (assembly / "resident_island.S").read_text(encoding="utf-8")
    nested = (assembly / "nested.S").read_text(encoding="utf-8")
    lines = nested.splitlines(keepends=True)
    index = 0
    while index < len(lines):
        declaration = re.fullmatch(
            r"\.macro (matrixhv_resident_nested_\w+)\s*", lines[index]
        )
        if declaration is None:
            index += 1
            continue
        name = declaration[1]
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
        invocation = re.compile(rf"^{re.escape(name)}\n", re.MULTILINE)
        island, count = invocation.subn(lambda match: "".join(lines[start:index]), island)
        if count != 1:
            raise ValueError(f"Expected one resident expansion for {name}, found {count}")
        index += 1
    return island
