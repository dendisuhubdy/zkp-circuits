#!/usr/bin/env python3
"""Pack a compiled guest ELF into the M4.3 image container `Program::from_flat_image` loads.

    mkimage.py <guest.elf> <out.bin>

The container is six little-endian header words followed by the two segments:

    [0x444e4152 ("RAND"), version 1, text_base, n_text, data_base, n_data, text..., data...]

`text` is `.text`; `data` is every other allocated PROGBITS section (`.rodata`, `.data`, …) as one
contiguous span from the lowest to the highest, with any gap between them zero-filled — the loader
skips zero words anyway, since RAM starts zero in-circuit. `.bss` is NOBITS and never appears.

Why this exists: the loader writes the data segment into RAM with a synthesised `li`/`sw` prologue
placed below `text_base`, so a compiled guest may have a `.rodata` (jump tables, panic locations,
constants LLVM materialised) instead of having to be data-free, and `hc` binds the data because it
is part of the program. See `research/docs/01-isa.md` and `Program::from_flat_image`.

No dependencies: the ELF32 section headers are read directly, so the guest Makefiles need nothing
but python3.
"""

import struct
import sys

MAGIC = 0x444E4152
VERSION = 1
SHT_PROGBITS = 1
SHF_ALLOC = 0x2


def sections(elf: bytes):
    """(name, addr, offset, size, type, flags) for every section of an ELF32 little-endian file."""
    if elf[:4] != b"\x7fELF" or elf[4] != 1 or elf[5] != 1:
        sys.exit("mkimage: not an ELF32 little-endian file")
    e_shoff, = struct.unpack_from("<I", elf, 0x20)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", elf, 0x2E)
    raw = []
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        name, typ, flags, addr, off, size = struct.unpack_from("<IIIIII", elf, base)
        raw.append((name, typ, flags, addr, off, size))
    strtab_off = raw[e_shstrndx][4]
    out = []
    for name, typ, flags, addr, off, size in raw:
        end = elf.index(b"\0", strtab_off + name)
        out.append((elf[strtab_off + name : end].decode(), addr, off, size, typ, flags))
    return out


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    elf = open(sys.argv[1], "rb").read()
    loadable = [
        s for s in sections(elf) if s[4] == SHT_PROGBITS and s[5] & SHF_ALLOC and s[3] > 0
    ]
    text = [s for s in loadable if s[0] == ".text"]
    if len(text) != 1:
        sys.exit("mkimage: expected exactly one non-empty .text section")
    _, text_addr, text_off, text_size, _, _ = text[0]
    if text_addr % 4 or text_size % 4:
        sys.exit("mkimage: .text must be word-aligned in both address and size")
    text_bytes = elf[text_off : text_off + text_size]

    data_sections = sorted((s for s in loadable if s[0] != ".text"), key=lambda s: s[1])
    if data_sections:
        data_base = data_sections[0][1]
        end = max(s[1] + s[3] for s in data_sections)
        if data_base % 4:
            sys.exit(f"mkimage: data segment base {data_base:#x} is not word-aligned")
        if data_base < text_addr + text_size:
            sys.exit("mkimage: the data segment overlaps .text")
        data = bytearray(((end - data_base) + 3) // 4 * 4)
        for name, addr, off, size, _, _ in data_sections:
            data[addr - data_base : addr - data_base + size] = elf[off : off + size]
        data_bytes = bytes(data)
    else:
        data_base, data_bytes = 0, b""

    header = struct.pack(
        "<6I", MAGIC, VERSION, text_addr, text_size // 4, data_base, len(data_bytes) // 4
    )
    with open(sys.argv[2], "wb") as f:
        f.write(header + text_bytes + data_bytes)
    names = ", ".join(s[0] for s in data_sections) or "none"
    print(
        f"mkimage: {sys.argv[2]}: text {text_size} B at {text_addr:#x}, "
        f"data {len(data_bytes)} B at {data_base:#x} ({names})"
    )


if __name__ == "__main__":
    main()
