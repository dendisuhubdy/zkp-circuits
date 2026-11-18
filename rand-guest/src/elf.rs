//! ELF32 little-endian section table, read directly — the guest toolchain needs nothing
//! but this (a port of the former `guests-compiled/mkimage.py`).

use anyhow::{bail, Context, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub addr: u32,
    pub offset: u32,
    pub size: u32,
    /// `SHT_PROGBITS`
    pub progbits: bool,
    /// `SHF_ALLOC`
    pub alloc: bool,
}

const SHT_PROGBITS: u32 = 1;
const SHF_ALLOC: u32 = 0x2;

fn u16_at(b: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(b.get(at..at + 2).context("ELF header truncated")?.try_into()?))
}
fn u32_at(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(b.get(at..at + 4).context("ELF header truncated")?.try_into()?))
}

/// The bytes of `[offset, offset + size)` in `elf`, bounds-checked: a structurally plausible but
/// corrupt section header (an `sh_offset`/`sh_size` past the end of the file, or one that wraps)
/// must return `Err`, never panic on an overflow or an out-of-range slice.
pub(crate) fn span(elf: &[u8], offset: u32, size: u32) -> Result<&[u8]> {
    let end = match offset.checked_add(size) {
        Some(end) if (end as usize) <= elf.len() => end as usize,
        _ => bail!(
            "section [{offset}, {}) is outside the file ({} bytes)",
            offset as u64 + size as u64,
            elf.len()
        ),
    };
    Ok(&elf[offset as usize..end])
}

pub fn read_sections(elf: &[u8]) -> Result<Vec<Section>> {
    if elf.len() < 0x34 || &elf[..4] != b"\x7fELF" || elf[4] != 1 || elf[5] != 1 {
        bail!("not an ELF32 little-endian file");
    }
    let e_shoff = u32_at(elf, 0x20)? as usize;
    let e_shentsize = u16_at(elf, 0x2e)? as usize;
    let e_shnum = u16_at(elf, 0x30)? as usize;
    let e_shstrndx = u16_at(elf, 0x32)? as usize;
    let mut raw = Vec::with_capacity(e_shnum);
    for i in 0..e_shnum {
        let base = e_shoff + i * e_shentsize;
        raw.push((u32_at(elf, base)?, u32_at(elf, base + 4)?, u32_at(elf, base + 8)?, u32_at(elf, base + 12)?, u32_at(elf, base + 16)?, u32_at(elf, base + 20)?));
    }
    let strtab_off = raw.get(e_shstrndx).context("no section name table")?.4 as usize;
    let mut out = Vec::with_capacity(e_shnum);
    for (name, typ, flags, addr, off, size) in raw {
        let start = strtab_off + name as usize;
        if start > elf.len() {
            bail!("section name offset {start} is outside the file ({} bytes)", elf.len());
        }
        let end = elf[start..].iter().position(|&b| b == 0).map(|p| start + p).context("unterminated section name")?;
        out.push(Section {
            name: String::from_utf8_lossy(&elf[start..end]).into_owned(),
            addr, offset: off, size,
            progbits: typ == SHT_PROGBITS,
            alloc: flags & SHF_ALLOC != 0,
        });
    }
    Ok(out)
}

/// A defined symbol from the ELF's `.symtab`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    pub value: u32,
    pub size: u32,
    /// `STT_FUNC`
    pub func: bool,
}

const SHT_SYMTAB: u32 = 2;
const STT_FUNC: u8 = 2;

/// Every defined, named symbol in the ELF's symbol table (`SHT_SYMTAB`, names from the string table
/// its `sh_link` points at), or `None` when the file has no symbol table at all (it was stripped).
/// Bounds-checked like [`read_sections`]: a corrupt table is an `Err`, never a panic.
pub fn read_symbols(elf: &[u8]) -> Result<Option<Vec<Symbol>>> {
    if elf.len() < 0x34 || &elf[..4] != b"\x7fELF" || elf[4] != 1 || elf[5] != 1 {
        bail!("not an ELF32 little-endian file");
    }
    let e_shoff = u32_at(elf, 0x20)? as usize;
    let e_shentsize = u16_at(elf, 0x2e)? as usize;
    let e_shnum = u16_at(elf, 0x30)? as usize;
    // (type, offset, size, link, entsize) of section `i`.
    let header = |i: usize| -> Result<(u32, u32, u32, u32, u32)> {
        let base = e_shoff.checked_add(i.checked_mul(e_shentsize).context("section header table overflows")?).context("section header table overflows")?;
        Ok((u32_at(elf, base + 4)?, u32_at(elf, base + 16)?, u32_at(elf, base + 20)?, u32_at(elf, base + 24)?, u32_at(elf, base + 36)?))
    };
    let mut out = None;
    for i in 0..e_shnum {
        let (typ, off, size, link, entsize) = header(i)?;
        if typ != SHT_SYMTAB {
            continue;
        }
        if entsize != 16 {
            bail!("symbol table entries are {entsize} bytes, not ELF32's 16");
        }
        if link as usize >= e_shnum {
            bail!("the symbol table names string table {link}, but there are {e_shnum} sections");
        }
        let (_, str_off, str_size, _, _) = header(link as usize)?;
        let strtab = span(elf, str_off, str_size)?;
        let table = span(elf, off, size)?;
        let syms = out.get_or_insert_with(Vec::new);
        for e in table.chunks_exact(16) {
            let st_name = u32::from_le_bytes(e[0..4].try_into()?) as usize;
            let st_shndx = u16::from_le_bytes(e[14..16].try_into()?);
            if st_name == 0 || st_shndx == 0 {
                continue; // unnamed, or undefined
            }
            let rest = strtab.get(st_name..).context("symbol name offset is outside the string table")?;
            let end = rest.iter().position(|&b| b == 0).context("unterminated symbol name")?;
            syms.push(Symbol {
                name: String::from_utf8_lossy(&rest[..end]).into_owned(),
                value: u32::from_le_bytes(e[4..8].try_into()?),
                size: u32::from_le_bytes(e[8..12].try_into()?),
                func: e[12] & 0xf == STT_FUNC,
            });
        }
    }
    Ok(out)
}
