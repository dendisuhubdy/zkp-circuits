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
