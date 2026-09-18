//! The image container `Program::from_flat_image` loads, built from an ELF the way
//! `mkimage.py` built it: `.text`, then every other allocated PROGBITS section as one span from
//! the lowest to the highest address, gaps zero-filled. `.bss` never appears.

use crate::elf::{read_sections, span};
use anyhow::{bail, Context, Result};
use std::path::Path;
use rand_zkvm::isa::{IMAGE_HEADER_WORDS, IMAGE_MAGIC, IMAGE_VERSION};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageInfo { pub text_base: u32, pub n_text: usize, pub data_base: u32, pub n_data: usize }

pub fn pack(elf: &[u8]) -> Result<Vec<u8>> {
    let loadable: Vec<_> = read_sections(elf)?.into_iter().filter(|s| s.progbits && s.alloc && s.size > 0).collect();
    let text: Vec<_> = loadable.iter().filter(|s| s.name == ".text").collect();
    let [text] = text[..] else { bail!("expected exactly one non-empty .text section, found {}", text.len()) };
    if text.addr % 4 != 0 || text.size % 4 != 0 {
        bail!(".text must be word-aligned in both address ({:#x}) and size ({})", text.addr, text.size);
    }
    let text_bytes = span(elf, text.offset, text.size)?;
    let mut data_sections: Vec<_> = loadable.iter().filter(|s| s.name != ".text").collect();
    data_sections.sort_by_key(|s| s.addr);
    let (data_base, data_bytes) = if let Some(first) = data_sections.first() {
        let base = first.addr;
        let end = data_sections.iter().map(|s| s.addr + s.size).max().unwrap();
        if base % 4 != 0 { bail!("data segment base {base:#x} is not word-aligned"); }
        if base < text.addr + text.size { bail!("the data segment overlaps .text"); }
        let mut data = vec![0u8; ((end - base) as usize + 3) / 4 * 4];
        for s in &data_sections {
            let at = (s.addr - base) as usize;
            data[at..at + s.size as usize].copy_from_slice(span(elf, s.offset, s.size)?);
        }
        (base, data)
    } else {
        (0, Vec::new())
    };
    let mut out = Vec::with_capacity(4 * IMAGE_HEADER_WORDS + text_bytes.len() + data_bytes.len());
    for w in [IMAGE_MAGIC, IMAGE_VERSION, text.addr, text.size / 4, data_base, (data_bytes.len() / 4) as u32] {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out.extend_from_slice(text_bytes);
    out.extend_from_slice(&data_bytes);
    Ok(out)
}

pub fn describe(image: &[u8]) -> Result<ImageInfo> {
    if image.len() < 4 * IMAGE_HEADER_WORDS || image.len() % 4 != 0 { bail!("not an image: {} bytes", image.len()); }
    let w = |i: usize| u32::from_le_bytes(image[4 * i..4 * i + 4].try_into().unwrap());
    if w(0) != IMAGE_MAGIC { bail!("not an image: magic {:#x}", w(0)); }
    if w(1) != IMAGE_VERSION { bail!("image version {} is not {IMAGE_VERSION}", w(1)); }
    Ok(ImageInfo { text_base: w(2), n_text: w(3) as usize, data_base: w(4), n_data: w(5) as usize })
}

/// The text words of an image (for the checker) and its data words.
pub fn split(image: &[u8]) -> Result<(ImageInfo, Vec<u32>, Vec<u32>)> {
    let info = describe(image)?;
    let body: Vec<u32> = image[4 * IMAGE_HEADER_WORDS..].chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
    if body.len() != info.n_text + info.n_data { bail!("image body has {} words, header says {} + {}", body.len(), info.n_text, info.n_data); }
    let (t, d) = body.split_at(info.n_text);
    Ok((info, t.to_vec(), d.to_vec()))
}

/// Write `image` to `out` and its pin beside it, `<out>.sha256`, in the form
/// `guests-compiled/bin/*.bin.sha256` uses (`shasum -a 256`'s: `<hex>  <file name>\n`). `pack` and
/// `build` both write through here, so a rebuilt guest's pin is never left stale beside it.
pub fn write_image(out: &Path, image: &[u8]) -> Result<()> {
    use sha2::Digest;
    let name = out.file_name().with_context(|| format!("{} names no file to write the image to", out.display()))?;
    std::fs::write(out, image).with_context(|| format!("writing {}", out.display()))?;
    let pin = format!("{}.sha256", out.display());
    std::fs::write(&pin, format!("{}  {}\n", hex::encode(sha2::Sha256::digest(image)), name.to_string_lossy()))
        .with_context(|| format!("writing {pin}"))?;
    Ok(())
}
