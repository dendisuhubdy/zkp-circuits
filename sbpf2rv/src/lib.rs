//! `sbpf2rv`: translates an sBPF ELF into C that runs natively in the Rand zkVM.
//!
//! Design: `docs/superpowers/specs/2026-09-18-sbpf-to-rv32-translator-design.md`. Three stages:
//! the scanner ([`scan`]) walks a loaded [`sbpf_core::elf::Program`] and recovers its functions,
//! basic blocks and control-flow edges; the emitter ([`emit`]) turns that into `program.c` over the
//! `sbpf-rt` runtime; and [`shim`] writes the Rust crate around it that `rand-guest build` turns
//! into an image publishing exactly the interpreter guest's eight output words.

pub mod emit;
pub mod scan;
pub mod shim;
