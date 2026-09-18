//! `sbpf2rv`: translates an sBPF ELF into C that runs natively in the Rand zkVM.
//!
//! Design: `docs/superpowers/specs/2026-09-18-sbpf-to-rv32-translator-design.md`. This crate's
//! first stage is the scanner ([`scan`]): it walks a loaded [`sbpf_core::elf::Program`] and
//! recovers the functions, basic blocks and control-flow edges the emitter (a later task)
//! translates into C, refusing anything it cannot statically account for.

pub mod scan;
