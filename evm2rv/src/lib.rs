//! `evm2rv`: translates Shanghai EVM runtime bytecode (`solc`'s output) into RV32 C over
//! `evm-rt/`, so `rand-guest build` can turn a Solidity contract into a zkVM image without the
//! interpreter's opcode-by-opcode dispatch.
//!
//! This crate currently provides the block analysis ([`blocks`]): the interpreter's jumpdest
//! rule, basic-block splitting, per-block static gas and the stack bounds a single check at each
//! block head enforces. The stage-one emitter that turns a [`blocks::Block`] into C is a later
//! task; today's `main.rs` only runs the analysis and prints a summary.

pub mod blocks;
