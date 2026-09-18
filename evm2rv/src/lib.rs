//! `evm2rv`: translates Shanghai EVM runtime bytecode (`solc`'s output) into RV32 C over
//! `evm-rt/`, so `rand-guest build` can turn a Solidity contract into a zkVM image without the
//! interpreter's opcode-by-opcode dispatch.
//!
//! [`blocks`] is the analysis: the interpreter's jumpdest rule, basic-block splitting, per-block
//! static gas and the stack bounds a single check at each block head enforces. [`emit`] is stage
//! one: every block to C over `evm-rt`'s memory stack, with one `switch` for the dynamic jumps.
//! [`shim`] is the generated crate around that C: the interpreter guest's ABI harness
//! (`evm_core::abi::run_call_with_executor`) with the translated code as the executor.

pub mod blocks;
pub mod emit;
pub mod shim;
