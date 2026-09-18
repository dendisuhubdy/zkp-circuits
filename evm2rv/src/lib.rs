//! `evm2rv`: translates Shanghai EVM runtime bytecode (`solc`'s output) into RV32 C over
//! `evm-rt/`, so `rand-guest build` can turn a Solidity contract into a zkVM image without the
//! interpreter's opcode-by-opcode dispatch.
//!
//! [`blocks`] is the analysis: the interpreter's jumpdest rule, basic-block splitting, per-block
//! static gas and the stack bounds a single check at each block head enforces. [`emit`] is stage
//! one: every block to C over `evm-rt`'s memory stack, with one `switch` for the dynamic jumps.
//! [`lift`] is stage two: the same blocks with each block's words in C locals, spilled to the
//! memory stack only where another block or the runtime needs them.
//! [`guard`] is the code guard: a digest of the source bytecode baked into the C, which the shim
//! checks the input vector's code against before anything runs.
//! [`shim`] is the generated crate around that C: the interpreter guest's ABI harness
//! (`evm_core::abi::run_call_with_executor`) with the translated code as the executor.

pub mod blocks;
pub mod emit;
/// Test-only: the fuzz corpus generator (`tests/fuzz.rs`). Not part of the translator.
#[doc(hidden)]
pub mod gen;
pub mod guard;
pub mod lift;
pub mod shim;
