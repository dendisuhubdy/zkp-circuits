#![no_std]
#![no_main]

//! M4.4's exit guest: an sBPF interpreter. It reads a Solana program's ELF and one serialized
//! instruction as private input, runs the program over it, and publishes a status word plus a
//! 224-bit digest binding the program, the instruction and the accounts' post-state
//! (`sbpf_core::abi`). The whole interpreter — 91 opcodes, the four memory regions, twelve
//! syscalls, the ELF loader and its relocations — is `sbpf-core`, compiled to RV32IM and proved by
//! the machine like any other guest; the only syscalls it takes are `SHA256` (the M4.4 chip, for
//! the three digests and for the program's own `sol_sha256`) and `POSEIDON2` (the output digest).
//!
//! This file is forty lines because that is the whole point: everything the milestone is about is
//! library code that runs identically on the host, where it is unit-tested against `solana-sbpf`
//! 0.11.1, and in-circuit.

use sbpf_core::abi::{run_call, Workspace};

/// The `Host` the interpreter is generic over, backed by the machine's own syscalls: SHA-256
/// compression is `SYS_SHA256` (one row of the sha256 chip per round) and the Poseidon2 sponge is
/// `SYS_POSEIDON2`.
struct Syscalls;

impl sbpf_core::Host for Syscalls {
    fn sha256_compress(&mut self, words: &mut [u32; 24]) {
        guest_sdk::sha256_compress(words.as_mut_ptr());
    }

    fn poseidon2(&mut self, words: &mut [u32], n: usize) {
        guest_sdk::poseidon2(words.as_mut_ptr(), n);
    }
}

/// The run's whole state — the decoded ELF and instruction region, the sBPF stack and heap, 368 KiB
/// — as one all-zero `static`, so it lands in `.bss` and costs the image nothing. It cannot be a
/// local: the RV32 stack is 64 KiB (`sbpf.ld`) and this is nearly six times that. `sbpf-core` is
/// `#![forbid(unsafe_code)]`, which is why the cell lives here rather than there.
static mut W: Workspace = Workspace::ZERO;

#[no_mangle]
pub extern "C" fn main() -> ! {
    let w = unsafe { &mut *core::ptr::addr_of_mut!(W) };
    // `READ_INPUT` past the committed input length is unsatisfiable in-circuit (M4.1's salted
    // `H_IN`), so the machine itself is the bound on the vector and `u32::MAX` is the honest `len`.
    let out = run_call(&mut Syscalls, w, guest_sdk::read_input, u32::MAX);
    let mut slot = 0;
    while slot < 8 {
        guest_sdk::write_output(slot as u32, out[slot]);
        slot += 1;
    }
    guest_sdk::halt()
}
