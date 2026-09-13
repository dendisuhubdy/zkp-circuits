#![no_std]
#![no_main]

//! M4.4's exit guest: an sBPF interpreter. It reads a Solana program's ELF from the **public**
//! input segment and one serialized instruction from the private one, runs the program over it,
//! and publishes a status word plus a 224-bit digest binding the instruction and the accounts'
//! post-state (`sbpf_core::abi`). The program itself is bound by `H_PUB`, which the chain checks
//! against the ELF it published, so the guest no longer hashes it. The whole interpreter — 91
//! opcodes, the four memory regions, twelve syscalls, the ELF loader and its relocations — is
//! `sbpf-core`, compiled to RV32IM and proved by the machine like any other guest; the only
//! syscalls it takes are `SHA256` (the M4.4 chip, for the two digests and for the program's own
//! `sol_sha256`) and `POSEIDON2` (the output digest).
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
    // A read past either segment's committed length is unsatisfiable in-circuit — `READ_INPUT`
    // past `n_in` (M4.1's salted `H_IN`) and `READ_PUBLIC` past `n_pub` (the unsalted `H_PUB`) are
    // both unwitnessable — so the machine is the bound on both vectors and `u32::MAX` is the honest
    // `len` for each.
    let out = run_call(
        &mut Syscalls,
        w,
        guest_sdk::read_public,
        u32::MAX,
        guest_sdk::read_input,
        u32::MAX,
    );
    let mut slot = 0;
    while slot < 8 {
        guest_sdk::write_output(slot as u32, out[slot]);
        slot += 1;
    }
    guest_sdk::halt()
}
