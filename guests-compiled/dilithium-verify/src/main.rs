#![no_std]
#![no_main]

use guest_sdk::{halt, read_input, write_output, SyscallKeccak};

/// Dilithium2 verification, the phase-1 measurement guest of the private multisig.
///
/// Input words: `0..328` the 1 312-byte public key, `328..933` the 2 420-byte signature,
/// `933` the message byte length `n` (`n <= 64`), `934..` the message. Four bytes per word,
/// little-endian. Output slot 0 is `1` on a valid signature and `0` otherwise (also `0` for
/// `n > 64`). Every Keccak-f permutation is the `KECCAK` syscall.
#[no_mangle]
pub extern "C" fn main() -> ! {
    let n = read_input(933) as usize;
    if n > 64 {
        write_output(0, 0);
        halt();
    }
    let mut pk = [0u8; dilithium_core::PK_BYTES];
    let mut sig = [0u8; dilithium_core::SIG_BYTES];
    let mut msg = [0u8; 64];
    let mut i = 0;
    while i < pk.len() {
        pk[i] = (read_input((i / 4) as u32) >> (8 * (i % 4))) as u8;
        i += 1;
    }
    i = 0;
    while i < sig.len() {
        sig[i] = (read_input(328 + (i / 4) as u32) >> (8 * (i % 4))) as u8;
        i += 1;
    }
    i = 0;
    while i < n {
        msg[i] = (read_input(934 + (i / 4) as u32) >> (8 * (i % 4))) as u8;
        i += 1;
    }
    let ok = dilithium_core::verify(&mut SyscallKeccak, &pk, &msg[..n], &sig);
    write_output(0, ok as u32);
    halt();
}
