#![no_std]
#![no_main]

use dilithium_core::ring::Arena;
use guest_sdk::{halt, read_input, read_input_words, write_output, SyscallKeccak, SyscallRing};

/// The ring arena (21 KiB), in `.bss`: the stack stays at 64 KiB.
static mut ARENA: Arena = Arena::new();
/// The public key and signature as the words they arrive in, also `.bss`.
static mut PK: [u32; 328] = [0; 328];
static mut SIG: [u32; 605] = [0; 605];

/// Dilithium2 verification, the phase-1 measurement guest of the private multisig.
///
/// Input words: `0..328` the 1 312-byte public key, `328..933` the 2 420-byte signature,
/// `933` the message byte length `n` (`n <= 64`), `934..` the message. Four bytes per word,
/// little-endian. Output slot 0 is `1` on a valid signature and `0` otherwise (also `0` for
/// `n > 64`). Every Keccak-f permutation is the `KECCAK` syscall, every ring operation the `MODQ` syscall.
#[no_mangle]
pub extern "C" fn main() -> ! {
    let n = read_input(933) as usize;
    if n > 64 {
        write_output(0, 0);
        halt();
    }
    // SAFETY: single-threaded; these are the only references to PK / SIG / ARENA, live for this
    // call.
    let (pk, sig, ar) = unsafe {
        (
            &mut *core::ptr::addr_of_mut!(PK),
            &mut *core::ptr::addr_of_mut!(SIG),
            &mut *core::ptr::addr_of_mut!(ARENA),
        )
    };
    read_input_words(0, pk);
    read_input_words(328, sig);
    let mut msg = [0u8; 64];
    let mut i = 0;
    while i < n {
        msg[i] = (read_input(934 + (i / 4) as u32) >> (8 * (i % 4))) as u8;
        i += 1;
    }
    let ok = dilithium_core::verify_words_with(&mut SyscallKeccak, &mut SyscallRing, ar, pk, &msg[..n], sig);
    write_output(0, ok as u32);
    halt();
}
