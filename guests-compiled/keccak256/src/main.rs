#![no_std]
#![no_main]

use guest_sdk::{halt, keccak256, read_input, write_output};

/// Keccak-256 of a message supplied as private input: `input[0]` is the byte length `n`
/// (`n <= 136`, one rate block — the guest's own buffer is that wide), `input[1..]` the message
/// packed four bytes per word, little-endian. The 32-byte digest goes to output slots 0..7, also
/// four bytes per word little-endian, so it compares directly against
/// `rand_zkvm::keccak::keccak256`'s output.
///
/// The sponge — rate, `0x01`/`0x80` padding, the squeeze — is `guest_sdk::keccak256`, i.e.
/// ordinary guest code; only the permutation itself is the `KECCAK` syscall and hence the
/// keccak chip's 32-row block. A 135-byte message is the interesting case: one byte shy of the
/// rate, so the padding fits in the same block and the whole hash is *one* permutation.
#[no_mangle]
pub extern "C" fn main() -> ! {
    let n = read_input(0) as usize;
    let mut msg = [0u8; 136];
    let mut i = 0;
    while i < n {
        let w = read_input(1 + (i / 4) as u32);
        msg[i] = (w >> (8 * (i % 4))) as u8;
        i += 1;
    }
    let d = keccak256(&msg[..n]);
    let mut k = 0;
    while k < 8 {
        write_output(
            k as u32,
            u32::from_le_bytes([d[4 * k], d[4 * k + 1], d[4 * k + 2], d[4 * k + 3]]),
        );
        k += 1;
    }
    halt();
}
