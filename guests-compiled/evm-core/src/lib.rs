//! `evm-core`: the EVM interpreter the Rand zkVM's EVM guest runs, as a `no_std` library with no
//! allocation, generic over a [`Host`] for the two things a guest cannot compute itself — the
//! Keccak-f[1600] permutation and the Poseidon2 sponge. On the target both are syscalls
//! (`guest_sdk::keccak`, `guest_sdk::poseidon2`); on the host they are the research crate's own
//! reference functions (`keccak::keccak_f`, `hash::sponge_hash`), so every opcode, the 256-bit
//! arithmetic and the storage tree are unit-tested natively and the guest binary is a thin
//! wrapper over the same code (`docs/superpowers/plans/2026-09-12-zkvm-m4-3.md`).

#![no_std]

pub mod abi;
pub mod interp;
pub mod storage;
pub mod u256;

/// The two things a guest cannot compute itself. Both operate in place on 32-bit words.
pub trait Host {
    /// One Keccak-f[1600] permutation of the 50-word state (lane i: low word 2i, high word 2i+1).
    fn keccak_f(&mut self, state: &mut [u32; 50]);
    /// The Poseidon2 sponge over `words[..n]`, digest written to `words[..8]` (POSEIDON2 syscall
    /// semantics).
    fn poseidon2(&mut self, words: &mut [u32], n: usize);
}

/// The rate of Keccak-256 in bytes: 136, the low 34 words of the 50-word state.
const KECCAK_RATE: usize = 136;

/// keccak256 over the host's permutation: rate 136, pad `0x01`…`0x80`, little-endian lanes.
/// Byte-identical to `guest_sdk::keccak256` (M4.2) and to research's `keccak::keccak256` — the
/// padding and absorption are this function's, the permutation is the host's.
///
/// A message whose length is an exact multiple of 136 (zero included) still needs a whole extra
/// all-padding block; the loop gets that from `take == 0` on its final pass, since `last` is set
/// by `take < 136` rather than by exhausting the message.
pub fn keccak256<H: Host>(h: &mut H, msg: &[u8]) -> [u8; 32] {
    let mut state = [0u32; 50];
    let mut block = [0u8; KECCAK_RATE];
    let mut off = 0;
    loop {
        let take = core::cmp::min(KECCAK_RATE, msg.len() - off);
        block.fill(0);
        block[..take].copy_from_slice(&msg[off..off + take]);
        let last = take < KECCAK_RATE;
        if last {
            block[take] ^= 0x01;
            block[KECCAK_RATE - 1] ^= 0x80;
        }
        for i in 0..KECCAK_RATE / 4 {
            state[i] ^= u32::from_le_bytes([
                block[4 * i],
                block[4 * i + 1],
                block[4 * i + 2],
                block[4 * i + 3],
            ]);
        }
        h.keccak_f(&mut state);
        off += take;
        if last {
            break;
        }
    }
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

/// The longest `dhash` message this crate hashes: the 40-word public-output preimage plus its
/// domain word.
const DHASH_MAX_WORDS: usize = 48;

/// `hash(domain, msg) = poseidon2([domain, msg…])` — the domain-tagged sponge every leaf, node
/// and digest here is built from, byte-identical to research's `notes::hash`. `1 + msg.len()`
/// must be at most 48 words.
pub fn dhash<H: Host>(h: &mut H, domain: u32, msg: &[u32]) -> [u32; 8] {
    let n = 1 + msg.len();
    debug_assert!(n <= DHASH_MAX_WORDS);
    let mut buf = [0u32; DHASH_MAX_WORDS];
    buf[0] = domain;
    buf[1..n].copy_from_slice(msg);
    h.poseidon2(&mut buf, n);
    let mut out = [0u32; 8];
    out.copy_from_slice(&buf[..8]);
    out
}
