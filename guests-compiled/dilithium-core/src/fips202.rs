//! SHAKE128/SHAKE256 over a [`Keccak`] permutation (FIPS 202), ported from
//! `crystals-dilithium` 2.0.0's `fips202.rs` with the permutation abstracted.
use crate::Keccak;

const SHAKE128_RATE: usize = 168;
const SHAKE256_RATE: usize = 136;

/// An incremental SHAKE sponge that owns its permutation.
pub struct Shake<K: Keccak> {
    k: K,
    s: [u64; 25],
    pos: usize,
    rate: usize,
    finalized: bool,
}

impl<K: Keccak> Shake<K> {
    pub fn new128(k: K) -> Self {
        Self { k, s: [0; 25], pos: 0, rate: SHAKE128_RATE, finalized: false }
    }

    pub fn new256(k: K) -> Self {
        Self { k, s: [0; 25], pos: 0, rate: SHAKE256_RATE, finalized: false }
    }

    /// Absorb `input`. Must not be called after `finalize`.
    pub fn absorb(&mut self, input: &[u8]) {
        debug_assert!(!self.finalized, "absorb after finalize");
        let mut input = input;
        while !input.is_empty() {
            if self.pos % 8 == 0 && input.len() >= 8 {
                // Aligned: one whole lane at a time.
                let mut w = [0u8; 8];
                w.copy_from_slice(&input[..8]);
                self.s[self.pos / 8] ^= u64::from_le_bytes(w);
                self.pos += 8;
                input = &input[8..];
            } else {
                // Ragged head or tail.
                self.s[self.pos / 8] ^= (input[0] as u64) << (8 * (self.pos % 8));
                self.pos += 1;
                input = &input[1..];
            }
            if self.pos == self.rate {
                self.k.permute(&mut self.s);
                self.pos = 0;
            }
        }
    }

    /// Pad (domain byte 0x1f, final bit 0x80) and switch to squeezing.
    pub fn finalize(&mut self) {
        debug_assert!(!self.finalized, "finalize twice");
        self.s[self.pos / 8] ^= 0x1fu64 << (8 * (self.pos % 8));
        self.s[self.rate / 8 - 1] ^= 1u64 << 63;
        self.pos = self.rate;
        self.finalized = true;
    }

    /// Squeeze `out.len()` bytes; may be called repeatedly.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        debug_assert!(self.finalized, "squeeze before finalize");
        let mut out = out;
        while !out.is_empty() {
            if self.pos == self.rate {
                self.k.permute(&mut self.s);
                self.pos = 0;
            }
            let lane = self.s[self.pos / 8];
            if self.pos % 8 == 0 && out.len() >= 8 {
                let (head, rest) = out.split_at_mut(8);
                head.copy_from_slice(&lane.to_le_bytes());
                self.pos += 8;
                out = rest;
            } else {
                out[0] = (lane >> (8 * (self.pos % 8))) as u8;
                self.pos += 1;
                out = &mut out[1..];
            }
        }
    }
}

/// One-shot SHAKE256 over the concatenation of `input`.
pub fn shake256<K: Keccak>(k: &mut K, input: &[&[u8]], out: &mut [u8]) {
    let mut sh = Shake::new256(k);
    for part in input {
        sh.absorb(part);
    }
    sh.finalize();
    sh.squeeze(out);
}
