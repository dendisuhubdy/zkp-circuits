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
}

impl<K: Keccak> Shake<K> {
    pub fn new128(k: K) -> Self {
        Self { k, s: [0; 25], pos: 0, rate: SHAKE128_RATE }
    }

    pub fn new256(k: K) -> Self {
        Self { k, s: [0; 25], pos: 0, rate: SHAKE256_RATE }
    }

    /// Absorb `input`. Must not be called after `finalize`.
    pub fn absorb(&mut self, input: &[u8]) {
        for &b in input {
            self.s[self.pos / 8] ^= (b as u64) << (8 * (self.pos % 8));
            self.pos += 1;
            if self.pos == self.rate {
                self.k.permute(&mut self.s);
                self.pos = 0;
            }
        }
    }

    /// Pad (domain byte 0x1f, final bit 0x80) and switch to squeezing.
    pub fn finalize(&mut self) {
        self.s[self.pos / 8] ^= 0x1fu64 << (8 * (self.pos % 8));
        self.s[self.rate / 8 - 1] ^= 1u64 << 63;
        self.pos = self.rate;
    }

    /// Squeeze `out.len()` bytes; may be called repeatedly.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        for o in out.iter_mut() {
            if self.pos == self.rate {
                self.k.permute(&mut self.s);
                self.pos = 0;
            }
            *o = (self.s[self.pos / 8] >> (8 * (self.pos % 8))) as u8;
            self.pos += 1;
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
