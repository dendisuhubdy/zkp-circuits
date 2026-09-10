//! Notes, commitments, nullifiers, and the key hierarchy the `transfer` guest and the
//! viewing-key layer share. Everything here is a pure function of `arx::hash`, and every
//! function the guest recomputes in-circuit has its reference here.
//!
//! ```text
//!   sk  ──H_NK──▶  nk (= the viewing key)  ──H_PK──▶  pk (the address)
//!                    │
//!                    ├──H_NF(nk, cm)──▶  nf    (nullifier of the note with commitment cm)
//!                    ├──H_OVK───────▶  ovk    (wraps outgoing envelopes, `viewing.rs`)
//!                    └──H_KEM_SEED───▶  ML-KEM keypair (receives envelopes, `viewing.rs`)
//! ```
//!
//! The one-way arrows are what make "view without spend" true: `nk` is derived *from* `sk`,
//! so a holder of `nk` can compute every address, nullifier and decryption key of the party
//! but cannot satisfy the `transfer` guest, which takes `sk` as a private input and derives
//! `nk` itself (`guests::transfer`). Widths are development widths — one or two 32-bit
//! machine words per field (`docs/06-viewing-keys.md`).

use crate::arx::{domain, hash, squeeze};
use rand::Rng;

/// A 64-bit value as the two machine words the guest handles it as.
pub type Word2 = [u32; 2];

/// The spend authority. Never leaves the wallet; the guest reads it through `READ_INPUT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendKey(pub Word2);

impl SpendKey {
    pub fn random() -> Self {
        let mut rng = rand::rng();
        SpendKey([rng.next_u32(), rng.next_u32()])
    }
    /// The full viewing key: everything the party can see, nothing it can spend.
    pub fn viewing_key(&self) -> ViewingKey { ViewingKey { nk: hash(domain::NK, &self.0) } }
}

/// A party's full viewing key. Holding it means seeing the party's whole history — every
/// note received and every note spent — and being able to check each row of that history
/// against the chain. It cannot produce a proof: see `SpendKey`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ViewingKey { pub nk: Word2 }

impl ViewingKey {
    /// The public address, the field a note names its owner and its creator by.
    pub fn pk(&self) -> Word2 { hash(domain::PK, &self.nk) }
    /// The nullifier of the party's note with commitment `cm`. Binding the nullifier to
    /// the commitment — rather than to a sender-chosen nonce — means two notes minted for
    /// the same owner can never collide to one nullifier (the ledger already rejects
    /// duplicate commitments, so distinct notes have distinct nullifiers). Only `nk` can
    /// compute it, which is why an auditor holding the sender's viewing key can check a
    /// spend row's nullifier against the chain while a receiver, holding only the note,
    /// cannot.
    pub fn nullifier(&self, cm: &Word2) -> Word2 { hash(domain::NF, &[self.nk[0], self.nk[1], cm[0], cm[1]]) }
    /// Outgoing viewing key: the symmetric key under which every envelope this party sends
    /// carries a copy of its transaction key.
    pub fn ovk(&self) -> [u8; 32] {
        let mut w = [0u32; 8];
        squeeze(domain::OVK, &self.nk, &mut w);
        words_to_bytes(&w).try_into().unwrap()
    }
    /// Seed for the ML-KEM decapsulation key (64 bytes, per FIPS 203's `d || z`).
    pub fn kem_seed(&self) -> [u8; 64] {
        let mut w = [0u32; 16];
        squeeze(domain::KEM_SEED, &self.nk, &mut w);
        words_to_bytes(&w).try_into().unwrap()
    }
}

/// What a note records. `from` is the address of the party that created it — the sender of
/// the transfer, or the minter — so the commitment authenticates the sender to whoever can
/// open the note, with no extra disclosure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Note {
    /// Owner.
    pub pk: Word2,
    /// Creator.
    pub from: Word2,
    pub amount: u32,
    pub asset: u32,
    /// Creation time, as the transaction that created the note published it.
    pub time: u32,
    /// Commitment randomness.
    pub r: Word2,
}

impl Note {
    pub const WORDS: usize = 9;
    pub const BYTES: usize = 4 * Self::WORDS;

    /// The word layout the guest hashes: `pk, from, amount, asset, time, r`.
    pub fn words(&self) -> [u32; Self::WORDS] {
        [self.pk[0], self.pk[1], self.from[0], self.from[1], self.amount, self.asset, self.time, self.r[0], self.r[1]]
    }
    pub fn from_words(w: [u32; Self::WORDS]) -> Note {
        Note { pk: [w[0], w[1]], from: [w[2], w[3]], amount: w[4], asset: w[5], time: w[6], r: [w[7], w[8]] }
    }
    pub fn commitment(&self) -> Word2 { hash(domain::CM, &self.words()) }
    pub fn to_bytes(&self) -> Vec<u8> { words_to_bytes(&self.words()) }
    pub fn from_bytes(b: &[u8]) -> Option<Note> {
        if b.len() != Self::BYTES { return None; }
        let mut w = [0u32; Self::WORDS];
        for (i, c) in b.chunks(4).enumerate() { w[i] = u32::from_le_bytes(c.try_into().unwrap()); }
        Some(Note::from_words(w))
    }
    /// A fresh note for `owner`, created by `from`, with random `r`.
    pub fn new(owner: Word2, from: Word2, amount: u32, asset: u32, time: u32) -> Note {
        let mut rng = rand::rng();
        Note { pk: owner, from, amount, asset, time, r: [rng.next_u32(), rng.next_u32()] }
    }
}

pub fn words_to_bytes(w: &[u32]) -> Vec<u8> { w.iter().flat_map(|x| x.to_le_bytes()).collect() }

/// The private-input vector of `guests::transfer`: the spend key, the note being spent,
/// and the fields of the note being created that the guest does not derive itself. Index
/// constants are the `READ_INPUT` indices the guest uses.
pub mod input {
    pub const SK: usize = 0;         // 2 words
    pub const IN_FROM: usize = 2;    // 2 words
    pub const IN_AMOUNT: usize = 4;
    pub const IN_ASSET: usize = 5;
    pub const IN_TIME: usize = 6;
    pub const IN_R: usize = 7;       // 2 words
    pub const OUT_PK: usize = 9;     // 2 words
    pub const OUT_TIME: usize = 11;
    pub const OUT_R: usize = 12;     // 2 words
    pub const COUNT: usize = 14;
}

/// Output-slot layout of `guests::transfer`: the public values a ledger reads.
pub mod output {
    pub const CM_IN: usize = 0;  // 2 words
    pub const NF: usize = 2;     // 2 words
    pub const CM_OUT: usize = 4; // 2 words
    pub const TIME: usize = 6;
}

/// Builds the guest's private inputs for spending `spent` (which must be owned by `sk`) into
/// `created` (whose `from` must be `sk`'s address and whose amount and asset must match).
pub fn transfer_inputs(sk: &SpendKey, spent: &Note, created: &Note) -> [u32; input::COUNT] {
    let mut v = [0u32; input::COUNT];
    v[input::SK] = sk.0[0]; v[input::SK + 1] = sk.0[1];
    v[input::IN_FROM] = spent.from[0]; v[input::IN_FROM + 1] = spent.from[1];
    v[input::IN_AMOUNT] = spent.amount; v[input::IN_ASSET] = spent.asset; v[input::IN_TIME] = spent.time;
    v[input::IN_R] = spent.r[0]; v[input::IN_R + 1] = spent.r[1];
    v[input::OUT_PK] = created.pk[0]; v[input::OUT_PK + 1] = created.pk[1];
    v[input::OUT_TIME] = created.time;
    v[input::OUT_R] = created.r[0]; v[input::OUT_R + 1] = created.r[1];
    v
}

/// What the guest's eight output words should be for an honest run — the reference the
/// emulator and the proof are checked against.
pub fn expected_outputs(sk: &SpendKey, spent: &Note, created: &Note) -> [u32; crate::isa::NUM_OUTPUTS] {
    let vk = sk.viewing_key();
    let cm_in = spent.commitment();
    let nf = vk.nullifier(&cm_in);
    let cm_out = created.commitment();
    [cm_in[0], cm_in[1], nf[0], nf[1], cm_out[0], cm_out[1], created.time, 0]
}
