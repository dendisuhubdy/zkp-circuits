//! Notes, commitments, nullifiers, and the key hierarchy the `transfer` guest and the
//! viewing-key layer share. Everything here is a pure function of `notes::hash` (the
//! Poseidon2 sponge, `hash::sponge_hash`, under a domain tag), and every function the guest
//! recomputes in-circuit has its reference here.
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
//! `nk` itself (`guests::transfer`).
//!
//! Widths (M3.3): keys, commitments and nullifiers are `Word8` — four canonical Goldilocks
//! field elements, each split lo/hi into two 32-bit machine words, exactly what
//! `hash::sponge_hash`/`hash::split_digest` produce. `SpendKey` alone stays two words: it is
//! never hashed to standalone security-bearing output the way `nk`/`pk`/`nf`/`cm` are, and
//! nothing recomputes it in-circuit — only `H_NK(sk)` is.

use crate::hash::sponge_hash;
use rand::Rng;

/// A 64-bit value as two machine words — `SpendKey` only; every hash *output* is `Word8`.
pub type Word2 = [u32; 2];

/// A 256-bit value as eight machine words: four canonical Goldilocks field elements, each
/// split lo/hi (`hash::split_digest`'s layout). Every key, commitment and nullifier is one.
pub type Word8 = [u32; 8];

/// Depth of the commitment Merkle tree `MERKLE_VERIFY`/`ledger::CommitmentTree` use.
pub const DEPTH: usize = 32;

/// Fixed domain tags. Every use of the hash has its own tag as the *first* absorbed word, so
/// a note commitment can never collide with a nullifier, a key, a tree node or the output
/// commitment even on identical remaining inputs.
pub mod domain {
    pub const NK: u32 = 1;
    pub const PK: u32 = 2;
    pub const NF: u32 = 3;
    pub const CM: u32 = 4;
    pub const OVK: u32 = 5;
    pub const KEM_SEED: u32 = 6;
    /// A commitment tree node: `H(NODE, left(8), right(8))`.
    pub const NODE: u32 = 7;
    /// The in-circuit program commitment (M3.4): `hash::program_digest`'s capacity-lane
    /// header, `[HC, base_pc, len]`, seeded into the very first digest-row permutation
    /// before any program word is absorbed.
    pub const HC: u32 = 8;
    /// The `transfer` guest's output commitment: `H(OUT, anchor(8), nf(8), cm_out(8), time)`
    /// — see `output_digest` and `docs/06-viewing-keys.md`'s "Public outputs" section.
    pub const OUT: u32 = 9;
    /// M4.1: the input commitment (`hash::input_digest`), sealing the private-input vector
    /// `READ_INPUT` draws from — the capacity-lane header `[IN, n_in, 0]` seeded into the very
    /// first input-digest-row permutation, mirroring `HC`'s `[HC, base_pc, len]` exactly.
    pub const IN: u32 = 10;
    pub const TEST: u32 = 0xff;
}

/// The domain-tagged Poseidon2 sponge every key, commitment, nullifier and tree node is
/// built from: `H(domain, msg) = sponge_hash([domain, msg...])`. Exactly what the `POSEIDON2`
/// syscall computes over the same words (`hash::sponge_hash`), so the guest and this
/// function agree bit for bit.
pub fn hash(domain: u32, msg: &[u32]) -> Word8 {
    let mut full = Vec::with_capacity(1 + msg.len());
    full.push(domain);
    full.extend_from_slice(msg);
    sponge_hash(&full)
}

/// A host-only wide hash (never computed in-circuit): squeezes `out_words` words by hashing
/// `[domain, msg..., counter]` for `counter = 0, 1, ...` and concatenating 8-word chunks.
/// Used for `ovk`/`kem_seed`, which need more output than one `Word8`.
fn wide_hash(domain: u32, msg: &[u32], out_words: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(out_words);
    let mut counter = 0u32;
    while out.len() < out_words {
        let mut full = Vec::with_capacity(2 + msg.len());
        full.push(domain);
        full.extend_from_slice(msg);
        full.push(counter);
        let chunk = sponge_hash(&full);
        let take = (out_words - out.len()).min(chunk.len());
        out.extend_from_slice(&chunk[..take]);
        counter += 1;
    }
    out
}

/// The spend authority. Never leaves the wallet; the guest reads it through `READ_INPUT`.
/// Stays two words (see the module doc comment) — only `H_NK(sk)` is ever hashed from it.
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
pub struct ViewingKey { pub nk: Word8 }

impl ViewingKey {
    /// The public address, the field a note names its owner and its creator by.
    pub fn pk(&self) -> Word8 { hash(domain::PK, &self.nk) }
    /// The nullifier of the party's note with commitment `cm`: `H_NF(nk, cm)`. Binding the
    /// nullifier to the commitment — rather than to a sender-chosen nonce — means two notes
    /// minted for the same owner can never collide to one nullifier (the ledger already
    /// rejects duplicate commitments, so distinct notes have distinct nullifiers). Only `nk`
    /// can compute it, which is why an auditor holding the sender's viewing key can check a
    /// spend row's nullifier against the chain while a receiver, holding only the note,
    /// cannot.
    pub fn nullifier(&self, cm: &Word8) -> Word8 {
        let mut msg = [0u32; 16];
        msg[..8].copy_from_slice(&self.nk);
        msg[8..].copy_from_slice(cm);
        hash(domain::NF, &msg)
    }
    /// Outgoing viewing key: the symmetric key under which every envelope this party sends
    /// carries a copy of its transaction key.
    pub fn ovk(&self) -> [u8; 32] {
        let w = wide_hash(domain::OVK, &self.nk, 8);
        words_to_bytes(&w).try_into().unwrap()
    }
    /// Seed for the ML-KEM decapsulation key (64 bytes, per FIPS 203's `d || z`).
    pub fn kem_seed(&self) -> [u8; 64] {
        let w = wide_hash(domain::KEM_SEED, &self.nk, 16);
        words_to_bytes(&w).try_into().unwrap()
    }
}

/// What a note records. `from` is the address of the party that created it — the sender of
/// the transfer, or the minter — so the commitment authenticates the sender to whoever can
/// open the note, with no extra disclosure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Note {
    /// Owner.
    pub pk: Word8,
    /// Creator.
    pub from: Word8,
    pub amount: u32,
    pub asset: u32,
    /// Creation time, as the transaction that created the note published it.
    pub time: u32,
    /// Commitment randomness.
    pub r: Word8,
}

impl Note {
    /// `pk(8) from(8) amount(1) asset(1) time(1) r(8)`.
    pub const WORDS: usize = 8 + 8 + 1 + 1 + 1 + 8;
    pub const BYTES: usize = 4 * Self::WORDS;

    /// The word layout the guest hashes: `pk, from, amount, asset, time, r`.
    pub fn words(&self) -> [u32; Self::WORDS] {
        let mut w = [0u32; Self::WORDS];
        w[0..8].copy_from_slice(&self.pk);
        w[8..16].copy_from_slice(&self.from);
        w[16] = self.amount;
        w[17] = self.asset;
        w[18] = self.time;
        w[19..27].copy_from_slice(&self.r);
        w
    }
    pub fn from_words(w: [u32; Self::WORDS]) -> Note {
        Note {
            pk: w[0..8].try_into().unwrap(),
            from: w[8..16].try_into().unwrap(),
            amount: w[16],
            asset: w[17],
            time: w[18],
            r: w[19..27].try_into().unwrap(),
        }
    }
    pub fn commitment(&self) -> Word8 { hash(domain::CM, &self.words()) }
    pub fn to_bytes(&self) -> Vec<u8> { words_to_bytes(&self.words()) }
    pub fn from_bytes(b: &[u8]) -> Option<Note> {
        if b.len() != Self::BYTES { return None; }
        let mut w = [0u32; Self::WORDS];
        for (i, c) in b.chunks(4).enumerate() { w[i] = u32::from_le_bytes(c.try_into().unwrap()); }
        Some(Note::from_words(w))
    }
    /// A fresh note for `owner`, created by `from`, with random `r`.
    pub fn new(owner: Word8, from: Word8, amount: u32, asset: u32, time: u32) -> Note {
        let mut rng = rand::rng();
        let r = std::array::from_fn(|_| rng.next_u32());
        Note { pk: owner, from, amount, asset, time, r }
    }
}

pub fn words_to_bytes(w: &[u32]) -> Vec<u8> { w.iter().flat_map(|x| x.to_le_bytes()).collect() }

/// `H(OUT_DOMAIN, anchor, nf, cm_out, time)` — the single 8-word digest `guests::transfer`
/// publishes in place of four separate public outputs (`docs/06-viewing-keys.md`'s "Public
/// outputs" section explains why: at `Word8` widths, `anchor`/`nf`/`cm_out`/`time` no longer
/// fit in the CPU table's 8 output slots, and growing `NUM_OUTPUTS` would widen the CPU table
/// and reopen its pinned constraint-degree budget). `Ledger::apply` is handed the four
/// plaintext values alongside the proof (the same way it is already handed `time`/`cm_out` as
/// plain `Tx` fields, never hidden) and recomputes this digest to check the proof attests to
/// exactly those values.
pub fn output_digest(anchor: &Word8, nf: &Word8, cm_out: &Word8, time: u32) -> Word8 {
    let mut msg = [0u32; 25];
    msg[0..8].copy_from_slice(anchor);
    msg[8..16].copy_from_slice(nf);
    msg[16..24].copy_from_slice(cm_out);
    msg[24] = time;
    hash(domain::OUT, &msg)
}

/// The private-input vector of `guests::transfer`: the spend key, the note being spent, the
/// fields of the note being created that the guest does not derive itself, and the Merkle
/// witness (path and index) proving the spent note's commitment is in the tree. Index
/// constants are the `READ_INPUT` indices the guest uses.
pub mod input {
    use super::DEPTH;
    pub const SK: usize = 0;          // 2 words
    pub const IN_FROM: usize = 2;     // 8 words
    pub const IN_AMOUNT: usize = 10;
    pub const IN_ASSET: usize = 11;
    pub const IN_TIME: usize = 12;
    pub const IN_R: usize = 13;       // 8 words
    pub const OUT_PK: usize = 21;     // 8 words
    pub const OUT_TIME: usize = 29;
    pub const OUT_R: usize = 30;      // 8 words
    /// `DEPTH` sibling `Word8`s, leaf to root (private: the Merkle witness).
    pub const PATH: usize = 38;       // DEPTH * 8 words
    /// The spent note's leaf index; bit `level` selects which side it's on at that level.
    pub const INDEX: usize = PATH + DEPTH * 8;
    pub const COUNT: usize = INDEX + 1;
}

/// Output-slot layout of `guests::transfer`: the public values a ledger reads. `NUM_OUTPUTS`
/// stays 8 (`isa.rs`) — the whole slot range is the single output-commitment digest
/// (`output_digest`), not four separate `Word8`s.
pub mod output {
    pub const DIGEST: usize = 0; // 8 words
}

/// Builds the guest's private inputs for spending `spent` (which must be owned by `sk` and
/// whose commitment is the tree leaf at `index`, with sibling path `path`, leaf to root) into
/// `created` (whose `from` must be `sk`'s address and whose amount and asset must match).
pub fn transfer_inputs(sk: &SpendKey, spent: &Note, created: &Note, path: &[Word8; DEPTH], index: u32) -> [u32; input::COUNT] {
    let mut v = [0u32; input::COUNT];
    v[input::SK] = sk.0[0];
    v[input::SK + 1] = sk.0[1];
    v[input::IN_FROM..input::IN_FROM + 8].copy_from_slice(&spent.from);
    v[input::IN_AMOUNT] = spent.amount;
    v[input::IN_ASSET] = spent.asset;
    v[input::IN_TIME] = spent.time;
    v[input::IN_R..input::IN_R + 8].copy_from_slice(&spent.r);
    v[input::OUT_PK..input::OUT_PK + 8].copy_from_slice(&created.pk);
    v[input::OUT_TIME] = created.time;
    v[input::OUT_R..input::OUT_R + 8].copy_from_slice(&created.r);
    for (level, sib) in path.iter().enumerate() { v[input::PATH + 8 * level..input::PATH + 8 * level + 8].copy_from_slice(sib); }
    v[input::INDEX] = index;
    v
}

/// What the guest's eight output words should be for an honest run — the reference the
/// emulator and the proof are checked against. `anchor` is the tree root the Merkle witness
/// (`path`/`index` inside `inputs`, not taken here) proves membership against; callers get it
/// from `ledger::CommitmentTree::root` (or `Ledger::path_for`, which returns both).
pub fn expected_outputs(sk: &SpendKey, spent: &Note, created: &Note, anchor: Word8) -> [u32; crate::isa::NUM_OUTPUTS] {
    let vk = sk.viewing_key();
    let cm_in = spent.commitment();
    let nf = vk.nullifier(&cm_in);
    let cm_out = created.commitment();
    output_digest(&anchor, &nf, &cm_out, created.time)
}
