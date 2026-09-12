//! The host side of the EVM guest (M4.3): the [`evm_core::Host`] implementation `evm-core` is
//! generic over, and the sparse storage-tree builder that produces the witnesses the guest
//! consumes.
//!
//! `evm-core` is `no_std` and cannot depend on this crate, so it carries its own copies of the
//! Keccak padding, the domain-tagged sponge wrapper and the storage-tree hashes. Everything here
//! is the reference those copies are checked against, from the same primitives the guest's
//! syscalls compute (`keccak::keccak_f`, `hash::sponge_hash`) — `tests/evm_storage.rs` asserts
//! host and guest agree on every index, leaf and root.
//!
//! The tree is `notes::DEPTH = 32` levels of the commitment tree's own node hash over storage
//! leaves: position is the top 32 bits, big-endian, of `keccak256(slot as 32 big-endian bytes)`,
//! whose bit `i` (LSB first) chooses left/right at level `i` — `asm::emit_merkle_verify`'s
//! convention. The leaf is canonical in the value, so the empty tree has a well-defined root and
//! writing a slot back to zero restores it ([`leaf_hash`]).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use evm_core::abi::{run_call_with, Workspace};
use evm_core::interp::Outcome;
use evm_core::u256::U256;

use crate::hash::sponge_hash;
use crate::keccak;
use crate::notes::{self, domain, Word8, DEPTH};

/// [`evm_core::Host`] over this crate's reference primitives: the Keccak-f[1600] permutation the
/// `KECCAK` syscall computes and the Poseidon2 sponge the `POSEIDON2` syscall computes. Every
/// `evm-core` function is therefore exercised natively on exactly the arithmetic the guest will
/// see in-circuit.
pub struct HostRef;

impl evm_core::Host for HostRef {
    fn keccak_f(&mut self, state: &mut [u32; 50]) {
        let mut lanes = keccak::words_to_state(state);
        keccak::keccak_f(&mut lanes);
        *state = keccak::state_to_words(&lanes);
    }
    fn poseidon2(&mut self, words: &mut [u32], n: usize) {
        let digest = sponge_hash(&words[..n]);
        words[..8].copy_from_slice(&digest);
    }
}

/// The leaf position of `slot`: the top 32 bits, big-endian, of `keccak256(slot)`, read as a `u32`
/// whose bit `i` chooses left (0) or right (1) at level `i`.
pub fn slot_index(slot: &U256) -> u32 {
    let k = keccak::keccak256(&slot.to_be_bytes());
    u32::from_be_bytes([k[0], k[1], k[2], k[3]])
}

/// `H(STORAGE_LEAF, [slot(8), value(8)])`, **canonical in the value**: a zero value gives the one
/// `H(STORAGE_LEAF, [0; 16])` whatever the slot is. So an absent slot, a never-written slot and a
/// slot written back to zero are the same leaf; the storage root is history-independent and the
/// empty tree's root is just this leaf lifted 32 levels ([`empty_root`]). Every leaf on both sides
/// — witnesses, verification, loads, stores and the default subtrees — goes through this function
/// or its `evm_core::storage::leaf_hash` twin.
pub fn leaf_hash(slot: &U256, value: &U256) -> Word8 {
    let mut msg = [0u32; 16];
    if !value.is_zero() {
        msg[..8].copy_from_slice(&slot.0);
        msg[8..].copy_from_slice(&value.0);
    }
    notes::hash(domain::STORAGE_LEAF, &msg)
}

/// `H(NODE, [left(8), right(8)])` — the commitment tree's node hash exactly.
fn node_hash(l: &Word8, r: &Word8) -> Word8 {
    let mut msg = [0u32; 16];
    msg[..8].copy_from_slice(l);
    msg[8..].copy_from_slice(r);
    notes::hash(domain::NODE, &msg)
}

/// `defaults()[l]` is the root of an empty subtree of depth `l`: `defaults()[0]` is the zero-value
/// leaf and `defaults()[l] = H(NODE, defaults()[l-1], defaults()[l-1])`. Computed once — the 32
/// sponge hashes are the same for every tree, and `SparseTree` consults the table at every level
/// where a subtree holds nothing.
fn defaults() -> &'static [Word8; DEPTH + 1] {
    static TABLE: OnceLock<[Word8; DEPTH + 1]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut d = [[0u32; 8]; DEPTH + 1];
        d[0] = leaf_hash(&U256::ZERO, &U256::ZERO);
        for l in 1..=DEPTH {
            d[l] = node_hash(&d[l - 1], &d[l - 1]);
        }
        d
    })
}

/// The root of the tree with no slot written: `defaults()[DEPTH]`.
pub fn empty_root() -> Word8 {
    defaults()[DEPTH]
}

/// The host's contract storage: the written slots, keyed by leaf position, with empty subtrees
/// standing in for everything else. Builds the roots and the witnesses the guest verifies.
#[derive(Clone, Debug, Default)]
pub struct SparseTree {
    /// Leaf position → (slot, value). Only non-zero values are held: a zero value is the default
    /// leaf, so storing one is removing the entry (and both hash the same).
    entries: BTreeMap<u32, (U256, U256)>,
}

impl SparseTree {
    pub fn new() -> Self {
        SparseTree::default()
    }

    /// Write `value` at `slot`. A zero value removes the entry, which is the same tree either way
    /// because the leaf is canonical in the value.
    ///
    /// Panics if two distinct slots collide on one leaf position — a 2^-32-per-pair event that
    /// would otherwise silently drop a slot, and the tests would rather see it than debug a root.
    pub fn insert(&mut self, slot: U256, value: U256) {
        let idx = slot_index(&slot);
        if value.is_zero() {
            self.entries.remove(&idx);
            return;
        }
        if let Some((held, _)) = self.entries.get(&idx) {
            assert_eq!(*held, slot, "leaf position {idx} is already held by a different slot");
        }
        self.entries.insert(idx, (slot, value));
    }

    /// The hash of the subtree at level `level` whose nodes all share the leaf-position prefix
    /// `prefix = index >> level`. Empty subtrees short-circuit to the default table, so the walk
    /// costs `O(entries × DEPTH)` hashes rather than `O(2^DEPTH)`.
    fn node_at(&self, level: usize, prefix: u64) -> Word8 {
        let Some((_, (slot, value))) = self.entries.iter().find(|(i, _)| (**i as u64) >> level == prefix) else {
            return defaults()[level];
        };
        if level == 0 {
            return leaf_hash(slot, value);
        }
        let l = self.node_at(level - 1, prefix << 1);
        let r = self.node_at(level - 1, (prefix << 1) | 1);
        node_hash(&l, &r)
    }

    pub fn root(&self) -> Word8 {
        self.node_at(DEPTH, 0)
    }

    /// The witness for `slot`: its value (zero if the slot was never written) and, for each level
    /// `l = 0..DEPTH`, the hash of the sibling subtree of the path's node at that level, bottom-up.
    pub fn witness(&self, slot: &U256) -> Witness {
        let idx = slot_index(slot);
        let value = self.entries.get(&idx).map(|(_, v)| *v).unwrap_or(U256::ZERO);
        let siblings = std::array::from_fn(|l| self.node_at(l, ((idx as u64) >> l) ^ 1));
        Witness { slot: *slot, value, siblings }
    }
}

/// One slot's Merkle witness against a `SparseTree`'s root: the value and `DEPTH` siblings from
/// the leaf up. `evm_core::storage::Witness` is the guest's copy, plus its own `verified` flag.
#[derive(Clone, PartialEq, Debug)]
pub struct Witness {
    pub slot: U256,
    pub value: U256,
    pub siblings: [Word8; DEPTH],
}

impl Witness {
    /// The input-vector encoding: `slot(8) ‖ value(8) ‖ sibling_0(8) ‖ … ‖ sibling_31(8)`, 272
    /// words. 256-bit values are their own little-endian limbs, so nothing is byte-swapped.
    pub fn words(&self) -> Vec<u32> {
        let mut w = Vec::with_capacity(WITNESS_WORDS);
        w.extend_from_slice(&self.slot.0);
        w.extend_from_slice(&self.value.0);
        for sib in &self.siblings {
            w.extend_from_slice(sib);
        }
        w
    }
}

/// Words per witness in the input vector: slot 8 + value 8 + `DEPTH` × 8 siblings.
pub const WITNESS_WORDS: usize = 16 + DEPTH * 8;

/// One call to the EVM guest, host side: everything the input vector holds, plus the storage tree
/// the witnesses come from. [`input_words`](EvmCall::input_words) encodes it as the machine's
/// private input and [`expected`](EvmCall::expected) says what the guest must output — the pair
/// `tests/evm_abi.rs` checks against each other and against digests recomputed from this crate's
/// own primitives.
pub struct EvmCall {
    pub code: Vec<u8>,
    pub calldata: Vec<u8>,
    pub address: U256,
    pub caller: U256,
    pub callvalue: U256,
    pub gas_limit: u64,
    /// The pre-state storage. `witness(slot)` against this is what the guest verifies.
    pub tree: SparseTree,
    /// The slots a witness is supplied for, in the order they appear in the vector. A slot the
    /// bytecode touches without one is an exceptional halt, so this is the call's access list.
    pub touched: Vec<U256>,
}

impl EvmCall {
    /// The input vector, exactly as the plan's Global Constraints lay it out:
    /// `[n_code, code…, n_calldata, calldata…, address(8), caller(8), callvalue(8), gas_limit(1),
    /// pre_root(8), n_witnesses(1), witness…]`, byte strings packed 4 per word little-endian and
    /// zero-padded, 256-bit values as their own little-endian limbs, each witness
    /// [`WITNESS_WORDS`] long.
    ///
    /// Panics on a gas limit above `u32::MAX`, which the single `gas_limit` word cannot carry —
    /// a test's own constant, not prover-supplied, so an assert is the right choke point here.
    pub fn input_words(&self) -> Vec<u32> {
        let mut w = Vec::new();
        push_bytes(&mut w, &self.code);
        push_bytes(&mut w, &self.calldata);
        w.extend_from_slice(&self.address.0);
        w.extend_from_slice(&self.caller.0);
        w.extend_from_slice(&self.callvalue.0);
        assert!(self.gas_limit <= u32::MAX as u64, "the layout's gas_limit is one word");
        w.push(self.gas_limit as u32);
        w.extend_from_slice(&self.tree.root());
        w.push(self.touched.len() as u32);
        for slot in &self.touched {
            w.extend_from_slice(&self.tree.witness(slot).words());
        }
        w
    }

    /// Run `evm-core` natively over [`HostRef`] and return the eight public output words, the
    /// interpreter's outcome, and the post-state tree.
    ///
    /// The post-state tree is this call's `tree` with every witness's final value written back —
    /// for a successful call only: a revert or an exceptional halt changes no state, however far
    /// the interpreter's own tree got before it failed. When the call did succeed, the host tree's
    /// root and the guest's witness-updated root are asserted equal, which is the one check that
    /// `StorageTree::store`'s sibling refresh and `SparseTree`'s rebuild agree.
    pub fn expected(&self) -> ([u32; 8], Outcome, SparseTree) {
        let words = self.input_words();
        // The guest keeps this in `.bss`; a host test boxes it (146 KiB is not for a frame).
        let mut ws = Box::new(Workspace::ZERO);
        let (out, o) =
            run_call_with(&mut HostRef, &mut ws, |i| words[i as usize], words.len() as u32);
        let mut post = self.tree.clone();
        if o.status() == 1 {
            for i in 0..ws.input.storage.len() {
                let w = ws.input.storage.witness(i);
                post.insert(w.slot, w.value);
            }
            assert_eq!(
                post.root(),
                ws.input.storage.root(),
                "the host tree and the guest's witnesses disagree on the post-state root"
            );
        }
        (out, o, post)
    }
}

/// Append a byte string in the input layout: its length, then `ceil(n/4)` words holding four bytes
/// each little-endian, the last zero-padded.
fn push_bytes(w: &mut Vec<u32>, bytes: &[u8]) {
    w.push(bytes.len() as u32);
    for chunk in bytes.chunks(4) {
        let mut word = [0u8; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        w.push(u32::from_le_bytes(word));
    }
}
