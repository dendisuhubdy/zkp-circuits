//! A simulated chain for the shielded transfer: an append-only commitment Merkle tree, the
//! nullifier set, a clock, and one envelope per transaction. `apply` is what a node would
//! run: check the proof's output-commitment digest against the plaintext values it is handed
//! (`docs/06-viewing-keys.md`'s "Public outputs"), check the claimed anchor is a recent root,
//! verify the proof under the transfer guest's `hc`, then apply the effects.
//!
//! M3.3: `cm_in` (the spent note's commitment) is no longer public anywhere — `MERKLE_VERIFY`
//! proves it in-circuit against `anchor`, a tree root, so the chain no longer shows which
//! commitment a transfer spent. `anchor` alone is public (as part of the output-commitment
//! digest), and only as one of a bounded window of recent roots, not a single fixed point.

use crate::isa::Program;
use crate::machine::{Machine, Proof, VerifyError};
use crate::notes::{output_digest, Note, Word8, DEPTH};
use crate::viewing::Envelope;
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Clone, Debug)]
pub struct Tx {
    /// `None` for a mint (created from nothing, no note spent).
    pub anchor: Option<Word8>,
    pub nf: Option<Word8>,
    pub cm_out: Word8,
    pub time: u32,
    pub envelope: Envelope,
}

#[derive(Debug)]
pub enum LedgerError {
    Proof(VerifyError),
    /// The proof's published digest does not match `output_digest(anchor, nf, cm_out, time)`
    /// for the plaintext values `apply` was handed.
    BadDigest,
    /// `anchor` is not one of the ledger's recently recorded tree roots.
    UnknownAnchor(Word8),
    /// `nf` has already been published.
    Spent(Word8),
    /// `cm_out` already exists.
    Duplicate(Word8),
    /// The created note's time is not the chain's current time.
    Time { claimed: u32, now: u32 },
}

/// How many of the tree's most recent roots `Ledger::apply` accepts as an `anchor` — a proof
/// may be built against a root that is no longer the very latest one (another transaction can
/// land first), as long as it is recent enough. The standard incremental/sparse-Merkle-tree
/// approach: unfilled subtrees use a fixed "empty" digest per level, precomputed once, so a
/// depth-32 tree never requires materializing `2^32` leaves.
const RECENT_ROOTS: usize = 16;

/// An append-only, depth-`DEPTH` commitment Merkle tree, using exactly the hash the guest's
/// `MERKLE_VERIFY` uses (`notes::hash(domain::NODE, ..)`) so a witness built from
/// `path_for`/`root` verifies in-circuit.
pub struct CommitmentTree {
    leaves: Vec<Word8>,
    index: HashMap<Word8, usize>,
    /// `empty[d]` is the default digest of an empty subtree of depth `d`: `empty[0]` is the
    /// all-zero "no leaf" value, `empty[d] = H(NODE, empty[d-1], empty[d-1])`.
    empty: [Word8; DEPTH + 1],
}

impl CommitmentTree {
    pub fn new() -> CommitmentTree {
        let mut empty = [[0u32; 8]; DEPTH + 1];
        for d in 1..=DEPTH {
            let prev = empty[d - 1];
            let mut msg = [0u32; 16];
            msg[..8].copy_from_slice(&prev);
            msg[8..].copy_from_slice(&prev);
            empty[d] = crate::notes::hash(crate::notes::domain::NODE, &msg);
        }
        CommitmentTree { leaves: Vec::new(), index: HashMap::new(), empty }
    }

    /// Every level's node list, level 0 (the leaves, real values only — no trailing padding)
    /// through `DEPTH` (the root, one node). An odd tail at any level is paired with that
    /// level's `empty` default rather than materialized, which is what keeps this whole
    /// computation `O(leaves)` instead of `O(2^DEPTH)`.
    fn levels(&self) -> Vec<Vec<Word8>> {
        let mut levels = vec![self.leaves.clone()];
        for level in 0..DEPTH {
            let cur = &levels[level];
            let next = if cur.is_empty() {
                vec![self.empty[level + 1]]
            } else {
                let mut out = Vec::with_capacity(cur.len().div_ceil(2));
                let mut i = 0;
                while i < cur.len() {
                    let left = cur[i];
                    let right = if i + 1 < cur.len() { cur[i + 1] } else { self.empty[level] };
                    let mut msg = [0u32; 16];
                    msg[..8].copy_from_slice(&left);
                    msg[8..].copy_from_slice(&right);
                    out.push(crate::notes::hash(crate::notes::domain::NODE, &msg));
                    i += 2;
                }
                out
            };
            levels.push(next);
        }
        levels
    }

    pub fn append(&mut self, cm: Word8) -> usize {
        let idx = self.leaves.len();
        self.leaves.push(cm);
        self.index.insert(cm, idx);
        idx
    }

    pub fn root(&self) -> Word8 { *self.levels()[DEPTH].first().unwrap_or(&self.empty[DEPTH]) }

    /// The sibling path (leaf to root) and index for the leaf at `index`.
    pub fn path(&self, index: usize) -> [Word8; DEPTH] {
        let levels = self.levels();
        let mut path = [[0u32; 8]; DEPTH];
        let mut idx = index;
        for level in 0..DEPTH {
            let nodes = &levels[level];
            let sib = idx ^ 1;
            path[level] = if sib < nodes.len() { nodes[sib] } else { self.empty[level] };
            idx /= 2;
        }
        path
    }

    /// The path and index for the leaf equal to `cm`, if it has been appended.
    pub fn path_for(&self, cm: &Word8) -> Option<([Word8; DEPTH], u32)> {
        let idx = *self.index.get(cm)?;
        Some((self.path(idx), idx as u32))
    }
}

impl Default for CommitmentTree {
    fn default() -> Self { Self::new() }
}

pub struct Ledger {
    /// The transfer guest; every proof is verified against its `hc`.
    pub program: Program,
    pub txs: Vec<Tx>,
    tree: CommitmentTree,
    /// Bounded window of the tree's most recent roots, oldest first — what `apply` accepts an
    /// `anchor` against. Starts with the genesis (empty-tree) root.
    recent_roots: VecDeque<Word8>,
    nullifiers: HashSet<Word8>,
    /// Block time. A transaction must carry it.
    pub now: u32,
}

impl Ledger {
    pub fn new(now: u32) -> Ledger {
        let tree = CommitmentTree::new();
        let mut recent_roots = VecDeque::new();
        recent_roots.push_back(tree.root());
        Ledger { program: crate::guests::transfer(), txs: Vec::new(), tree, recent_roots, nullifiers: HashSet::new(), now }
    }
    pub fn advance(&mut self, seconds: u32) { self.now += seconds; }
    pub fn has_commitment(&self, cm: &Word8) -> bool { self.tree.index.contains_key(cm) }
    pub fn has_nullifier(&self, nf: &Word8) -> bool { self.nullifiers.contains(nf) }
    /// The current tree root — the freshest valid `anchor`.
    pub fn root(&self) -> Word8 { self.tree.root() }
    /// The Merkle witness (path, index) for a commitment already in the tree — what
    /// `notes::transfer_inputs` needs to spend the note it belongs to.
    pub fn path_for(&self, cm: &Word8) -> Option<([Word8; DEPTH], u32)> { self.tree.path_for(cm) }

    fn record_root(&mut self) {
        self.recent_roots.push_back(self.tree.root());
        while self.recent_roots.len() > RECENT_ROOTS { self.recent_roots.pop_front(); }
    }

    /// A deposit: a note created in the open (the bridge's mint, a public deposit) with its
    /// commitment appended to the tree directly. Its envelope is sealed like any other so the
    /// receiver's viewing key finds it.
    pub fn mint(&mut self, note: &Note, envelope: Envelope) -> Result<usize, LedgerError> {
        if note.time != self.now { return Err(LedgerError::Time { claimed: note.time, now: self.now }); }
        let cm = note.commitment();
        if self.tree.index.contains_key(&cm) { return Err(LedgerError::Duplicate(cm)); }
        self.tree.append(cm);
        self.record_root();
        self.txs.push(Tx { anchor: None, nf: None, cm_out: cm, time: note.time, envelope });
        Ok(self.txs.len() - 1)
    }

    /// The consensus check for a transfer. `anchor`/`nf`/`cm_out`/`time` are the plaintext
    /// values the guest's output-commitment digest attests to (`docs/06-viewing-keys.md`) —
    /// published the same way `cm_out`/`time` always were, as plain transaction metadata, not
    /// hidden inside the envelope. Cheap structural checks run first so a node never pays for
    /// a STARK verification of a transaction it would reject anyway; the proof is then
    /// verified and the tree/nullifier set updated.
    #[allow(clippy::too_many_arguments)]
    pub fn apply(&mut self, machine: &Machine, proof: &Proof, anchor: Word8, nf: Word8, cm_out: Word8, time: u32, envelope: Envelope) -> Result<usize, LedgerError> {
        use crate::tables::cpu::pv;
        // Same shape check `verify` makes first, so a malformed proof is a proof error and not
        // a misleading digest mismatch. A slot outside 32 bits cannot come from an honest
        // trace (an output is a register word); `verify` rejects it, and until then the digest
        // simply cannot match.
        if proof.public_values.len() != pv::NUM { return Err(LedgerError::Proof(VerifyError::PublicValues)); }
        if proof.public_values[pv::OUT0..pv::OUT0 + 8].iter().any(|v| *v > u32::MAX as u64) { return Err(LedgerError::BadDigest); }
        let published: Word8 = std::array::from_fn(|i| proof.public_values[pv::OUT0 + i] as u32);
        if published != output_digest(&anchor, &nf, &cm_out, time) { return Err(LedgerError::BadDigest); }
        if !self.recent_roots.contains(&anchor) { return Err(LedgerError::UnknownAnchor(anchor)); }
        if self.nullifiers.contains(&nf) { return Err(LedgerError::Spent(nf)); }
        if self.tree.index.contains_key(&cm_out) { return Err(LedgerError::Duplicate(cm_out)); }
        if time != self.now { return Err(LedgerError::Time { claimed: time, now: self.now }); }
        machine.verify(&self.program, proof).map_err(LedgerError::Proof)?;
        self.nullifiers.insert(nf);
        self.tree.append(cm_out);
        self.record_root();
        self.txs.push(Tx { anchor: Some(anchor), nf: Some(nf), cm_out, time, envelope });
        Ok(self.txs.len() - 1)
    }
}
