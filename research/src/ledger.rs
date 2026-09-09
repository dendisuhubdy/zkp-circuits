//! A simulated chain for the shielded transfer: the commitment set, the nullifier set, a
//! clock, and one envelope per transaction. `apply` is what a node would run: verify the
//! proof under the transfer guest's `hc`, then apply the public values to the two sets.
//!
//! Membership of `cm_in` is checked here, against the public value, because milestone 1
//! has no `MERKLE_VERIFY` syscall: the spent commitment is visible on chain and so is the
//! link from a note's creation to its spend. That leak is the roadmap's (M3), not the
//! viewing-key layer's — nothing in `viewing.rs` depends on how membership is proved.

use crate::isa::Program;
use crate::machine::{Machine, Proof, VerifyError};
use crate::notes::{output, Note, Word2};
use crate::viewing::Envelope;
use std::collections::HashSet;

#[derive(Clone, Debug)]
pub struct Tx {
    pub cm_in: Option<Word2>,
    pub nf: Option<Word2>,
    pub cm_out: Word2,
    pub time: u32,
    pub envelope: Envelope,
}

#[derive(Debug)]
pub enum LedgerError {
    Proof(VerifyError),
    /// `cm_in` is not a commitment this chain has seen.
    UnknownCommitment(Word2),
    /// `nf` has already been published.
    Spent(Word2),
    /// `cm_out` already exists.
    Duplicate(Word2),
    /// The created note's time is not the chain's current time.
    Time { claimed: u32, now: u32 },
}

pub struct Ledger {
    /// The transfer guest; every proof is verified against its `hc`.
    pub program: Program,
    pub txs: Vec<Tx>,
    commitments: HashSet<Word2>,
    nullifiers: HashSet<Word2>,
    /// Block time. A transaction must carry it.
    pub now: u32,
}

impl Ledger {
    pub fn new(now: u32) -> Ledger {
        Ledger { program: crate::guests::transfer(), txs: Vec::new(), commitments: HashSet::new(), nullifiers: HashSet::new(), now }
    }
    pub fn advance(&mut self, seconds: u32) { self.now += seconds; }
    pub fn has_commitment(&self, cm: &Word2) -> bool { self.commitments.contains(cm) }
    pub fn has_nullifier(&self, nf: &Word2) -> bool { self.nullifiers.contains(nf) }

    /// A deposit: a note created in the open (the bridge's mint, a public deposit) with its
    /// commitment recorded directly. Its envelope is sealed like any other so the receiver's
    /// viewing key finds it.
    pub fn mint(&mut self, note: &Note, envelope: Envelope) -> Result<usize, LedgerError> {
        if note.time != self.now { return Err(LedgerError::Time { claimed: note.time, now: self.now }); }
        let cm = note.commitment();
        if !self.commitments.insert(cm) { return Err(LedgerError::Duplicate(cm)); }
        self.txs.push(Tx { cm_in: None, nf: None, cm_out: cm, time: note.time, envelope });
        Ok(self.txs.len() - 1)
    }

    /// The consensus check for a transfer. Cheap structural checks on the public values run
    /// first so a node never pays for a STARK verification of a transaction it would reject
    /// anyway; the proof is then verified and the sets updated.
    pub fn apply(&mut self, machine: &Machine, proof: &Proof, envelope: Envelope) -> Result<usize, LedgerError> {
        use crate::tables::cpu::pv;
        // Same shape check `verify` makes first, so a malformed proof is a proof error and not
        // a misleading "unknown commitment". A slot outside 32 bits cannot come from an honest
        // trace (an output is a register word); `verify` rejects it, and until then it is
        // simply a value no set contains.
        if proof.public_values.len() != pv::NUM { return Err(LedgerError::Proof(VerifyError::PublicValues)); }
        let out = |i: usize| proof.public_values[pv::OUT0 + i];
        let word2 = |i: usize| [out(i) as u32, out(i + 1) as u32];
        let (cm_in, nf, cm_out) = (word2(output::CM_IN), word2(output::NF), word2(output::CM_OUT));
        if out(output::CM_IN) > u32::MAX as u64 || out(output::CM_IN + 1) > u32::MAX as u64 || !self.commitments.contains(&cm_in) { return Err(LedgerError::UnknownCommitment(cm_in)); }
        if self.nullifiers.contains(&nf) { return Err(LedgerError::Spent(nf)); }
        if self.commitments.contains(&cm_out) { return Err(LedgerError::Duplicate(cm_out)); }
        if out(output::TIME) != self.now as u64 { return Err(LedgerError::Time { claimed: out(output::TIME) as u32, now: self.now }); }
        let time = self.now;
        machine.verify(&self.program, proof).map_err(LedgerError::Proof)?;
        self.nullifiers.insert(nf);
        self.commitments.insert(cm_out);
        self.txs.push(Tx { cm_in: Some(cm_in), nf: Some(nf), cm_out, time, envelope });
        Ok(self.txs.len() - 1)
    }
}
