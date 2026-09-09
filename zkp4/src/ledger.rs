//! Simulated chain: transparent balances ("t-addresses") and the shielded
//! pool (commitment tree + nullifier set + pool total).

use crate::circuit::TransferCircuit;
use crate::merkle::MerkleTree;
use crate::note::{Note, SpendingKey};
use crate::Fr;
use ark_bn254::Bn254;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use std::collections::{BTreeMap, HashSet};

pub type Pk = ProvingKey<Bn254>;
pub type Vk = VerifyingKey<Bn254>;

#[derive(Debug)]
pub enum LedgerError {
    InsufficientBalance,
    UnknownRoot,
    NullifierSeen,
    InvalidProof,
}

/// What a shielded transfer looks like on chain. No values, no addresses.
pub struct ShieldedTx {
    pub root: Fr,
    pub nullifier: Fr,
    pub cm_out: [Fr; 2],
    /// Value leaving the pool to `to_transparent` (0 for z→z).
    pub v_pub: u64,
    pub to_transparent: Option<String>,
    pub proof: Proof<Bn254>,
}

/// Off-chain: what the sender hands to each recipient so they can spend.
/// Zcash encrypts this into the transaction; we pass it by hand.
pub struct NoteDelivery {
    pub note: Note,
    pub leaf_index: usize,
}

pub struct Ledger {
    pub transparent: BTreeMap<String, u64>,
    pub pool: u64,
    tree: MerkleTree,
    known_roots: HashSet<Fr>,
    nullifiers: HashSet<Fr>,
    pvk: PreparedVerifyingKey<Bn254>,
}

impl Ledger {
    pub fn new(vk: &Vk) -> Self {
        let tree = MerkleTree::new();
        let mut known_roots = HashSet::new();
        known_roots.insert(tree.root());
        Ledger {
            transparent: BTreeMap::new(),
            pool: 0,
            tree,
            known_roots,
            nullifiers: HashSet::new(),
            pvk: Groth16::<Bn254>::process_vk(vk).expect("vk"),
        }
    }

    pub fn mint(&mut self, who: &str, amount: u64) {
        *self.transparent.entry(who.into()).or_default() += amount;
    }

    pub fn root(&self) -> Fr {
        self.tree.root()
    }
    pub fn notes(&self) -> usize {
        self.tree.len()
    }
    pub fn path(&self, idx: usize) -> crate::merkle::MerklePath {
        self.tree.path(idx)
    }

    /// t → z. The value is public here (it comes from a transparent
    /// balance); only the recipient of the new note is hidden. Zcash still
    /// attaches an output proof; we skip it because the commitment is the
    /// only thing being created and its value is already known.
    pub fn shield(&mut self, from: &str, note: &Note) -> Result<usize, LedgerError> {
        let bal = self.transparent.entry(from.into()).or_default();
        if *bal < note.value {
            return Err(LedgerError::InsufficientBalance);
        }
        *bal -= note.value;
        self.pool += note.value;
        let idx = self.tree.insert(note.commitment());
        self.known_roots.insert(self.tree.root());
        Ok(idx)
    }

    /// z → z (v_pub = 0) or z → z + t (v_pub > 0). The contract does exactly
    /// what Tornado does plus insert two new leaves and pay out v_pub.
    pub fn apply(&mut self, tx: &ShieldedTx) -> Result<[usize; 2], LedgerError> {
        if !self.known_roots.contains(&tx.root) {
            return Err(LedgerError::UnknownRoot);
        }
        if self.nullifiers.contains(&tx.nullifier) {
            return Err(LedgerError::NullifierSeen);
        }
        let public = [tx.root, tx.nullifier, tx.cm_out[0], tx.cm_out[1], Fr::from(tx.v_pub)];
        if !Groth16::<Bn254>::verify_with_processed_vk(&self.pvk, &public, &tx.proof).unwrap_or(false) {
            return Err(LedgerError::InvalidProof);
        }
        self.nullifiers.insert(tx.nullifier);
        let i0 = self.tree.insert(tx.cm_out[0]);
        let i1 = self.tree.insert(tx.cm_out[1]);
        self.known_roots.insert(self.tree.root());
        if tx.v_pub > 0 {
            self.pool -= tx.v_pub;
            *self.transparent.entry(tx.to_transparent.clone().unwrap_or_default()).or_default() += tx.v_pub;
        }
        Ok([i0, i1])
    }
}

/// Wallet side: build a transfer. `notes_out` values must sum with v_pub to
/// the input value or the prover will produce a proof that fails to verify.
#[allow(clippy::too_many_arguments)]
pub fn build_transfer<R: rand::Rng + rand::CryptoRng>(
    ledger: &Ledger,
    pk: &Pk,
    sk: &SpendingKey,
    note_in: &Note,
    leaf_index: usize,
    notes_out: [Note; 2],
    v_pub: u64,
    to_transparent: Option<&str>,
    rng: &mut R,
) -> Result<ShieldedTx, ark_relations::r1cs::SynthesisError> {
    let root = ledger.root();
    let nullifier = sk.nullifier(note_in);
    let cm_out = [notes_out[0].commitment(), notes_out[1].commitment()];
    let circuit = TransferCircuit {
        root: Some(root),
        nullifier: Some(nullifier),
        cm_out: [Some(cm_out[0]), Some(cm_out[1])],
        v_pub: Some(v_pub),
        sk: Some(*sk),
        note_in: Some(*note_in),
        path: Some(ledger.path(leaf_index)),
        notes_out: [Some(notes_out[0]), Some(notes_out[1])],
    };
    let proof = Groth16::<Bn254>::prove(pk, circuit, rng)?;
    Ok(ShieldedTx { root, nullifier, cm_out, v_pub, to_transparent: to_transparent.map(String::from), proof })
}

pub fn setup<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> (Pk, Vk) {
    Groth16::<Bn254>::circuit_specific_setup(TransferCircuit::blank(), rng).expect("setup")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn world() -> (Pk, Ledger, SpendingKey, SpendingKey, Note, usize, rand::rngs::OsRng) {
        let mut rng = rand::rngs::OsRng;
        let (pk, vk) = setup(&mut rng);
        let mut l = Ledger::new(&vk);
        let alice = SpendingKey::random(&mut rng);
        let bob = SpendingKey::random(&mut rng);
        l.mint("alice", 10);
        let n = Note::new(10, alice.public_key(), &mut rng);
        let idx = l.shield("alice", &n).unwrap();
        (pk, l, alice, bob, n, idx, rng)
    }

    #[test]
    fn z_to_z_then_unshield() {
        let (pk, mut l, alice, bob, n, idx, mut rng) = world();
        let to_bob = Note::new(3, bob.public_key(), &mut rng);
        let change = Note::new(7, alice.public_key(), &mut rng);
        let tx = build_transfer(&l, &pk, &alice, &n, idx, [to_bob, change], 0, None, &mut rng).unwrap();
        let [bob_idx, _] = l.apply(&tx).unwrap();
        assert_eq!(l.pool, 10);

        // Bob unshields 2 to "bob-t", keeps 1 shielded
        let keep = Note::new(1, bob.public_key(), &mut rng);
        let dust = Note::new(0, bob.public_key(), &mut rng);
        let tx2 = build_transfer(&l, &pk, &bob, &to_bob, bob_idx, [keep, dust], 2, Some("bob-t"), &mut rng).unwrap();
        l.apply(&tx2).unwrap();
        assert_eq!(l.transparent["bob-t"], 2);
        assert_eq!(l.pool, 8);
        // double spend
        assert!(matches!(l.apply(&tx2), Err(LedgerError::NullifierSeen)));
    }

    #[test]
    fn inflation_and_theft_rejected() {
        let (pk, mut l, alice, bob, n, idx, mut rng) = world();
        // inflation: 10 in, 12 out
        let o1 = Note::new(6, bob.public_key(), &mut rng);
        let o2 = Note::new(6, alice.public_key(), &mut rng);
        let tx = build_transfer(&l, &pk, &alice, &n, idx, [o1, o2], 0, None, &mut rng).unwrap();
        assert!(matches!(l.apply(&tx), Err(LedgerError::InvalidProof)));
        // wrap-around: v1 = 2^64 - 1 + ... cannot even be expressed as u64 here, but a
        // value ≥ 2^64 would fail enforce_u64; test the sum-wrap via v_pub instead:
        // theft: bob tries to spend alice's note with his key
        let o1 = Note::new(5, bob.public_key(), &mut rng);
        let o2 = Note::new(5, bob.public_key(), &mut rng);
        let tx = build_transfer(&l, &pk, &bob, &n, idx, [o1, o2], 0, None, &mut rng).unwrap();
        assert!(matches!(l.apply(&tx), Err(LedgerError::InvalidProof)));
    }
}
