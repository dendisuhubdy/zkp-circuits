//! Simulated chain: transparent balances ("t-addresses") and the shielded
//! pool (commitment tree + nullifier set + pool total).

use crate::circuit::TransferCircuit;
use crate::merkle::MerkleTree;
use crate::note::{Note, SpendingKey};
use crate::Fr;
use ark_bn254::Bn254;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
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

/// How a leaf got into the tree, as far as the chain can tell.
#[derive(Clone, Debug)]
pub enum LeafOrigin {
    /// t → z: the sender and the value are public.
    Shield { from: String, value: u64 },
    /// Output `which` of the shielded transfer that revealed `nullifier`.
    /// Value and recipient are hidden.
    TxOutput { nullifier: Fr, which: usize },
}

pub struct Ledger {
    pub transparent: BTreeMap<String, u64>,
    pub pool: u64,
    tree: MerkleTree,
    /// One entry per leaf, in leaf order.
    origins: Vec<LeafOrigin>,
    known_roots: HashSet<Fr>,
    nullifiers: HashSet<Fr>,
    /// `nullifiers` in insertion order, for display.
    nullifier_log: Vec<Fr>,
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
            origins: Vec::new(),
            known_roots,
            nullifiers: HashSet::new(),
            nullifier_log: Vec::new(),
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
    pub fn tree(&self) -> &MerkleTree {
        &self.tree
    }
    pub fn origin(&self, idx: usize) -> &LeafOrigin {
        &self.origins[idx]
    }
    /// Nullifiers revealed so far, oldest first.
    pub fn nullifiers(&self) -> &[Fr] {
        &self.nullifier_log
    }
    pub fn known_roots(&self) -> usize {
        self.known_roots.len()
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
        self.origins.push(LeafOrigin::Shield { from: from.into(), value: note.value });
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
        self.nullifier_log.push(tx.nullifier);
        let i0 = self.tree.insert(tx.cm_out[0]);
        let i1 = self.tree.insert(tx.cm_out[1]);
        self.origins.push(LeafOrigin::TxOutput { nullifier: tx.nullifier, which: 0 });
        self.origins.push(LeafOrigin::TxOutput { nullifier: tx.nullifier, which: 1 });
        self.known_roots.insert(self.tree.root());
        if tx.v_pub > 0 {
            self.pool -= tx.v_pub;
            *self.transparent.entry(tx.to_transparent.clone().unwrap_or_default()).or_default() += tx.v_pub;
        }
        Ok([i0, i1])
    }
}

/// Wallet side: build a transfer.
///
/// The wallet checks its own witness before proving. Groth16 itself does
/// not: ark-groth16's prover has a `debug_assert!(cs.is_satisfied())` that
/// panics in debug builds, and in release builds it silently emits a proof
/// the ledger would reject. So a transfer that does not balance, or that
/// spends a note with the wrong key, comes back as
/// `SynthesisError::Unsatisfiable` here instead of reaching the chain.
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
) -> Result<ShieldedTx, SynthesisError> {
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
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.clone().generate_constraints(cs.clone())?;
    if !cs.is_satisfied()? {
        return Err(SynthesisError::Unsatisfiable);
    }
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
    fn inflation_and_theft_refused_by_wallet() {
        let (pk, l, alice, bob, n, idx, mut rng) = world();
        // inflation: 10 in, 12 out
        let o1 = Note::new(6, bob.public_key(), &mut rng);
        let o2 = Note::new(6, alice.public_key(), &mut rng);
        let r = build_transfer(&l, &pk, &alice, &n, idx, [o1, o2], 0, None, &mut rng);
        assert!(matches!(r, Err(SynthesisError::Unsatisfiable)));
        // theft: bob tries to spend alice's note with his key
        let o1 = Note::new(5, bob.public_key(), &mut rng);
        let o2 = Note::new(5, bob.public_key(), &mut rng);
        let r = build_transfer(&l, &pk, &bob, &n, idx, [o1, o2], 0, None, &mut rng);
        assert!(matches!(r, Err(SynthesisError::Unsatisfiable)));
    }

    /// Bypass the wallet's check and forge proofs straight from Groth16.
    /// ark-groth16's prover `debug_assert!`s on a bad witness, so this can
    /// only run in a release build (`cargo test --release`); there the
    /// ledger's verifier rejects both forgeries.
    #[test]
    #[cfg(not(debug_assertions))]
    fn forged_proofs_rejected_by_ledger() {
        let (pk, mut l, alice, bob, n, idx, mut rng) = world();
        fn forge(l: &Ledger, pk: &Pk, sk: &SpendingKey, n: &Note, idx: usize, outs: [Note; 2], rng: &mut rand::rngs::OsRng) -> ShieldedTx {
            let cm_out = [outs[0].commitment(), outs[1].commitment()];
            let circuit = TransferCircuit {
                root: Some(l.root()),
                nullifier: Some(sk.nullifier(n)),
                cm_out: [Some(cm_out[0]), Some(cm_out[1])],
                v_pub: Some(0),
                sk: Some(*sk),
                note_in: Some(*n),
                path: Some(l.path(idx)),
                notes_out: [Some(outs[0]), Some(outs[1])],
            };
            let proof = Groth16::<Bn254>::prove(pk, circuit, rng).unwrap();
            ShieldedTx { root: l.root(), nullifier: sk.nullifier(n), cm_out, v_pub: 0, to_transparent: None, proof }
        }
        let inflate = forge(&l, &pk, &alice, &n, idx, [Note::new(6, bob.public_key(), &mut rng), Note::new(6, alice.public_key(), &mut rng)], &mut rng);
        assert!(matches!(l.apply(&inflate), Err(LedgerError::InvalidProof)));
        let theft = forge(&l, &pk, &bob, &n, idx, [Note::new(5, bob.public_key(), &mut rng), Note::new(5, bob.public_key(), &mut rng)], &mut rng);
        assert!(matches!(l.apply(&theft), Err(LedgerError::InvalidProof)));
    }
}
