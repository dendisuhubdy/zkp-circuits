//! The simulated **contract** plus a simulated **wallet**.
//!
//! The contract holds:
//!   * the Merkle tree of commitments
//!   * a set of historical roots (a withdrawal may reference an older root,
//!     because more deposits may land while your proof is in flight)
//!   * the set of spent nullifier hashes
//!   * account balances (standing in for ETH balances on chain)
//!   * the Groth16 verifying key (on chain this is a Solidity verifier)

use crate::circuit::WithdrawCircuit;
use crate::hash::{hash1, hash2};
use crate::merkle::MerkleTree;
use crate::Fr;
use ark_bn254::Bn254;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use ark_std::UniformRand;
use std::collections::{BTreeMap, HashSet};

pub type Pk = ProvingKey<Bn254>;
pub type Vk = VerifyingKey<Bn254>;

/// What a depositor writes down and keeps offline. Tornado encodes this as
/// the "note" string `tornado-eth-1-<netId>-0x<nullifier><secret>`.
#[derive(Clone, Debug)]
pub struct Note {
    pub nullifier: Fr,
    pub secret: Fr,
    /// Filled in by the contract on deposit; needed to build the Merkle path.
    pub leaf_index: Option<usize>,
}

impl Note {
    pub fn random<R: rand::Rng>(rng: &mut R) -> Self {
        Note { nullifier: Fr::rand(rng), secret: Fr::rand(rng), leaf_index: None }
    }
    pub fn commitment(&self) -> Fr {
        hash2(self.nullifier, self.secret)
    }
    pub fn nullifier_hash(&self) -> Fr {
        hash1(self.nullifier)
    }
}

#[derive(Debug)]
pub enum MixerError {
    InsufficientBalance,
    UnknownRoot,
    NoteAlreadySpent,
    InvalidProof,
    TreeFull,
}

pub struct Mixer {
    pub denomination: u64,
    tree: MerkleTree,
    known_roots: HashSet<Fr>,
    spent: HashSet<Fr>,
    pvk: PreparedVerifyingKey<Bn254>,
    pub balances: BTreeMap<String, u64>,
    pub pool: u64,
}

impl Mixer {
    pub fn new(denomination: u64, vk: &Vk) -> Self {
        let tree = MerkleTree::new();
        let mut known_roots = HashSet::new();
        known_roots.insert(tree.root());
        Mixer {
            denomination,
            tree,
            known_roots,
            spent: HashSet::new(),
            pvk: Groth16::<Bn254>::process_vk(vk).expect("vk"),
            balances: BTreeMap::new(),
            pool: 0,
        }
    }

    pub fn fund(&mut self, who: &str, amount: u64) {
        *self.balances.entry(who.to_string()).or_default() += amount;
    }

    pub fn root(&self) -> Fr {
        self.tree.root()
    }

    pub fn deposits(&self) -> usize {
        self.tree.len()
    }

    /// `deposit(commitment)` — the depositor's identity is visible here
    /// (it's a normal transaction), but the commitment reveals nothing.
    pub fn deposit(&mut self, from: &str, commitment: Fr) -> Result<usize, MixerError> {
        let bal = self.balances.entry(from.to_string()).or_default();
        if *bal < self.denomination {
            return Err(MixerError::InsufficientBalance);
        }
        if self.tree.len() >= 1 << crate::TREE_DEPTH {
            return Err(MixerError::TreeFull);
        }
        *bal -= self.denomination;
        self.pool += self.denomination;
        let idx = self.tree.insert(commitment);
        self.known_roots.insert(self.tree.root());
        Ok(idx)
    }

    /// `withdraw(proof, root, nullifierHash, recipient)` — nothing here
    /// references a deposit. The contract learns only that *some* deposit
    /// is being redeemed.
    pub fn withdraw(&mut self, proof: &Proof<Bn254>, root: Fr, nullifier_hash: Fr, recipient: &str) -> Result<(), MixerError> {
        if !self.known_roots.contains(&root) {
            return Err(MixerError::UnknownRoot);
        }
        if self.spent.contains(&nullifier_hash) {
            return Err(MixerError::NoteAlreadySpent);
        }
        let public = [root, nullifier_hash, crate::addr(recipient)];
        let ok = Groth16::<Bn254>::verify_with_processed_vk(&self.pvk, &public, proof).unwrap_or(false);
        if !ok {
            return Err(MixerError::InvalidProof);
        }
        self.spent.insert(nullifier_hash);
        self.pool -= self.denomination;
        *self.balances.entry(recipient.to_string()).or_default() += self.denomination;
        Ok(())
    }

    /// The wallet side: build a withdraw proof for `note` paying `recipient`.
    /// Needs read access to the tree (on chain: fetch all Deposit events and
    /// rebuild the tree locally — that is what the Tornado UI does).
    pub fn prove_withdraw<R: rand::Rng + rand::CryptoRng>(
        &self,
        pk: &Pk,
        note: &Note,
        recipient: &str,
        rng: &mut R,
    ) -> Result<(Proof<Bn254>, Fr, Fr), ark_relations::r1cs::SynthesisError> {
        let idx = note.leaf_index.expect("note was never deposited");
        let path = self.tree.path(idx);
        let root = self.tree.root();
        let nh = note.nullifier_hash();
        let circuit = WithdrawCircuit {
            root: Some(root),
            nullifier_hash: Some(nh),
            recipient: Some(crate::addr(recipient)),
            nullifier: Some(note.nullifier),
            secret: Some(note.secret),
            path: Some(path),
        };
        let proof = Groth16::<Bn254>::prove(pk, circuit, rng)?;
        Ok((proof, root, nh))
    }
}

/// One-time circuit setup. On chain, the vk is compiled into the verifier
/// contract; the pk ships with the wallet.
pub fn setup<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> (Pk, Vk) {
    Groth16::<Bn254>::circuit_specific_setup(WithdrawCircuit::blank(), rng).expect("setup")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deposit_withdraw_double_spend() {
        let mut rng = rand::rngs::OsRng;
        let (pk, vk) = setup(&mut rng);
        let mut m = Mixer::new(1, &vk);
        m.fund("alice", 3);

        let mut note = Note::random(&mut rng);
        note.leaf_index = Some(m.deposit("alice", note.commitment()).unwrap());
        assert_eq!(m.balances["alice"], 2);

        let (proof, root, nh) = m.prove_withdraw(&pk, &note, "carol", &mut rng).unwrap();
        m.withdraw(&proof, root, nh, "carol").unwrap();
        assert_eq!(m.balances["carol"], 1);

        // same note again → nullifier already seen
        assert!(matches!(m.withdraw(&proof, root, nh, "carol"), Err(MixerError::NoteAlreadySpent)));
        // proof bound to carol cannot pay dave
        let (proof2, root2, nh2) = m.prove_withdraw(&pk, &Note { leaf_index: note.leaf_index, ..Note::random(&mut rng) }, "dave", &mut rng).unwrap();
        // ^ a random note that was never deposited: path is for leaf 0 but leaf != commitment
        assert!(matches!(m.withdraw(&proof2, root2, nh2, "dave"), Err(MixerError::InvalidProof)));
    }

    #[test]
    fn recipient_is_bound() {
        let mut rng = rand::rngs::OsRng;
        let (pk, vk) = setup(&mut rng);
        let mut m = Mixer::new(1, &vk);
        m.fund("alice", 1);
        let mut note = Note::random(&mut rng);
        note.leaf_index = Some(m.deposit("alice", note.commitment()).unwrap());
        let (proof, root, nh) = m.prove_withdraw(&pk, &note, "carol", &mut rng).unwrap();
        // front-runner swaps recipient
        assert!(matches!(m.withdraw(&proof, root, nh, "mallory"), Err(MixerError::InvalidProof)));
    }
}
