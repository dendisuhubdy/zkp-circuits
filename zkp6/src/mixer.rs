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
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
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

    /// The note string the depositor saves. Tornado's format is
    /// `tornado-<currency>-<amount>-<netId>-0x<nullifier 31B><secret 31B>`.
    /// We use 32-byte little-endian field elements. This string is the
    /// ONLY thing needed to withdraw — no account, no signature.
    pub fn to_note_string(&self, currency: &str, amount: u64, net_id: u64) -> String {
        use ark_ff::{BigInteger, PrimeField};
        let hex = |f: &Fr| f.into_bigint().to_bytes_le().iter().map(|b| format!("{b:02x}")).collect::<String>();
        format!("tornado-{currency}-{amount}-{net_id}-0x{}{}", hex(&self.nullifier), hex(&self.secret))
    }

    /// Parse a note string back into (ν, s). Everything else (commitment,
    /// leaf index, Merkle path) is recomputed from public chain data.
    pub fn parse(note: &str) -> Result<(Self, String, u64, u64), String> {
        use ark_ff::PrimeField;
        let parts: Vec<&str> = note.split('-').collect();
        if parts.len() != 5 || parts[0] != "tornado" {
            return Err("expected tornado-<currency>-<amount>-<netId>-0x<hex>".into());
        }
        let amount: u64 = parts[2].parse().map_err(|_| "bad amount")?;
        let net_id: u64 = parts[3].parse().map_err(|_| "bad netId")?;
        let hex = parts[4].strip_prefix("0x").ok_or("missing 0x")?;
        if hex.len() != 128 {
            return Err(format!("expected 128 hex chars, got {}", hex.len()));
        }
        let bytes = |h: &str| -> Result<Vec<u8>, String> {
            (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).map_err(|e| e.to_string())).collect()
        };
        let nullifier = Fr::from_le_bytes_mod_order(&bytes(&hex[..64])?);
        let secret = Fr::from_le_bytes_mod_order(&bytes(&hex[64..])?);
        Ok((Note { nullifier, secret, leaf_index: None }, parts[1].to_string(), amount, net_id))
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
    /// `spent` in insertion order, for display.
    spent_log: Vec<Fr>,
    /// Who sent each deposit transaction, by leaf index. Public on chain.
    depositors: Vec<String>,
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
            spent_log: Vec::new(),
            depositors: Vec::new(),
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

    pub fn withdrawals(&self) -> usize {
        self.spent_log.len()
    }

    pub fn tree(&self) -> &MerkleTree {
        &self.tree
    }

    /// Sender of the deposit that filled leaf `idx`.
    pub fn depositor(&self, idx: usize) -> &str {
        &self.depositors[idx]
    }

    /// Nullifier hashes recorded so far, oldest first.
    pub fn spent_nullifiers(&self) -> &[Fr] {
        &self.spent_log
    }

    pub fn known_roots(&self) -> usize {
        self.known_roots.len()
    }

    /// The contract's event log: every `Deposit(commitment, leafIndex)` in
    /// order. A wallet reads this to locate its own leaf and rebuild the
    /// tree — it never asks the contract "where is my note?".
    pub fn deposit_events(&self) -> Vec<(usize, Fr)> {
        self.tree.leaves().iter().copied().enumerate().collect()
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
        self.depositors.push(from.to_string());
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
        self.spent_log.push(nullifier_hash);
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
        let proof = prove(pk, circuit, rng)?;
        Ok((proof, root, nh))
    }
}

/// Prove, but check the witness first. ark-groth16 never rejects a bad
/// witness: in debug builds it hits `debug_assert!(cs.is_satisfied())` and
/// panics, in release builds it silently emits a proof the verifier will
/// reject. A real wallet checks its own witness, so we do that here and
/// return `Unsatisfiable` instead of calling into the library.
pub fn prove<R: rand::Rng + rand::CryptoRng>(pk: &Pk, circuit: WithdrawCircuit, rng: &mut R) -> Result<Proof<Bn254>, SynthesisError> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.clone().generate_constraints(cs.clone())?;
    if !cs.is_satisfied()? {
        return Err(SynthesisError::Unsatisfiable);
    }
    Groth16::<Bn254>::prove(pk, circuit, rng)
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
        // a random note that was never deposited: the path is for leaf 0 but
        // H(ν, s) != leaf, so the witness is unsatisfying and the prover refuses
        let never_deposited = Note { leaf_index: note.leaf_index, ..Note::random(&mut rng) };
        assert!(matches!(m.prove_withdraw(&pk, &never_deposited, "dave", &mut rng), Err(SynthesisError::Unsatisfiable)));
    }

    #[test]
    fn note_string_round_trips() {
        let mut rng = rand::rngs::OsRng;
        let n = Note::random(&mut rng);
        let s = n.to_note_string("eth", 1, 1);
        assert!(s.starts_with("tornado-eth-1-1-0x"));
        let (back, cur, amt, net) = Note::parse(&s).unwrap();
        assert_eq!((cur.as_str(), amt, net), ("eth", 1, 1));
        assert_eq!(back.nullifier, n.nullifier);
        assert_eq!(back.secret, n.secret);
        assert_eq!(back.commitment(), n.commitment());
        assert!(Note::parse("tornado-eth-1-1-0xdeadbeef").is_err());
        assert!(Note::parse("hello").is_err());
    }

    #[test]
    fn withdraw_from_note_string_only() {
        let mut rng = rand::rngs::OsRng;
        let (pk, vk) = setup(&mut rng);
        let mut m = Mixer::new(1, &vk);
        m.fund("alice", 1);
        let note = crate::cli::deposit(&mut m, "alice", &mut rng).unwrap();
        assert!(crate::cli::withdraw(&mut m, &pk, &note, "carol", &mut rng).is_ok());
        assert_eq!(m.balances["carol"], 1);
        assert!(crate::cli::withdraw(&mut m, &pk, &note, "carol", &mut rng).is_err());
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
