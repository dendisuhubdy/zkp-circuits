//! Transactions and chain state.
//!
//! ```text
//!   TX = { inputs:  [ { ring: 11 output indices, pseudo_out C', clsag } ],
//!          outputs: [ { one_time_pk P, commitment C, enc_amount } ],
//!          tx_pubkey R, fee, range_proof over all output amounts }
//!
//!   VERIFY (what every node does):
//!     for each input:   clsag.verify(ring members, C')      ← owns one of 11, same amount
//!                       key_image not seen before           ← no double spend
//!     Σ C'  ==  Σ C_out + fee·H                              ← balance, in the clear
//!     bulletproof.verify(all C_out)                          ← every v_out ∈ [0, 2⁶⁴)
//! ```

use crate::clsag;
use crate::keys::{make_output, Account, Address};
use crate::pedersen::{commit, gens, h_gen};
use crate::{pt, Point, Scalar, RING_SIZE};
use bulletproofs::{BulletproofGens, RangeProof};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::traits::Identity;
use merlin::Transcript;
use std::collections::HashSet;

#[derive(Clone)]
pub struct Output {
    pub one_time_pk: Point,
    pub commitment: Point,
    pub enc_amount: u64,
    /// R of the transaction that created it (needed to scan).
    pub tx_pubkey: Point,
    pub index_in_tx: u64,
}

pub struct Input {
    pub ring: Vec<usize>, // global output indices, sorted (the real one is hidden among them)
    pub pseudo_out: Point,
    pub sig: clsag::Signature,
}

pub struct Tx {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub tx_pubkey: Point,
    pub fee: u64,
    pub range_proof: RangeProof,
}

impl Tx {
    pub fn size_bytes(&self) -> usize {
        self.inputs.iter().map(|i| i.sig.size_bytes() + 32 + 8 * i.ring.len()).sum::<usize>()
            + self.outputs.len() * (32 + 32 + 8)
            + 32
            + 8
            + self.range_proof.to_bytes().len()
    }
}

/// An output we own, with everything needed to spend it.
#[derive(Clone)]
pub struct Owned {
    pub global_index: usize,
    pub amount: u64,
    pub mask: Scalar,
    pub one_time_sk: Scalar,
}

#[derive(Debug)]
pub enum TxError {
    RingSignature(usize),
    KeyImageSeen(usize),
    Unbalanced,
    RangeProof,
    BadRing,
}

/// How an output got on chain, as far as an observer can tell.
#[derive(Clone, Debug)]
pub enum OutputOrigin {
    /// Coinbase amounts are public in Monero too.
    Coinbase { amount: u64 },
    /// Output `which` of the `tx`-th accepted transaction. Amount and
    /// recipient hidden.
    TxOutput { tx: usize, which: usize },
}

pub struct Chain {
    pub outputs: Vec<Output>,
    /// One entry per output, in output order.
    origins: Vec<OutputOrigin>,
    key_images: HashSet<[u8; 32]>,
    /// `key_images` in insertion order, for display.
    key_image_log: Vec<[u8; 32]>,
    /// Accepted (non-coinbase) transactions so far.
    txs: usize,
    bp_gens: BulletproofGens,
}

impl Chain {
    pub fn new() -> Self {
        Chain {
            outputs: Vec::new(),
            origins: Vec::new(),
            key_images: HashSet::new(),
            key_image_log: Vec::new(),
            txs: 0,
            bp_gens: BulletproofGens::new(64, 16),
        }
    }

    pub fn origin(&self, idx: usize) -> &OutputOrigin {
        &self.origins[idx]
    }

    /// Key images recorded so far, oldest first.
    pub fn key_images(&self) -> &[[u8; 32]] {
        &self.key_image_log
    }

    pub fn tx_count(&self) -> usize {
        self.txs
    }

    /// Coinbase: mint an output with a public amount (blinding chosen by the
    /// miner but the value is known, as in Monero coinbase txs).
    pub fn mint<R: rand::Rng + rand::CryptoRng>(&mut self, to: &Address, amount: u64, rng: &mut R) -> usize {
        let r = Scalar::random(rng);
        let o = make_output(&r, to, 0, amount);
        self.outputs.push(Output {
            one_time_pk: o.one_time_pk,
            commitment: commit(amount, &o.mask),
            enc_amount: o.enc_amount,
            tx_pubkey: r * G,
            index_in_tx: 0,
        });
        self.origins.push(OutputOrigin::Coinbase { amount });
        self.outputs.len() - 1
    }

    /// Wallet scanning: try our view key against every output.
    pub fn scan(&self, acct: &Account) -> Vec<Owned> {
        let mut mine = Vec::new();
        for (gi, o) in self.outputs.iter().enumerate() {
            if let Some((x, mask, v)) = acct.scan(&o.tx_pubkey, o.index_in_tx, &o.one_time_pk, o.enc_amount) {
                if commit(v, &mask) == o.commitment {
                    mine.push(Owned { global_index: gi, amount: v, mask, one_time_sk: x });
                }
            }
        }
        mine
    }

    pub fn key_image_seen(&self, i: &Point) -> bool {
        self.key_images.contains(&pt(i))
    }

    /// Full node verification, then append outputs and key images.
    pub fn apply(&mut self, tx: &Tx) -> Result<(), TxError> {
        let msg = tx_message(tx);
        let mut pseudo_sum = Point::identity();
        let mut new_images = Vec::new();
        for (k, inp) in tx.inputs.iter().enumerate() {
            if inp.ring.len() != RING_SIZE {
                return Err(TxError::BadRing);
            }
            let ring: Vec<(Point, Point)> = inp.ring.iter().map(|&i| (self.outputs[i].one_time_pk, self.outputs[i].commitment)).collect();
            if !clsag::verify(&msg, &ring, &inp.pseudo_out, &inp.sig) {
                return Err(TxError::RingSignature(k));
            }
            let ki = pt(&inp.sig.key_image);
            if self.key_images.contains(&ki) || new_images.contains(&ki) {
                return Err(TxError::KeyImageSeen(k));
            }
            new_images.push(ki);
            pseudo_sum += inp.pseudo_out;
        }
        let out_sum: Point = tx.outputs.iter().map(|o| o.commitment).sum();
        if pseudo_sum != out_sum + Scalar::from(tx.fee) * h_gen() {
            return Err(TxError::Unbalanced);
        }
        let commitments: Vec<_> = tx.outputs.iter().map(|o| o.commitment.compress()).collect();
        let mut t = Transcript::new(b"zkp5-range");
        if tx.range_proof.verify_multiple(&self.bp_gens, &gens(), &mut t, &commitments, 64).is_err() {
            return Err(TxError::RangeProof);
        }
        // accepted
        for ki in new_images {
            self.key_images.insert(ki);
            self.key_image_log.push(ki);
        }
        for which in 0..tx.outputs.len() {
            self.origins.push(OutputOrigin::TxOutput { tx: self.txs, which });
        }
        self.txs += 1;
        self.outputs.extend(tx.outputs.iter().cloned());
        Ok(())
    }
}

impl Default for Chain {
    fn default() -> Self {
        Self::new()
    }
}

/// What the ring signatures sign: everything in the tx except the signatures.
fn tx_message(tx: &Tx) -> Vec<u8> {
    let mut m = Vec::new();
    for i in &tx.inputs {
        for idx in &i.ring {
            m.extend_from_slice(&(*idx as u64).to_le_bytes());
        }
        m.extend_from_slice(&pt(&i.pseudo_out));
    }
    for o in &tx.outputs {
        m.extend_from_slice(&pt(&o.one_time_pk));
        m.extend_from_slice(&pt(&o.commitment));
        m.extend_from_slice(&o.enc_amount.to_le_bytes());
    }
    m.extend_from_slice(&pt(&tx.tx_pubkey));
    m.extend_from_slice(&tx.fee.to_le_bytes());
    m
}

/// Wallet: spend `inputs` (all ours) to `payments` plus `fee`. Change must be
/// included in `payments` by the caller (as a payment to ourselves).
pub fn build_tx<R: rand::Rng + rand::CryptoRng>(
    chain: &Chain,
    inputs: &[Owned],
    payments: &[(Address, u64)],
    fee: u64,
    rng: &mut R,
) -> Result<Tx, &'static str> {
    let v_in: u64 = inputs.iter().map(|i| i.amount).sum();
    let v_out: u64 = payments.iter().map(|p| p.1).sum();
    if v_in != v_out + fee {
        return Err("inputs ≠ outputs + fee");
    }
    // Bulletproofs aggregate over a power-of-two count; pad with zero-value
    // outputs to ourselves would be the real fix, we just require it here.
    if !payments.len().is_power_of_two() {
        return Err("number of outputs must be a power of two");
    }

    // ---- outputs: stealth keys + commitments ----
    let tx_sk = Scalar::random(rng);
    let tx_pubkey = tx_sk * G;
    let mut outputs = Vec::new();
    let mut out_masks = Vec::new();
    let mut out_values = Vec::new();
    for (i, (addr, v)) in payments.iter().enumerate() {
        let o = make_output(&tx_sk, addr, i as u64, *v);
        outputs.push(Output {
            one_time_pk: o.one_time_pk,
            commitment: commit(*v, &o.mask),
            enc_amount: o.enc_amount,
            tx_pubkey,
            index_in_tx: i as u64,
        });
        out_masks.push(o.mask);
        out_values.push(*v);
    }

    // ---- range proof over all outputs (one aggregated Bulletproof) ----
    let bp_gens = BulletproofGens::new(64, 16);
    let mut t = Transcript::new(b"zkp5-range");
    let (range_proof, _) = RangeProof::prove_multiple(&bp_gens, &gens(), &mut t, &out_values, &out_masks, 64).map_err(|_| "range proof")?;

    // ---- pseudo-outputs: fresh blindings that sum to the outputs' ----
    let out_mask_sum: Scalar = out_masks.iter().sum();
    let mut pseudo_masks: Vec<Scalar> = (0..inputs.len() - 1).map(|_| Scalar::random(rng)).collect();
    let partial: Scalar = pseudo_masks.iter().sum();
    pseudo_masks.push(out_mask_sum - partial); // Σ pseudo = Σ out  ⇒ balance check passes

    // ---- rings + CLSAG per input ----
    let mut tx = Tx { inputs: Vec::new(), outputs, tx_pubkey, fee, range_proof };
    let mut planned = Vec::new();
    for (k, inp) in inputs.iter().enumerate() {
        let ring = pick_ring(chain.outputs.len(), inp.global_index, rng);
        let pseudo_out = commit(inp.amount, &pseudo_masks[k]);
        planned.push((ring, pseudo_out, inp.mask - pseudo_masks[k]));
    }
    // signatures cover the message, which includes rings and pseudo-outs
    for (ring, pseudo_out, _) in &planned {
        tx.inputs.push(Input { ring: ring.clone(), pseudo_out: *pseudo_out, sig: dummy_sig(ring.len()) });
    }
    let msg = tx_message(&tx);
    for (k, inp) in inputs.iter().enumerate() {
        let (ring, pseudo_out, z) = &planned[k];
        let pi = ring.iter().position(|&i| i == inp.global_index).unwrap();
        let members: Vec<(Point, Point)> = ring.iter().map(|&i| (chain.outputs[i].one_time_pk, chain.outputs[i].commitment)).collect();
        tx.inputs[k].sig = clsag::sign(&msg, &members, pseudo_out, pi, &inp.one_time_sk, z, rng);
    }
    Ok(tx)
}

fn dummy_sig(n: usize) -> clsag::Signature {
    clsag::Signature { c0: Scalar::ZERO, s: vec![Scalar::ZERO; n], key_image: Point::identity(), d: Point::identity() }
}

/// Decoy selection. Monero uses a gamma distribution over output age so
/// decoys look like plausible recent spends; uniform is fine for a demo.
fn pick_ring<R: rand::Rng>(n_outputs: usize, real: usize, rng: &mut R) -> Vec<usize> {
    assert!(n_outputs >= RING_SIZE, "not enough outputs on chain for a ring");
    let mut set = HashSet::new();
    set.insert(real);
    while set.len() < RING_SIZE {
        set.insert(rng.gen_range(0..n_outputs));
    }
    let mut ring: Vec<usize> = set.into_iter().collect();
    ring.sort_unstable(); // sorted, so position carries no information
    ring
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pay_and_double_spend() {
        let mut rng = rand::rngs::OsRng;
        let mut chain = Chain::new();
        let alice = Account::new("alice", &mut rng);
        let bob = Account::new("bob", &mut rng);
        for _ in 0..12 {
            chain.mint(&Account::new("x", &mut rng).address(), 7, &mut rng);
        }
        chain.mint(&alice.address(), 10, &mut rng);
        let mine = chain.scan(&alice);
        assert_eq!(mine.len(), 1);
        let tx = build_tx(&chain, &mine, &[(bob.address(), 6), (alice.address(), 3)], 1, &mut rng).unwrap();
        chain.apply(&tx).unwrap();
        assert_eq!(chain.scan(&bob)[0].amount, 6);
        assert_eq!(chain.scan(&alice).iter().map(|o| o.amount).sum::<u64>(), 10 + 3); // old one still scans; key image marks it spent
        let tx2 = build_tx(&chain, &mine, &[(bob.address(), 6), (alice.address(), 3)], 1, &mut rng).unwrap();
        assert!(matches!(chain.apply(&tx2), Err(TxError::KeyImageSeen(0))));
    }

    #[test]
    fn inflation_rejected() {
        let mut rng = rand::rngs::OsRng;
        let mut chain = Chain::new();
        let alice = Account::new("alice", &mut rng);
        for _ in 0..12 {
            chain.mint(&Account::new("x", &mut rng).address(), 7, &mut rng);
        }
        chain.mint(&alice.address(), 10, &mut rng);
        let mut mine = chain.scan(&alice);
        mine[0].amount = 50; // wallet lies about its own amount
        let tx = build_tx(&chain, &mine, &[(alice.address(), 49), (alice.address(), 0)], 1, &mut rng).unwrap();
        // pseudo-out commits to 50 but the ring member commits to 10 → CLSAG fails
        assert!(matches!(chain.apply(&tx), Err(TxError::RingSignature(0))));
    }
}
