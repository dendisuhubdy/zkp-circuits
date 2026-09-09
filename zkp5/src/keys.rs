//! Stealth addresses.
//!
//! A Monero address is two public keys (A, B). The *view* key a lets a
//! wallet recognise incoming outputs; the *spend* key b lets it spend them.
//! Every payment goes to a fresh one-time key that nobody but the recipient
//! can connect to (A, B):
//!
//! ```text
//!   sender:     r ← random,  R = r·G  (published as the "tx public key")
//!               P = Hs(r·A ‖ i)·G + B          ← one-time output key
//!   recipient:  scans every output:  Hs(a·R ‖ i)·G + B == P ?
//!               (works because a·R = a·r·G = r·A — Diffie-Hellman)
//!               if yes, private key of P is  x = Hs(a·R ‖ i) + b
//! ```
//!
//! The chain sees P and R only; P is uniformly random to an outsider.
//! A view-only wallet (a, B) can *find* outputs but not spend them —
//! useful for auditors and exchanges.
//!
//! The same shared secret also encrypts the amount and derives the
//! commitment blinding, so the recipient can open their own commitment.

use crate::{hs, pt, Point, Scalar};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;

#[derive(Clone)]
pub struct Account {
    pub name: String,
    pub view_sk: Scalar,
    pub spend_sk: Scalar,
}

#[derive(Clone, Copy)]
pub struct Address {
    pub view_pk: Point,
    pub spend_pk: Point,
}

/// What the sender computes for one output and what the recipient recovers.
pub struct OutputSecrets {
    pub one_time_pk: Point,
    /// Blinding γ for the amount commitment, derived from the shared secret.
    pub mask: Scalar,
    /// v ⊕ Hs("amount", shared) — the 8-byte "ecdhInfo" field in Monero.
    pub enc_amount: u64,
}

impl Account {
    pub fn new<R: rand::Rng + rand::CryptoRng>(name: &str, rng: &mut R) -> Self {
        Account { name: name.into(), view_sk: Scalar::random(rng), spend_sk: Scalar::random(rng) }
    }

    pub fn address(&self) -> Address {
        Address { view_pk: self.view_sk * G, spend_pk: self.spend_sk * G }
    }

    /// Recipient side. Returns the one-time private key and the opened
    /// amount if this output is ours.
    pub fn scan(&self, tx_pubkey: &Point, index: u64, one_time_pk: &Point, enc_amount: u64) -> Option<(Scalar, Scalar, u64)> {
        let shared = self.view_sk * tx_pubkey; // a·R
        let d = derive(&shared, index);
        let expect = d.scalar * G + self.spend_sk * G;
        if expect != *one_time_pk {
            return None;
        }
        let x = d.scalar + self.spend_sk;
        Some((x, d.mask, enc_amount ^ d.amount_pad))
    }
}

struct Derivation {
    scalar: Scalar,
    mask: Scalar,
    amount_pad: u64,
}

fn derive(shared: &Point, index: u64) -> Derivation {
    let s = pt(shared);
    let i = index.to_le_bytes();
    let pad = hs(b"monero-amount", &[&s, &i]).to_bytes();
    Derivation {
        scalar: hs(b"monero-derivation", &[&s, &i]),
        mask: hs(b"monero-mask", &[&s, &i]),
        amount_pad: u64::from_le_bytes(pad[..8].try_into().unwrap()),
    }
}

/// Sender side: build the one-time key and amount secrets for output `index`.
pub fn make_output(tx_sk: &Scalar, to: &Address, index: u64, amount: u64) -> OutputSecrets {
    let shared = tx_sk * to.view_pk; // r·A
    let d = derive(&shared, index);
    OutputSecrets { one_time_pk: d.scalar * G + to.spend_pk, mask: d.mask, enc_amount: amount ^ d.amount_pad }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipient_finds_and_can_spend_output() {
        let mut rng = rand::rngs::OsRng;
        let bob = Account::new("bob", &mut rng);
        let eve = Account::new("eve", &mut rng);
        let r = Scalar::random(&mut rng);
        let big_r = r * G;
        let out = make_output(&r, &bob.address(), 0, 1234);
        let (x, mask, v) = bob.scan(&big_r, 0, &out.one_time_pk, out.enc_amount).unwrap();
        assert_eq!(v, 1234);
        assert_eq!(mask, out.mask);
        assert_eq!(x * G, out.one_time_pk); // bob holds the private key
        assert!(eve.scan(&big_r, 0, &out.one_time_pk, out.enc_amount).is_none());
    }
}
