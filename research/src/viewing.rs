//! The viewing-key layer: how a note's plaintext travels with its transaction, who can open
//! it, and how an opened row is checked against the chain.
//!
//! Every transfer publishes an [`Envelope`] next to its proof. The envelope carries the
//! created note's plaintext under a fresh per-transaction key, and that key is wrapped twice:
//! once to the receiver's address (ML-KEM-768, so the receiver's *viewing key* — which owns
//! the decapsulation key — can open it) and once under the sender's outgoing viewing key
//! (`ViewingKey::ovk`). Three keys therefore open a transaction, and they are the three
//! scopes of disclosure:
//!
//! | key handed over | who holds it | what it opens |
//! |---|---|---|
//! | `ViewingKey` of a party | the party's wallet | every transaction the party sent or received — its history, nothing else |
//! | `TxKey` of one transaction | sender and receiver | that one transaction |
//! | `SpendKey` | the owner only | never needed to view; needed to prove |
//!
//! Every ciphertext is ChaCha20-Poly1305 with the on-chain commitment `cm_out` as associated
//! data, so an envelope cannot be re-attached to another transaction, and a wrong key fails
//! authentication instead of yielding garbage — which is what makes a scan with one party's
//! key silent about everyone else's transactions.

use crate::ledger::{Ledger, Tx};
use crate::notes::{words_to_bytes, Note, ViewingKey, Word2};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ml_kem::kem::FromSeed;
use ml_kem::{Decapsulate, Encapsulate, KeyExport, MlKem768};
use rand::Rng;

type Dk = ml_kem::ml_kem_768::DecapsulationKey;
type Ek = ml_kem::ml_kem_768::EncapsulationKey;
type KemCt = ml_kem::ml_kem_768::Ciphertext;

/// A party's address as a sender needs it: the note owner field `pk` plus the ML-KEM
/// encapsulation key envelopes are sealed to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address { pub pk: Word2, pub kem_ek: Vec<u8> }

impl ViewingKey {
    fn kem_keys(&self) -> (Dk, Ek) { MlKem768::from_seed(&ml_kem::Seed::from(self.kem_seed())) }
    pub fn address(&self) -> Address {
        let (_, ek) = self.kem_keys();
        Address { pk: self.pk(), kem_ek: ek.to_bytes().to_vec() }
    }
}

/// The per-transaction disclosure key. Handing it over discloses exactly one transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxKey(pub [u8; 32]);
impl TxKey {
    pub fn random() -> Self { let mut k = [0u8; 32]; rand::rng().fill_bytes(&mut k); TxKey(k) }
}

/// What travels with a transaction besides its proof. Nothing in it is checked by the
/// ledger; it exists only so the right keys can open the note later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// ML-KEM-768 ciphertext to the receiver's address.
    pub kem_ct: Vec<u8>,
    /// `TxKey` under the KEM shared secret.
    pub to_receiver: Vec<u8>,
    /// `TxKey` under the sender's `ovk`.
    pub to_sender: Vec<u8>,
    /// The note plaintext under `TxKey`.
    pub body: Vec<u8>,
}

const AAD_RECEIVER: &[u8] = b"rand-envelope-receiver";
const AAD_SENDER: &[u8] = b"rand-envelope-sender";
const AAD_BODY: &[u8] = b"rand-envelope-body";

fn aad(tag: &[u8], cm: Word2) -> Vec<u8> { [tag, &words_to_bytes(&cm)].concat() }

/// Random-nonce ChaCha20-Poly1305; the 12-byte nonce is prepended to the ciphertext.
fn seal(key: &[u8; 32], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let ct = ChaCha20Poly1305::new(&Key::from(*key)).encrypt(&Nonce::from(nonce), Payload { msg: pt, aad }).expect("aead");
    [&nonce[..], &ct].concat()
}
fn open(key: &[u8; 32], aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    if ct.len() < 12 { return None; }
    let nonce: [u8; 12] = ct[..12].try_into().ok()?;
    ChaCha20Poly1305::new(&Key::from(*key)).decrypt(&Nonce::from(nonce), Payload { msg: &ct[12..], aad }).ok()
}

impl Envelope {
    /// Seals `note` (which must be the note whose commitment the transaction publishes) to
    /// `receiver`, with a copy of `tx_key` for `sender`'s viewing key.
    pub fn seal(sender: &ViewingKey, receiver: &Address, note: &Note, tx_key: &TxKey) -> Envelope {
        let cm = note.commitment();
        let ek = Ek::new(&ml_kem::kem::Key::<Ek>::try_from(&receiver.kem_ek[..]).expect("1184-byte encapsulation key")).expect("valid encapsulation key");
        let (kem_ct, ss) = ek.encapsulate_with_rng(&mut rand::rng());
        let ss: [u8; 32] = ss.into();
        Envelope {
            kem_ct: kem_ct.to_vec(),
            to_receiver: seal(&ss, &aad(AAD_RECEIVER, cm), &tx_key.0),
            to_sender: seal(&sender.ovk(), &aad(AAD_SENDER, cm), &tx_key.0),
            body: seal(&tx_key.0, &aad(AAD_BODY, cm), &note.to_bytes()),
        }
    }

    /// Opens the note with the transaction key. `cm` is the on-chain commitment the
    /// envelope was published with.
    pub fn open_with_tx_key(&self, cm: Word2, key: &TxKey) -> Option<Note> {
        let note = Note::from_bytes(&open(&key.0, &aad(AAD_BODY, cm), &self.body)?)?;
        (note.commitment() == cm).then_some(note)
    }
    /// Opens as the receiver: decapsulate, unwrap the transaction key, open the body.
    pub fn open_as_receiver(&self, cm: Word2, vk: &ViewingKey) -> Option<(TxKey, Note)> {
        let (dk, _) = vk.kem_keys();
        let ct = KemCt::try_from(&self.kem_ct[..]).ok()?;
        let ss: [u8; 32] = dk.decapsulate(&ct).into();
        let key = TxKey(open(&ss, &aad(AAD_RECEIVER, cm), &self.to_receiver)?.try_into().ok()?);
        Some((key, self.open_with_tx_key(cm, &key)?))
    }
    /// Opens as the sender, through `ovk`.
    pub fn open_as_sender(&self, cm: Word2, vk: &ViewingKey) -> Option<(TxKey, Note)> {
        let key = TxKey(open(&vk.ovk(), &aad(AAD_SENDER, cm), &self.to_sender)?.try_into().ok()?);
        Some((key, self.open_with_tx_key(cm, &key)?))
    }
}

/// What an auditor is handed. Scope is the type: a party, or one transaction.
#[derive(Clone, Debug)]
pub enum Disclosure {
    Party(ViewingKey),
    Transaction { tx: usize, key: TxKey },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role { Received, Sent, Transaction }

/// One row of disclosed history: the travel-rule fields, and the openings that let anyone
/// holding the same disclosure check the row against the chain (`verify_row`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub tx: usize,
    pub role: Role,
    pub sender: Word2,
    pub receiver: Word2,
    pub amount: u32,
    pub asset: u32,
    pub time: u32,
    /// The created note's on-chain commitment.
    pub cm_out: Word2,
    /// The spent note's commitment and nullifier, as the chain published them (mints have none).
    pub cm_in: Option<Word2>,
    pub nf: Option<Word2>,
    /// The created note, opened.
    pub note: Note,
    /// For a `Sent` row: the note that was spent, opened — the party's own earlier `Received`
    /// note whose commitment is `cm_in`. What lets the nullifier be recomputed.
    pub spent: Option<Note>,
}

impl Row {
    fn new(tx: usize, t: &Tx, role: Role, note: Note, spent: Option<Note>) -> Row {
        Row { tx, role, sender: note.from, receiver: note.pk, amount: note.amount, asset: note.asset, time: note.time, cm_out: t.cm_out, cm_in: t.cm_in, nf: t.nf, note, spent }
    }
}

/// Everything the disclosure opens, in chain order. A party's key yields one `Received` row
/// per note it was paid and one `Sent` row per note it spent; a transaction key yields the
/// one row of that transaction. Nothing else on the chain opens, so nothing else is listed.
pub fn scan(ledger: &Ledger, d: &Disclosure) -> Vec<Row> {
    let mut rows = Vec::new();
    match d {
        Disclosure::Transaction { tx, key } => {
            if let Some(t) = ledger.txs.get(*tx) {
                if let Some(note) = t.envelope.open_with_tx_key(t.cm_out, key) { rows.push(Row::new(*tx, t, Role::Transaction, note, None)); }
            }
        }
        Disclosure::Party(vk) => {
            let mut owned: Vec<Note> = Vec::new();
            for (i, t) in ledger.txs.iter().enumerate() {
                if let Some((_, note)) = t.envelope.open_as_receiver(t.cm_out, vk) {
                    owned.push(note);
                    rows.push(Row::new(i, t, Role::Received, note, None));
                }
                if let Some((_, note)) = t.envelope.open_as_sender(t.cm_out, vk) {
                    let spent = t.cm_in.and_then(|cm| owned.iter().copied().find(|n| n.commitment() == cm));
                    rows.push(Row::new(i, t, Role::Sent, note, spent));
                }
            }
        }
    }
    rows
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowError {
    /// No such transaction on the chain.
    UnknownTx,
    /// The note in the row does not open the transaction's commitment.
    Commitment,
    /// The row's travel-rule fields disagree with the note that commits to them.
    Fields,
    /// The row's time is not the time the chain recorded for the transaction.
    Time,
    /// The row claims the party was sender/receiver but the note does not name the party's address.
    Party,
    /// A `Sent` row whose nullifier or spent commitment does not match the chain.
    Nullifier,
    /// The row's role is not one this disclosure can produce.
    Scope,
}

/// Checks `row` against the chain using nothing but `d` — the same key the row was
/// produced with — so a third party handed the disclosure and the rows can confirm every
/// row independently of whoever produced them.
pub fn verify_row(ledger: &Ledger, d: &Disclosure, row: &Row) -> Result<(), RowError> {
    let t = ledger.txs.get(row.tx).ok_or(RowError::UnknownTx)?;
    let n = &row.note;
    if n.commitment() != t.cm_out || row.cm_out != t.cm_out { return Err(RowError::Commitment); }
    if (row.sender, row.receiver, row.amount, row.asset, row.time) != (n.from, n.pk, n.amount, n.asset, n.time) { return Err(RowError::Fields); }
    if row.time != t.time { return Err(RowError::Time); }
    if row.cm_in != t.cm_in || row.nf != t.nf { return Err(RowError::Nullifier); }
    match (d, row.role) {
        (Disclosure::Transaction { tx, key }, Role::Transaction) => {
            if *tx != row.tx { return Err(RowError::Scope); }
            if t.envelope.open_with_tx_key(t.cm_out, key).as_ref() != Some(n) { return Err(RowError::Commitment); }
        }
        (Disclosure::Party(vk), Role::Received) => {
            if n.pk != vk.pk() { return Err(RowError::Party); }
        }
        (Disclosure::Party(vk), Role::Sent) => {
            if n.from != vk.pk() { return Err(RowError::Party); }
            match (t.cm_in, row.spent) {
                // A mint: created from nothing, so there is no nullifier to check.
                (None, None) => {}
                (Some(cm_in), Some(spent)) => {
                    if spent.pk != vk.pk() { return Err(RowError::Party); }
                    if spent.commitment() != cm_in || Some(vk.nullifier(spent.rho)) != t.nf { return Err(RowError::Nullifier); }
                }
                _ => return Err(RowError::Nullifier),
            }
        }
        _ => return Err(RowError::Scope),
    }
    Ok(())
}
