//! The viewing-key layer end to end: the guest's hash agrees with the native one, a transfer
//! proves and a ledger accepts it, each disclosure scope opens exactly what it should, every
//! row checks against the chain, and a viewing key cannot spend.
use rand_zkvm::arx::{self, domain};
use rand_zkvm::emulator::execute;
use rand_zkvm::guests;
use rand_zkvm::ledger::{Ledger, LedgerError};
use rand_zkvm::machine::{build_traces, FriProfile, Machine, Tier};
use rand_zkvm::notes::{self, Note, SpendKey, ViewingKey};
use rand_zkvm::tables::{cpu, F};
use rand_zkvm::viewing::{scan, verify_row, Disclosure, Envelope, Role, RowError, TxKey};
use p3_field::PrimeCharacteristicRing;
use std::panic::{catch_unwind, AssertUnwindSafe};

#[test]
fn guest_arx_matches_native_arx() {
    for msg in [vec![], vec![1], vec![1, 2, 3, 4], vec![0xdead_beef, 7, 0, 0xffff_ffff, 42], (1..=10).collect::<Vec<u32>>()] {
        let e = execute(&guests::arx_probe(&msg), &[], 1 << 16).unwrap();
        let mut want = [0u32; 4];
        arx::squeeze(domain::TEST, &msg, &mut want);
        assert_eq!(e.outputs[..4], want, "msg {msg:?}");
        assert_eq!(e.outputs[..2], arx::hash(domain::TEST, &msg));
    }
}

#[test]
fn domains_and_lengths_separate() {
    assert_ne!(arx::hash(domain::NK, &[1, 2]), arx::hash(domain::PK, &[1, 2]));
    assert_ne!(arx::hash(domain::CM, &[1, 2, 0]), arx::hash(domain::CM, &[1, 2]), "zero padding must not collide with a shorter message");
    let sk = SpendKey([1, 2]);
    let vk = sk.viewing_key();
    assert_ne!(vk.nk, sk.0);
    assert_ne!(vk.pk(), vk.nk);
    assert_ne!(vk.ovk(), SpendKey([1, 3]).viewing_key().ovk());
}

struct Party { sk: SpendKey, vk: ViewingKey }
impl Party {
    fn new() -> Party { let sk = SpendKey::random(); Party { sk, vk: sk.viewing_key() } }
}

/// The sender side of a transfer: the created note, its envelope and transaction key, and
/// the guest's private inputs.
fn build_transfer(sender: &Party, spent: &Note, receiver: &ViewingKey, now: u32) -> (Note, Envelope, TxKey, [u32; notes::input::COUNT]) {
    let created = Note::new(receiver.pk(), sender.vk.pk(), spent.amount, spent.asset, now);
    let key = TxKey::random();
    let env = Envelope::seal(&sender.vk, &receiver.address(), &created, &key);
    (created, env, key, notes::transfer_inputs(&sender.sk, spent, &created))
}

fn mint(ledger: &mut Ledger, minter: &Party, to: &ViewingKey, amount: u32, asset: u32) -> Note {
    let note = Note::new(to.pk(), minter.vk.pk(), amount, asset, ledger.now);
    let env = Envelope::seal(&minter.vk, &to.address(), &note, &TxKey::random());
    ledger.mint(&note, env).unwrap();
    note
}

#[test]
fn transfer_guest_fits_tier_12_and_computes_the_reference_outputs() {
    let alice = Party::new();
    let bob = Party::new();
    let spent = Note::new(alice.vk.pk(), Party::new().vk.pk(), 500, 1, 1_700_000_000);
    let (created, _, _, inputs) = build_transfer(&alice, &spent, &bob.vk, 1_700_000_060);
    let program = guests::transfer();
    let e = execute(&program, &inputs, 1 << 20).unwrap();
    assert!(e.halted);
    assert_eq!(e.outputs, notes::expected_outputs(&alice.sk, &spent, &created));
    assert!(e.cycles() <= Tier(12).max_cycles(), "{} cycles", e.cycles());
    assert_eq!(Tier::for_cycles(e.cycles()), Some(Tier(12)));
    assert!(program.len() <= 1024, "{} words", program.len());
}

#[test]
fn envelope_opens_for_exactly_the_right_keys() {
    let alice = Party::new();
    let bob = Party::new();
    let carol = Party::new();
    let note = Note::new(bob.vk.pk(), alice.vk.pk(), 5, 1, 10);
    let key = TxKey::random();
    let env = Envelope::seal(&alice.vk, &bob.vk.address(), &note, &key);
    let cm = note.commitment();
    assert_eq!(env.open_with_tx_key(cm, &key), Some(note));
    assert_eq!(env.open_as_receiver(cm, &bob.vk), Some((key, note)));
    assert_eq!(env.open_as_sender(cm, &alice.vk), Some((key, note)));
    assert_eq!(env.open_as_receiver(cm, &alice.vk), None, "the sender is not the receiver");
    assert_eq!(env.open_as_sender(cm, &bob.vk), None);
    assert_eq!(env.open_as_receiver(cm, &carol.vk), None);
    assert_eq!(env.open_as_sender(cm, &carol.vk), None);
    assert_eq!(env.open_with_tx_key(cm, &TxKey::random()), None);
    let other = Note::new(bob.vk.pk(), alice.vk.pk(), 5, 1, 11).commitment();
    assert_eq!(env.open_with_tx_key(other, &key), None, "bound to its own commitment");
    assert_eq!(env.open_as_receiver(other, &bob.vk), None);
}

/// One chain, two transfers, three parties. Everything below that needs a proof shares it.
struct Scenario { ledger: Ledger, alice: Party, bob: Party, carol: Party, bridge: Party, alice_note: Note, alice_key: TxKey, alice_created: Note }

fn scenario() -> Scenario {
    let m = Machine::new(FriProfile::Test);
    let (alice, bob, carol, bridge) = (Party::new(), Party::new(), Party::new(), Party::new());
    let mut ledger = Ledger::new(1_700_000_000);
    let alice_note = mint(&mut ledger, &bridge, &alice.vk, 500, 1);
    let carol_note = mint(&mut ledger, &bridge, &carol.vk, 70, 2);
    ledger.advance(60);
    // Alice → Bob
    let (alice_created, env, alice_key, inputs) = build_transfer(&alice, &alice_note, &bob.vk, ledger.now);
    let (proof, _) = m.prove(&ledger.program, &inputs, None).unwrap();
    assert_eq!(proof.tier, Tier(12));
    let tx = ledger.apply(&m, &proof, env.clone()).unwrap();
    assert_eq!(tx, 2);
    // Replays are refused before the proof is even verified.
    assert!(matches!(ledger.apply(&m, &proof, env), Err(LedgerError::Spent(_))));
    ledger.advance(60);
    // Carol → Bob
    let (_, env, _, inputs) = build_transfer(&carol, &carol_note, &bob.vk, ledger.now);
    let (proof, _) = m.prove(&ledger.program, &inputs, None).unwrap();
    ledger.apply(&m, &proof, env).unwrap();
    Scenario { ledger, alice, bob, carol, bridge, alice_note, alice_key, alice_created }
}

#[test]
fn disclosure_scopes_and_row_verification() {
    let s = scenario();
    let l = &s.ledger;
    assert!(l.has_commitment(&s.alice_created.commitment()));
    assert!(l.has_nullifier(&s.alice.vk.nullifier(s.alice_note.rho)));

    // One party's history: Alice sees the mint she received and the transfer she sent — not Carol's.
    let alice = Disclosure::Party(s.alice.vk);
    let rows = scan(l, &alice);
    assert_eq!(rows.iter().map(|r| (r.tx, r.role)).collect::<Vec<_>>(), vec![(0, Role::Received), (2, Role::Sent)]);
    assert_eq!((rows[1].sender, rows[1].receiver, rows[1].amount, rows[1].asset, rows[1].time), (s.alice.vk.pk(), s.bob.vk.pk(), 500, 1, 1_700_000_060));
    assert_eq!(rows[0].sender, s.bridge.vk.pk());
    assert_eq!(rows[1].spent, Some(s.alice_note), "the spent note is the earlier received one");
    for r in &rows { verify_row(l, &alice, r).unwrap(); }

    // Bob received twice and sent nothing; Carol mirrors Alice; the bridge sees only what it minted.
    let bob = Disclosure::Party(s.bob.vk);
    let rows = scan(l, &bob);
    assert_eq!(rows.iter().map(|r| (r.tx, r.role, r.sender, r.amount)).collect::<Vec<_>>(), vec![(2, Role::Received, s.alice.vk.pk(), 500), (3, Role::Received, s.carol.vk.pk(), 70)]);
    for r in &rows { verify_row(l, &bob, r).unwrap(); }
    let carol = Disclosure::Party(s.carol.vk);
    assert_eq!(scan(l, &carol).iter().map(|r| (r.tx, r.role)).collect::<Vec<_>>(), vec![(1, Role::Received), (3, Role::Sent)]);
    let bridge = Disclosure::Party(s.bridge.vk);
    let rows = scan(l, &bridge);
    assert_eq!(rows.iter().map(|r| (r.tx, r.role, r.spent)).collect::<Vec<_>>(), vec![(0, Role::Sent, None), (1, Role::Sent, None)], "mints are sent from nothing");
    for r in &rows { verify_row(l, &bridge, r).unwrap(); }
    for r in scan(l, &carol) { verify_row(l, &carol, &r).unwrap(); }
    assert!(scan(l, &Disclosure::Party(Party::new().vk)).is_empty(), "a stranger's key opens nothing");

    // One transaction: the key opens tx 2 and only tx 2.
    let one = Disclosure::Transaction { tx: 2, key: s.alice_key };
    let rows = scan(l, &one);
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0].role, rows[0].sender, rows[0].receiver, rows[0].amount, rows[0].asset, rows[0].time), (Role::Transaction, s.alice.vk.pk(), s.bob.vk.pk(), 500, 1, 1_700_000_060));
    assert_eq!(rows[0].nf, l.txs[2].nf);
    verify_row(l, &one, &rows[0]).unwrap();
    assert!(scan(l, &Disclosure::Transaction { tx: 3, key: s.alice_key }).is_empty());

    // Tampered rows fail against the chain, whichever field is touched.
    let honest = scan(l, &alice).remove(1);
    let mut r = honest.clone(); r.amount = 499;
    assert_eq!(verify_row(l, &alice, &r), Err(RowError::Fields));
    let mut r = honest.clone(); r.note.amount = 499; r.amount = 499;
    assert_eq!(verify_row(l, &alice, &r), Err(RowError::Commitment));
    let mut r = honest.clone(); r.receiver = s.carol.vk.pk();
    assert_eq!(verify_row(l, &alice, &r), Err(RowError::Fields));
    let mut r = honest.clone(); r.tx = 3;
    assert_eq!(verify_row(l, &alice, &r), Err(RowError::Commitment));
    let mut r = honest.clone(); r.spent = Some(s.alice_created);
    assert_eq!(verify_row(l, &alice, &r), Err(RowError::Party));
    let mut r = honest.clone(); r.spent = Some(Note { rho: honest.spent.unwrap().rho ^ 1, ..honest.spent.unwrap() });
    assert_eq!(verify_row(l, &alice, &r), Err(RowError::Nullifier));
    // A row from one disclosure does not verify under another scope.
    assert_eq!(verify_row(l, &bob, &honest), Err(RowError::Party));
    assert_eq!(verify_row(l, &one, &honest), Err(RowError::Scope));
}

/// Anything other than a constraint failure or a verify error is not a rejection
/// (`tests/cheating.rs` explains the discipline).
fn rejects(f: impl FnOnce() -> Result<(), rand_zkvm::machine::VerifyError>) -> bool {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => false,
        Ok(Err(_)) => true,
        Err(p) => {
            let msg = p.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| p.downcast_ref::<String>().cloned()).unwrap_or_default();
            msg.contains("constraints not satisfied on row")
        }
    }
}

#[test]
fn a_viewing_key_cannot_spend() {
    let m = Machine::new(FriProfile::Test);
    let (alice, bob, bridge) = (Party::new(), Party::new(), Party::new());
    let mut ledger = Ledger::new(1_700_000_000);
    let note = mint(&mut ledger, &bridge, &alice.vk, 500, 1);
    ledger.advance(1);
    // The thief holds Alice's viewing key and, through it, her note — but not her spend key.
    let thief = Party { sk: SpendKey::random(), vk: alice.vk };
    assert_eq!(scan(&ledger, &Disclosure::Party(thief.vk))[0].note, note);
    let (_, env, _, inputs) = build_transfer(&thief, &note, &bob.vk, ledger.now);
    // The guest derives the address from the spend key it is given, so the run is honest
    // about a different note: its cm_in is not on the chain.
    let e = execute(&ledger.program, &inputs, 1 << 20).unwrap();
    let cm_in = [e.outputs[0], e.outputs[1]];
    assert_ne!(cm_in, note.commitment());
    assert!(!ledger.has_commitment(&cm_in));
    let (proof, _) = m.prove(&ledger.program, &inputs, None).unwrap();
    assert!(matches!(ledger.apply(&m, &proof, env), Err(LedgerError::UnknownCommitment(_))));
    // Claiming Alice's commitment (or her nullifier) as the public value is a constraint failure.
    let real = notes::expected_outputs(&alice.sk, &note, &note);
    for (slot, word) in [(0, real[0]), (1, real[1]), (2, real[2]), (3, real[3])] {
        let mut t = build_traces(&ledger.program, &e, Tier(12)).unwrap();
        t.public_values[cpu::pv::OUT0 + slot] = F::from_u32(word);
        assert!(rejects(|| { let p = m.prove_traces(&ledger.program, &t, Tier(12)); m.verify(&ledger.program, &p) }), "slot {slot}");
    }
}
