//! The viewing-key layer end to end: NOTE_COMMIT/NULLIFY/MERKLE_VERIFY agree with their host
//! references, a transfer proves in-circuit membership and a ledger accepts it, each
//! disclosure scope opens exactly what it should, every row checks against the chain, a
//! viewing key cannot spend, and the cheating cases (a wrong Merkle witness, a stale anchor, a
//! forged output digest) are all rejected.
use rand_zkvm::emulator::execute;
use rand_zkvm::guests;
use rand_zkvm::ledger::{CommitmentTree, Ledger, LedgerError};
use rand_zkvm::machine::{build_traces, FriProfile, Machine, Tier};
use rand_zkvm::notes::{self, domain, output_digest, Note, SpendKey, ViewingKey, Word8, DEPTH};
use rand_zkvm::tables::{cpu, F};
use rand_zkvm::viewing::{scan, verify_row, Disclosure, Envelope, Role, RowError, TxKey};
use p3_field::PrimeCharacteristicRing;
use std::panic::{catch_unwind, AssertUnwindSafe};

#[test]
fn domains_and_lengths_separate() {
    assert_ne!(notes::hash(domain::NK, &[1, 2]), notes::hash(domain::PK, &[1, 2]), "different domains separate");
    assert_ne!(notes::hash(domain::CM, &[1, 2]), notes::hash(domain::CM, &[1, 3]), "different messages separate");
    // NOT a collision to guard against: a padding-free sponge starting from an all-zero state
    // cannot distinguish a message from itself with extra zero words appended *within the same
    // rate block* — the overwritten lane and the lane's untouched initial value are both zero
    // either way. This is `PaddingFreeSponge`'s (`hash.rs`) documented behavior, exactly what
    // the `POSEIDON2` chip proves, not a defect introduced here (the M1.5 `Arx8` hash avoided
    // it by baking the message length into its capacity, which this domain-tagged sponge does
    // not). It is not a soundness gap for this crate: every domain's message length is fixed
    // by the call site (`Note::WORDS`, `nk`/`cm`'s 8 words, ...), never attacker-chosen, so no
    // real message this crate hashes can be reinterpreted as a shorter or longer one.
    assert_eq!(notes::hash(domain::CM, &[1, 2, 0]), notes::hash(domain::CM, &[1, 2]), "documented same-block zero-padding property, not a bug");
    let sk = SpendKey([1, 2]);
    let vk = sk.viewing_key();
    assert_ne!(vk.nk[..2], sk.0, "the viewing key is not the spend key, even in its low words");
    assert_ne!(vk.pk(), vk.nk);
    assert_ne!(vk.ovk(), SpendKey([1, 3]).viewing_key().ovk());
}

/// M3.3 widths: every key/commitment/nullifier/tree-node hash is `Word8` (8 machine words);
/// `SpendKey` alone stays two words (nothing hashes it in-circuit except `H_NK`).
#[test]
fn digest_widths_are_eight_words() {
    let sk = SpendKey::random();
    let vk = sk.viewing_key();
    assert_eq!(sk.0.len(), 2);
    assert_eq!(vk.nk.len(), 8);
    assert_eq!(vk.pk().len(), 8);
    let note = Note::new(vk.pk(), vk.pk(), 1, 1, 0);
    assert_eq!(note.commitment().len(), 8);
    assert_eq!(vk.nullifier(&note.commitment()).len(), 8);
    assert_eq!(notes::hash(domain::NODE, &[0u32; 16]).len(), 8);
    assert_eq!(output_digest(&[0; 8], &[0; 8], &[0; 8], 0).len(), 8);
}

/// Bound to the commitment, not a sender-chosen nonce: changing `cm` (holding `nk` fixed)
/// always changes `nf`, and changing `nk` (holding `cm` fixed) always changes `nf` too.
#[test]
fn nullifier_is_bound_to_the_commitment() {
    let vk = SpendKey::random().viewing_key();
    let other_vk = SpendKey::random().viewing_key();
    let cm1 = Note::new(vk.pk(), vk.pk(), 1, 1, 0).commitment();
    let cm2 = Note::new(vk.pk(), vk.pk(), 2, 1, 0).commitment();
    assert_ne!(cm1, cm2);
    assert_ne!(vk.nullifier(&cm1), vk.nullifier(&cm2), "same key, different commitment");
    assert_ne!(vk.nullifier(&cm1), other_vk.nullifier(&cm1), "same commitment, different key");
}

/// `NOTE_COMMIT` (the guest routine `guests::note_commit_probe` wraps) against the host
/// reference `notes::hash(domain::CM, ..)`.
#[test]
fn note_commit_matches_the_host_reference() {
    let msg: [u32; Note::WORDS] = std::array::from_fn(|i| i as u32 + 1);
    let e = execute(&guests::note_commit_probe(&msg), &[], 1 << 16).unwrap();
    assert_eq!(e.outputs[..8], notes::hash(domain::CM, &msg));
}

/// `MERKLE_VERIFY` (`guests::merkle_probe`) against a host-side `CommitmentTree`: build a
/// small tree, take one leaf's path/index, and check the guest's computed root equals
/// `CommitmentTree::root()`.
#[test]
fn merkle_verify_matches_a_host_side_tree() {
    let mut tree = CommitmentTree::new();
    let leaves: Vec<Word8> = (0..5u32).map(|i| notes::hash(domain::TEST, &[i])).collect();
    for cm in &leaves { tree.append(*cm); }
    for (i, leaf) in leaves.iter().enumerate() {
        let path = tree.path(i);
        let e = execute(&guests::merkle_probe(*leaf, &path, i as u32), &[], 1 << 20).unwrap();
        assert_eq!(e.outputs[..8], tree.root(), "leaf {i}");
    }
}

struct Party { sk: SpendKey, vk: ViewingKey }
impl Party {
    fn new() -> Party { let sk = SpendKey::random(); Party { sk, vk: sk.viewing_key() } }
}

/// The sender side of a transfer: the created note, its envelope and transaction key, the
/// guest's private inputs (including the spent note's current Merkle witness), and the
/// `(anchor, nf)` pair the guest's output-commitment digest attests to.
fn build_transfer(sender: &Party, spent: &Note, receiver: &ViewingKey, now: u32, ledger: &Ledger) -> (Note, Envelope, TxKey, [u32; notes::input::COUNT], Word8, Word8) {
    let created = Note::new(receiver.pk(), sender.vk.pk(), spent.amount, spent.asset, now);
    let key = TxKey::random();
    let env = Envelope::seal(&sender.vk, &receiver.address(), &created, &key);
    let (path, index) = ledger.path_for(&spent.commitment()).expect("spent note must already be in the tree");
    let anchor = ledger.root();
    let inputs = notes::transfer_inputs(&sender.sk, spent, &created, &path, index);
    let nf = sender.vk.nullifier(&spent.commitment());
    (created, env, key, inputs, anchor, nf)
}

fn mint(ledger: &mut Ledger, minter: &Party, to: &ViewingKey, amount: u32, asset: u32) -> Note {
    let note = Note::new(to.pk(), minter.vk.pk(), amount, asset, ledger.now);
    let env = Envelope::seal(&minter.vk, &to.address(), &note, &TxKey::random());
    ledger.mint(&note, env).unwrap();
    note
}

#[test]
fn transfer_guest_proves_membership_and_computes_the_reference_outputs() {
    let alice = Party::new();
    let bob = Party::new();
    let bridge = Party::new();
    let mut ledger = Ledger::new(1_700_000_000);
    let spent = mint(&mut ledger, &bridge, &alice.vk, 500, 1);
    ledger.advance(60);
    let (created, _, _, inputs, anchor, nf) = build_transfer(&alice, &spent, &bob.vk, ledger.now, &ledger);
    let program = guests::transfer();
    let e = execute(&program, &inputs, 1 << 22).unwrap();
    assert!(e.halted);
    assert_eq!(e.outputs, notes::expected_outputs(&alice.sk, &spent, &created, anchor));
    // The guest's own root computation agrees with the tree's actual root and the nullifier
    // agrees with the host reference (both folded into the one published digest, but checked
    // separately here so a future regression in either can't cancel the other out).
    assert_eq!(anchor, ledger.root());
    assert_eq!(nf, alice.vk.nullifier(&spent.commitment()));
}

/// M3.3's measured cost (`docs/06-viewing-keys.md`'s cost table): 190 Poseidon2 permutations
/// (5 non-Merkle hash calls at `Word8` widths plus 32 Merkle levels at 5 permutations each
/// plus the 7-permutation output-commitment digest) and 3 764 cycles, both within tier 12
/// (4 095 max cycles; `poseidon2_height` bumped to `2^13` = 256 slots so 190 permutations
/// fit — `machine::Tier::poseidon2_height`). Pinned so a future change to the guest or the
/// hash is caught here rather than surfacing as a mysterious `NoTier`/`TooManyCycles`.
#[test]
fn transfer_guest_permutation_and_row_counts_are_measured() {
    let alice = Party::new();
    let bob = Party::new();
    let bridge = Party::new();
    let mut ledger = Ledger::new(1_700_000_000);
    let spent = mint(&mut ledger, &bridge, &alice.vk, 500, 1);
    ledger.advance(60);
    let (_, _, _, inputs, _, _) = build_transfer(&alice, &spent, &bob.vk, ledger.now, &ledger);
    let program = guests::transfer();
    let e = execute(&program, &inputs, 1 << 22).unwrap();
    assert!(e.halted);
    let permutations = e.events.iter().filter(|ev| matches!(ev.hash_row, Some(rand_zkvm::emulator::HashRow::Absorb { .. }))).count();
    let hash_calls = e.events.iter().filter(|ev| matches!(ev.hash_row, Some(rand_zkvm::emulator::HashRow::Ecall { .. }))).count();
    assert_eq!(hash_calls, 5 + DEPTH + 1, "5 note/key/nullifier hashes + 32 Merkle levels + 1 output digest");
    assert_eq!(permutations, 190);
    assert_eq!(e.cycles(), 3764);
    assert_eq!(Tier::for_cycles(e.cycles()), Some(Tier(12)));
    assert!(e.cycles() <= Tier(12).max_cycles());
    assert!(permutations <= Tier(12).poseidon2_height() / 32, "must fit the tier's permutation slots, not just its cycle budget");
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
    let (alice_created, env, alice_key, inputs, anchor, nf) = build_transfer(&alice, &alice_note, &bob.vk, ledger.now, &ledger);
    let (proof, _) = m.prove(&ledger.program, &inputs, None).unwrap();
    assert_eq!(proof.tier, Tier(12));
    let (cm_out, time) = (alice_created.commitment(), alice_created.time);
    let tx = ledger.apply(&m, &proof, anchor, nf, cm_out, time, env.clone()).unwrap();
    assert_eq!(tx, 2);
    // Replays are refused before the proof is even verified.
    assert!(matches!(ledger.apply(&m, &proof, anchor, nf, cm_out, time, env), Err(LedgerError::Spent(_))));
    ledger.advance(60);
    // Carol → Bob
    let (carol_created, env, _, inputs, anchor, nf) = build_transfer(&carol, &carol_note, &bob.vk, ledger.now, &ledger);
    let (proof, _) = m.prove(&ledger.program, &inputs, None).unwrap();
    ledger.apply(&m, &proof, anchor, nf, carol_created.commitment(), carol_created.time, env).unwrap();
    Scenario { ledger, alice, bob, carol, bridge, alice_note, alice_key, alice_created }
}

#[test]
fn disclosure_scopes_and_row_verification() {
    let s = scenario();
    let l = &s.ledger;
    assert!(l.has_commitment(&s.alice_created.commitment()));
    assert!(l.has_nullifier(&s.alice.vk.nullifier(&s.alice_note.commitment())));

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
    let mut r = honest.clone(); r.spent = Some(Note { r: { let mut r = honest.spent.unwrap().r; r[0] ^= 1; r }, ..honest.spent.unwrap() });
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
    let (steal, env, _, inputs, anchor, _) = build_transfer(&thief, &note, &bob.vk, ledger.now, &ledger);
    // The guest derives the address from the spend key it is given, so the leaf it feeds
    // MERKLE_VERIFY is not Alice's real `cm_in`: its root (and therefore the whole published
    // digest) does not match anything an honest witness for this anchor would produce.
    let e = execute(&ledger.program, &inputs, 1 << 22).unwrap();
    assert!(e.halted);
    assert_ne!(e.outputs, notes::expected_outputs(&alice.sk, &note, &steal, anchor));
    let (proof, _) = m.prove(&ledger.program, &inputs, None).unwrap();
    // Whatever plaintext (anchor, nf, cm_out, time) the thief tries to hand `apply`, it cannot
    // match the digest the proof actually attests to (the thief does not know the real `nk`,
    // so cannot even compute the honest `nf`) — a structural rejection, not a STARK failure.
    let guess_nf = thief.vk.nullifier(&note.commitment());
    assert!(matches!(ledger.apply(&m, &proof, anchor, guess_nf, steal.commitment(), steal.time, env), Err(LedgerError::BadDigest)));

    // Claiming the *real* digest as the public value (rather than whatever the witness
    // actually computed) is a constraint failure: the write-back rows pin `MEM_VAL` to what
    // the emulator put in RAM, and the public-value columns are pinned to that.
    let real = notes::expected_outputs(&alice.sk, &note, &note, anchor);
    let mut t = build_traces(&ledger.program, &e, Tier(12)).unwrap();
    t.public_values[cpu::pv::OUT0] = F::from_u32(real[0]);
    assert!(rejects(|| { let p = m.prove_traces(&ledger.program, &t, Tier(12)); m.verify(&ledger.program, &p) }));
}

/// A wrong Merkle witness (a tampered sibling) makes the guest honestly compute a different
/// root — it is not "cheating" from the circuit's point of view, so the proof itself verifies.
/// What rejects it is `Ledger::apply`'s anchor check: the computed root is not a recorded tree
/// root, so it cannot be a recent one either. `LedgerError`, not a STARK failure.
#[test]
fn a_transfer_with_a_wrong_merkle_path_is_rejected() {
    let m = Machine::new(FriProfile::Test);
    let (alice, bob, bridge) = (Party::new(), Party::new(), Party::new());
    let mut ledger = Ledger::new(1_700_000_000);
    let note = mint(&mut ledger, &bridge, &alice.vk, 500, 1);
    ledger.advance(1);
    let created = Note::new(bob.vk.pk(), alice.vk.pk(), note.amount, note.asset, ledger.now);
    let env = Envelope::seal(&alice.vk, &bob.vk.address(), &created, &TxKey::random());
    let (path, index) = ledger.path_for(&note.commitment()).unwrap();
    let mut bad_path = path;
    bad_path[0][0] ^= 1; // tamper the leaf's immediate sibling
    let inputs = notes::transfer_inputs(&alice.sk, &note, &created, &bad_path, index);
    let e = execute(&ledger.program, &inputs, 1 << 22).unwrap();
    assert!(e.halted);
    let (proof, _) = m.prove(&ledger.program, &inputs, None).unwrap();
    // The STARK itself verifies fine — the guest faithfully computed *a* root, just not the
    // real one.
    assert!(m.verify(&ledger.program, &proof).is_ok());
    // Recompute what the guest actually derived so `apply` is handed a self-consistent
    // (anchor, nf, cm_out, time) — the tampered witness's own honest outputs, which is exactly
    // what a real submitter would (have to) supply alongside this proof.
    let bad_anchor = {
        let mut running = note.commitment();
        for (level, sib) in bad_path.iter().enumerate() {
            let bit = (index >> level) & 1;
            let mut msg = [0u32; 16];
            if bit == 0 { msg[..8].copy_from_slice(&running); msg[8..].copy_from_slice(sib); } else { msg[..8].copy_from_slice(sib); msg[8..].copy_from_slice(&running); }
            running = notes::hash(domain::NODE, &msg);
        }
        running
    };
    assert_ne!(bad_anchor, ledger.root());
    let nf = alice.vk.nullifier(&note.commitment());
    assert!(matches!(ledger.apply(&m, &proof, bad_anchor, nf, created.commitment(), created.time, env), Err(LedgerError::UnknownAnchor(_))));
}

/// A proof built against a once-valid root that has since scrolled out of the ledger's
/// recent-roots window is rejected — even though the proof is perfectly valid math (Merkle
/// membership against *that* root is true forever), and even though nothing else about the
/// transaction is wrong.
#[test]
fn a_stale_anchor_is_rejected_by_the_ledger() {
    let m = Machine::new(FriProfile::Test);
    let (alice, bob, bridge) = (Party::new(), Party::new(), Party::new());
    let mut ledger = Ledger::new(1_700_000_000);
    let note = mint(&mut ledger, &bridge, &alice.vk, 500, 1);
    ledger.advance(1);
    // Capture the witness and anchor now, while the note's tree position is still current.
    let (created, env, _, inputs, anchor, nf) = build_transfer(&alice, &note, &bob.vk, ledger.now, &ledger);
    let (proof, _) = m.prove(&ledger.program, &inputs, None).unwrap();
    assert!(m.verify(&ledger.program, &proof).is_ok(), "the proof is valid math regardless of what the ledger does next");
    // Push the tree far enough that `anchor` falls out of the 16-entry recent-roots window
    // (one root recorded per mint).
    for _ in 0..20 {
        let filler = Party::new();
        mint(&mut ledger, &bridge, &filler.vk, 1, 9);
    }
    assert_ne!(ledger.root(), anchor);
    assert!(matches!(ledger.apply(&m, &proof, anchor, nf, created.commitment(), created.time, env), Err(LedgerError::UnknownAnchor(a)) if a == anchor));
}
