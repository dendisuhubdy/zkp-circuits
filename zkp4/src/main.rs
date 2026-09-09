//! Scenario: Alice shields 10, pays Bob 3 shielded, Bob unshields 2.

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use std::time::Instant;
use zkp4::circuit::TransferCircuit;
use zkp4::ledger::{build_transfer, setup, Ledger, LedgerError};
use zkp4::note::{Note, SpendingKey};
use zkp4::{Fr, TREE_DEPTH};

fn fr(f: &Fr) -> String {
    use ark_ff::{BigInteger, PrimeField};
    let h: String = f.into_bigint().to_bytes_be().iter().map(|b| format!("{b:02x}")).collect();
    format!("0x{}…", &h[..10])
}
fn state(l: &Ledger) {
    let t: Vec<String> = l.transparent.iter().map(|(k, v)| format!("{k}={v}")).collect();
    println!("    transparent: {}   shielded pool total={}   commitments={}", t.join(" "), l.pool, l.notes());
}

fn main() {
    let mut rng = rand::rngs::OsRng;
    println!("zkp4 · Zcash-style shielded pool   (Merkle depth {TREE_DEPTH}, 64-bit values)");
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_mode(SynthesisMode::Setup);
    TransferCircuit::blank().generate_constraints(cs.clone()).unwrap();
    println!("transfer circuit: {} constraints, 5 public inputs (root, nf, cm1, cm2, v_pub)", cs.num_constraints());
    println!("                  vs Tornado's 827: ownership + 2 output commitments + 2×64-bit range checks + balance");
    let t = Instant::now();
    let (pk, vk) = setup(&mut rng);
    println!("setup {:?}\n", t.elapsed());

    let mut l = Ledger::new(&vk);
    let alice = SpendingKey::random(&mut rng);
    let bob = SpendingKey::random(&mut rng);
    println!("── keys");
    println!("    alice sk={} → z-address pk={}", fr(&alice.0), fr(&alice.public_key()));
    println!("    bob   sk={} → z-address pk={}", fr(&bob.0), fr(&bob.public_key()));
    l.mint("alice-t", 10);
    state(&l);

    println!("\n── Alice shields 10 (t → z)");
    let n_alice = Note::new(10, alice.public_key(), &mut rng);
    let idx_alice = l.shield("alice-t", &n_alice).unwrap();
    println!("    on chain: value=10 (public), cm={}  leaf {}", fr(&n_alice.commitment()), idx_alice);
    state(&l);

    println!("\n── Alice pays Bob 3, shielded (z → z). Change 7 back to herself.");
    let to_bob = Note::new(3, bob.public_key(), &mut rng);
    let change = Note::new(7, alice.public_key(), &mut rng);
    let t = Instant::now();
    let tx = build_transfer(&l, &pk, &alice, &n_alice, idx_alice, [to_bob, change], 0, None, &mut rng).unwrap();
    println!("    proof {:?}", t.elapsed());
    println!("    on chain: nf={}  cm_out=[{}, {}]  v_pub=0", fr(&tx.nullifier), fr(&tx.cm_out[0]), fr(&tx.cm_out[1]));
    println!("    ↑ no amounts, no addresses, no link to leaf {idx_alice}. Alice sends Bob (3, ρ, r) off-chain.");
    let [idx_bob, _idx_change] = l.apply(&tx).unwrap();
    state(&l);

    println!("\n── Bob unshields 2 to 'bob-t', keeps 1 shielded (z → z + t)");
    let keep = Note::new(1, bob.public_key(), &mut rng);
    let zero = Note::new(0, bob.public_key(), &mut rng);
    let tx2 = build_transfer(&l, &pk, &bob, &to_bob, idx_bob, [keep, zero], 2, Some("bob-t"), &mut rng).unwrap();
    println!("    on chain: nf={}  v_pub=2 → bob-t", fr(&tx2.nullifier));
    l.apply(&tx2).unwrap();
    state(&l);

    println!("\n── Attacks");
    let r = l.apply(&tx2);
    println!("    replay Bob's tx           → {:?}", r.unwrap_err());
    let o1 = Note::new(6, bob.public_key(), &mut rng);
    let o2 = Note::new(6, alice.public_key(), &mut rng);
    // The next two are prover-side forgeries. The wallet checks its witness
    // before calling Groth16 and refuses; a wallet that skipped the check
    // would emit a proof the ledger rejects as InvalidProof (see build_transfer).
    let bad = build_transfer(&l, &pk, &alice, &change, idx_bob + 1, [o1, o2], 0, None, &mut rng);
    println!("    7 in, 6+6 out (inflate)   → wallet refused: {:?}   (v_in ≠ v1 + v2 + v_pub)", bad.err().unwrap());
    let o1 = Note::new(5, bob.public_key(), &mut rng);
    let o2 = Note::new(2, bob.public_key(), &mut rng);
    let bad = build_transfer(&l, &pk, &bob, &change, idx_bob + 1, [o1, o2], 0, None, &mut rng);
    println!("    Bob spends Alice's change → wallet refused: {:?}   (pk ≠ H(bob.sk))", bad.err().unwrap());
    let bad = build_transfer(&l, &pk, &alice, &n_alice, idx_alice, [to_bob, change], 0, None, &mut rng).unwrap();
    println!("    Alice re-spends note 0    → {:?}", l.apply(&bad).unwrap_err());
    let _ = LedgerError::UnknownRoot;
    println!("\n    Observer's view: 5 commitments, 2 nullifiers, one public unshield of 2. Nothing else.");
}
