//! Scenario: Alice and Bob deposit; Carol withdraws one of the notes; the
//! chain cannot tell whose. Then every attack the contract must resist.

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use ark_serialize::CanonicalSerialize;
use std::time::Instant;
use zkp6::circuit::WithdrawCircuit;
use zkp6::mixer::{setup, Mixer, MixerError, Note};
use zkp6::{Fr, TREE_DEPTH};

fn fr(f: &Fr) -> String {
    use ark_ff::{BigInteger, PrimeField};
    let h: String = f.into_bigint().to_bytes_be().iter().map(|b| format!("{b:02x}")).collect();
    format!("0x{}…", &h[..12])
}

fn balances(m: &Mixer) {
    let parts: Vec<String> = m.balances.iter().map(|(k, v)| format!("{k}={v}")).collect();
    println!("    balances: {}   pool={}   deposits={}", parts.join("  "), m.pool, m.deposits());
}

fn main() {
    let mut rng = rand::rngs::OsRng;
    println!("zkp6 · Tornado Cash simulation   (denomination 1 ETH, Merkle depth {TREE_DEPTH})");

    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_mode(SynthesisMode::Setup); // count constraints from the shape alone, no witness
    WithdrawCircuit::blank().generate_constraints(cs.clone()).unwrap();
    println!("withdraw circuit: {} constraints, 3 public inputs (root, nullifierHash, recipient)", cs.num_constraints());

    let t = Instant::now();
    let (pk, vk) = setup(&mut rng);
    println!("trusted setup: {:?}  (Tornado's was a 1114-participant ceremony in 2020)\n", t.elapsed());

    let mut m = Mixer::new(1, &vk);
    m.fund("alice", 2);
    m.fund("bob", 2);
    println!("── initial state");
    balances(&m);

    // ---- deposits ------------------------------------------------------------
    println!("\n── Alice deposits");
    let mut a = Note::random(&mut rng);
    a.leaf_index = Some(m.deposit("alice", a.commitment()).unwrap());
    println!("    note (kept offline): nullifier={} secret={}", fr(&a.nullifier), fr(&a.secret));
    println!("    on chain: Deposit(commitment={}, leafIndex={})", fr(&a.commitment()), a.leaf_index.unwrap());

    println!("\n── Bob deposits");
    let mut b = Note::random(&mut rng);
    b.leaf_index = Some(m.deposit("bob", b.commitment()).unwrap());
    println!("    on chain: Deposit(commitment={}, leafIndex={})", fr(&b.commitment()), b.leaf_index.unwrap());
    balances(&m);
    println!("    root now {}", fr(&m.root()));

    // ---- withdraw ------------------------------------------------------------
    println!("\n── Alice hands her note to Carol (off-chain). Carol withdraws to 'carol'.");
    let t = Instant::now();
    let (proof, root, nh) = m.prove_withdraw(&pk, &a, "carol", &mut rng).unwrap();
    let mut bytes = Vec::new();
    proof.serialize_compressed(&mut bytes).unwrap();
    println!("    proof built in {:?}, {} bytes", t.elapsed(), bytes.len());
    println!("    on chain: Withdraw(root={}, nullifierHash={}, recipient=carol)", fr(&root), fr(&nh));
    println!("    ↑ nothing here says 'leaf 0' or 'alice'. Anonymity set = {} deposits.", m.deposits());
    println!("\n── Mallory sees the proof in the mempool and resubmits it with her own address");
    let r = m.withdraw(&proof, root, nh, "mallory");
    println!("    front-run, swap recipient → {:?}   (recipient is baked into the proof)", r.unwrap_err());
    println!("\n── Carol's original transaction is mined");
    let t = Instant::now();
    m.withdraw(&proof, root, nh, "carol").unwrap();
    println!("    contract verified in {:?}", t.elapsed());
    balances(&m);

    // ---- attacks -------------------------------------------------------------
    println!("\n── Attacks the contract must reject");
    let r = m.withdraw(&proof, root, nh, "carol");
    println!("    replay same proof         → {:?}", r.unwrap_err());
    let (p2, r2, nh2) = m.prove_withdraw(&pk, &a, "dave", &mut rng).unwrap();
    let r = m.withdraw(&p2, r2, nh2, "dave");
    println!("    spend Alice's note twice  → {:?}   (same nullifierHash)", r.unwrap_err());
    let fake = Note { leaf_index: Some(5), ..Note::random(&mut rng) };
    let r = match m.prove_withdraw(&pk, &fake, "dave", &mut rng) {
        Ok((p, r, n)) => format!("{:?}", m.withdraw(&p, r, n, "dave").unwrap_err()),
        Err(e) => format!("prover refused: {e:?}"),
    };
    println!("    never-deposited note      → {r}");
    let r = m.withdraw(&proof, Fr::from(1234u64), nh, "carol");
    println!("    made-up root              → {:?}", r.unwrap_err());
    let r = m.deposit("alice", Note::random(&mut rng).commitment());
    m.fund("alice", 0);
    println!("    deposit with 1 ETH left   → ok? {}", r.is_ok());
    let r = m.deposit("alice", Note::random(&mut rng).commitment());
    println!("    deposit with 0 ETH left   → {:?}", r.unwrap_err());

    // ---- Bob later -------------------------------------------------------------
    println!("\n── Later, Bob withdraws his own note to a fresh account 'bob2'");
    let (p, r, n) = m.prove_withdraw(&pk, &b, "bob2", &mut rng).unwrap();
    m.withdraw(&p, r, n, "bob2").unwrap();
    balances(&m);
    println!("\n    An observer sees 3 deposits and 2 withdrawals and cannot pair them.");
    let _ = MixerError::TreeFull;
}
