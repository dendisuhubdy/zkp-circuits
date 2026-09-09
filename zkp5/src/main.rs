//! Scenario: a chain with some outputs; Alice pays Bob hiding among 10 decoys.

use std::time::Instant;
use zkp5::keys::Account;
use zkp5::tx::{build_tx, Chain, TxError};
use zkp5::viz::{print_state, render_outputs};
use zkp5::{pt, RING_SIZE};

fn short(b: &[u8; 32]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}…", b[0], b[1], b[2], b[3])
}

fn main() {
    let mut rng = rand::rngs::OsRng;
    println!("zkp5 · Monero-style transactions   (ring size {RING_SIZE}, Ristretto255, CLSAG + Bulletproofs)\n");

    let mut chain = Chain::new();
    let alice = Account::new("alice", &mut rng);
    let bob = Account::new("bob", &mut rng);

    println!("── chain bootstrap: 14 coinbase outputs to strangers, 2 to Alice");
    for _ in 0..14 {
        chain.mint(&Account::new("stranger", &mut rng).address(), 7, &mut rng);
    }
    chain.mint(&alice.address(), 5, &mut rng);
    chain.mint(&alice.address(), 8, &mut rng);
    println!("    {} outputs on chain, each = (one-time key P, commitment C, R, encrypted amount)", chain.outputs.len());
    let o = &chain.outputs[15];
    println!("    e.g. output 15: P={} C={}  — nothing says 'alice' or '8'", short(&pt(&o.one_time_pk)), short(&pt(&o.commitment)));
    print_state(&chain, &[&alice, &bob]);

    println!("\n── Alice's wallet scans the chain with her view key");
    let mine = chain.scan(&alice);
    for o in &mine {
        println!("    found output {} worth {} (recovered the blinding, can open C)", o.global_index, o.amount);
    }
    println!("    Bob's wallet scanning the same chain finds {} outputs", chain.scan(&bob).len());

    println!("\n── Alice pays Bob 3 from her 5-output; change 1 to herself; fee 1");
    let t = Instant::now();
    let tx = build_tx(&chain, &mine[..1], &[(bob.address(), 3), (alice.address(), 1)], 1, &mut rng).unwrap();
    let t_build = t.elapsed();
    println!("    built in {t_build:?}, {} bytes total", tx.size_bytes());
    println!("    on chain:");
    println!("      input  ring = {:?}", tx.inputs[0].ring);
    println!("             key image {}   pseudo-out C' {}", short(&pt(&tx.inputs[0].sig.key_image)), short(&pt(&tx.inputs[0].pseudo_out)));
    println!("             CLSAG {} bytes", tx.inputs[0].sig.size_bytes());
    for (i, o) in tx.outputs.iter().enumerate() {
        println!("      output {i}: P={} C={} enc_amount=0x{:016x}", short(&pt(&o.one_time_pk)), short(&pt(&o.commitment)), o.enc_amount);
    }
    println!("      fee = 1 (public)   range proof {} bytes", tx.range_proof.to_bytes().len());
    println!("    ↑ real input is one of {RING_SIZE} (Alice's is index 14). Amounts hidden. Bob's address hidden.");
    println!("    the ring, as Alice's wallet sees it (the ◀ is known only to her):");
    print!("{}", render_outputs(&chain, "      ", Some(&tx.inputs[0].ring), Some(mine[0].global_index)));

    let t = Instant::now();
    chain.apply(&tx).unwrap();
    println!("    node verified in {:?}: ring sig ✓  key image new ✓  ΣC' = ΣC_out + fee·H ✓  range ✓", t.elapsed());
    print_state(&chain, &[&alice, &bob]);

    println!("\n── Bob scans and finds his payment");
    let bobs = chain.scan(&bob);
    println!("    output {} worth {}", bobs[0].global_index, bobs[0].amount);

    println!("\n── Attacks");
    let r = chain.apply(&tx);
    println!("    replay tx                     → {:?}", r.unwrap_err());
    let tx2 = build_tx(&chain, &mine[..1], &[(bob.address(), 3), (alice.address(), 1)], 1, &mut rng).unwrap();
    println!("    spend same output, new ring   → {:?}   (same key image)", chain.apply(&tx2).unwrap_err());
    let mut lie = mine[1].clone();
    lie.amount = 100;
    let tx3 = build_tx(&chain, &[lie], &[(bob.address(), 99), (alice.address(), 0)], 1, &mut rng).unwrap();
    println!("    claim 8-output is worth 100   → {:?}   (C_real − C' not a commitment to 0)", chain.apply(&tx3).unwrap_err());
    let mut steal = mine[1].clone();
    steal.one_time_sk = zkp5::Scalar::random(&mut rng);
    let tx4 = build_tx(&chain, &[steal], &[(bob.address(), 7), (alice.address(), 0)], 1, &mut rng).unwrap();
    println!("    sign without the one-time key → {:?}", chain.apply(&tx4).unwrap_err());
    let mut tx5 = build_tx(&chain, &mine[1..2], &[(bob.address(), 7), (alice.address(), 0)], 1, &mut rng).unwrap();
    tx5.fee = 0; // try to keep the fee: outputs 7 + fee 0 ≠ pseudo-out 8
    println!("    edit fee after signing        → {:?}   (fee is inside the signed message)", chain.apply(&tx5).unwrap_err());
    let _ = (TxError::RangeProof, TxError::BadRing);

    println!("\n── Honest spend of the 8-output: 7 to Bob, fee 1");
    let tx6 = build_tx(&chain, &mine[1..2], &[(bob.address(), 7), (alice.address(), 0)], 1, &mut rng).unwrap();
    chain.apply(&tx6).unwrap();
    println!("    Bob now owns {} shielded", chain.scan(&bob).iter().map(|o| o.amount).sum::<u64>());
    print_state(&chain, &[&alice, &bob]);
    println!("    Observer: {} outputs, 2 key images, two rings of {RING_SIZE}. No amounts, no addresses.", chain.outputs.len());
}
