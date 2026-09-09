//! Scenario, as a terminal session. Alice and Bob deposit and each get a
//! note string. Alice hands hers to Carol. Carol withdraws using nothing but
//! the note. Then every attack the contract must resist.

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use std::time::Instant;
use zkp6::circuit::WithdrawCircuit;
use zkp6::cli;
use zkp6::viz;
use zkp6::mixer::{setup, Mixer, MixerError, Note};
use zkp6::{Fr, TREE_DEPTH};

fn main() {
    let mut rng = rand::rngs::OsRng;
    println!("zkp6 · Tornado Cash simulation   (denomination 1 ETH, Merkle depth {TREE_DEPTH})");
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_mode(SynthesisMode::Setup);
    WithdrawCircuit::blank().generate_constraints(cs.clone()).unwrap();
    println!("withdraw circuit: {} constraints, 3 public inputs (root, nullifierHash, recipient)", cs.num_constraints());
    let t = Instant::now();
    let (pk, vk) = setup(&mut rng);
    println!("trusted setup: {:?}  (Tornado's was a 1114-participant ceremony in 2020)\n", t.elapsed());

    let mut m = Mixer::new(1, &vk);
    m.fund("alice", 2);
    m.fund("bob", 2);
    viz::print_state(&m);

    // ---- deposits: each prints a note string ----------------------------------
    let note_alice = cli::deposit(&mut m, "alice", &mut rng).unwrap();
    println!();
    let note_bob = cli::deposit(&mut m, "bob", &mut rng).unwrap();
    println!();
    viz::print_state(&m);

    // ---- withdraw with a note ---------------------------------------------------
    println!("── Alice sends her note string to Carol over Signal. Carol has no account here.");
    cli::withdraw(&mut m, &pk, &note_alice, "carol", &mut rng).unwrap();
    println!();
    viz::print_state(&m);

    // ---- attacks, all driven through the same CLI --------------------------------
    println!("── Attacks");
    println!("• Carol tries the same note again");
    let _ = cli::withdraw(&mut m, &pk, &note_alice, "carol", &mut rng);
    println!("\n• Mallory guesses a note (valid format, random contents)");
    let fake = Note::random(&mut rng).to_note_string("eth", 1, 1);
    let _ = cli::withdraw(&mut m, &pk, &fake, "mallory", &mut rng);
    println!("\n• Mallory corrupts one hex digit of Bob's note");
    let mut chars: Vec<char> = note_bob.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'a' { 'b' } else { 'a' };
    let corrupted: String = chars.into_iter().collect();
    let _ = cli::withdraw(&mut m, &pk, &corrupted, "mallory", &mut rng);
    println!("\n• Mallory submits a malformed note");
    match Note::parse("tornado-eth-1-1-0xdeadbeef") {
        Err(e) => println!("$ tornado withdraw --note tornado-eth-1-1-0xdeadbeef\n  parse error: {e}"),
        Ok(_) => unreachable!(),
    }
    println!("\n• Front-running: Mallory copies Carol's pending proof and swaps the recipient");
    m.fund("dave", 1);
    let dave_note = cli::deposit(&mut m, "dave", &mut rng).unwrap();
    let (n, ..) = Note::parse(&dave_note).unwrap();
    let n = Note { leaf_index: Some(m.deposit_events().iter().position(|(_, c)| *c == n.commitment()).unwrap()), ..n };
    let (proof, root, nh) = m.prove_withdraw(&pk, &n, "erin", &mut rng).unwrap();
    println!("  proof built for recipient=erin; Mallory resubmits it with recipient=mallory");
    println!("  → {:?}", m.withdraw(&proof, root, nh, "mallory").unwrap_err());
    println!("  original lands: {:?}", m.withdraw(&proof, root, nh, "erin"));
    let _ = MixerError::TreeFull;
    println!();
    viz::print_state(&m);

    // ---- Bob later ----------------------------------------------------------------
    println!("── Weeks later, Bob withdraws his own note to a fresh account");
    cli::withdraw(&mut m, &pk, &note_bob, "bob-fresh", &mut rng).unwrap();
    println!();
    viz::print_state(&m);
    println!("An observer sees {} deposits and 3 withdrawals and cannot pair them.", m.deposits());
}
