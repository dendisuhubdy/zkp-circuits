//! `cargo run --release` — the Rand reference zkVM, narrated end to end.
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;
use rand_zkvm::emulator::execute;
use rand_zkvm::guests;
use rand_zkvm::isa::Instr;
use rand_zkvm::machine::{build_traces, FriProfile, Machine, Tier, TIERS};
use rand_zkvm::tables::{alu, cpu, memory, nibble, program, range, F};
use std::time::Instant;

fn hr(title: &str) { println!("\n══ {title} {}", "═".repeat(70usize.saturating_sub(title.len()))); }

fn main() {
    hr("Part 1 · What R_exec proves");
    println!("A confidential call is: code hash hc (public), private inputs and state (witness),");
    println!("public outputs (8 words). The verifier learns only hc, the gas tier, and the outputs.");
    println!("Everything else — registers, memory, branches, the number of cycles — stays hidden.");

    hr("Part 2 · The guest: a confidential balance check");
    let threshold = 1000;
    let program = guests::balance_check(threshold);
    let inputs = [400u32, 250, 300, 75];
    println!("{} instructions at pc 0. It reads four private balances, sums them, and outputs", program.len());
    println!("1 if the sum ≥ {threshold}, else 0. Listing:");
    for (i, w) in program.words.iter().enumerate() {
        println!("  {:>4x}: {:08x}  {:?}", program.pc_of(i), w, Instr::decode(*w).unwrap());
    }

    hr("Part 3 · Execute (prover side; nothing here is visible to the chain)");
    let t = Instant::now();
    let exec = execute(&program, &inputs, 1 << 20).unwrap();
    println!("inputs {:?} → outputs {:?} in {} cycles ({:?})", inputs, &exec.outputs[..2], exec.cycles(), t.elapsed());

    hr("Part 4 · Arithmetize: six tables on eight buses");
    let tier = Tier::for_cycles(exec.cycles()).unwrap();
    let traces = build_traces(&program, &exec, tier).unwrap();
    println!("tier {} → cpu 2^{} rows (actual {} cycles), padding hides the rest", tier.0, tier.0, exec.cycles());
    println!("{:<10}{:>10}{:>8}   {}", "table", "rows", "cols", "role");
    for (name, h, w, role) in [
        ("program", traces.program.height(), program::col::WIDTH + program::pre::WIDTH, "preprocessed ROM; its commitment is hc"),
        ("cpu", traces.cpu.height(), cpu::col::WIDTH, "one row per cycle; fetch, decode selectors, pc"),
        ("memory", traces.memory.height(), memory::col::WIDTH, "registers + RAM sorted by (addr, ts)"),
        ("alu", traces.alu.height(), alu::col::WIDTH, "byte-limb arithmetic, shifts, compares"),
        ("range", traces.range.height(), range::col::WIDTH + range::pre::WIDTH, "256 rows: byte range checks, pow2"),
        ("nibble", traces.nibble.height(), nibble::col::WIDTH + nibble::pre::WIDTH, "256 rows: 16×16 and/or/xor"),
    ] { println!("{name:<10}{h:>10}{w:>8}   {role}"); }
    println!("buses: PROGRAM MEMORY ALU RANGE8 AND4 OR4 XOR4 POW2 (LogUp, verified globally)");

    hr("Part 5 · Prove and verify (production FRI: blowup 8, 27 queries, 20 PoW bits, ZK on)");
    let m = Machine::new(FriProfile::Production);
    let hc = m.code_hash(&program, tier);
    println!("hc = {hc}");
    let t = Instant::now();
    let proof = m.prove_traces(&program, &traces, tier);
    let prove_ms = t.elapsed().as_millis();
    println!("proof: {} bytes in {} ms", proof.size(), prove_ms);
    let t = Instant::now();
    m.verify(&program, &proof).unwrap();
    let verify_ms = t.elapsed().as_micros() as f64 / 1000.0;
    println!("verified in {verify_ms:.1} ms with public values {:?}", proof.public_values);

    hr("Part 6 · Cheating provers");
    let mut bad = build_traces(&program, &exec, tier).unwrap();
    bad.public_values[cpu::pv::OUT0] = F::from_u32(0);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { let p = m.prove_traces(&program, &bad, tier); m.verify(&program, &p) }));
    println!("claim output 0 instead of 1        → {}", if matches!(r, Ok(Ok(()))) { "ACCEPTED (bug)" } else { "rejected" });
    let other = guests::balance_check(threshold + 1);
    println!("verify against a different program → {}", if m.verify(&other, &proof).is_ok() { "ACCEPTED (bug)" } else { "rejected" });

    hr("Part 7 · Zero knowledge and tier padding");
    let (p1, _) = m.prove(&program, &inputs, None).unwrap();
    let (p2, _) = m.prove(&program, &[1000, 0, 0, 0], None).unwrap();
    println!("same output, different private inputs: public values equal = {}, proof bytes equal = {}", p1.public_values == p2.public_values, p1.to_bytes() == p2.to_bytes());
    let (p3, _) = m.prove(&program, &inputs, Some(Tier(12))).unwrap();
    println!("same run at tier 12: {} bytes (tier 10: {} bytes) — size reveals the tier, never the cycle count", p3.size(), p1.size());

    hr("Part 8 · Summary");
    let mt = Machine::new(FriProfile::Test);
    let t = Instant::now(); let pt = mt.prove_traces(&program, &traces, tier); let test_ms = t.elapsed().as_millis();
    println!("{:<28}{:>14}{:>14}", "", "production", "test profile");
    println!("{:<28}{:>14}{:>14}", "FRI queries / PoW bits", "80 / 20", "16 / 4");
    println!("{:<28}{:>14}{:>14}", "prove (ms)", prove_ms, test_ms);
    println!("{:<28}{:>14}{:>14}", "proof size (bytes)", proof.size(), pt.size());
    println!("{:<28}{:>14.1}", "verify (ms)", verify_ms);
    println!("field Goldilocks · challenge F_p² · hash Poseidon2 · blowup 8 · ZK hiding FRI · tiers {TIERS:?}");
    println!("\nRead docs/02-tables-and-buses.md for the constraint list, docs/03-privacy.md for what leaks.");
    for (name, p, inp) in guests::all() {
        let (pr, ex) = m.prove(&p, &inp, None).unwrap();
        m.verify(&p, &pr).unwrap();
        println!("{name:<16} cycles {:>6} tier {:>2} proof {:>7} B", ex.cycles(), pr.tier.0, pr.size());
    }

    part9_viewing_keys();
}

fn hex2(w: [u32; 2]) -> String { format!("{:08x}{:08x}", w[0], w[1]) }

/// A shielded transfer, its envelope, and the three ways to look at it. Runs at the test FRI
/// profile so the two tier-12 proofs take seconds; the mechanism is identical at production.
fn part9_viewing_keys() {
    use rand_zkvm::ledger::{Ledger, LedgerError};
    use rand_zkvm::notes::{self, Note, SpendKey};
    use rand_zkvm::viewing::{scan, verify_row, Disclosure, Envelope, Role, TxKey};

    hr("Part 9 · Viewing keys: see a shielded transfer without being able to make one");
    let m = Machine::new(FriProfile::Test);
    let mut ledger = Ledger::new(1_700_000_000);
    println!("transfer guest: {} instructions, hc = {}…", ledger.program.len(), &m.code_hash(&ledger.program, Tier(12))[..16]);
    let (alice_sk, bob_sk, bridge_sk) = (SpendKey::random(), SpendKey::random(), SpendKey::random());
    let (alice, bob, bridge) = (alice_sk.viewing_key(), bob_sk.viewing_key(), bridge_sk.viewing_key());
    println!("alice: sk (secret) → nk = viewing key {} → pk = address {}", hex2(alice.nk), hex2(alice.pk()));
    println!("bob:   address {}, plus a {}-byte ML-KEM-768 encapsulation key", hex2(bob.pk()), bob.address().kem_ek.len());

    // A bridge mint pays Alice 500 of asset 1.
    let alice_note = Note::new(alice.pk(), bridge.pk(), 500, 1, ledger.now);
    ledger.mint(&alice_note, Envelope::seal(&bridge, &alice.address(), &alice_note, &TxKey::random())).unwrap();
    println!("tx 0: bridge mints 500 of asset 1 to alice — chain sees cm_out = {}", hex2(alice_note.commitment()));
    ledger.advance(60);

    // Alice → Bob. The guest derives Alice's address from her spend key and recomputes cm_in, nf, cm_out.
    let created = Note::new(bob.pk(), alice.pk(), 500, 1, ledger.now);
    let tx_key = TxKey::random();
    let envelope = Envelope::seal(&alice, &bob.address(), &created, &tx_key);
    let inputs = notes::transfer_inputs(&alice_sk, &alice_note, &created);
    let t = Instant::now();
    let (proof, exec) = m.prove(&ledger.program, &inputs, None).unwrap();
    println!("alice → bob: {} cycles, tier {}, proof {} B in {:?}; envelope {} B", exec.cycles(), proof.tier.0, proof.size(), t.elapsed(), envelope.kem_ct.len() + envelope.to_receiver.len() + envelope.to_sender.len() + envelope.body.len());
    let tx = ledger.apply(&m, &proof, envelope.clone()).unwrap();
    let t1 = &ledger.txs[tx];
    println!("tx {tx}: chain sees cm_in = {} nf = {} cm_out = {} time = {}", hex2(t1.cm_in.unwrap()), hex2(t1.nf.unwrap()), hex2(t1.cm_out), t1.time);
    println!("        and nothing else: sender, receiver, amount, asset are inside the envelope");
    println!("replay → {}", match ledger.apply(&m, &proof, envelope) { Err(LedgerError::Spent(_)) => "rejected (nullifier seen), before any STARK verification", _ => "ACCEPTED (bug)" });

    let show = |title: &str, d: &Disclosure| {
        let rows = scan(&ledger, d);
        println!("{title}: {} row(s)", rows.len());
        for r in &rows {
            let role = match r.role { Role::Received => "received", Role::Sent => "sent    ", Role::Transaction => "tx      " };
            println!("  tx {} {role}  from {} to {}  amount {} asset {} time {}  → verify_row: {:?}", r.tx, hex2(r.sender), hex2(r.receiver), r.amount, r.asset, r.time, verify_row(&ledger, d, r).map(|_| "ok"));
        }
        rows
    };
    let alice_rows = show("alice's viewing key (her history)", &Disclosure::Party(alice));
    show("bob's viewing key (his history)", &Disclosure::Party(bob));
    show("the bridge's viewing key", &Disclosure::Party(bridge));
    show("a stranger's viewing key", &Disclosure::Party(SpendKey::random().viewing_key()));
    show(&format!("the transaction key of tx {tx} alone"), &Disclosure::Transaction { tx, key: tx_key });
    let mut forged = alice_rows[1].clone();
    forged.amount = 5;
    println!("alice's sent row with amount changed to 5 → verify_row: {:?}", verify_row(&ledger, &Disclosure::Party(alice), &forged));

    // The viewing key cannot spend.
    ledger.advance(60);
    let thief = SpendKey::random();
    let spent = alice_rows[0].note; // her received note, as her own scan found it
    let steal = Note::new(bob.pk(), alice.pk(), spent.amount, spent.asset, ledger.now);
    let inputs = notes::transfer_inputs(&thief, &spent, &steal);
    let (proof, exec) = m.prove(&ledger.program, &inputs, None).unwrap();
    println!("someone holding alice's viewing key and her note, but not her spend key, tries to spend it:");
    println!("  the guest derives an address from the key it was given: cm_in = {} (alice's is {})", hex2([exec.outputs[0], exec.outputs[1]]), hex2(spent.commitment()));
    println!("  ledger → {}", match ledger.apply(&m, &proof, Envelope::seal(&alice, &bob.address(), &steal, &TxKey::random())) { Err(LedgerError::UnknownCommitment(_)) => "rejected: unknown commitment", _ => "ACCEPTED (bug)" });
    let mut bad = build_traces(&ledger.program, &exec, proof.tier).unwrap();
    let cm = spent.commitment();
    bad.public_values[cpu::pv::OUT0] = F::from_u32(cm[0]);
    bad.public_values[cpu::pv::OUT0 + 1] = F::from_u32(cm[1]);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { let p = m.prove_traces(&ledger.program, &bad, proof.tier); m.verify(&ledger.program, &p) }));
    println!("  claiming alice's cm_in as the public value → {}", if matches!(r, Ok(Ok(()))) { "ACCEPTED (bug)" } else { "rejected by the constraint system" });
    println!("
Read docs/06-viewing-keys.md for the construction and what it does not yet cover.");
}
