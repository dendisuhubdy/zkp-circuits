//! The wallet CLI, as the user experiences it:
//!
//! ```text
//!   $ tornado deposit  --amount 1 --from alice          → prints a note string; SAVE IT
//!   $ tornado withdraw --note tornado-eth-1-1-0x…  --recipient carol
//! ```
//!
//! `withdraw` takes nothing but the note and a recipient. Everything else
//! is derived: the commitment from (ν, s), the leaf index by scanning the
//! contract's Deposit events for that commitment, the Merkle path from the
//! rebuilt tree, the nullifier hash from ν, and finally the proof. This
//! module prints every one of those steps.

use crate::circuit::WithdrawCircuit;
use crate::merkle::{root_from_path, MerkleTree};
use crate::mixer::{prove, Mixer, MixerError, Note, Pk};
use crate::viz::{fr, render_tree};
use ark_serialize::CanonicalSerialize;
use std::time::Instant;

/// `tornado deposit`: make a note, send the commitment, print the note.
pub fn deposit<R: rand::Rng>(m: &mut Mixer, from: &str, rng: &mut R) -> Result<String, MixerError> {
    println!("$ tornado deposit --amount {} --from {from}", m.denomination);
    let note = Note::random(rng);
    println!("  generating random nullifier ν = {}", fr(&note.nullifier));
    println!("  generating random secret    s = {}", fr(&note.secret));
    let c = note.commitment();
    println!("  commitment C = H(ν, s)        = {}", fr(&c));
    let idx = m.deposit(from, c)?;
    println!("  → contract.deposit(C)  emitted Deposit(commitment={}, leafIndex={})", fr(&c), idx);
    let s = note.to_note_string("eth", m.denomination, 1);
    println!("  YOUR NOTE (the only way to withdraw — back it up, never share it):");
    println!("    {s}");
    Ok(s)
}

/// `tornado withdraw --note … --recipient …`: the whole wallet-side flow,
/// narrated. Returns the contract's verdict.
pub fn withdraw<R: rand::Rng + rand::CryptoRng>(m: &mut Mixer, pk: &Pk, note_str: &str, recipient: &str, rng: &mut R) -> Result<(), String> {
    println!("$ tornado withdraw --note {}… --recipient {recipient}", &note_str[..40]);

    // 1. parse
    let (note, currency, amount, net_id) = Note::parse(note_str)?;
    println!("  [1] parse note      → currency={currency} amount={amount} netId={net_id}");
    println!("                        ν = {}   s = {}", fr(&note.nullifier), fr(&note.secret));

    // 2. recompute commitment
    let c = note.commitment();
    println!("  [2] commitment      → C = H(ν, s) = {}", fr(&c));

    // 3. scan the event log for it
    let events = m.deposit_events();
    println!("  [3] scan events     → fetched {} Deposit events from the contract", events.len());
    let idx = match events.iter().find(|(_, leaf)| *leaf == c) {
        Some((i, _)) => {
            println!("                        found C at leafIndex={i}");
            *i
        }
        None => {
            println!("                        C not found — this note was never deposited (or wrong contract)");
            return Err("commitment not in tree".into());
        }
    };

    // 4. rebuild the tree locally and take the path
    let mut local = MerkleTree::new();
    for (_, leaf) in &events {
        local.insert(*leaf);
    }
    let path = local.path(idx);
    let root = local.root();
    println!("  [4] rebuild tree    → {} leaves, local root {}", local.len(), fr(&root));
    println!("                        path for leaf {idx}: {} siblings, position bits {:?}", path.siblings.len(), path.is_right.iter().map(|b| *b as u8).collect::<Vec<_>>());
    debug_assert_eq!(root_from_path(c, &path), root);
    print!("{}", render_tree(&local, "                        ", &|i| m.depositor(i).to_string(), Some(idx)));
    println!("                        contract root {}  match={}", fr(&m.root()), root == m.root());

    // 5. nullifier hash
    let nh = note.nullifier_hash();
    println!("  [5] nullifierHash   → H(ν) = {}", fr(&nh));

    // 6. prove
    let t = Instant::now();
    let circuit = WithdrawCircuit {
        root: Some(root),
        nullifier_hash: Some(nh),
        recipient: Some(crate::addr(recipient)),
        nullifier: Some(note.nullifier),
        secret: Some(note.secret),
        path: Some(path),
    };
    let proof = prove(pk, circuit, rng).map_err(|e| format!("{e:?}"))?;
    let mut bytes = Vec::new();
    proof.serialize_compressed(&mut bytes).unwrap();
    println!("  [6] prove           → {} bytes in {:?}   (public: root, nullifierHash, recipient)", bytes.len(), t.elapsed());

    // 7. submit
    println!("  [7] submit          → contract.withdraw(proof, root={}, nullifierHash={}, recipient={recipient})", fr(&root), fr(&nh));
    match m.withdraw(&proof, root, nh, recipient) {
        Ok(()) => {
            println!("                        ✓ accepted: {} paid to {recipient}, nullifierHash recorded", m.denomination);
            Ok(())
        }
        Err(e) => {
            println!("                        ✗ rejected: {e:?}");
            Err(format!("{e:?}"))
        }
    }
}
