# zkp4 — Zcash-style shielded pool

A simulated shielded pool with notes that carry arbitrary hidden values, are owned by spending keys, and can be transferred inside the pool without ever leaving it. Groth16 over BN254 via arkworks.

```
cargo run --release     # Alice shields 10, pays Bob 3 shielded, Bob unshields 2; then attacks
cargo test --release
```

Read `../zkp6` (Tornado Cash) first. This crate is the same Merkle-membership circuit plus three additions, each marked ★ in `src/circuit.rs`:

1. **Ownership.** The input note's public key is derived in-circuit as `H(sk)`, so only the holder of `sk` can spend it. Tornado has no keys at all.
2. **Hidden values with conservation.** `v_in = v_out1 + v_out2 + v_pub`, proven in the circuit. Tornado has fixed denominations and nothing to check.
3. **Range checks.** Each output value is decomposed into 64 Boolean wires. Without this the balance equation holds mod a 254-bit prime and a thief can wrap around to mint unbounded value. Zcash's 2018 counterfeiting bug lived in this area.

## Files

| file | what it shows |
|---|---|
| `src/lib.rs` | notes, commitments, nullifiers, and what the chain sees for a transfer |
| `src/note.rs` | spending key → public key, note commitment `H(H(v, pk), H(ρ, r))`, nullifier `H(sk, ρ)` |
| `src/circuit.rs` | the 1-input 2-output transfer circuit (1 679 constraints) |
| `src/ledger.rs` | transparent balances, shielded pool, `shield` (t→z), `apply` (z→z or z→z+t), wallet-side `build_transfer` |
| `src/hash.rs`, `src/merkle.rs` | identical to zkp6 |
| `src/viz.rs` | stdout drawings: the commitment tree with empty subtrees collapsed (chain view, and the wallet's view with the spend path marked), transparent balances and the pool |
| `src/main.rs` | scenario and attacks: replay, inflation, spending someone else's note, re-spend |

## Simplifications

- MiMC in place of Pedersen / Sinsemilla / Poseidon, Merkle depth 8 instead of 32.
- Note delivery is done off-chain by handing the note to the recipient. Zcash encrypts it into the transaction.
- One combined spend-and-output circuit. Sapling proves inputs and outputs separately and balances them with homomorphic value commitments outside the circuit.
