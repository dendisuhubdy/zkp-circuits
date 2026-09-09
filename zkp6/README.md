# zkp6 — Tornado Cash mixer

A fixed-denomination mixer simulated end to end: a Groth16 withdraw circuit over a MiMC Merkle tree, and a simulated contract that holds account balances, the commitment tree, a history of roots, and the set of spent nullifiers.

```
cargo run --release     # Alice and Bob deposit; Carol withdraws Alice's note; then every attack
cargo test --release
```

## The mechanism

```
DEPOSIT   pick random (ν, s); commitment C = H(ν, s); send 1 ETH + C; contract inserts C into the tree
WITHDRAW  prove in ZK: I know (ν, s) with H(ν, s) in the tree under root R, nullifierHash = H(ν), recipient = X
          contract: proof valid, R known, H(ν) unseen → pay X, record H(ν)
```

The proof is the same size whether the tree has 2 leaves or a million, and it reveals neither the leaf index nor the depositor. That is why a SNARK is used rather than a plain Merkle path.

## Files

| file | what it shows |
|---|---|
| `src/lib.rs` | why each piece exists: commitment, membership, nullifier, recipient binding |
| `src/hash.rs` | MiMC 2-to-1 hash, native and as a gadget, kept side by side so they cannot drift |
| `src/merkle.rs` | full in-memory tree, path extraction, and the in-circuit root recomputation with hidden position bits |
| `src/circuit.rs` | the withdraw circuit (827 constraints): commitment, nullifier hash, membership, recipient binding |
| `src/mixer.rs` | the contract: `deposit`, `withdraw`, root history, nullifier set, balances; wallet-side `prove_withdraw` |
| `src/main.rs` | scenario and attacks |

## Attacks the demo shows being rejected

- replaying a proof (nullifier already seen)
- a front-runner resubmitting the proof with their own address (recipient is a public input the circuit binds)
- spending the same note to a different recipient (same nullifier hash)
- a note that was never deposited (membership fails)
- a made-up root
- depositing with insufficient balance

## Simplifications

MiMC with 20 rounds instead of MiMC-Sponge, depth 8 instead of 20, and the whole tree in memory instead of the incremental "filled subtrees" structure the real contract uses.
