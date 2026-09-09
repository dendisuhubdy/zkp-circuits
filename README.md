# circuits/ — zero-knowledge proof walkthroughs in Rust

| crate | system | library | what it teaches |
|---|---|---|---|
| `zkp1` | zk-SNARK (Groth16) | arkworks | what a circuit / R1CS is; setup → prove → verify; the three ZK properties |
| `zkp2` | zk-SNARK (Groth16) | arkworks | **SNARK half of a matched pair** — same statement as zkp3 |
| `zkp3` | zk-STARK | winterfell | **STARK half of a matched pair** — same statement as zkp2 |
| `zkp4` | Zcash-style shielded pool | arkworks | notes with hidden values, spend keys, nullifiers, in-circuit balance + range checks |
| `zkp5` | Monero-style transactions | curve25519-dalek, bulletproofs | stealth addresses, Pedersen commitments, hand-written CLSAG ring signatures, key images |
| `zkp6` | Tornado Cash mixer | arkworks | Merkle-membership withdraw proof, simulated contract with account balances, front-running / double-spend defences |
| `research` | **Rand reference zkVM** | Plonky3 (Goldilocks, LogUp, hiding FRI) | RV32I guest programs proved under one universal relation; the guidance circuit for the whole protocol |

Each crate: `cargo run --release` for a narrated demo, `cargo test --release` for the tests.

## zkp2 vs zkp3: the same statement, two proof systems

Both prove: *"I know a secret x₀ such that iterating x ← x³ + 42 sixty-three
times ends at the public value y."* Run both and compare the summary boxes.
Measured on this machine (Apple Silicon, release build):

|                    | zkp2 · SNARK (Groth16, BN254)     | zkp3 · STARK (winterfell, f128)          |
|--------------------|-----------------------------------|------------------------------------------|
| arithmetization    | R1CS circuit, 127 gates unrolled  | AIR: 64-row trace + 1 transition rule    |
| setup              | trusted, per-circuit, ~20 ms      | none (transparent)                       |
| proving key        | 29 KB                             | none                                     |
| verifying key      | 296 B                             | none (the AIR source is the "key")       |
| commitment scheme  | elliptic-curve points + pairings  | Merkle trees of Blake3 hashes + FRI      |
| assumption         | discrete log on a pairing curve   | collision-resistant hash                 |
| post-quantum       | no                                | yes                                      |
| field              | 254-bit                           | 128-bit (chosen for FFT speed)           |
| proof size         | 128 B, constant                   | 12.4 KB, grows ~log²(N)                  |
| prove time         | ~9 ms                             | ~2 ms                                    |
| verify time        | ~2 ms, constant                   | ~0.3 ms, grows ~log(N)                   |
| zero-knowledge     | built in (proofs are randomized)  | **not in winterfell 0.13** (deterministic proofs) |

Things to notice in the code:

- **Where the loop runs.** In `zkp2/src/chain.rs` the `for` loop executes at
  circuit-construction time and emits gates; N is frozen into the proving key.
  In `zkp3/src/stark.rs` the loop executes at prove time and fills a table;
  the rule in `zkp3/src/air.rs` is written once.
- **The function that only one side has.** `zkp2/src/snark.rs::setup` has no
  counterpart in zkp3. That absence is what "transparent" means.
- **What the verifier needs.** SNARK: verifying key + public inputs + proof.
  STARK: the AIR type + public inputs + proof + a minimum-security policy.
- **Where security comes from.** SNARK: the curve's group order, fixed.
  STARK: `ProofOptions` (queries, blowup, grinding) — tunable, and the demo
  prints the resulting bits.
- **Zero-knowledge is not free in STARKs.** zkp3's demo shows two proofs of the
  same statement are byte-identical. Adding ZK means masking the trace with
  random rows; winterfell does not do this, and neither do StarkNet or Miden
  in production. Groth16 blinds every proof with two random scalars.
- **Same computation, different y.** The two crates print different numeric
  results because they compute mod different primes. Field choice is a
  first-class design decision in a STARK.

## zkp4 / zkp5 / zkp6: three privacy systems, side by side

All three simulate a ledger you can watch: deposits, transfers, an observer's
view, and a list of attacks the verifier must reject.

|                    | Tornado (zkp6)          | Zcash (zkp4)                     | Monero (zkp5)                    |
|--------------------|-------------------------|----------------------------------|----------------------------------|
| proof system       | Groth16 SNARK           | Groth16 SNARK                    | CLSAG ring sig + Bulletproofs    |
| circuit size       | 827 constraints         | 1 679 constraints                | no circuit                       |
| trusted setup      | yes                     | yes                              | no                               |
| anonymity set      | whole pool              | whole pool                       | ring of 11 per input             |
| amounts            | fixed denomination      | hidden, range-checked in circuit | hidden, Pedersen + range proof   |
| ownership          | whoever holds the note  | spending key, pk = H(sk)         | one-time key from stealth addr   |
| double-spend tag   | nullifier H(ν)          | nullifier H(sk, ρ)               | key image x·Hp(P)                |
| spend proof size   | 128 B                   | 128 B                            | ~1.5 KB                          |
| verify time (here) | ~1 ms                   | ~1 ms                            | ~3 ms                            |

Suggested order: zkp6 (simplest), then zkp4 (adds values and keys to the
same Merkle circuit), then zkp5 (no circuit at all — see what the SNARK was
buying you).

## Reading order

1. `zkp1` — learn what a constraint is, and the three phases.
2. `zkp2/src/lib.rs` — the comparison table, then `chain.rs`, `snark.rs`.
3. `zkp3/src/lib.rs` — the same table from the other side, then `air.rs`, `stark.rs`.
4. `research/README.md` — the real thing: a zkVM, and what "confidential arbitrary computation" means concretely.
