# zkp2 — zk-SNARK half of the SNARK-vs-STARK pair

Groth16 over BN254 (arkworks) proving:

> I know a secret x₀ such that iterating `x ← x³ + 42` sixty-three times ends at the public value y.

`../zkp3` proves the identical statement with a STARK. Run both and compare the summary boxes.

```
cargo run --release     # narrated demo with timings and sizes
cargo test --release
```

## Files

| file | what it shows |
|---|---|
| `src/lib.rs` | the SNARK-vs-STARK comparison table |
| `src/chain.rs` | the chain as an R1CS circuit — the loop runs at circuit-build time and emits 2 gates per step, so N is frozen into the key |
| `src/snark.rs` | `setup` (the phase a STARK does not have), `prove`, `verify`, with comments on toxic waste, pairings, and why ZK is free here |
| `src/main.rs` | demo: arithmetize → trusted setup → prove → verify → attacks → zero-knowledge check |

## Measured here (Apple Silicon, release)

| | |
|---|---|
| constraints | 127 |
| trusted setup | ~20 ms, proving key 29 KB, verifying key 296 B |
| proof | 128 B, constant |
| verify | ~2 ms, 3 pairings, independent of N |

## What to notice

- Change N or K and you need a new trusted setup. The STARK verifier needs only the AIR source.
- Two proofs of the same statement are different bytes: Groth16 blinds A and C with fresh scalars. winterfell's STARK proofs in zkp3 are byte-identical.
- Verification cost does not depend on N. In zkp3 it grows with log(N).
