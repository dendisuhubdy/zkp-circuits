# zkp3 — zk-STARK half of the SNARK-vs-STARK pair

winterfell (128-bit field, Blake3 Merkle commitments, FRI) proving:

> I know a secret x₀ such that iterating `x ← x³ + 42` sixty-three times ends at the public value y.

`../zkp2` proves the identical statement with Groth16. Run both and compare the summary boxes.

```
cargo run --release
cargo test --release
```

## Files

| file | what it shows |
|---|---|
| `src/lib.rs` | what is different on the STARK side: no setup, hashes not curves, trace not circuit, small field, bigger proof, ZK is optional |
| `src/air.rs` | the AIR: a 64-row execution trace, one transition constraint `next − (cur³ + K) = 0` written once, one boundary assertion on the last row (x₀ is never asserted, so it stays private) |
| `src/stark.rs` | `build_trace`, `ProofOptions` (the security knobs), the `Prover` impl, `prove`, `verify_proof` |
| `src/main.rs` | demo mirroring zkp2 step for step |

## Measured here (Apple Silicon, release)

| | |
|---|---|
| trace | 1 column × 64 rows ⇒ 63 transitions |
| setup | none |
| proof | 12.4 KB, 95 bits conjectured security (32 queries, blowup ×8) |
| prove | ~2 ms |
| verify | ~0.3 ms, grows with log(N) |

## Two things to know

- **winterfell 0.13 is not zero-knowledge.** It produces a transparent, succinct argument of knowledge but does not mask the trace, so proofs are deterministic. That is how StarkNet and Miden use it. Adding ZK means appending random rows to the trace; the code comments say where.
- **The off-by-one.** A trace of R rows has R − 1 transitions. If the public y does not match the trace's last cell, the verifier rejects with no helpful message. Both crates use N = 63 for this reason, and the constants in `src/lib.rs` explain it.
