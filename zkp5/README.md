# zkp5 — Monero-style private transactions

The one crate in this series with no SNARK and no circuit. Privacy comes from four primitives composed on Ristretto255:

| primitive | hides | file |
|---|---|---|
| stealth addresses | who receives | `src/keys.rs` |
| Pedersen commitments + Bulletproofs | how much | `src/pedersen.rs`, range proof in `src/tx.rs` |
| CLSAG linkable ring signature | who spends (one of 11) | `src/clsag.rs` |
| key images | double spends, without linking | `src/clsag.rs`, checked in `src/tx.rs` |

There is no Merkle tree here (the anonymity set is a ring, not a pool), so
`src/viz.rs` draws the flat **output set** instead: every output's one-time
key, commitment and public origin, the ring of a transaction overlaid on it
with the real spend marked in the wallet's view only, the key images seen,
and each wallet's balance as recovered by scanning with its view key.

```
cargo run --release     # Alice pays Bob hiding among 10 decoys; Bob's wallet finds it; attacks
cargo test --release
```

## What to read

- `src/clsag.rs` builds the ring signature up from a plain Schnorr signature in its module comment, then implements it in about 100 lines. Every index in the ring looks the same to the verifier; only the signer can close the loop of challenges.
- `src/pedersen.rs` explains why `Σ C_in − Σ C_out − fee·H = 0` is a complete balance proof with no circuit, and why pseudo-outputs are needed when the ring contains decoys.
- `src/keys.rs` shows the Diffie-Hellman trick behind one-time addresses and why a view-only wallet can find outputs but not spend them.
- `src/lib.rs` has the Tornado / Zcash / Monero comparison table.

## Measured here

| | |
|---|---|
| transaction (1 input, 2 outputs) | ~1.5 KB |
| CLSAG (ring 11) | 448 B |
| aggregated Bulletproof (2 × 64-bit) | 736 B |
| build | ~28 ms |
| verify | ~3 ms |

## Simplifications

- Ring size 11 (mainnet uses 16), decoys chosen uniformly instead of by the gamma-over-age distribution.
- Outputs per transaction must be a power of two because of how the `bulletproofs` crate aggregates; real wallets pad with zero-value outputs.
- Amount encryption and mask derivation use a simplified key schedule; the shape (shared secret from view key × tx key) is Monero's.
