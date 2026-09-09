# zkp1 — how a zk-SNARK works, in Rust

A small, heavily commented walkthrough of a zero-knowledge proof using
[arkworks](https://github.com/arkworks-rs), the standard Rust ZK toolkit.
Groth16 proof system, BN254 curve — the same combination Ethereum
precompiles, circom and snarkjs use.

```
cargo run --release     # narrated demo
cargo test              # constraint-system + end-to-end tests
```

## What you are proving

| Circuit | Statement | Private | Public | Constraints |
|---|---|---|---|---|
| `src/cubic.rs` | I know x with x³ + x + 5 = out | x | out | 3 |
| `src/mimc.rs` | I know x with MiMC(x) = h | x | k, h | 41 |

Both give a 128-byte proof that verifies in about a millisecond. That
independence from circuit size is the whole point of a SNARK.

## The mental model

**1. A circuit is a system of equations, not a program.**
A SNARK proves "there exist secret values that satisfy these quadratic
equations over a prime field". Each equation (constraint) has the form

    (linear combo of wires) × (linear combo of wires) = (linear combo of wires)

This is *R1CS*: Rank-1 Constraint System. Additions are free; every
multiplication costs one constraint. `src/cubic.rs` builds three of these
by hand so you can see the raw shape. `src/mimc.rs` uses `FpVar` gadgets
that overload `+` and `*` and emit constraints for you — the way real
circuits are written.

**2. Wires are public or private.**
`new_input_variable` / `FpVar::new_input` → public, the verifier is told
its value. `new_witness_variable` / `FpVar::new_witness` → private, only
the prover ever knows it. The proof convinces the verifier that *some*
private values exist making every constraint hold, given the public ones.

**3. Three operations.** (`src/snark.rs`)

| | Input | Output | Who |
|---|---|---|---|
| Setup | circuit *shape*, randomness τ | proving key, verifying key | once per circuit, ceremony |
| Prove | proving key, public + private values | proof π (3 curve points) | prover |
| Verify | verifying key, public values, π | accept / reject | anyone |

The setup randomness τ is "toxic waste": whoever knows it can forge
proofs. Production systems destroy it with a multi-party ceremony
(e.g. Zcash's Powers of Tau). The demo just lets the RNG state die.

**4. The three properties, and where the demo shows them.**

- *Completeness* — honest prover with x = 3 is accepted. Part 1 step [3].
- *Soundness* — a prover with x = 4 builds a proof; the verifier rejects
  it. Same proof against the wrong public input: rejected. Step [4].
- *Zero-knowledge* — two proofs of the same statement are different
  bytes and both verify. The prover blinds the proof with fresh
  randomness every time; the witness only appears as an exponent of
  elliptic-curve points, protected by the discrete-log problem. Step [5].

**5. Why MiMC and not SHA-256?**
Circuits do field arithmetic. SHA-256 is bitwise and costs ~25 000
constraints. MiMC is a hash *designed* for circuits: one round is
`(x + k + c)^7`, four multiplications. Swap MiMC for Poseidon and this
circuit becomes the membership proof at the heart of Tornado Cash,
Semaphore and zk-rollups.

## Same circuits in circom

`circom/cubic.circom` and `circom/mimc_preimage.circom` express the
identical constraints in circom's DSL. circom is not installed on this
machine; if you install it (`cargo install --git https://github.com/iden3/circom`)
you can compile them with `circom cubic.circom --r1cs --wasm --sym` and
compare constraint counts. The Rust and circom versions produce the same
R1CS shape, and `ark-circom` can load circom's output and prove it with
the same Groth16 code used here.

## Where to go next

- Replace MiMC with Poseidon (`ark-crypto-primitives` has a gadget).
- Add a Merkle-tree membership proof on top: "I know a leaf in this tree".
- Export the verifying key to a Solidity verifier (snarkjs `zkey export
  solidityverifier` does this for circom; arkworks needs a small script).
- Compare with a *transparent* system (no trusted setup): halo2, Plonky3,
  or STARKs. Same circuit idea, different proof system.

## Reading

- Vitalik Buterin, *Quadratic Arithmetic Programs: from Zero to Hero* — the cubic example, derived by hand.
- Groth, *On the Size of Pairing-based Non-interactive Arguments* (2016) — the proof system.
- arkworks `r1cs-tutorial` repo — the next step up from this crate.
