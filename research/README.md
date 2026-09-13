# `research` — the Rand reference zkVM

## What this is

`rand_zkvm` is the concrete form of the whitepaper's universal execution
relation `R_exec` ("Confidential Arbitrary Computation"): one constraint
system, one verifier, every program bound only by its code commitment `hc`.
It proves *"there exist private inputs and an execution trace such that
running program `hc` on them produced these public outputs"* — nothing more
specific about the program is ever a parameter of the verifier.

It sits above `circuits/zkp1`–`zkp6`, which are teaching demos for individual
proof-system ideas (Groth16 vs. STARK, shielded pools, ring signatures,
Merkle mixers), and below the eventual `fullnode/`: this crate is a
standalone library and demo today, and the node that does not yet exist is
meant to embed its verifier as consensus code (see "Reading order" below and
`docs/05-roadmap.md`). Everything else in the protocol that touches proofs —
the node's `zkp` module, the SVM precompiles, the EVM and Solana guest
story — is expected to converge on what this crate does, rather than each
growing its own proof system.

## Run it

```
cd research
cargo build --release   # first build takes a few minutes; Plonky3 is a large dependency tree
cargo run --release     # the narrated demo, ~6-7 minutes wall time (thirteen proofs — M4.4's sha256_demo is the newest guest in the closing sweep — one of them the narrated production-profile one)
cargo test              # 394 tests (388 pass, 6 ignored, ~17 min): emulator, per-table constraints, cheating provers, zero knowledge, end-to-end, keccak, sha256, the public input segment, the EVM guest's four host suites, the sBPF interpreter + the real SPL Token program, viewing keys, shielded-pool bundles
```

The toolchain is pinned by `rust-toolchain.toml` (1.98.1); `rustup` will pick
it up automatically. `cargo test` uses `FriProfile::Test` throughout (16
queries, 4 proof-of-work bits) so the suite runs in well under a minute per
proving test; the demo runs one full `FriProfile::Production` proof (80
queries, 20 PoW bits, folding arity 8 — the whitepaper's own parameters,
restored on 2026-09-12 after the zk audit found M2.2's 27-query retune met
the *conjectured* 100-bit target only by giving up the *proven*
proximity-gaps floor: see `docs/03-privacy.md`) to
show the real numbers, and one `FriProfile::Test` proof of the same trace so
you can see the parameter effect directly.

## The machine in one picture

The relation is proved as one batch of nine AIR tables, plus either of two
optional hash chips — ten with a keccak table (M4.2), ten with a sha256 one
(M4.4), eleven with both — under a single
commitment and a single FRI opening. Tables never call each other directly;
they exchange facts through sixteen named LogUp buses, and the batch verifier
checks that every bus balances globally.

```
                                  ┌───────────┐
                                  │  PROGRAM  │ witness trace, in-circuit decoder; hc is proved, not preprocessed
                                  └───────────┘
                                   │ PROGRAM (fetch)  │ PROGRAM_WORD (digest rows)
                                   ▼                   ▼
                  MEMORY bus            ┌───────────┐  ALU bus
                            ◄─────      │    CPU    │  ─────►
                 (permutation)          └───────────┘ (lookup)
                                        │        │
                    ┌───────────────────┘        └───────────────┐
                    ▼                                             ▼
               ┌───────────┐                                 ┌───────────┐
               │  MEMORY   │                                 │    ALU    │
               └───────────┘                                 └───────────┘
                     │ RANGE8                                      │ RANGE8 AND4 OR4 XOR4 POW2
                     └──────────────────┬──────────────────────────┘
                              ┌──────────┴──────────┐
                              ▼                     ▼
                        ┌───────────┐         ┌───────────┐
                        │   RANGE   │         │  NIBBLE   │
                        └───────────┘         └───────────┘
                    preprocessed, 256 rows   preprocessed, 256 rows

                        ┌─────────────┐
                        │  POSEIDON2  │  provides POSEIDON2; consumed by cpu's
                        └─────────────┘  hash rows, its digest rows (hc) and
                                         its indigest rows (H_IN)
                        ┌─────────────┐
                        │    INPUT    │  one row per committed private-input
                        └─────────────┘  word; INPUT_DIGEST / INPUT_READ (M4.1)
                        ┌─────────────┐
                        │   PUBLIC    │  its unsalted twin: one row per public
                        └─────────────┘  segment word; PUBLIC_DIGEST /
                                         PUBLIC_READ (CS6). Mandatory — an
                                         empty segment still costs four rows
                        ┌─────────────┐
                        │   KECCAK    │  Keccak-f[1600], one row per round;
                        └─────────────┘  provides KECCAK (clk, ptr) and sends
                                         its own 100 MEMORY accesses (M4.2)
                        ┌─────────────┐
                        │   SHA256    │  SHA-256 compression, one row per round;
                        └─────────────┘  provides SHA256 (clk, ptr) and sends
                                         its own 32 MEMORY accesses (M4.4)
```

`range` and `nibble` are preprocessed (committed once, independent of any
witness, and of any program — since M3.4 that's true of every preprocessed
table); `program`, `cpu`, `memory`, `alu`, `poseidon2`, `input`, `public`,
`keccak` and `sha256`
are main traces, rebuilt per execution (`poseidon2`'s, `keccak`'s and
`sha256`'s own round-constant/row-kind columns are preprocessed too, but their
state columns are not; `program`'s decoder columns are all main now — M3.4
retired its preprocessed half entirely). `keccak` and `sha256` are the two
**optional** tables, independently so: a proof whose guest never calls `KECCAK`
declares `keccak_log_height = 0` and leaves that instance out of the batch
altogether, and likewise `sha256_log_height = 0` for `SHA256` — which is worth
~1.91 MB and ~0.40 MB respectively at the production profile, since FRI openings
scale with a batch's column count.
Full column lists and constraints: `docs/02-tables-and-buses.md`.

## How confidential arbitrary computation works

Run `cargo run --release` alongside this section — it narrates exactly this.

A confidential call publishes three things: the code hash `hc`, the gas tier
(which bounds proof/verify cost and reveals itself through proof size
regardless), and a fixed-length array of output words. Everything else —
every register, every memory cell, every branch, the exact cycle count, and
every private input — stays inside the witness and is never seen by a
verifier (Part 1 of the demo). The *program* is not among the hidden things:
`verify` takes only `hc` (M3.4: the program table is a witness trace and its
digest is computed in-circuit, not held by the verifier at all) — `hc` still
identifies the program to anyone who can guess it, but the verifier itself
never sees a single instruction word. See `docs/03-privacy.md` for exactly
what that does and doesn't buy.

Private inputs enter through the `READ_INPUT idx` syscall: the prover
supplies whatever word it wants at that index, and the constraint system
only ever sees it flow through arithmetic and comparisons on the way to an
output (Part 2 builds `balance_check`, which sums four private balances and
outputs a single bit: is the sum over a threshold). Outputs leave through
`WRITE_OUTPUT slot word`, which is constrained directly against the proof's
public values — there is no other way for a value to become public. Since
M4.1, `READ_INPUT` is bound to the salted commitment `H_IN`: two reads of
the same index are constrained to agree, and an index ≥ n_in is
unsatisfiable. See `docs/03-privacy.md` for exactly why that matters and
what closes the gap.

Constraint set 6 adds the **public** twin: `READ_PUBLIC idx` reads a second,
independently-indexed vector bound to `H_PUB`, which is *unsalted* — so a
verifier holding the words recomputes the digest natively and compares
(`Machine::verify_public`), which is exactly what `H_IN`'s salt makes
impossible for the private one. The two spaces are independent and a guest may
use either, both or neither; a value's space is a privacy decision. The segment
is mandatory in the batch even when empty, and the first guest to need it is the
sBPF interpreter, whose Solana ELF now lives there instead of on the private
tape (`docs/03-privacy.md`, `docs/04-guests.md`).

Execution happens natively and in the clear on the prover's machine (Part
3) — the emulator is the reference semantics, and nothing about running it
is itself confidential; confidentiality is a property of the *proof*, not
of the execution environment. Arithmetization (Part 4) turns that execution
into nine, ten or eleven tables padded to the smallest gas tier that fits, which is why the
trace height — and hence the tier — is the only thing about "how much work
happened" that a verifier can see. Proving and verifying (Part 5) run
against Plonky3's hiding FRI PCS, so the main-trace and quotient commitments
carry fresh randomness on every call: two proofs of the identical run are
different byte strings and both verify (Part 7), which is what makes the
zero-knowledge property real rather than aspirational — though it is
*statistical*, not perfect zero knowledge, because that is what Plonky3
0.7's hiding PCS provides (`docs/03-privacy.md` cites the library's own
comment saying so). Part 6 tries to cheat twice — claiming a wrong output,
and verifying a proof against a different program's `hc` — and both are
rejected, because both change something the constraint system or the
verifier key actually pins down.

Mapped onto the whitepaper's shielded-pool language: `R_transfer` (the
Zcash-style spend/output relation from `zkp4`/`zkp6`) is just another guest
program under this same `R_exec`, built on notes, nullifiers, and in-circuit
Merkle membership. Those arrive as the `POSEIDON2` syscall (3) plus three
guest-level routines built on it — `NOTE_COMMIT`, `NULLIFY`, `MERKLE_VERIFY`
(`asm.rs`; no new syscall numbers) — in milestone 3 — see
`docs/05-roadmap.md`. Milestone 1 proves the general-purpose machine works;
milestone 3 is what turns it into a shielded pool.

## Viewing keys

The crate carries a shielded transfer and the disclosure layer that makes it
auditable — `guests::transfer`, `notes.rs`, `viewing.rs`, `ledger.rs`, and
Part 9 of the demo. The transfer spends one note and creates one,
recomputing both commitments and the nullifier inside the guest with the
Poseidon2 chip (`NOTE_COMMIT`/`NULLIFY`, built on the `POSEIDON2` syscall),
and proves the spent commitment's membership in an append-only commitment
tree in-circuit (`MERKLE_VERIFY`) rather than publishing it. Beside the
proof the sender publishes an envelope: the created note's plaintext under a
per-transaction key, wrapped to the receiver (ML-KEM-768) and to the
sender's own outgoing key.

A party's **viewing key** is a one-way image of its spend key. It opens every
envelope the party sent or received and nothing else; a **transaction key**
opens one envelope. Each opened row carries sender, receiver, amount, asset
and time, plus the note opening, and anyone holding the same key can check
the row against the chain's commitments and nullifiers. The viewing key
cannot spend: the guest takes the spend key as its private input and derives
the address itself, so a witness built from the viewing key names a
commitment the chain has never seen, and claiming the real one is a
constraint failure. The spent commitment itself is never public — only the
commitment-tree root (`anchor`) the proof was built against is, one of the
ledger's last 64 recorded roots (`Ledger::ANCHOR_WINDOW`):
`docs/06-viewing-keys.md`.

## The three targets

Only RISC-V executes natively today. Solidity and Solana are software
running under the same relation, not separate circuits:

| Target | Path into `R_exec` | Coprocessor tables it will want |
|---|---|---|
| RISC-V | native | none |
| Solidity | **done (M4.3)**: `solc` → EVM bytecode → `evm-core`, a `no_std` EVM interpreter compiled to RV32IM, bytecode and storage witnesses as private input. An ERC-20 `transfer` executes and binds its state-root transition, measured at `Tier(18)`; the same guest proves and verifies in-suite on a smaller call at `Tier(16)` | Keccak-256 **(done, M4.2)**; a looped `MERKLE_VERIFY`-style storage syscall or a wider sponge rate (the measured top cost); then 256-bit `ADDMOD`/`MULMOD`/`EXP` and `ECRECOVER` (secp256k1) |
| Solana / SVM | sBPF ELF → an sBPF interpreter compiled to RV32IM — **built, M4.4** (`guests-compiled/sbpf-core` + `guests-compiled/sbpf`, differentially tested against `solana-sbpf` 0.11.1; it runs the real SPL Token program, fetched from mainnet and committed). Since **constraint set 6** the ELF is the *public* input segment rather than a private-tape value, which is what took an SPL `Transfer` from unprovable to **`Tier(20)`** | SHA-256 (**done, M4.4** — the `sha256` chip behind `SYS_SHA256`), Ed25519 verify, 64-bit multiply; a direct sBPF→RV32 translator is a natural later optimisation |

Publishing a contract under this model means registering a hash, never
generating a bespoke circuit. Details, cycle-cost estimates, and what
milestone 4 builds first: `docs/04-guests.md`.

The Solana interpreter **runs** an SPL Token `Transfer` correctly in the machine's
executor, and since constraint set 6 the run also *fits* a tier: **694 498 cycles
against `Tier(20)`'s 1 048 575**, where M4.4 measured 1 753 945 and fitted nothing.
What bought it was the public input segment. The 108 600-byte ELF used to ride the
private tape (27 151 of 37 609 words) and be hashed in-circuit as `program_hash` —
1 698 of the run's 2 368 SHA-256 compressions, about 1.20 M of the 1.75 M cycles —
and that hashing could not just be dropped, because `H_IN` is hiding and a digest
the guest does not recompute is bound to nothing. Moving the ELF to the *unsalted*
public segment makes the chain's own check the binding: the guest hashes nothing,
`H_PUB` binds the words, and `input_hash` over a canonical 837-byte encoding
replaces 654 compressions with 14. Thirty compressions remain, `sha256_log_height`
is 11, and the price is that the ELF words are public. The tier-20 **proof** has
not been produced here — a tier-20 batch needs a ≥ 64 GB machine, as M4.3's
tier-18 EVM proof already did — and tier 18 needs the tape cost itself addressed.
`docs/04-guests.md`'s "The `sbpf` guest" has the measured table and both remedies;
the design spec's §5.1 item 8 and §9 are the decision record.

## What leaks and what does not

| Data | Status |
|---|---|
| The code hash `hc`, entry point `pc_entry`, gas tier, eight output words, and the declared program / input / public / keccak / sha256 / memory table heights | public |
| The **public input segment**'s words (CS6) | published by construction — that is its purpose, and `H_PUB = pv::PUB0..7` is unsalted precisely so a verifier can recompute it |
| The program itself (M3.4 — `verify` takes only `hc`), private inputs, every register/memory value, every branch, the exact cycle count, which syscalls ran | hidden |

`hc` is binding but not hiding: a verifier who can guess the program can
confirm the guess against a published `hc`. The declared heights are coarse
power-of-two bounds: every guest whose memory traffic fits the tier's own
budget declares the same `mem_log_height`, and `keccak_log_height` (with M4.4's
`sha256_log_height` beside it) reveals the
permutation count only to within a factor of two. Its one exact disclosure is
`0` — "this program made no `KECCAK` call at all", which is also what lets the
proof drop the 2 612-column keccak table (or the 466-column sha256 one) and stay
the size it was before M4.2. `public_log_height` has no such exact value: the
`public` table is **mandatory**, so its minimum covers every segment of three
words or fewer alike, and it bounds `n_pub` to within a factor of two — the least
consequential leak in the table, since the words themselves are published
(`docs/03-privacy.md`).

Full detail, including the tier-to-row-count table and the delegated-proving
boundary: `docs/03-privacy.md`.

## Deviations from the whitepaper

1. **Closed in M3.4.** `hc` is now an ordinary public value, computed
   in-circuit by the program table's digest rows with the Poseidon2 chip,
   and checked by the universal, program-independent verifier key
   (`Machine::verifier_key`, still program-*content*-independent). It is still binding but not hiding — a
   verifier who can guess the program can still confirm the guess against
   a published `hc` — see `docs/03-privacy.md`.
2. The gas tier is public per proof, not only as a batch-level histogram.
3. Zero knowledge is statistical in Plonky3 0.7, not perfect.
4. The transcript hash is Poseidon2, not the whitepaper's SHA3-384/BLAKE3-384
   — a config swap, not a rewrite.
5. Recursion and per-batch aggregation are out of scope until milestone 4+.
6. Selector refinement: 23 pre-decoded semantic fields replace one flag per
   mnemonic (`docs/01-isa.md`) — same trust model, fewer columns.

## Reading order

1. `src/isa.rs` — the instruction set, encoding, and the 23-field selector
   set the program table commits (and, M3.4, `Program::digest`/`digest_rows`
   — the host-side twin of the in-circuit `hc` computation).
2. `src/emulator.rs` — the reference semantics; if the AIR and this
   disagree, the AIR is wrong.
3. `src/tables/program.rs` — the in-circuit decoder (M3.4): a raw
   instruction word, its bit decomposition, and every `Decoded` field
   proved as a function of those bits, mirroring `Instr::decode` opcode by
   opcode.
4. `src/tables/cpu.rs` — one row per cycle, fetch/decode-selectors/pc, plus
   (M3.4) the digest-row prefix that computes `hc`.
5. `src/tables/memory.rs` — registers and RAM in one sorted table.
6. `src/tables/alu.rs` — byte-limb arithmetic, shifts, compares, and (M2.6)
   the RV32M extension as exact integer identities (64 main columns; RANGE8
   limb checks are op-gated — see `docs/02` for the exact per-op lookup
   counts).
7. `src/machine.rs` — the Plonky3 config, tiers, `prove`/`verify(hc, proof)`.
8. `src/notes.rs`, `src/viewing.rs`, `src/ledger.rs` — keys, notes, envelopes,
   disclosures, and the simulated chain the transfer guest is checked against.
