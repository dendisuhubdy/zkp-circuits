# Rand zkVM milestone 4 — compatibility: compiled guests, Keccak, an EVM interpreter

Date: 2026-09-11. Status: draft for review. Applies to `research` at 35fceab (M2 and M3 done).
Roadmap row: `research/docs/05-roadmap.md` M4 — "EVM and sBPF guest interpreters, Keccak/SHA
coprocessors; exit criterion: an ERC-20 `transfer` and an SPL `Transfer` each prove under
`R_exec`". Background: `research/docs/04-guests.md`.

## 1. Goal and order

M4 makes code from other ecosystems provable without a circuit per contract: an interpreter for
the foreign bytecode is itself an RV32IM guest, the contract's bytecode is private input, and
publishing a "confidential contract" is registering `hc` of the interpreter plus a commitment to
the bytecode. Nothing in M4 changes the machine's soundness or privacy model; it adds a loader, one
coprocessor chip, and guests.

Order, each phase shippable on its own:

| phase | delivers | exit test |
|---|---|---|
| M4.1 | flat-binary loader and a compiled-guest toolchain; `READ_INPUT` bound to a committed input | a `no_std` Rust guest built for `riscv32im-unknown-none-elf` proves and verifies |
| M4.2 | Keccak-f[1600] chip and `KECCAK` syscall | `keccak256` of a 136-byte block from a guest matches the host in 1 permutation |
| M4.3 | EVM interpreter guest (ERC-20 subset), storage as Merkle witnesses | an ERC-20 `transfer` proves; the state-root transition is the public output |
| M4.4 | sBPF interpreter guest and SHA-256 chip | an SPL `Transfer` proves |

M4.4 is specified only to the level of its interfaces here; its own detail follows once M4.3
has proven the interpreter-plus-coprocessor pattern, as `docs/04-guests.md` already plans.

## 2. M4.1 — compiled guests

**Loader.** `Program::from_flat_binary(base_pc, bytes)`: little-endian words, length a multiple
of 4, `base_pc % 4 == 0`, every word must decode (as `Deploy` requires today). Data sections are
part of the same flat image: the linker script places `.text` then `.rodata`/`.data` contiguously
at `base_pc`, and `.bss` is zero by the memory table's initial state. A guest entry convention:
`pc = base_pc`, `sp` initialised by the guest's own start code to the top of a RAM region the
linker script defines (RAM is word-addressed; the 32-bit address space is the guest's).

**Toolchain.** Target `riscv32im-unknown-none-elf` (available in Rust 1.98.1; not installed on the
build machines today). Guests are `#![no_std]`, `panic = "abort"`, built with `-C link-arg=-T
guest.ld` and converted to a flat image with `llvm-objcopy -O binary` (from the `llvm-tools`
rustup component, so no GNU RISC-V toolchain is needed). A `guest-sdk` crate provides the syscalls
as `#[inline(always)]` `asm!` wrappers: `read_input(i)`, `write_output(slot, w)`, `poseidon2(ptr,
n)`, `keccak(ptr)` (M4.2), `halt()`. Compiled guests are committed as `.bin` files with their
build command in a `Makefile`, so a reviewer without the target installed can still run every test.

**Unsupported instructions.** The compiler must not emit anything outside RV32IM: `FENCE`,
`EBREAK`, CSR ops and the A/C extensions are absent from the target; a decode failure at load time
is the check. Misaligned loads and stores remain a constraint violation, so the guest is built
with `-C target-feature=-unaligned-scalar-mem` (the default for this target).

**`READ_INPUT` binding.** Today a `READ_INPUT` is a prover-chosen witness word, unconstrained across
repeated reads of the same index (`docs/03-privacy.md`). M4.1 adds an input commitment:
`pv::IN0..IN7` (8 new public values, `pv::NUM` 18 → 26) carry `H_IN = Poseidon2(domain IN, n_in;
salt, inputs)`, where `salt` is a 128-bit prover-chosen value drawn per proof (four witness words
absorbed as the first rate block, never published), so `H_IN` is hiding as well as binding
(ruling 2026-09-11: an unsalted digest let a verifier test guesses of the private inputs, which
the crate's zero-knowledge tests forbid). It is computed by the same digest-row mechanism the
program digest uses (a second digest region
absorbs the `input` memory space in index order). Reads then go through a witness `input` table
(`IDX, WORD, IS_REAL, MULT_READ`, proof-declared height like the program table) that provides
`(IDX, WORD)` on **two separate buses**, `INPUT_DIGEST` (count `IS_REAL`, consumed once per real
row by the digest rows) and `INPUT_READ` (count `IS_REAL * MULT_READ`, consumed by `READ_INPUT`),
so two reads of the same index return the same word and the verifier learns `H_IN` without the
inputs. (Ruling 2026-09-11: this mirrors the program-digest mechanism exactly; an earlier draft
said a read-only memory space, which would have needed new memory-table rules.) (Ruling
2026-09-11, implementation review round 1: a single `INPUT_WORD` bus with count `IS_REAL * (1 +
MULT_READ)` let a prover shrink the digest's absorbed set while a genuine read at the dropped
index still succeeded, since LogUp balances per `(idx, word)` key only, not per consumer class —
splitting into `INPUT_DIGEST`/`INPUT_READ` closes it, at the cost of one more bus.) A guest that
wants its inputs private publishes nothing about them beyond the hiding `H_IN` (opening it needs
the salt); a guest that wants an input
public (a bytecode commitment, a calldata hash) is expected to absorb it into an output. Cost: one
digest row per 4 input words, the same rate as the program digest.

## 3. M4.2 — Keccak-f[1600] chip

**Why a chip.** `KECCAK256` appears in every ERC-20 path (storage-slot derivation for `mapping`
keys, event topics). Simulated in RV32IM it costs on the order of 10^4 cycles per permutation;
an ERC-20 `transfer` needs at least three, which alone would push the guest past tier 16.

**ABI.** `SYS_KECCAK = 4`: `a0 = ptr` (word address of a 50-word, 200-byte state), one
Keccak-f[1600] permutation in place. Padding and the sponge (rate 136 bytes, `0x01`/`0x80` bits)
are done by the guest SDK in software, so the chip proves only the permutation. This mirrors the
`POSEIDON2` syscall's split (host sponge, in-circuit permutation) and keeps the chip
message-length free.

**Table.** Hand-written, since the vendored Plonky3 0.7 set has `p3-keccak` (the permutation) but
no `p3-keccak-air` (correction to `docs/04-guests.md`, which assumed it existed). Layout: one row
per round, 24 rows per permutation, state held as 25 lanes × 64 bits in 16-bit limbs (100 limb
columns) plus the bit decompositions the θ, ρ, π, χ steps need. The original Plonky3 keccak AIR
used about 2,600 columns per row with the full state bit-decomposed; this design bit-decomposes
only the lanes χ and θ touch per row and keeps the rest as limbs, targeting under 1,000 columns.
Constraint degree stays ≤ 4 (χ is degree 2 in bits; ι is a constant). Interface: a `KECCAK` bus
carrying `(clk, ptr, is_first_round, is_last_round, state limbs)`, the cpu table's hash rows
sending the input state on round 0 and receiving the output on round 23, the same shape as the
`POSEIDON2` bus. Padding rows carry count 0 and pinned message columns (AGENTS.md invariants).

**Height.** `keccak_height(tier) = 2^(t-2)` rows: 24 rows per permutation, so tier 12 allows 42
permutations, tier 14 allows 170. The verifier key is keyed by tier as today; `program_log_height`
is unaffected.

**Equality contract.** The chip's output on every test vector must equal `p3_keccak`'s
`KeccakF` bit for bit; a randomized test compares 1,000 states.

### 3.1 Amendment to §3 (proposed 2026-09-12, **approved by the user 2026-09-12**; supersedes §3 where they differ)

A code-level survey of how the Poseidon2 chip is wired (`research/src/tables/{poseidon2,cpu}.rs`,
`machine.rs`, `emulator.rs`) found four places where §3 as written does not fit the machine.
Each comes with the proposed resolution; none changes M4.2's exit test.

1. **Column count.** §3 targets "under 1,000 columns" by bit-decomposing "only the lanes χ and
   θ touch per row" — but θ and χ touch every lane in every round, so a degree-≤4 AIR that
   never stores the state's bits does not exist. The proven layout (Plonky3's own `keccak-air`,
   degree 3) stores per row: the state as 100 16-bit limbs, the column parities `C` and
   `C' = C ⊕ D` as 2 × 320 bits, the post-θρπ state `A'` as 1,600 bits, the post-χ state as 100
   limbs, plus the 64 bits and 4 limbs ι needs on lane (0,0) and 24 step flags: about 2,630
   columns. A nibble-lookup design (XOR4/AND4 buses, no bit columns) was costed at roughly
   2,400 lookups per round-row and is worse. **Proposal:** adopt the `keccak-air` layout and
   round constraints (hand-written into `tables/keccak.rs`, with our LogUp interactions added;
   `p3-keccak-air` itself is not in the vendored set), state the column count honestly
   (~2,650), degree 3.
2. **Height.** With ~2,650 columns, a tier-derived `keccak_height = 2^(t-2)` makes every
   program pay for a Keccak table it may never use (tier 14: 4,096 rows × 2,650 columns, more
   cells than the cpu table). **Proposal:** the height is proof-declared like the program and
   input tables (`Proof.keccak_log_height`, minimum 5 = one 32-row block), so a guest with no
   `KECCAK` call declares the minimum; the verifier-key cache key gains a fourth component.
   §6's "only `pv::NUM` grows" stays true; `Proof` gains one `u8`.
3. **Bus shape.** §3 says the `KECCAK` bus carries `(clk, ptr, is_first_round, is_last_round,
   state limbs)` "the same shape as the `POSEIDON2` bus" — but `POSEIDON2` carries only
   `[in0..7, out0..7]`, provided once per permutation on the block's last round row, and the
   cpu table moves the words to and from memory itself through its four per-cycle memory slots.
   A 50-word state through the cpu table would cost 13 absorb rows and 13 write-back rows per
   permutation and 200 new cpu columns. **Proposal:** the Keccak chip talks to the `MEMORY`
   bus itself. The cpu's ecall row sends `(clk, ptr)` on a two-element `KECCAK` bus (count
   `SYS_KECCAK`); the chip's block for that permutation provides `(clk, ptr)` once and issues
   the 50 word reads (`ts = 4·clk + 0`, spread 4 per row over rows 0..12, values packed from the
   block-constant input limbs) and the 50 word writes (`ts = 4·clk + 1`, spread 7 per row over
   the block's 8 idle rows, values packed from the output limbs held constant on idle rows).
   The cpu row group is then a single ecall row with a `SYS_KECCAK` selector, `KECCAK_PTR`
   bounded below 2^30 exactly as `HASH_PTR` is, and `MEM_VAL` pinned to zero (no second
   argument). This keeps the cpu table's degree-8 packed-lookup budget untouched.
4. **Block.** 24 round rows + 8 idle rows = a 32-row block with preprocessed round selectors
   and round constants, like Poseidon2's 30 + 2; idle rows carry the output state unchanged
   and do the write-backs. Padding blocks are honest permutations of the zero state with
   count 0.

Cost, to be measured: the Keccak table at its minimum height adds under 1% to a proof; a
guest with `n` permutations pays `32n` rows × ~2,650 columns, about 3× the cpu table's cells
per permutation at tier 14 for 170 permutations.

## 4. M4.3 — EVM interpreter guest

**Scope.** Enough of the EVM to run OpenZeppelin-style ERC-20 `transfer`, `balanceOf` and
`approve`: stack, memory, calldata, `SLOAD`/`SSTORE`, arithmetic including 256-bit `MUL`/`DIV`
(software over eight 32-bit limbs, RV32M), comparison, bitwise, `KECCAK256` (M4.2), `CALLER`,
`CALLVALUE`, `RETURN`, `REVERT`, `LOG*` (topics hashed into the output, data dropped), `JUMP*`
with the JUMPDEST table, gas accounting as a counter (no refunds). Out of scope: `CALL`/`CREATE`
family, precompiles (`ECRECOVER` needs a secp256k1 chip, shared work with the bridge), `SELFDESTRUCT`,
`BLOCKHASH`. Unsupported opcodes trap; a trap is a guest `halt` with an error output word.

**Inputs and outputs.** Private inputs: bytecode, calldata, caller address, the pre-state storage
values touched by the run with their Merkle witnesses. Public outputs (8 words): `out0` = status
(0 revert, 1 success), `out1..3` = the post-state storage root (96 bits of a 256-bit root, the
rest carried in the next proof shape when the shielded pool's action model lands), `out4..7` =
the Keccak of the ABI-encoded return data. The contract identity is a `H_IN`-committed bytecode
(M4.1), so `(hc_evm, H_IN)` identifies "this interpreter, this contract, these inputs".

**Storage.** Contract storage is a binary Merkle tree over 256-bit slots keyed by
`keccak256(slot)` prefix bits, depth 32 for this milestone, hashed with Poseidon2 over limbs so
membership uses the existing `MERKLE_VERIFY` routine rather than a Keccak walk. Each `SLOAD` is a
membership proof against the pre-state root; each `SSTORE` updates the leaf and the guest
recomputes the root; the final root is the public output. Slots not touched need no witness.

**Cycle budget.** Estimated from `docs/04-guests.md` (5–20 cycles per interpreted opcode, no
interpreter exists yet): an ERC-20 `transfer` is about 400 opcodes and 3 Keccak calls plus two
storage membership proofs, so roughly 8,000–12,000 cycles → tier 14. Measuring this is the
milestone's first result; if it lands above tier 14, the dispatch loop is the target (a jump
table over the opcode byte instead of a compare chain).

**Solidity source.** The test contract is compiled with `solc` once and the bytecode committed as
a hex file with the compiler version; no `solc` in the build.

## 5. M4.4 — sBPF and SHA-256 (interfaces only)

- `SYS_SHA256 = 5`: `a0 = ptr` to a 24-word block (16 message words + 8 state words), one
  compression in place; a `sha256` chip with one row per round (64 rows), degree ≤ 4, `sha256_height
  = 2^(t-1)`.
- The interpreter is `solana-sbpf` 0.11.1's instruction set (already in the registry) reduced to
  `no_std`: 11 registers × 64 bits as register pairs, the same memory regions (program, stack,
  heap, input), syscalls `sol_sha256`, `sol_log` (dropped), `sol_memcpy`. `sol_ed25519` needs an
  Ed25519 chip and is out of scope, as in `docs/04-guests.md`.
- Exit test: an SPL Token `Transfer` instruction with its accounts as private input.

### 5.1 Amendment to §5 (proposed by the M4.4 plan and its Task 6 measurements, 2026-09-13; **pending the user's approval**; supersedes §5 where they differ)

§5 is four bullets of interface. Building it turned six of them into decisions, and measuring the
exit test turned one into a contradiction. Items 1–5 are rulings the M4.4 plan made and Tasks 1–5
implemented; items 6–8 are Task 6's measurements, and **item 8 is the one place the milestone's exit
criterion is not met**.

1. **The sha256 chip is optional per proof, with a proof-declared height — not `sha256_height =
   2^(t-1)`.** M4.2 measured what a wide table costs *every* proof (+1.91 MB for keccak's 2 612
   columns), and §3.1's precedent already made that table optional. `Proof::sha256_log_height = 0`
   means "no sha256 instance in the batch"; a cpu row claiming `SYS_SHA256` in such a proof has no
   provider for its `SHA256` lookup and is unprovable. Measured cost of carrying the chip: +92 307
   bytes at `FriProfile::Test`, +400 563 at the production profile. **Cost:** one more `u8` in
   `Proof`, and `Machine::verifier_key` becomes a 5-tuple `(tier, program_log_height,
   input_log_height, keccak_log_height, sha256_log_height)`.

2. **64-row blocks with no idle rows**, 24 `MEMORY` reads on row 0 and 8 writes on row 63.
   SHA-256's final add is a function of row 63's post-round state and the block-constant `H`, so the
   write-backs need no extra row. Measured: 466 main columns + 10 preprocessed, max constraint
   degree 3 (pinned by `tests/tables.rs`).

3. **The exit test's three digests go through the chip.** The spec's exit test — an SPL `Transfer` —
   does not itself call `sol_sha256`, so binding the run's identity and effect with SHA-256
   (`program_hash`, `input_hash`, `output_hash`) is what puts the chip on the critical path with a
   real workload. See item 8: this is also what makes the exit test unprovable, and item 8's
   proposal narrows it rather than abandoning it.

4. **SBPF v1 = `solana-sbpf` 0.11.1's `SBPFVersion::V0`**, with a **static** stack. The crate's own
   `V1` is SIMD-0166's *dynamic* frames, which came later; the fixed-frame format is what a
   BPFLoader2-era program is built for. No compute-unit costs are modelled (nothing on-chain depends
   on them yet); the only meter is `MAX_INSTRUCTIONS = 200 000`.

5. **The status word carries no error code.** `1` = `r0 == 0`, `0` = a non-zero return, `2` = an
   exceptional halt. Seven of the eight output words are the digest, so a `ProgramError`'s code has
   nowhere to go; `0` and `2` both bind the **pre**-state as `output_hash`, which is what makes "the
   post-state equals the pre-state" the on-chain signal that nothing happened. **Cost:** a chain
   that wants the code re-cuts `out1..7`.

6. **The SPL Token program is fetched from the live account and committed**, because building it
   needs a Solana toolchain the build machines do not have. **What the fetch found differs from §5's
   assumption:** `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` is owned by the **upgradeable**
   loader, not `BPFLoader2`, so its account data is a 36-byte `UpgradeableLoaderState::Program` and
   the ELF lives 45 bytes into a second, program-data account. Its upgrade authority is `None`, so
   the bytes are immutable in practice — the property the plan actually needed.
   `guests-compiled/sbpf/programs/SPL_TOKEN.md` records both calls, the slot and the sha256.

7. **Two geometry constants are measured, and both of the plan's were wrong.**
   * **Stack frames are Solana's 4 KiB, not 512 bytes.** With 512-byte frames the real SPL Token ELF
     faults on its first instruction, 1 560 bytes below the stack region: the release build inlines
     the whole transfer into one function whose frame is around 2 KiB. A frame size is part of the
     ABI a program was compiled against, not a budget the host may pick. The plan's 32 KiB stack is
     kept by reducing the depth to **8** frames; the measured frame-depth high-water mark for a
     `Transfer` is **0** (no nested call at all).
   * **`MAX_INPUT_BYTES` is 49 152, not 16 384.** The aligned format the entrypoint deserializes
     skips `MAX_PERMITTED_DATA_INCREASE = 10 240` bytes after *every* account unconditionally, so a
     three-account `Transfer` is 31 401 bytes. §5's own exit test could not have fitted the plan's
     cap.

8. **The exit test does not prove, and §5's own ruling 3 is why.** The compiled guest is correct —
   it runs the real SPL Token ELF in the machine's executor and publishes exactly the eight words
   `sbpf-core` produces natively — but it takes **1 753 945 cycles**, against the M4.4 plan's
   tier-18 budget of 262 143 and the largest tier this machine has (20) at 1 048 575. The breakdown
   (`research/docs/04-guests.md`) is unambiguous: of 2 368 SHA-256 compressions, **1 698 are
   `program_hash` over the 108 600-byte ELF**, and the ELF also occupies 27 151 of the 37 609 input
   words — about 1.20 M of the 1.75 M cycles spent binding a program of which the run executes 143
   instructions. A further ~290 K goes to `input_hash` over a region that is 98 %
   `MAX_PERMITTED_DATA_INCREASE` zeros.

   This is not a tuning gap. **Proposal, narrowing item 3 rather than abandoning it:**
   * `program_hash` becomes a **declared** value checked against the input commitment, not recomputed
     in-circuit. `hc` already binds the guest, and the ELF already arrives through `H_IN`, so the
     digest costs nothing in-circuit and the binding is unchanged. It also removes a privacy leak:
     `sha256_log_height` currently bounds the *size of the program that ran*.
   * `input_hash` is taken over a **canonical, unpadded** encoding of the instruction (the accounts'
     real fields, as `output_hash` already does), not over the aligned region.

   With both, the remaining work is ~250 K cycles — tier 18, as §5 intends — and the chip keeps a
   real workload (`output_hash`, `input_hash` and any `sol_sha256` the program itself calls). Until
   this is decided, `tests/e2e.rs::compiled_sbpf_spl_token_transfer_proves_and_verifies` is committed
   in full and `#[ignore]`d with the measurement in its ignore message, and **M4's exit criterion
   ("an ERC-20 `transfer` and an SPL `Transfer` each prove") is met on the EVM side only.**

## 6. What does not change

Tiers, the FRI profile, the seven existing tables and their constraints, `Machine::verify(hc,
proof)` (only `pv::NUM` grows in M4.1), the fullnode's `Deploy`/`Call` model. Each of M4.1, M4.2
and M4.3 is a constraint-set change and therefore a hard fork when vendored.

## 7. Rulings made in this draft

| ruling | why | cost if wrong |
|---|---|---|
| `llvm-objcopy` flat binaries, no ELF loader | the machine has a flat word-addressed program space; ELF parsing would be dead weight | guests with many sections need a careful linker script |
| inputs committed through a third memory space and a digest, not per-read hashing | reuses the program-digest mechanism; O(inputs/4) rows | `pv::NUM` grows; every vendored consumer updates |
| Keccak chip proves only the permutation | keeps the chip message-length free like Poseidon2 | sponge padding is guest code (cheap, ~100 cycles) |
| storage tree hashed with Poseidon2, not Keccak | reuses `MERKLE_VERIFY`; 32 Poseidon2 hashes vs 32 Keccak permutations | not Ethereum's Patricia trie; state roots are Rand-specific |
| ERC-20 subset first, no `CALL` family | matches the exit criterion; `CALL` needs reentrancy and gas forwarding semantics | contracts calling other contracts wait |
| M4.4 interfaces only | the pattern must be proven once before being repeated | sBPF details may move |

## 8. Open items

- secp256k1 chip (`ECRECOVER`, bridge attestations in-circuit) and Ed25519 chip: shared with the
  bridge, no owner yet.
- 256-bit modular arithmetic chip (`ADDMOD`/`MULMOD`/`EXP`) if software limbs prove too slow.
- Recursion to aggregate many interpreter proofs into one; not before M4.3 is measured.
