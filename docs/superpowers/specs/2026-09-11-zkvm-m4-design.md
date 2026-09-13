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

### 4.1 Amendment to §4 (proposed by the M4.3 plan 2026-09-12, **pending the user's approval**; supersedes §4 where they differ)

Implementing §4 settled four things it left open or specified differently. None of them changes
the machine: M4.3 added no table, bus, syscall or public value.

1. **The public output is a digest, not a truncated root.** §4 gives `out1..3` = 96 bits of the
   post-state root and `out4..7` = the Keccak of the return data. 96 bits of a state root is 2^48
   collision work, below the proof's own ~86-bit floor, and §4 binds the *pre*-state root not at
   all (`H_IN` is hiding, so the roots the call ran against are invisible to a verifier). **As
   implemented:** `out0` = status (1 success, 0 `REVERT`, **2 exceptional halt** — a chain has to
   tell "the contract said no", whose revert data is meaningful, from "the run was invalid"), and
   `out1..out7` = words 0..6 of
   `hash(EVM_OUT, [codehash(8) ‖ pre_root(8) ‖ post_root(8) ‖ return_hash(8) ‖ logs_hash(8)])` —
   40 words through the domain-tagged Poseidon2 sponge, a 224-bit binding of the contract, **both**
   roots, the return data and the logs' topics. A chain verifying a call already holds all five
   fields and recomputes the digest, so nothing is lost and the pre-root is bound too. A status
   other than 1 binds `post_root = pre_root` and an empty log set; status 2 binds empty return data
   as well. One function, `evm_core::abi::public_output`, is the whole rule.
2. **The storage index convention.** §4 says "keyed by `keccak256(slot)` prefix bits, depth 32"
   without saying *which* bits. **As implemented:** the leaf position is the **top 32 bits,
   big-endian**, of `keccak256(slot as 32 big-endian bytes)`, read as a `u32` whose bit `i` (LSB
   first) chooses left/right at level `i` — `asm::emit_merkle_verify`'s own convention. The leaf is
   `hash(STORAGE_LEAF, [slot ‖ value])` and canonical in the value (a zero value hashes to one
   fixed leaf whatever the slot), so the root is history-independent and the empty tree has a
   well-defined root. `STORAGE_LEAF = 12` and `EVM_OUT = 13` are the two new `notes::domain` tags.
   Known limitation: a 32-bit index is grindable at ~2^32. A colliding pair is **refused where the
   witnesses enter** — `StorageTree::push` rejects a second witness at a leaf position already
   claimed, which `decode_input` turns into the canonical malformed output (status 2,
   `post_root = pre_root`) — so a call needing both slots of a ground pair cannot be proved:
   fail-closed griefing, never forgery. The refusal is load-bearing rather than defensive: because
   the leaf is canonical in the value, both witnesses of a ground pair *do* verify while the
   position is empty, and accepting them would let a call that reads both slots before writing both
   bind a `post_root` holding only the second store while the interpreter believed in both — a
   divergence between the bound root and the executed call. The remedy for the collision itself is
   a deeper index (`research/docs/04-guests.md`).
3. **`SLOAD`/`SSTORE` are guest code, not a syscall.** §4 says membership "uses the existing
   `MERKLE_VERIFY` routine". That routine is an `asm.rs` *guest-level* helper, not a syscall, and
   `evm-core` is compiled Rust: it walks the path itself over `POSEIDON2`. Multi-slot updates
   refresh the sibling every other witness holds at the level where its path diverges from the
   updated one, which §4 does not mention and which independent witnesses require.
4. **The cycle budget was optimistic by an order of magnitude.** §4 estimates ~400 opcodes at
   5–20 cycles → 8 000–12 000 cycles → tier 14. Measured: **121 638 executed cycles (126 373 with the digest prefixes), `Tier(18)`**.
   The estimate's error is not the dispatch loop (§4's predicted culprit): it is that each of the
   four 32-level Merkle walks is 33 `POSEIDON2` calls (~27 300 cycles in all) and that a software
   256-bit interpreter costs ~200 cycles an opcode, not 5–20. The dispatch loop *is* now a real
   target, but after a storage syscall or a wider sponge rate — the ordering is in
   `research/docs/05-roadmap.md`'s deviation 7 and `docs/04-guests.md`'s measured breakdown.

## 5. M4.4 — sBPF and SHA-256 (interfaces only)

- `SYS_SHA256 = 5`: `a0 = ptr` to a 24-word block (16 message words + 8 state words), one
  compression in place; a `sha256` chip with one row per round (64 rows), degree ≤ 4, `sha256_height
  = 2^(t-1)`.
- The interpreter is `solana-sbpf` 0.11.1's instruction set (already in the registry) reduced to
  `no_std`: 11 registers × 64 bits as register pairs, the same memory regions (program, stack,
  heap, input), syscalls `sol_sha256`, `sol_log` (dropped), `sol_memcpy`. `sol_ed25519` needs an
  Ed25519 chip and is out of scope, as in `docs/04-guests.md`.
- Exit test: an SPL Token `Transfer` instruction with its accounts as private input.

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
- **Caller authorisation — the M4.3 output binds no caller.** `caller`, `address` and `callvalue`
  are private inputs and no public output commits to them (`H_IN` is salted and hiding by the M4.1
  ruling), so a verified EVM-call proof attests only that *some* `(caller, calldata)` maps
  `pre_root` to `post_root` under `codehash` — not that the caller was entitled to it. Concretely:
  a prover holding the storage witnesses can prove an ERC-20 `transfer` out of any holder by
  choosing `caller`. §4's "`(hc_evm, H_IN)` identifies these inputs" is therefore not true for a
  *verifier*. Nothing downstream may treat the `EVM_OUT` digest as authorisation: **the chain must
  bind the caller** — the spend authority on the bundle that carries the proof, an in-guest
  signature check, or the shielded pool's nullifier model — **or `EVM_OUT` gains a caller field in
  a later constraint set.** No owner yet; M4.3's exit criterion does not ask for it, and
  `research/docs/{03-privacy,04-guests}.md` now state the gap where a reader would look for it.
