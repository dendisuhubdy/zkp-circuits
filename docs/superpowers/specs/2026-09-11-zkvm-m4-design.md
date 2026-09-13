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
   tier-18 budget of 262 143 and the largest tier this machine has (20) at 1 048 575. The measured
   breakdown (`research/docs/04-guests.md`, from a pc histogram over the guest's symbols):

   | what | cycles | share |
   |---|---|---|
   | `Sha256::update`/`compress` — 2 368 compressions at ~451 cycles each | 1 066 950 | 60.8 % |
   | `run_call_with` inlined into `main`: the input tape, the interpreter, the fills | 600 725 | 34.2 % |
   | `memset` — zeroing the 32 KiB stack and 32 KiB heap | 51 535 | 2.9 % |
   | `elf::load` — section walk, call-marker pass, 107 relocations | ~22 000 | 1.3 % |

   The 2 368 compressions decompose exactly: **1 698 for `program_hash`** over the 108 600-byte ELF,
   654 for `input_hash` over the 41 825-byte instruction region, 8 + 8 for the pre- and post-state
   account walks. The ELF also occupies 27 151 of the 37 609 input words. Carrying it on the tape and
   then hashing it is therefore about **1.20 M of the 1.75 M cycles**, spent binding a program of
   which the run executes 143 instructions. A further ~290 K goes to `input_hash` over a region that
   is 98 % `MAX_PERMITTED_DATA_INCREASE` zeros — 640 of its 654 compressions hash nothing else.

   **What does *not* work: declaring `program_hash` instead of recomputing it.** This was Task 6's
   first proposal and it is **unsound**; it is written down here so nobody proposes it again.
   `H_IN` has been *salted and hiding* since M4.1 (`research/docs/03-privacy.md`, "Private inputs are
   bound to `H_IN`"): the salt never leaves the prover, and it folds non-invertibly into the digest,
   so `H_IN` is not something a verifier can check a claimed digest of the input words against. A
   `program_hash` the guest does not recompute is therefore bound to **nothing** — a prover could run
   any ELF it liked, feed it through `READ_INPUT` under a fresh salt, and declare the SPL Token hash
   in the public output. The in-circuit recomputation is not redundancy; it is the entire binding.
   Under the machine as it stands, an ELF that arrives as private input *must* be hashed in-circuit
   for the digest to mean anything.

   Two sound paths remain, and they are genuinely different in kind.

   * **(A) Bake the ELF into the guest's data segment, so `hc` binds it.** The image container this
     plan cherry-picked from M4.3 (`Program::from_flat_image`, §5.1 of `research/docs/01-isa.md`)
     makes the data segment part of `Program::words`, and therefore part of `hc` — a binding the
     verifier already checks, with no salt and nothing prover-chosen, because the stored values are
     immediates in the prologue's own instructions. `program_hash` then need not be computed at all.
     Cost: the ELF is ~27 150 data words, and the synthesised `li`/`sw` prologue runs at the measured
     ~2.8 instructions per non-zero data word, so ~**72–76 K prologue words** and the same in cycles.
     The ELF's 1 698 compressions (~766 K cycles) and its 27 151 input words (~430 K) both come off.
     Estimated from the breakdown, not measured: ~**0.6 M cycles, i.e. tier 20** — inside the
     machine's largest tier, but a tier-20 batch still carrying a 466-column sha256 table is provable
     only on a machine far larger than the 48 GB of the development hardware.

     **A does not fit today, and this must be checked before committing to it.** A program is capped
     at **65 535 words** in both loaders (`LoadError::TooLong`), because the word count is `HASH_LEFT`
     on the first digest row — a 16-bit value in the cpu AIR's `LEFT0..1` byte limbs — so a longer
     program satisfies no tier's constraints. A's prologue alone is ~72–76 K words; with the guest's
     own 6 427 text words the image is ~78–82 K, **over the cap by ~20 %**. It fits only if the
     prologue lever this plan noted but never needed (dedupe the `lui` half across consecutive data
     words, ~25 % of prologue words) is implemented first, landing at ~60–63 K with a couple of
     thousand words of margin; a program much larger than SPL Token's 108 KB would need `HASH_LEFT`
     widened, which is itself a constraint-set change. A is therefore not the "no machine change"
     option it appears to be — it is a machine change deferred by one program size.

     A also makes the guest program-specific: one committed binary per Solana program, a real
     departure from "publishing a contract is registering a hash for the *interpreter*"
     (`docs/04-guests.md`).
   * **(B) Change the machine: a public, unsalted segment in the input commitment.** If the chain
     itself sees the ELF words — or hashes them natively, outside the guest — then a *declared*
     `program_hash` checked against that segment **is** sound, the guest hashes nothing, and the run
     lands at **tier 18** as §5 intends. This is a constraint-set change (a second input commitment
     or a split `H_IN`, new public values, verifier changes) and needs its own spec addendum and
     implementation plan; it is not an M4.4 edit. Note the privacy consequence, which is the price of
     the soundness: a public segment makes the ELF words public, so the program is no longer hidden
     — the leak row in `research/docs/03-privacy.md` changes from "bounds the size of the program
     that ran" to "publishes the program".

   **Also deferred into the same follow-up:** `input_hash` over a **canonical, unpadded** encoding of
   the instruction (the accounts' real fields, as `output_hash` already does) rather than over the
   aligned region, worth ~290 K cycles. It is legitimate and cheap, but it changes the plan's binding
   "Public output" ruling exactly as A and B do, so it is decided with them rather than smuggled in.

   Until one of A or B is taken,
   `tests/e2e.rs::compiled_sbpf_spl_token_transfer_proves_and_verifies` is committed **in full** and
   `#[ignore]`d with the measurement in its ignore message, and the executor-level half of the exit
   test — which checks the guest's eight output words against the native run and tripwires in both
   directions on the cycle count — is what pins the behaviour.

   **M4's exit criterion, without spin.** "An ERC-20 `transfer` and an SPL `Transfer` each prove
   under `R_exec`" is met on neither side as an actually-produced proof on this hardware:

   * **EVM (M4.3):** the interpreter proves and verifies at **tier 16** for a storage call through
     the same committed binary. The tier-18 ERC-20 `transfer` proof was **not produced** on the
     development hardware — the run did not complete there. So the path is demonstrated and the
     specific exit artefact is outstanding for want of a machine, not for want of a design.
   * **SPL (M4.4):** the interpreter **runs** a real `Transfer` and binds its outputs — the eight
     public words are the documented digest over the program, the instruction and the accounts'
     post-state, and they match the native interpreter — but it is **unprovable at any tier this
     machine has**, and no amount of guest-side work changes that. It needs A or B.

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

## 9. Addendum 2026-09-13 — the public input segment (constraint set 6)

Date: 2026-09-13. Status: rulings fixed by the coordinator; this section is the decision record.
Applies to `circuits` at `fe98305`. Implementation plan:
`docs/superpowers/plans/2026-09-13-zkvm-public-input.md`.

This is **option B of §5.1 item 8**, taken. §5.1 item 8 established that an ELF arriving as private
input *must* be hashed in-circuit, because `H_IN` is salted and hiding and therefore cannot check a
declared digest; and that the only way to make a declared digest sound is to give the machine a
second input space the verifier can see. That is what this addendum specifies. Option A (bake the
ELF into the data segment so `hc` binds it) is **not** taken: it exceeds the loader's 65 535-word
program cap by ~20 % and makes the guest program-specific.

Numbering: §6 "What does not change" through §8 "Open items" are M4's own and are untouched; this
addendum is §9 because §6 is taken, exactly as §3.1/§4.1/§5.1 are amendments in place. Where this
section and §5.1 item 8 differ — they differ on one number, the resulting tier — **this section
supersedes it**.

### 9.1 The design: a second, unsalted input space

The private input space is untouched. Alongside it the machine gains a **public segment**: the same
mechanism, minus the salt, with its own digest published as its own public values.

**A new witness table `public`**, `research/src/tables/public.rs`, mirroring `input` column for
column: `IDX` (the row's own index, 0 at row 0, `+1` every row including through padding), `WORD`,
`IS_REAL` (a boolean monotone prefix), `MULT_READ`; `col::WIDTH = 4`. Its height is proof-declared
as `Proof::public_log_height`, under `public_log_height(n) = pad_height(n + 1, MIN_HEIGHT)` with
`MIN_HEIGHT = 4`, `MIN_LOG_HEIGHT = 2`, `MAX_LOG_HEIGHT = 20` — `tables::input`'s rule, constants
included, and `check_declared_heights` bounds the declaration to `[MIN_LOG_HEIGHT, MAX_LOG_HEIGHT]`
before anything is sized from it. Padding rows pin `WORD` and `MULT_READ` to zero (AGENTS.md
invariants 1 and 2).

**Two new buses, `PUBLIC_DIGEST` and `PUBLIC_READ`**, mirroring `INPUT_DIGEST`/`INPUT_READ`
including the split, and for the identical reason — M4.1 review round 1, C1:

* `PUBLIC_DIGEST`, count `IS_REAL`, the digest rows' *only* source of `(IDX, WORD)`, one unit per
  real row and completely independent of how many times that index is read.
* `PUBLIC_READ`, count `IS_REAL * MULT_READ`, `SYS_READ_PUBLIC`'s only source.

A single bus with count `IS_REAL * (1 + MULT_READ)` would be unsound here for exactly the reason it
was unsound for `input`: LogUp balances per `(idx, word)` key, not per *consumer class*, so a prover
could stop the digest absorbing index `k` (dropping demand by one) while a genuine
`READ_PUBLIC(k)` still succeeded on the row's remaining unit of supply — `H_PUB` would then commit
to fewer words than the guest read, with every constraint satisfied. With the buses split,
`PUBLIC_DIGEST` alone forces `real_count == n_pub` and forces the absorbed words to equal the
table's `WORD` values, exactly as `program`'s `MULT_WORD = VALID` argument does for `PROGRAM_WORD`.
Bus count: fourteen → **sixteen**.

**A third digest region on the cpu table**, `IS_PUBDIGEST`, entered off `INDIGEST_LAST` precisely as
`IS_INDIGEST` is entered off `DIGEST_LAST`, sharing the absorb machinery (`HS0..7`, `HV0..3`,
`ACT0..3`, `HASH_LEFT`, `HASH_IDX`, `LEFT0..1`, `IDX0..1` — `IS_DIGEST`, `IS_HASH`, `IS_INDIGEST`
and `IS_PUBDIGEST` are pairwise mutually exclusive) and getting its own final-encoding columns
`PHVL0..31`/`PHIMAX0..3`/`PINV0..3`, on the same reasoning that gave the indigest region
`IHVL`/`IHIMAX`/`IINV` rather than reusing `DHVL`. It computes

```
H_PUB = Poseidon2(domain PUB, n_pub; words)
```

with **no salt**: capacity lanes seeded `[PUB_DOMAIN, n_pub, 0]` on the transition out of
`INDIGEST_LAST`, then `⌈n_pub/4⌉` blocks of public words absorbed four to a row, each active lane
consuming `PUBLIC_DIGEST` at `(HASH_IDX * 4 + k, HV0+k)`. There is no salt row, so — unlike `H_IN`,
whose salt block guarantees at least one permutation — the region uses `program_digest`'s
`max(1, ⌈n/4⌉)` rule: `public_digest_row_count(n) = n.div_ceil(4).max(1)`, and `n_pub == 0` costs
one permutation of the header alone. `notes::domain::PUB = 15` (next free; `SBPF_OUT` is 14).

**The `H_IN` region is touched in exactly one place, and it is not optional.** M4.1 hit this bug
once already (`DPOUT0..7`'s doc comment): the last indigest row's own permutation output is read
back through `n(HS0 + j)`, and the row after it is now the first *pubdigest* row, whose `n(HS0..7)`
must carry `H_PUB`'s header seed. Two unrelated values cannot occupy one cell, so the last indigest
row gains dedicated output columns **`IPOUT0..7`**, and both its `POSEIDON2` `state_out` argument
and its `IHVL` canonical-encoding pin retarget from `n(HS0 + j)` to `v(IPOUT0 + j)` — the same fix
`DPOUT0..7` is, one region later. `H_IN` itself, its salt, the `input` table and both input buses
are otherwise unchanged.

**Eight new public values.** `pv::PUB0 = pv::IN0 + 8 = 26`, `pv::PUB7 = 33`, `pv::NUM` **26 → 34**,
pinned by the last `IS_PUBDIGEST` row exactly as `pv::IN0..7` is pinned by the last `IS_INDIGEST`
row.

### 9.2 ABI

**`SYS_READ_PUBLIC = 6`** — `a0 = idx` in, `a0 = word` out; `SYS_READ_INPUT`'s shape exactly, one
cpu row, a new `SYS_READ_PUB` selector, the returned word drawn on `PUBLIC_READ` with
`Count::bounded(v(SYS_READ_PUB), 1)` keyed `[v(B), v(C)]`, and the ordinary
`WRITES_RD`/register-writeback path carrying `C` back to `a0`. **`idx >= n_pub` is refused the way
`READ_INPUT` refuses it, which is not a halt**: `emulator::execute` returns
`ExecError::PublicIndex(idx)` and the run produces no trace at all, mirroring
`ExecError::InputIndex`. (Recorded because the ruling said "exceptional halt"; the machine has no
such notion for this syscall, and mirroring `READ_INPUT` is what the ruling asks for.)

**Guest SDK** gains `guest_sdk::read_public(idx) -> u32`; `research/src/asm.rs` gains
`ops::read_public(idx)`, the twin of `ops::read_input`.

**Prover API.** `public: &[u32]` is a new parameter of every entry point that took `inputs`:

```rust
Machine::prove(&self, program: &Program, inputs: &[u32], public: &[u32], tier: Option<Tier>)
Machine::prove_salted(&self, program: &Program, inputs: &[u32], public: &[u32], salt: [u32; 4], tier: Option<Tier>)
Machine::prove_with(&self, backend: Backend, program: &Program, inputs: &[u32], public: &[u32], tier: Option<Tier>)
machine::build_traces(program, inputs, public, exec, tier)
machine::build_traces_salted(program, inputs, public, salt, exec, tier)
emulator::execute(program, inputs, public, max_cycles)
hash::public_digest(public: &[u32]) -> [u32; 8]
hash::public_digest_rows(public: &[u32]) -> Vec<DigestBlock>
hash::public_digest_row_count(n: usize) -> usize
```

`Proof` gains `public_log_height: u8`; `Traces` gains `public: RowMajorMatrix<Val>` and
`public_log_height: u8`; `Machine::verifier_key` gains a sixth component and becomes
`(tier, program_log_height, input_log_height, keccak_log_height, sha256_log_height,
public_log_height)`; `check_declared_heights`, `log_ext_degrees` and `max_constraint_degrees` all
gain the parameter. `Chip::Public` is appended **last** in `machine::chips()`, after `Sha256`, with
its `log_ext_degrees` entry after sha256's.

Note the consequence of "last": `Chip::Public` is *mandatory* but sits behind two *optional* chips,
so its index is `8 + (klh != 0) + (slh != 0)` — 8, 9 or 10. Every pre-existing index is undisturbed
(`i == 1` is still `Cpu`, the public-values slot; `i == 2` is still `Memory`, which
`tests/cheating.rs` indexes directly), which is the property that mattered; but
`tests/tables.rs::alu_max_constraint_degree_is_pinned` now pins a **nine**-chip bare shape and an
**eleven**-chip full shape.

### 9.3 Verification, and what the chain does

`Machine::verify(hc, proof)` **keeps its signature and its meaning**: it checks the STARK and `hc`.
Alongside it:

```rust
Machine::verify_public(&self, hc: &[u32; 8], public_words: &[u32], proof: &Proof) -> Result<(), VerifyError>
```

which runs `verify` and then additionally recomputes `hash::public_digest(public_words)` natively
and compares it against `pv::PUB0..7`, returning `VerifyError::PublicValues` on a mismatch. **The
chain publishes the public words with the transaction and calls `verify_public`.** That is the
whole of the new soundness story: `H_PUB` is unsalted, so a party holding the words can check it,
which is exactly what `H_IN` cannot do and why a guest-declared `program_hash` was unsound before.

A proof with `n_pub = 0` carries `H_PUB = public_digest(&[])`, the digest of the header alone — a
fixed, known value. **Every existing guest keeps proving unchanged with `public = &[]`**, and every
existing test keeps its expected outputs; only the call sites gain an argument.

### 9.4 The sBPF guest

The guest stops carrying the ELF privately and stops hashing it.

* **The ELF moves to the public segment.** Public vector `[n_elf, elf bytes…]`; private vector
  `[n_input, input bytes…]` only. `sbpf_core::abi::decode_input` splits into two cursors, one per
  segment; `SbpfCall` gains `public_words()` beside `input_words()`.
* **`program_hash` is dropped** — the ~1.20 M cycles of SHA-256 over the 108 600-byte ELF go away.
  The run's program binding is now `H_PUB` itself, checked by the chain against the ELF it published.
* **The public output changes** (this supersedes the M4.4 "Public output" ruling):
  `out0 = status`, `out1..7` = words 0..6 of `hash(domain::SBPF_OUT,
  [input_hash(8) ‖ output_hash(8)])` — a 16-word preimage where M4.4's was 24.
* **`input_hash` becomes canonical and unpadded** (the change §5.1 item 8 deferred into this same
  milestone). Instead of `sha256` over the aligned region with its `MAX_PERMITTED_DATA_INCREASE =
  10 240`-byte realloc padding per account, it is `sha256` over:

| field | bytes | notes |
|---|---|---|
| `program_id` | 32 | |
| `n_accounts` | 8 | little-endian `u64`, the count the walk actually used (clamped at `MAX_ACCOUNTS`) |
| per account entry, in entry order — a duplicate entry re-encodes in full the account it duplicates, at the position it occupies, the same walk `output_hash` does: | | |
| `key` | 32 | |
| `owner` | 32 | |
| `lamports` | 8 | little-endian `u64` |
| `data_len` | 8 | little-endian `u64` |
| `data` | `data_len` | exactly — no realloc padding, no 8-byte alignment padding |
| `is_signer`, `is_writable`, `executable` | 1 each | 0 or 1 |
| `rent_epoch` | 8 | little-endian `u64` — a running program reads it through its `AccountInfo`, so the digest binds it |
| `instruction_data_len` | 8 | little-endian `u64` |
| instruction data | `instruction_data_len` | |

  **Every byte of the region is either in this preimage or pinned to zero.** The bytes the encoding
  omits — the `original_data_len` slot, the 10 240-byte realloc headroom, the 8-byte alignment
  padding, a duplicate entry's seven padding bytes, and anything after the trailing `program_id` —
  are all inside the region `r1` points at and therefore readable by the running program, so leaving
  them merely unhashed would let a prover vary them while the verifier's recomputed `input_hash`
  still matched. The Solana runtime writes zeros there, so the guest **refuses** a region with a
  non-zero byte in any of them, exactly as it refuses any other malformed input (status 2,
  `ParseError::MalformedRegion`; `sbpf_core::abi::check_region`). For the same reason `n_accounts`
  is the region's **exact** `u64` count and a region claiming more than `MAX_ACCOUNTS` is refused
  rather than clamped — a clamped count would make a region claiming 64 and one claiming 2^40 hash
  identically.

  The two length prefixes and the trailing instruction data are **not** decoration and are not in
  the ruling's field list: without `n_accounts` and the per-field `data_len`/`instruction_data_len`
  prefixes the concatenation is ambiguous between different account splits, and without the
  instruction data `input_hash` would not bind the instruction at all (for the exit fixture, not the
  transferred amount). Expected saving, per `docs/04-guests.md`: the fixture's 41 825-byte aligned
  region (654 compressions, 640 of them hashing nothing but zeros) becomes 833 bytes, 14
  compressions (measured) — **~290 K cycles**, against which the entry-time zero-check over the
  40 960 bytes the encoding no longer hashes is a byte-at-a-time scan, not a hash.
* **The EVM guest (M4.3) is not changed by this plan.** It may adopt the public segment later — a
  public `codehash` segment is the obvious next user — but nothing here touches `evm-core`,
  `src/evm.rs` or the `evm` binary.

### 9.5 Cost model

Per proof, against the machine as it stands:

| what | cost |
|---|---|
| `public` table | `2^public_log_height` rows × 4 columns; `MIN_HEIGHT = 4`, so a `public = &[]` proof pays 4 rows |
| cpu rows | `+ max(1, ⌈n_pub/4⌉)` digest rows, which are cycles and count against the tier's budget |
| poseidon2 blocks | `+ max(1, ⌈n_pub/4⌉)` permutations, `BLOCK = 32` rows each, against `tier.poseidon2_height()` |
| public values | 26 → 34 `u64`s in `Proof::public_values` |
| batch instances | 8/9/10 → 9/10/11 |
| effective cap on `n_pub` | 65 535 — `HASH_LEFT` is 16-bit in the cpu AIR's `LEFT0..1` limbs, exactly as for `n_in` and the program's length; `MAX_LOG_HEIGHT = 20` is only the table-shape ceiling |
| a guest that uses no public segment | four table rows, one permutation, eight public values; no syscall, no new leak beyond `public_log_height = 2` |

**The sBPF exit test, projected.** From `docs/04-guests.md`'s measured breakdown of the 1 753 945
cycles:

| term | cycles |
|---|---|
| measured baseline | 1 753 945 |
| − `program_hash`: 1 698 compressions at ~451 | −765 798 |
| − `input_hash` canonicalised: 654 compressions → ~13 | −288 941 |
| = projected | **~699 000** |

What does **not** come off is the tape: the guest still has to read all 27 151 ELF words to run
them, and under this design it reads them with `READ_PUBLIC` instead of `READ_INPUT` at the same
~15.8 cycles per word (~430 K, inside the 600 725 the breakdown attributes to `run_call_with`).

**This corrects §5.1 item 8 and `docs/04-guests.md`, which both say option B "lands at tier 18".**
It does not. ~699 K cycles is above `Tier(18)`'s 262 143 budget and lands at **`Tier(20)`** — the
same tier option A was estimated at, but without A's 65 535-word program cap problem and without
making the guest program-specific, and with two large secondary wins A does not get:
`sha256_log_height` falls from 18 to ~10 (2 368 compressions → ~29), and the private input vector
falls from 37 609 words to 10 459. Reaching tier 18 needs the tape cost itself addressed — a bulk
"read `n` public words into memory" syscall, one cpu row per four words instead of one per word, is
the obvious lever — and that is **out of scope here**, recorded as an open item.

Consequently `compiled_sbpf_spl_token_transfer_proves_and_verifies` is expected to stay `#[ignore]`d
after this work, with a *new* measurement in its message, and the ≥ 64 GB path written down as M4.3
does for its own tier-18 proof: a tier-20 batch is four times the cpu rows of the tier-18 EVM proof
that already needed ≥ 28.5 GB and was SIGKILLed on this 48 GB machine. The plan un-ignores it only
if the measured tier is ≤ 18 **and** the proof completes here.

### 9.6 Privacy

`docs/03-privacy.md`'s leak table gains, on the sBPF row and as a general statement:

> **the public segment is published by construction — that is its purpose**; a guest that wants its
> program hidden keeps it in the private input as before.

and a new structural row for `public_log_height`, which is the same class of coarse leak
`program_log_height`, `keccak_log_height` and `sha256_log_height` already are: it bounds `n_pub` to
within a factor of two, and its minimum (2) means "this proof has no public segment".

Nothing else about the privacy model moves. `H_IN` stays salted and hiding, `hc` stays binding and
not hiding, and the open item "a hiding program commitment" (§8, and `docs/03-privacy.md`) is
untouched — this addendum makes the *unhidden* case sound, it does not make the hidden case cheap.

### 9.7 Vendoring

**This is constraint set 6 for the fullnode. Proofs from set 5 no longer verify** — `pv::NUM`
changes, the batch's instance count changes, and `Proof` gains a field. The fullnode is **not**
re-vendored by this plan. Note for whoever does: `deploy/sync-zkvm.sh` patches on an anchor that is
the *exact* `verifier_key` signature line, and that signature gains a sixth parameter here; the
script also tracks `pv::NUM`. Both must be updated in the same vendoring, and the script fails
loudly rather than silently mispatching (it already carries the message for it).

**The recursion VM (M5) is unaffected.** `docs/superpowers/specs/2026-09-13-zkvm-m5-recursion-vm-design.md`
§2 "Witness, not input" states the rVM has no salted input commitment and does not want one, and §9
lists "the RV32 machine's public unsalted input segment" as explicitly out of M5's scope. Nothing
here changes an rVM table, bus or instruction.

### 9.8 Rulings

| ruling | why | cost if wrong |
|---|---|---|
| a second, unsalted **public segment** rather than splitting `H_IN` into public and private halves | a split `H_IN` would change the meaning of an existing public value and force every M4.1-era consumer to re-reason about what `pv::IN0..7` commits to; a second space leaves `H_IN`, its salt and the `input` table alone, and a guest that wants nothing public declares `public = &[]` | one more table, two more buses, one more digest region, one more `u8` in `Proof` |
| the `public` table mirrors `input` exactly, **including the two-bus split** | the M4.1 review-round-1 C1 attack applies verbatim: one bus with count `IS_REAL*(1 + MULT_READ)` lets a prover shrink the digest's absorbed set while the read of the dropped index still succeeds, because LogUp balances per key, not per consumer class | one extra bus; a single bus would be a soundness hole, not a size win |
| `H_PUB` carries **no salt** | the salt is what makes `H_IN` uncheckable by a verifier; the entire point of this segment is that `verify_public` can recompute the digest from published words | the segment would be as useless as `H_IN` for binding a declared digest |
| `Machine::verify(hc, proof)` keeps its signature; the digest check is a separate `verify_public` | every existing caller and every existing test keeps working, and a consumer that genuinely has no public words (`n_pub = 0`) should not be made to pass an empty slice to the primary entry point | a chain that calls `verify` instead of `verify_public` gets a proof whose public words are unchecked — documented, and the reason `verify_public` is the one the fullnode calls |
| `Chip::Public` appended **last**, after the two optional chips | keeps `i == 1` (`Cpu`, the public-values slot) and `i == 2` (`Memory`, indexed directly by `tests/cheating.rs`) exactly where they are — the property `chips()`'s doc comment protects | a mandatory chip whose index varies with two optional ones; the degree-pin test grows to nine- and eleven-chip shapes |
| the last indigest row gains dedicated `IPOUT0..7` output columns | the row after it is now the first pubdigest row, whose `n(HS0..7)` carries `H_PUB`'s header — the identical collision M4.1 solved with `DPOUT0..7`, one region later | eight columns; without them an *honest* witness is unsatisfiable, which is precisely how M4.1 found it |
| the sBPF guest's `out1..7` drops `program_hash` and becomes `hash(SBPF_OUT, [input_hash ‖ output_hash])` | with the ELF in the public segment the program is bound by `H_PUB`, which the chain checks directly; recomputing a SHA-256 of it in-circuit would be 1 698 compressions of pure redundancy | a chain built against M4.4's 24-word preimage re-cuts its digest; the domain constant is unchanged, so a stale verifier fails loudly rather than silently |
| `input_hash` over a canonical, unpadded encoding, with explicit length prefixes and the instruction data included | 640 of the aligned region's 654 compressions hash `MAX_PERMITTED_DATA_INCREASE` zeros; and a concatenation without length prefixes is ambiguous, while one without the instruction data would not bind the amount transferred | ~290 K cycles if not done; an ambiguous or incomplete preimage if done carelessly — the reason the layout is written out field by field above |
| the EVM guest is not changed | M4.3 is finished and measured; adopting the segment there is a separate, optional win and would put a second guest's re-measurement on this plan's critical path | the EVM guest keeps carrying its bytecode privately, which is also its privacy story |
| constraint set 6, and the fullnode is not re-vendored here | the node's vendoring is its own reviewed change, and `deploy/sync-zkvm.sh`'s anchor moves with the `verifier_key` signature | a hard fork when it is vendored, as M4.1–M4.4 each are |
| the exit test is un-ignored only if it measures ≤ tier 18 **and** proves on this 48 GB machine | §9.5's arithmetic says it will not; a test that is `#[ignore]`d with an honest measurement is worth more than one that is un-ignored and cannot run | the measurement stands in the ignore message and in `docs/04-guests.md`, as M4.3's tier-18 EVM proof already does |
