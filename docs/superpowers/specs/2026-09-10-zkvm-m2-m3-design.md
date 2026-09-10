# Rand zkVM milestones 2 and 3 — design

Date: 2026-09-10. Status: approved in discussion ("approving A, with the M2 list as
written"). Crate: `research` (`rand_zkvm`). Baseline: circuits `main` b970029.

## Goal

Milestone 2 makes the prover and verifier cheaper and the ISA complete enough for
compiled guests: a cached verifier key, FRI tuned to a stated security target, the
2^16-row byte table replaced by two 256-row tables, fewer ALU lookups, sub-word
loads/stores, and the M extension. Milestone 3 gives the machine a native hash: a
Poseidon2 chip driven by a `POSEIDON2` syscall, guest-level `NOTE_COMMIT`, `NULLIFY`
and `MERKLE_VERIFY` built on it, the note layer moved off the development hash, and
the program digest computed in-circuit as a public value so the verifier no longer
holds the code.

Both milestones change the proof format and the constraint set. They are hard forks
for any chain that verifies these proofs (chain 5 will start from them).

Not in scope: recursion/aggregation, the EVM/sBPF interpreters and Keccak (M4), the
flat-binary loader and binding `READ_INPUT` (deferred to the M2 follow-up once a
compiled guest exists), any fullnode change (a separate spec).

## Binding conventions (from `research/AGENTS.md`)

- Every bus message column is constrained on every row kind that sends it.
- A bus count is forced to zero wherever its message columns are unconstrained.
- The emulator is the reference semantics; when AIR and emulator disagree the AIR is wrong.
- Cheating tests use `rejects()`; only a constraint-checker panic or a verify error counts.
- Docs carry measured numbers; re-measure in the same change.
- Commit style `research: <area> — <what>`, one logical change per commit.

Decisions already taken by the user: conjectured security target **100 bits**; byte
table split into a **256-row range/pow2 table and a 256-row nibble bitwise table**;
Poseidon2 chip **one row per round** (approach A); M2 and M3 before any chain work.

---

## Milestone 2

### M2.1 Verifier key cache

`Machine` gains `keys: Mutex<HashMap<(u64, usize), Arc<CommonData<Config>>>>` keyed by
`(program_digest(program), tier.0)`. `verifier_key`, `verify` and `code_hash` read
through it; a miss computes `ProverData::from_airs_and_degrees(&key_config(..)).common`
exactly as today and inserts. `prove_traces` is unchanged (it needs the full
`ProverData`, not just `common`). The cache is bounded (64 entries, FIFO eviction) so
a node that verifies many programs does not grow without limit.

Test: two consecutive `verify` calls on the same program; the second must take under
10% of the first (`tests/e2e.rs`), and `cached_keys()` reports 1.

### M2.2 FRI arity and query count

`build_config`/`generic_config`: `max_log_arity: 3` (folding arity 8; Plonky3 lowers
the arity per round when a height cannot support it), `log_blowup: 3` unchanged.
Query count from the conjectured bound `log_blowup·num_queries + query_pow_bits ≥ 100`:
`Production` → 27 queries, 20 PoW bits (81 + 20 = 101); `Test` stays 16 queries, 4 PoW
bits (52 bits; tests only). `FriProfile::Production` doc comment and `docs/03-privacy.md`
state the derivation; a unit test asserts
`fri.conjectured_soundness_bits() >= 100` for `Production`.

Measured before/after (proof size, prove time, verify time at tier 10 and 12,
production profile) go into `docs/03-privacy.md` and the README.

### M2.3 Byte table split

`tables/byte.rs` is replaced by two preprocessed chips:

- `tables/range.rs` — height 256. Preprocessed `A, POW2, IS_POW2` (`POW2 = 2^A` for
  `A < 32`, else 0; `IS_POW2 = [A < 32]`). Main `M_RANGE, M_POW2`. Provides `RANGE8`
  `[a]` and `POW2` `[a, 2^a]` (count gated by `IS_POW2` as today).
- `tables/nibble.rs` — height 256. Preprocessed `A, B ∈ [0,16)`, `AND, OR, XOR`. Main
  `M_AND, M_OR, M_XOR`. Provides `AND4 [a,b,a&b]`, `OR4`, `XOR4`. A successful lookup
  proves both operands are nibbles, so nibble-keyed lookups double as range checks.

`bus::{AND8, OR8, XOR8}` are removed; `ByteCounts` becomes `RangeCounts` + `NibbleCounts`
with the same lock-step discipline (trace builders count every lookup the AIR emits).
Consumers:

- **ALU bitwise ops** (`and/or/xor` and the `-i` forms): each byte limb `A_i` of the
  operands is split into nibbles `A_i = AL_i + 16·AH_i`; the row emits 8 nibble lookups
  `[AL_i, BL_i, CL_i]`, `[AH_i, BH_i, CH_i]` and the constraint `C_i = CL_i + 16·CH_i`.
  The nibble columns reuse the op-exclusive scratch columns (`Q0..3, S0..3, T0..3` are
  unused on bitwise rows) plus 12 new columns; exact assignment in the plan.
- **Sign bits** (`slt`, `sra`, `sll` top limb): `AND4[AH_3, 8, SA·8]` replaces
  `AND8[A_3, 128, SA·128]`, where `AH_3` is the high nibble of the top limb.
- **Shift amount**: `AND4[BL_0, 15, SHL]` and `AND4[BH_0, 1, SHH]`, `SH = SHL + 16·SHH`.
- **cpu alignment** (`MEM_ADDR < 2^30`): `AND4[MA3_hi, 0xC, 0]` with `MA3 = MA3_lo + 16·MA3_hi`
  and `RANGE8` on `MA0..MA3` unchanged.
- **memory** `D0..3` range checks: unchanged (`RANGE8`).

`Tier` is untouched; the two tables have fixed height 256. `log_ext_degrees` and
`Traces` get six matrices (program, cpu, memory, alu, range, nibble).

### M2.4 Collapse the ALU lookups

Per-row lookup budget goes from up to 22 to at most 14, without weakening any range
argument:

1. On bitwise rows the eight nibble lookups already bound `A`, `B`, `C`; the twelve
   `RANGE8` limb lookups are gated by `is_real − and − or − xor` instead of `is_real`.
2. The two sign-bit lookups become one `AND4` lookup whose operand nibble is selected by
   the op (`slt`/`sra` use `AH_3`; `slt` additionally needs `BH_3`; the second lookup
   stays but is gated by `slt` only, so at most one extra lookup on `slt` rows).
3. `Q`, `S`, `T` limb checks stay op-gated as today.
4. The `add/sub` `C` limb checks stay (a wrong carry choice would otherwise make a limb
   negative and pass the field identity).

Every gate remains a sum of boolean selectors so `Count::bounded(gate, 1)` holds, and
the "count zero where columns unconstrained" invariant is re-verified for every new
gate in a cheating test that bumps a multiplicity on a padding row.

Target ALU width after M2.3 + M2.4: ≤ 56 columns (from 49 + nibble scratch − removed
sign columns). The plan fixes the exact layout.

### M2.5 Sub-word loads and stores

ISA: `LB LH LW LBU LHU SB SH SW` decode (`funct3` 0,1,2,4,5 for loads; 0,1,2 for
stores). `Instr::Load { rd, rs1, imm, width: Width, signed: bool }` and
`Instr::Store { rs1, rs2, imm, width }` replace `Lw`/`Sw`; `Width ∈ {Byte, Half, Word}`.

Memory stays **word-addressed** (`space=1`, `addr = byte_addr >> 2`). Semantics
(emulator, the reference):

- `off = byte_addr & 3`. `LW`/`SW` require `off = 0`, `LH`/`LHU`/`SH` require `off ∈ {0,2}`;
  otherwise `ExecError::Misaligned` (RISC-V allows trapping on misalignment).
- Load: read word `W`; `LB` → sign-extend byte `off`; `LBU` → zero-extend; `LH`/`LHU`
  → half at `off`; `LW` → `W`.
- Store: read word `W` (old), merge `rs2`'s low byte/half at `off` (or replace for `SW`),
  write the merged word. Every store is a read-modify-write of one word.

cpu table:

- New selectors `IS_LB, IS_LH, IS_LW` (loads) and `IS_SB, IS_SH, IS_SW` (stores) replace
  `IS_LOAD`/`IS_STORE` as one-hot groups (`IS_LOAD = ΣIS_L*`, `IS_STORE = ΣIS_S*` as
  expressions); `SIGNED` selector for `LB`/`LH`.
- Offset from the alignment limbs: `OFF0, OFF1` booleans with
  `MA0 = 4·MQ + OFF0 + 2·OFF1`, `MQ` range-checked (`RANGE8` on `MQ` and the identity
  bounds it to `[0,64)`); alignment: `IS_LW·(OFF0 + OFF1) = 0`, `IS_LH·OFF0 = 0`, same
  for stores.
- Word limbs `W0..3` of the memory word (`RANGE8` each, `MEM_VAL = ΣW_i·256^i`), byte
  selection `SEL_k = [off = k]` as products of `OFF0/OFF1`, selected byte
  `BYTE = ΣSEL_k·W_k`, selected half `HALF = (1−OFF1)·(W0 + 256·W1) + OFF1·(W2 + 256·W3)`.
- Sign extension: `SGN` boolean = top bit of `BYTE` (byte) or of the half's top limb,
  obtained by one `AND4[hi nibble, 8, SGN·8]` lookup (the hi nibble is a new column with
  `limb = lo + 16·hi`, `AND4` bounding both). `C = IS_LB·(BYTE + SGN·SIGNED·(2^32−2^8))
  + IS_LH·(HALF + SGN·SIGNED·(2^32−2^16)) + IS_LW·MEM_VAL` (as a field identity; the
  result is a canonical 32-bit value because the added constants complete the two's
  complement).
- Stores: rs2 limbs `B0..3` (`RANGE8`), merged limbs
  `MERGED_k = W_k + SEL'_k·(B_k' − W_k)` where `SEL'` selects the bytes the store
  overwrites (one byte for `SB`, two for `SH`, all four for `SW`) and `B_k'` is the
  rs2 byte that lands in position `k` (`B_0` for `SB`; `B_0,B_1` for `SH`; `B_k` for
  `SW`). `MERGED = ΣMERGED_k·256^i`.
- Memory bus: the `SLOT_MEM` send is always a read for loads and stores (`is_write = 0`);
  the `SLOT_W` send, which stores never used, carries the write:
  `[IS_STORE, IS_STORE·MEM_ADDR + (1−IS_STORE)·RD, ts(SLOT_W), IS_STORE·MERGED + (1−IS_STORE)·C, 1]`
  with count `WRITES_RD + SYS_READ + IS_STORE`. This keeps four timestamp slots per
  cycle. The `2c8a39d` pin ("a store's `mem_val` is the rs2 value") becomes "a store's
  written value is `MERGED`, and `MERGED = B` when `IS_SW`".
- `IS_ECALL` rows keep reading `a1` through `SLOT_MEM` as today.

Cheating tests (each must reject): a store whose merged word differs from the emulator's
(wrong byte replaced); a `LB` whose sign extension is flipped; a misaligned `LH`
accepted by the AIR; a `SB` that changes a byte outside `off`.

### M2.6 M extension

`AluOp` gains `Mul, Mulh, Mulhu, Mulhsu, Div, Divu, Rem, Remu` (`COUNT` 11 → 19, eight
new one-hot flags). Decode: `OP_ALU` with `funct7 = 1`. Emulator semantics per the
RISC-V spec: `DIV` by zero → `0xFFFF_FFFF`, `REM` by zero → dividend, signed overflow
(`MIN / −1`) → `MIN`, remainder 0.

Multiplication is proved as an **exact integer identity over 16-bit halves**, because
`HI·2^32 + LO` with `HI, LO < 2^32` can exceed the Goldilocks modulus (a prover could
choose `HI = 2^32−1, LO = A·B + 1` for small products; this attack is a required
cheating test). With `A = AL + 2^16·AH`, `B = BL + 2^16·BH`:

```
T0 = AL·BL            (< 2^32)
T1 = AL·BH + AH·BL    (< 2^33)
T2 = AH·BH            (< 2^32)
LO = T0 + 2^16·T1 − 2^32·CARRY,  CARRY ∈ [0, 2^17) range-checked (RANGE8 × 3 limbs)
HI = T2 + CARRY
```
`AL/AH/BL/BH` are sums of the existing byte limbs; `LO`, `HI` are decomposed into byte
limbs (`RANGE8`). Every intermediate is below 2^34, so no term wraps. `MUL` returns
`LO`; `MULHU` returns `HI`; `MULH`/`MULHSU` apply the sign correction
`HI_signed = HI − SA·B − SB·A` (mod 2^32, with a borrow column, `MULHSU` uses only `SA`),
where `SA`, `SB` are the existing sign-bit columns.

Division (`DIVU`/`REMU`): `A = Q·B + R`, `R < B` when `B ≠ 0`, `Q`, `R` decomposed into
byte limbs. `Q·B < 2^64 − 2^33 + 2 < p` for 32-bit operands, and `Q·B + R ≥ p` would
need `R > 2^32`, so the field identity is exact (this argument is written in
`docs/02-tables-and-buses.md`). `R < B` via the existing compare adder
(`B − R − 1` non-negative, limb range-checked). `B = 0` handled by a selector
`DIVZ` (`B·INVB = 1 − DIVZ`, `INVB` witness): `Q = 2^32−1`, `R = A`. Signed variants take
absolute values through `SA`/`SB` (`|x| = x + SA·(2^32 − 2x)` as a field identity with
the limb decomposition of `|x|` range-checked), divide unsigned, then fix the signs of
`Q` and `R`; overflow (`A = 2^31`, `B = 2^32−1`) via a selector `OVF` with
`Q = 2^31`, `R = 0`.

Cheating tests: the `HI = 2^32−1` product attack; `R ≥ B`; a wrong `DIVZ` on a nonzero
divisor; sign flip on `MULH`.

Guest: `tests/emulator.rs` and a new `guests::muldiv` covering every new op with
positive and negative operands, `MIN / −1`, and division by zero; it proves and
verifies (added to `guests::all()`).

---

## Milestone 3

### M3.1 Poseidon2 chip (`tables/poseidon2.rs`), approach A

Width 8 Goldilocks Poseidon2 with the crate's existing constants
(`Perm::new_from_rng_128(StdRng::seed_from_u64(PERM_SEED))`, 4 + 22 + 4 rounds), one
**row per round**, one permutation per aligned **32-row block** (30 round rows and 2
idle rows).

Preprocessed columns (height = table height, periodic with period 32):
`RC0..7` (round constants for the row's round; 0 on idle rows), `IS_FULL`, `IS_PARTIAL`,
`IS_FIRST` (row 0 of a block), `IS_LAST` (row 29), `IS_IDLE`.

Main columns: `IS_REAL`, `MULT`, `S0..7` (state entering the row), `X3_0..7` and
`X7_0..7` (S-box intermediates: `X3 = (S+RC)^3`, `X7 = X3·X3·(S+RC)`, degree-3
constraints), `IN0..7` (the block's input state, copied down every row of the block).

Constraints:
- Row 0 of a block: `IN = S`; `S` after the initial MDS-light layer is the state the
  first full round sees (the first round row applies the initial linear layer before
  its constants, matching Plonky3's `external_initial_permute_state`).
- Full round row: `X7_i` as above for all `i`; next `S = MDS_light(X7)`.
- Partial round row: `X7_0` only; `X7_i = S_i` for `i > 0` (no S-box); next
  `S = internal_matmul(X7)` with the diagonal `[-2, 1, 2, 1/2, 3, -1/2, -3, -4]`.
- `IN_next = IN` within a block; `IS_REAL_next = IS_REAL` within a block.
- On idle rows nothing is constrained except `MULT = 0`.
- Bus `POSEIDON2` (new): on the last round row of a real block,
  `table_entry([IN0..7, S_next0..7], MULT)`; `MULT = 0` unless `IS_REAL·IS_LAST`.
  (Count discipline: `MULT` is forced zero everywhere the message is unconstrained.)

Trace builder: one block per permutation event from the emulator, in event order;
padding blocks are all-zero with `IS_REAL = 0`. Height `Tier::poseidon2_height(t) = 2^t`
(2^(t−5) permutations: 32 at tier 10, 128 at tier 12, …). `Traces` gains the matrix;
`chips()` appends the chip **after** the CPU (the `i == 1` public-values convention
must not move).

Tests: (1) the table's transition function reproduces `Poseidon2Goldilocks<8>::permute`
on 10⁴ random states, checked round by round against `p3_poseidon2`'s scalar layers;
(2) `tests/tables.rs` constraint check on a trace of random permutations; (3) cheating:
a tampered `X7`, a tampered `IN` copy, and a bumped `MULT` on an idle row are rejected.

### M3.2 `POSEIDON2` syscall

`SYS_POSEIDON2 = 3`. Register contract: `a7 = 3`, `a0 = ptr` (word-aligned), `a1 = n`
(word count, `0 ≤ n ≤ 4096`). Semantics (emulator): read `n` words `w_0..w_{n−1}` at
`ptr`, run the padding-free sponge `PaddingFreeSponge<Perm, 8, 4, 4>` over them as
field elements (each `u32` word is one element), and write the 4 digest elements as
**8 words** (`lo, hi` of each `u64`, canonical) at `ptr`. `n = 0` writes the hash of
the empty input (all-zero state, no permutation → digest `[0;4]`).

cpu table: a `POSEIDON2` call occupies the ecall row plus `ceil(n/4) + 2` **hash rows**:

- Ecall row (`SYS_HASH` selector, joins `sys_sum`): reads `a7`, `a0` (`SLOT_R1/R2`) and
  `a1` (`SLOT_MEM`, as every ecall); pins `HASH_PTR = B` (a0), `HASH_N = MEM_VAL` (a1),
  initialises `HS0..7 = 0`, `HASH_LEFT = HASH_N`, `NEXT_PC = PC` (the instruction is not
  finished), `HASH_IDX = 0`.
- Absorb rows (`IS_HASH` selector, `pc` unchanged, `clk` advances): read up to 4 words at
  `HASH_PTR + 4·HASH_IDX + {0,1,2,3}` through the four timestamp slots (all reads;
  a slot with no word left sends count 0 and its value column is pinned to the previous
  state lane), overwrite lanes `S0..3` with the words, and look up
  `POSEIDON2[state_in, state_out]` with count 1; the next row's `HS = state_out`.
  `HASH_LEFT` decreases by the number of words absorbed; `HASH_IDX` increases by 1.
  `HASH_LEFT`, `HASH_IDX` are range-checked (`RANGE8` × 2 limbs).
- Two write rows (`IS_HASH_OUT`): write the 8 digest words (4 per row, `is_write = 1`)
  at `HASH_PTR + {0..3}` and `{4..7}`; the second sets `NEXT_PC = PC + 4` and ends the
  instruction.
- Columns added: `SYS_HASH, IS_HASH, IS_HASH_OUT, HASH_PTR, HASH_N, HASH_LEFT, HASH_IDX,
  HS0..7, HV0..3` (the four words of the row), and their limbs — about 24 columns. Every
  new bus message column is pinned on every row kind that sends it (AGENTS.md
  invariant 1); every count is a boolean selector product (invariant 2).
- Hash rows count as cycles for tier selection (`exec.cycles()` includes them).

Emulator: `Syscall::Poseidon2 { ptr, n }` emits the memory accesses and a
`HashEvent { input: Vec<u32>, permutations: Vec<[u64; 8] in/out> }` consumed by the
Poseidon2 trace builder.

Cheating tests: a digest word tampered (rejected by the write-row pin), a state lane
tampered between absorb rows, a `POSEIDON2` lookup with count 1 on a non-hash row.

### M3.3 Note-layer primitives on the chip

`arx.rs` is retired for note commitments and nullifiers. `notes.rs`/`viewing.rs`
switch `hash(domain, msg)` to the syscall-backed Poseidon2 sponge with the domain tag
as the first absorbed word (`[domain, msg...]`), producing 8-word (256-bit) commitments,
nullifiers and keys (the "development widths" placeholder ends). Guest-side wrappers
in `asm.rs`:

- `NOTE_COMMIT(note_ptr) → cm` = `POSEIDON2` over `[CM_DOMAIN, note words]`,
- `NULLIFY(nk_ptr, rho, cm_ptr) → nf` = `POSEIDON2` over `[NF_DOMAIN, nk, rho, cm]`
  (the M1.5 "nullifier bound to the commitment" form),
- `MERKLE_VERIFY(leaf_ptr, path_ptr, index, depth) → root` = `depth` compressions
  `POSEIDON2` over `[NODE_DOMAIN, left(8), right(8)]` choosing the order from the index
  bits; `depth = 32`.

These are guest library routines (no new syscall numbers) so the chip stays minimal.
The `transfer` guest moves `cm_in` from a public output to a Merkle witness: it reads
the path from private input, proves membership against an `anchor` public output, and
publishes `[anchor, nf, cm_out, time_out]`. The simulated `Ledger` keeps an append-only
commitment tree (host-side, same hash) and checks the anchor against recent roots.

Cycle budget: one permutation per 4 absorbed words; a transfer with a 32-deep membership
proof is ≈ 5 + 32·(1 + 4) permutations and well under tier 12's 128-permutation budget
(the cpu-row cost is `≈ 6 rows per hash call + 2 per absorbed block`).

### M3.4 Program digest in-circuit

The program table stops being preprocessed: `ProgramAir`'s columns
`(PC, WORD, FIELDS[18], VALID)` become **main** trace committed by the prover, and an
**in-circuit decoder** proves `FIELDS = decode(WORD)`: 32 boolean bit columns of `WORD`
(each boolean, `WORD = Σ bit_i·2^i`), and each decoded field as a linear function of
the bits with selector logic mirroring `Instr::decode` (opcode/funct3/funct7 one-hot
from bits, register indices and immediates as bit sums, illegal encodings forced to
`VALID = 0`). The `PROGRAM` bus contract is unchanged.

The digest: the cpu trace begins with `⌈len/4⌉` **digest rows** (`IS_DIGEST`) before
the first instruction row. Each looks up 4 consecutive program words through the
`PROGRAM` bus keyed by `PC` (the program table's multiplicity accounts for one extra
lookup per word) and absorbs them through the `POSEIDON2` bus exactly like hash rows,
with the running state in `HS0..7`; the last digest row pins the 8 digest words to new
public values `pv::HC0..HC7`. `verify(hc: &[u32; 8], proof)` replaces
`verify(program, proof)`: it checks `pv[HC..] == hc`, `pv[PC_ENTRY]` against the
proof's declared entry, and no longer needs the program. The verifier key becomes
program-independent (only the two 256-row tables are preprocessed) and is computed
once per `Machine`; M2.1's cache collapses to a single entry keyed by tier.

`code_hash` becomes the in-circuit digest (`hc` = Poseidon2 sponge over
`[HC_DOMAIN, base_pc, len, words...]`), computed host-side by `Program::digest()`.

Trade-off recorded: proving cost rises by `len` program-table rows with a 32-bit
decoder and `⌈len/4⌉` permutations (543-word transfer: 136 permutations, i.e. tier 12
still fits with the membership proof only if the Poseidon2 table height is
`2^(t+1)`; the plan measures and sets `poseidon2_height` accordingly).

Deployment consequence (fullnode, later spec): programs are identified by `hc`,
verification needs only `hc` and the proof, and a program's words can stay private
(published only inside an envelope) — the prerequisite for private programs on the
fully shielded chain.

### Ordering and dependencies

M2.1 → M2.2 → M2.3 → M2.4 → M2.5 → M2.6 (each independently mergeable; docs re-measured
each step). M3.1 → M3.2 → M3.3 → M3.4. M3.4's decoder can start after M2.6 (it needs
the final ISA). M3.3 touches `notes.rs`/`viewing.rs`, which another session edits;
that step rebases onto the latest `main` immediately before starting.

### Testing summary

- Every step keeps `cargo test` green and adds cheating tests for every new row kind
  and bus count (AGENTS.md).
- Poseidon2 chip equality with `Poseidon2Goldilocks<8>` is the M3 correctness anchor,
  as Plonky3 equality was for the CUDA backend.
- The measured tables in `README.md`, `docs/01`, `02`, `03`, `05` are updated in the
  commit that changes them.
