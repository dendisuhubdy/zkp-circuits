# rVM `MODQ` chip: Dilithium2's ring arithmetic as a coprocessor (private multisig, phase 3)

> Status: **design, 2026-10-11.** Nothing here is built. Parent spec:
> `docs/superpowers/specs/2026-10-11-private-multisig-design.md` (§6 cost, §7 phase 3). Plan:
> `docs/superpowers/plans/2026-10-11-rvm-modq-chip.md`.

## 0. Summary

| question | answer |
|---|---|
| granularity | a **polynomial-op family** on one optional table: `NTT`, `INTT`, `DOT4` (`Σ_{k<4} a_k∘b_k`), `MSUB4` (`w_k ← w_k − c∘t_k`). One cpu row per call, one 1 024-row chip block per call, 18 calls per verification |
| syscall | **`MODQ = 8`**: `a0` = word address of a polynomial arena, `a1` = packed op and poly offsets. The parent spec's "syscall 7" is stale: 7 is `POSEIDON2_LEN` (HCS-4) |
| AIR | 59 main + 16 preprocessed columns (+5 blind), about 62 constraints, maximum degree 3, 39 interactions (29 `RANGE8`, 5 `MEMORY`, 4 `MODQ_WIRE`, 1 `MODQ`). Exact integer arithmetic: `O + K·q = α·U + β·V (+γ)`, with byte limbs on `U, V, W, O, q−1−O, K` |
| output form | canonical `[0, q)`. Not bit-equal to the reference's unreduced `ntt`, but the `w1` that reaches `use_hint` equals the reference's `caddq(w1)` exactly, so accept/reject is identical on every input (§3.6) |
| cycles per verification | measured today 880 102. Chip only: about **304 k**. Chip plus the software trims of §4 (`use_hint`/`w1_pack` included, ruling 4): about **79 k** (range 67–91 k) |
| tier at `M_MAX = 3` | about **253 k cycles** (msauth, digest rows included; range 217–289 k), against tier 18's 262 143: inside it at the central estimate, with no margin. **Ruling: the target is tier 18 only, never 19 or 20.** If the measured `M = 3` misses, `M_MAX = 2` at tier 18 and `UNIFORM` is phase 3b (§4.3) |
| fork | constraint set: the cpu table gains one column, so every verifier key changes. The `Proof` gains one `u8`. Chip-free proofs grow about 1 KB; chip-bearing ones about 75 KB. Lands after rVM phase 4, then one recursion re-pin |

## 1. Where the 880 k cycles go (measured)

Phase 1 recorded the total. To split it, the committed guest ELF
(`guests-compiled/dilithium-verify/target/riscv32im-unknown-none-elf/release/dilithium-verify-guest`)
was run in a throwaway RV32IM profiler. The profiler counted every PC and attributed each hot loop by
reading its disassembly. Input: a 45-byte message, a random key, and a signature with `z = 0` and no
hints. The verify runs to the final `c̃` compare. Result: **877 782 cycles and 99 `KECCAK` calls**,
against the 879 970 measured for an invalid signature (0.25% apart).

| part | cycles | share | per unit |
|---|---:|---:|---|
| 9 forward NTTs (`z`×4, `c`, `t1`×4) | 271 966 | 31.0% | 30.2 k per NTT: 25 cycles per butterfly × 1 024 |
| 4 `invntt_tomont` | 147 640 | 16.8% | 36.9 k each, 4.6 k of it the final `F` scaling |
| `A·z` (16 `pointwise_montgomery` + 12 adds) | 108 562 | 12.4% | 21 cycles per product, 7 per add |
| `c·t1` (4), `shiftl` (4), `sub`/`reduce32`/`caddq` | 47 766 | 5.4% | |
| **ring arithmetic, subtotal** | **575 934** | **65.6%** | the chip's target |
| `ExpandA` (`rej_uniform` 82 k + squeeze-to-bytes 51 k) | 135 318 | 15.4% | 33 cycles per coefficient |
| input words to bytes in `main` (pk 1 312 B + sig 2 420 B) | 36 008 | 4.1% | 9–10 cycles per byte |
| zero-initialised buffers (`memset`, 47 KB) | 36 461 | 4.2% | `Poly*::default()` |
| SHAKE glue (u64-lane split/join per permute, byte absorb) | 40 185 | 4.6% | 285 cycles per `KECCAK` call |
| unpack `t1`, `z`, `chknorm` | 26 654 | 3.0% | |
| `use_hint` + `w1_pack` | 20 201 | 2.3% | |
| other (challenge, `mu`, compare) | 7 021 | 0.8% | |

Keccak itself is 99 cpu rows. **Two thirds of the cost is ring arithmetic, and one third is
software that a ring chip does not touch.** Section 4 deals with that third; without it the chip
alone stops at about 304 k per verification.

## 2. Granularity (question 1)

Columns: `S` = everything that is not ring arithmetic. That is 301.8 k as built today and about 79 k
after the §4 trims. Chip rows and memory accesses are per verification.

| option | ring cost on the cpu | cycles per verify (`S` = 79 k) | chip rows | chip memory accesses | verdict |
|---|---:|---:|---:|---:|---|
| (a) whole-transform only (`NTT`, `INTT`); pointwise stays in software | 156 k (Montgomery `A·z`, `c·t1`, sub/reduce/caddq) | ≈ 235 k | 13 312 | 6 656 | M = 3 ≈ 730 k → tier 20. ✗ |
| (b) per-layer call (one call per NTT layer through memory) | 13 × 8 + 5 = 109 calls ≈ 0.6 k | ≈ 80 k | 18 432 | 65 792 | same rows as (d), 3.4× the memory traffic, 6 extra range lookups per row on every layer's inputs. Fallback only, if the wire bus (§3.4) proves troublesome |
| (c) butterfly-per-call (or `MULMOD` in a register) | 18 432 calls × ≈ 6 cycles of glue ≈ 110 k (`MULMOD`: ≈ 200 k) | ≈ 189 k (≈ 279 k) | 18 432 | 36 864 | the cpu still pays a row per butterfly. M = 3 ≈ 600 k → tier 20. ✗ |
| **(d) polynomial-op family** | **18 calls ≈ 0.1 k** | **≈ 79 k** | **18 432** | **19 200** | **recommended** |

**Recommendation: (d).** One 1 024-row block per call, and four ops:

| op (`a1` bits 0–1) | effect, all mod `q`, outputs canonical | calls per verify | reads | writes |
|---|---|---:|---:|---:|
| `NTT` = 0 | `p ← NTT(p)` in place: 8 CT layers, ζ from the reference `ZETAS` | 9 | 256 | 256 |
| `INTT` = 1 | `p ← NTT⁻¹(p)` in place: 8 GS layers, `n⁻¹` fused into the last | 4 | 256 | 256 |
| `DOT4` = 2 | `out[c] ← Σ_{k<4} a_k[c]·b_k[c]` (one row of `Â·ẑ`) | 4 | 2 048 | 256 |
| `MSUB4` = 3 | `w_k[c] ← w_k[c] − ĉ[c]·t_k[c]` for `k < 4` (the `− ĉ∘t̂1` term) | 1 | 2 304 | 1 024 |

The verification then makes 9 + 4 + 4 + 1 = 18 calls. That is `ẑ` ×4, `ĉ`, `t̂1` ×4, then
`w_i = DOT4(Â_i, ẑ)` ×4, then `w −= ĉ∘t̂1`, then `INTT(w_i)` ×4. Dilithium2's `K = L = 4` makes
every pointwise op exactly 4 × 256 = 1 024 lanes, the same block height as a transform, so all four
ops share one block size and one preprocessed period.

## 3. The chip

### 3.1 Syscall ABI

`a7 = 8` (`isa::SYS_MODQ`). `a0` (`B`) is `BASE`: the word address of an arena of 256-word
polynomials. `a1` (`MEM_VAL`, already read and register-bound on every ecall row) is the op word:

```
a1 = op | OUT << 8 | A << 16 | B << 24        op ∈ {0,1,2,3};  OUT, A, B ∈ [0, 32)  (poly indices)
reserved bits 2..8, 13..16, 21..24, 29..32 must be zero
poly i of the arena = words BASE + 256·i .. BASE + 256·i + 255
```

`NTT`/`INTT` use `OUT` only, and `A = B = 0` is required. `DOT4` reads polys `A..A+4` and `B..B+4`
and writes poly `OUT`. `MSUB4` reads and writes `OUT..OUT+4`, reads poly `A` (the broadcast `ĉ`) and
reads `B..B+4`. The highest word touched is `BASE + 256·(31 + 3) + 255 = BASE + 8 959`. The emulator
refuses `BASE > MODQ_PTR_LIMIT = 0x3000_0000 − 8 960`. The cpu's existing cubic rule
(`HP3_HI ∈ {0,1,2}`, so `BASE < 0x3000_0000`) keeps every chip address below `2^30`. That rule is
the CRITICAL-1 key-aliasing argument, unchanged.

Emulator semantics (`modq::call`): decode `a1` (`ExecError::ModqArgs` on any reserved or unused bit),
check the aliasing rules of §5 (`ExecError::ModqAlias`), read every input (any read word
`≥ 2^24` → `ExecError::ModqCoefficient`), compute, then write. Reads are at slot 0
(`ts = 4·clk`) and writes at slot 1 (`ts = 4·clk + 1`), exactly as `SHA256`'s are. So every read
sees the pre-call state, and in-place ops are well defined.

### 3.2 The cpu side

The only cpu-table change is one appended column, `SYS_MODQ` (`WIDTH` 282 → 283, `SELECTORS` 31 →
32). Its rules are the `SYS_SHA256` block, copied:

- `SYS_MODQ · (A − 8) = 0`
- `HASH_PTR = B`, bounded by adding `SYS_MODQ` to `hp_gate`, plus the cubic `HP3_HI` rule
- `HASH_N`, `HASH_LEFT`, `HASH_IDX` and `HS0..7` pinned to zero
- `off_cpu · SYS_MODQ = 0`
- `SYS_MODQ` added to `sys_sum`
- gas weight `MODQ_GAS − 1` added to `w_next`
- `bus::MODQ.lookup_key([CLK, HASH_PTR, MEM_VAL], SYS_MODQ)`

`MEM_VAL` is not pinned, for the reason `SYS_SHA256`'s comment gives: it is the `a1` register read.

### 3.3 The block (1 024 rows, period of the preprocessed columns)

Row `r` is read two ways at once. **Transform view:** stage `p = r >> 7`, butterfly `b = r & 127`.
**Pointwise view:** coefficient `c = r >> 2`, poly `k = r & 3`, with `k` fastest, so a `DOT4` sum is
four adjacent rows.

- NTT stage `p`: `len = 128 >> p`, `g = b / len`, `j = 2·len·g + b % len`, pair `(j, j+len)`,
  `ζ = ζ_{2^p + g}`.
- INTT stage `p`: `len = 1 << p`, same `j` formula, `k = (256 >> p) − 1 − g`, `ζ' = q − ζ_k`. This is
  the reference's GS order exactly.
- `ζ_k = ZETAS[k] · 2^{−32} mod q = 1753^{brv8(k)} mod q`, canonical.
- `f = 256^{−1} mod q = 8 347 681`.

**Preprocessed (16):**

| columns | meaning |
|---|---|
| `IS_FIRST`, `IS_LAST` | block's first and last row |
| `STAGE` | `p` |
| `S_FIRST`, `S_LAST` | `p = 0`, `p = 7` |
| `JF`, `VF` | NTT pair `(j, j+len)` at stage `p` |
| `JI`, `VI` | INTT pair `(j, j+len)` at stage `p` |
| `ZF` | NTT `ζ` |
| `FI` | INTT outer factor: 1, or `f` at stage 7 |
| `ZI` | INTT `ζ'`, or `f·ζ'` at stage 7 |
| `PK`, `PC` | `k`, `c` |
| `K_FIRST`, `K_LAST` | `k = 0`, `k = 3` |

**Main (59):**

| columns | what |
|---|---|
| `IS_REAL`, `CLK`, `BASE`, `A1` | 4: block-constant; the `MODQ` handshake |
| `IS_NTT`, `IS_INTT`, `IS_DOT`, `IS_MSUB` | 4: block-constant one-hot op, sum = `IS_REAL` |
| `OUT_BITS`, `A_BITS`, `B_BITS` | 15: block-constant 5-bit offsets |
| `U_L`, `V_L`, `W_L` | 9: byte limbs of the inputs `U, V` and the multiplier `W` (each `< 2^24`) |
| `O0_L`, `D0_L`, `K0_L` | 3 + 3 + 4: output 0, `q − 1 − O0` and its quotient |
| `O1_L`, `D1_L`, `K1_L` | 3 + 3 + 4: output 1, likewise |
| `IDX_U`, `IDX_V` | 2: the op-selected pair indices (keep the bus messages degree 1) |
| `ADDR_U`, `ADDR_V`, `ADDR_W`, `ADDR_O0`, `ADDR_O1` | 5: the op-selected memory addresses |

`U = Σ U_L[i]·256^i`, and likewise for the others. `U`, `V`, `W`, `O`, `D` and `K` are linear forms,
not columns. The blind adds its 5 columns as for every table (`Chip::width`), so 64 main in all.

### 3.4 Constraints

With `T = IS_NTT + IS_INTT`:

1. **Booleans and shape.** `IS_REAL`, the four op bits and the 15 offset bits are boolean. The
   one-hot sum is `IS_REAL`. The column `A1` (the `a1` word) is `A1 = IS_INTT + 2·IS_DOT + 3·IS_MSUB + 2^8·OUT + 2^16·A + 2^24·B`.
   Because the bits are boolean and the reserved positions are absent, an `a1` with a reserved bit
   set has no satisfying assignment. Canonical args: `T·A = 0` and `T·B = 0`. Block constancy:
   `(1 − IS_LAST)·(next − cur) = 0` for all 23 block-constant columns.
2. **The arithmetic** (degree 3). Every term is a non-negative integer below `2^50 ≪ p` except the
   `−IS_MSUB·W·V` term, which `γ1` offsets. (The coefficients are `α`/`β`/`γ`, not `A`/`B`, so they cannot be confused with the `A1` column or the `A`/`B` offsets.) So each field identity is an integer identity, and with
   `O ∈ [0, q)` it fixes `O = (RHS mod q)` and `K = ⌊RHS/q⌋` uniquely.
   ```
   O0 + q·K0 = α0·U + β0·V
   O1 + q·K1 = α1·U + β1·V + γ1
   α0 = IS_NTT + IS_INTT·FI + IS_DOT          β0 = IS_NTT·ZF + IS_INTT·FI + IS_DOT·W
   α1 = IS_NTT + IS_INTT·ZI + IS_MSUB         β1 = IS_NTT·(q − ZF) + IS_INTT·(q − ZI) − IS_MSUB·W
   γ1 = IS_MSUB·q·2^26
   q − 1 − O0 = D0      q − 1 − O1 = D1
   ```
   - NTT row: `(u + ζv, u − ζv)`, the CT butterfly.
   - INTT row: `(FI·(u + v), ZI·(u − v))`, the GS butterfly, with `n⁻¹` on stage 7.
   - `DOT4` row: `O0 = U + W·V` and `O1 = 0`. `MSUB4` row: `O1 = U − W·V` and `O0 = 0`.
   - The unused output is forced to zero by its zero coefficients. `T·W = 0` pins the multiplier off
     the pointwise ops.
3. **Indices and addresses** (degree 2). `IDX_U = IS_NTT·JF + IS_INTT·JI` and
   `IDX_V = IS_NTT·VF + IS_INTT·VI`. With `P(i) = BASE + 256·i`:
   ```
   ADDR_U  = T·(P(OUT) + IDX_U) + IS_MSUB·(P(OUT + PK) + PC)
   ADDR_V  = T·(P(OUT) + IDX_V) + IS_DOT·(P(A + PK) + PC) + IS_MSUB·(P(B + PK) + PC)
   ADDR_W  = IS_DOT·(P(B + PK) + PC) + IS_MSUB·(P(A) + PC)
   ADDR_O0 = T·(P(OUT) + IDX_U) + IS_DOT·(P(OUT) + PC)
   ADDR_O1 = T·(P(OUT) + IDX_V) + IS_MSUB·(P(OUT + PK) + PC)
   ```
4. **Pointwise chaining.**
   - `IS_DOT·K_FIRST·U = 0`: each sum starts at 0.
   - Transition `IS_DOT·(1 − K_LAST)·(next.U − O0) = 0`: the running sum.
   - Transition `IS_MSUB·(1 − K_LAST)·(next.W − W) = 0`: `ĉ[c]` is read once on `k = 0` and carried.
     Reading it four times at one timestamp would break the memory table's strict `(addr, ts)` order.
5. **`MODQ_WIRE`** (a `PermutationCheckBus`, new). It carries a transform's 7 inter-stage hand-offs
   without touching memory. Sends `[CLK, STAGE+1, IDX_U, O0]` and `[CLK, STAGE+1, IDX_V, O1]` with
   count `T·(1 − S_LAST)`. Receives `[CLK, STAGE, IDX_U, U]` and `[CLK, STAGE, IDX_V, V]` with count
   `T·(1 − S_FIRST)`. Each `(CLK, stage, index)` key is produced once and consumed once in a real
   block. `CLK` is unique per real block because `MODQ` is a lookup with no `MULT`. So the multiset
   equality fixes every hand-off's value.
6. **`MEMORY`** (the chip sends, the memory table records, as `sha256`):

   | message | count |
   |---|---|
   | `[RAM, ADDR_U, 4·CLK, U, 0]` | `T·S_FIRST + IS_MSUB` |
   | `[RAM, ADDR_V, 4·CLK, V, 0]` | `T·S_FIRST + IS_DOT + IS_MSUB` |
   | `[RAM, ADDR_W, 4·CLK, W, 0]` | `IS_DOT + IS_MSUB·K_FIRST` |
   | `[RAM, ADDR_O0, 4·CLK+1, O0, 1]` | `T·S_LAST + IS_DOT·K_LAST` |
   | `[RAM, ADDR_O1, 4·CLK+1, O1, 1]` | `T·S_LAST + IS_MSUB` |

7. **`MODQ`**: `table_entry([CLK, BASE, A1], IS_REAL·IS_FIRST)`. As in `sha256`, with no `MULT`,
   a real block is always claimed.
8. **`RANGE8`**: the 29 limb columns, each with count `IS_REAL`.

**Degree and size.** Rule degree ≤ 3. Bus messages are degree 1 and counts degree ≤ 2, so the
instance should measure 3 or 4. Either gives `log_quotient = 2`, as `sha256` (pinned in
`tests/tables.rs`). Rows per verification: 18 432. At `M = 3` that is 55 296 → `modq_log_height = 16`.
Bounds: `MIN_LOG_HEIGHT = 10` (one block, above the private floor 7), flat
`MAX_LOG_HEIGHT = 20`, and `Tier::max_modq_log_height = min(t + 10, 20)` (one call is one cycle).

### 3.5 Range-check strategy

The strategy is byte limbs on the existing `RANGE8` table, with no shifted-limb tricks. A shifted
lookup of `2^k·x` alone does not bound `x`, because non-multiples of `2^{8−k}` map to huge field
elements.

- **Inputs** `U, V, W`: three bytes each, so `< 2^24`. That bound is all the arithmetic needs: with
  `|α|, |β| ≤ q < 2^23`, `|RHS| < 2^50`. Non-canonical inputs in `[q, 2^24)` are accepted and read
  mod `q`. The emulator refuses words `≥ 2^24`, so the two agree on what is provable.
- **Outputs** `O`: three bytes (`O ≥ 0`) plus three bytes of `D = q − 1 − O` (`O ≤ q − 1`). This
  makes the output **canonical and unique**, so the AIR admits exactly the emulator's value.
- **Quotients** `K`: four bytes (`< 2^32`). `K·q < 2^55`, so neither side of the identity can wrap
  mod `p`.

Cost: 29 lookups per row and no new table. The alternative, bit decomposition as `sha256` does,
costs about 210 boolean columns per row. The second alternative, lazy outputs in `[0, 2^24)`, drops
the six `D` lookups but makes outputs non-unique, and every consumer must then canonicalise. It is
rejected for that reason.

### 3.6 Equality with `crystals-dilithium` (the hard requirement)

The chip does **not** reproduce the reference's bits: `ntt` leaves coefficients unreduced in
`(−9q, 9q)`, and the reference carries Montgomery factors. **The guest switches to canonical
values, and the accept/reject result is provably unchanged.** Write `[x]` for `x mod q ∈ [0, q)`.

1. **The reference never overflows on the verify path,** so it computes exact residues.
   - `ntt` grows by `< q` per layer: `< 9q < 2^27`.
   - `montgomery_reduce` inputs stay `≤ 81q² < 2^31·q`.
   - The `A·z − c·t1` accumulator is `< 5q`, inside `reduce32`'s domain.
   - `invntt_tomont`'s lanes are `< 2^8·q` before `F`.

   Hence `montgomery_reduce(a) ≡ a·2^{−32}`, `ZETAS[k] ≡ ζ_k·2^{32}`, `ntt(a) ≡ NTT(a)`,
   `pointwise_montgomery(a, b) ≡ a·b·2^{−32}` and `invntt_tomont(a) ≡ 2^{32}·NTT^{−1}(a)`
   (`F = 2^{64}/256`).
2. **The reference's `w1`.**
   `w_ref = caddq(invntt_tomont(reduce32(Σ_j pm(Â_ij, ẑ_j) − pm(ĉ, t̂1_i))))
   ≡ 2^{32}·NTT^{−1}(2^{−32}·(Σ_j Â_ij∘ẑ_j − ĉ∘t̂1_i)) = NTT^{−1}(Σ_j Â_ij∘ẑ_j − ĉ∘t̂1_i)`.
   `invntt_tomont`'s output lies in `(−q, q)`, so `caddq` returns the canonical residue:
   `w_ref = [NTT^{−1}(…)]`.
3. **The chip's `w1`.** The guest feeds `[z]` (after `chknorm` has run on the centred `z`),
   `[t1·2^{13}]`, `[c]` and the sampled `Â` (already `< q`). The chip's ops are exact mod `q`, with
   canonical outputs, so `w_chip = [NTT^{−1}(…)]` over the same residues. Hence **`w_chip = w_ref`
   word for word.**
4. **Everything else is unchanged software on identical inputs.** Before the chip: unpacking,
   `chknorm`, `mu`, the challenge. After the chip: `use_hint` (which "assumes a standard
   representative", i.e. canonical), `w1_pack`, SHAKE256 and the `c̃` compare. **The boolean is the
   reference's on every input**, malformed ones included, because the early rejections never reach
   the chip. (Task 7 amendment: the
   `chknorm` rejection still returns before the chip; malformed *hint sections* are now detected
   after the ring arithmetic, so they do reach the chip and are rejected unconditionally before
   the c̃ compare. Hint bytes never feed chip inputs, so this is no soundness question; such a
   rejection costs a full verification, about 80 k cycles, prover-side only.)

The guest drops `reduce32`, `caddq` and the separate `shiftl` (`t1·2^{13} ≤ q − 1` is folded into
unpacking). It keeps `chknorm` on the centred `z` and must **not** canonicalise first. That ordering
is a review item.

Executable checks:
- `rand_zkvm::modq` against `dilithium_core::ntt`/`reduce` on random polys, and `intt∘ntt = id`.
- `ζ_k = 1753^{brv8(k)}`.
- The phase-1 suite (200 seeded honest cases, every malformed class, garbage, hint mutations,
  lengths, cross-key) run through three backends: the reference path, `SoftRing`, and `HostModq`,
  which is the emulator's semantics.
- The guest's differential against the host.

## 4. What stays in software, and the totals (question 4)

### 4.1 Software that remains

Input reading, `unpack_pk` (`t1`, fused with `<< 13`), `unpack_sig` (`z` with fused `chknorm` and
canonicalisation, plus the hint decoding and every malformed-hint rejection), the SHAKE256 for
`tr`/`mu`, `challenge` (SampleInBall, with `−1` written as `q − 1`), `ExpandA` (SHAKE128 plus
`rej_uniform`), `use_hint`, `w1_pack`, the final SHAKE256 and the `c̃` compare. In `msauth`, add the
Poseidon2 leaf, path, policy, `nk` and `c`.

### 4.2 Trims that do not change semantics

These are guest and `dilithium-core` refactors, each covered by the KAT suite. None of them is a
consensus change.

| trim | today | after |
|---|---:|---:|
| ring arithmetic → 18 `MODQ` calls | 575 934 | ≈ 100 |
| read input as words into 4-aligned buffers viewed as bytes (`verify_words`) | 36 008 | ≈ 4 700 |
| SHAKE state as the syscall's `[u32; 50]` (`Keccak::permute_words`), word-wise absorb | 40 185 | ≈ 4 000 |
| `ExpandA` straight from state words, 4 candidates per 3 words, no byte squeeze | 135 318 | ≈ 30 000 |
| no zero-fill: a caller-owned `Arena` (a `.bss` static in guests, which the loader zeroes for free) | 36 461 | ≈ 3 000 |
| unpack `t1`/`z` with fused `shiftl`, `chknorm` and canonicalisation | 26 654 | ≈ 18 000 |
| `use_hint` + `w1_pack` (ruling 4: `decompose` on the canonical value with one compare chain; `w1` packed straight into words) | 20 201 | ≈ 12 000 |
| other | 7 021 | ≈ 7 000 |
| **per verification** | **877 782** | **≈ 79 000** (±15%) |

`msauth` adds about 13.3 k per slot today: 895 676 / 1 789 166 / 2 682 525 cycles measured for 1/2/3
signers on this branch, against 880 102 per verify. Reading each `pk` once as words, for both
`MS_LEAF` and verify, brings that to about 4 k. The program and input digests add about 2 k rows.

### 4.3 Totals

The tier is the smallest in `TIERS` with `2^t − 1 ≥ cycles`.

| M | chip only | chip + trims (central; range) | tier: chip only / chip + trims | with `UNIFORM` (3b) ≈ 51 k/verify |
|---|---:|---:|---|---|
| 1 | ≈ 319 k | ≈ 87 k (75–98 k) | 20 / **18** | 18 (padded to `M_MAX`'s shape anyway, §5) |
| 2 | ≈ 636 k | ≈ 170 k (146–194 k) | 20 / **18** | 18 |
| 3 | ≈ 953 k | **≈ 253 k** (217–289 k) | 20 / **18 at or below the centre, else over** | **18** (≈ 169 k) |
| 5 | ≈ 1.59 M (over) | ≈ 419 k (359–479 k) | over / over 18 (not a target) | over 18 at ≈ 279 k (not a target) |

Cycles alone do not pick the tier: `Tier::for_workload(cycles, permutations)` also needs
`32·permutations ≤ 2^(t+2)`, where permutations are the Poseidon2 ones (program, input and public
digests plus `POSEIDON2` absorbs). At `M = 3` that is ≈ 1.2 k + 0.73 k + 3 + ≈ 0.3 k ≈ 2.3 k against
tier 18's 32 768 slots, so it does not bind, but Task 8 computes the tier from both numbers, as the
prover does.

**Measured (Task 8, `GATE:` lines in `research/tests/msauth.rs`):** 85 830 / 169 068 / 251 946 cycles
at `M = 1 / 2 / 3` (estimate ≈ 87 k / 170 k / 253 k), 1 736 / 1 839 / 1 942 Poseidon2 permutations,
all tier 18; the memory table stays at 2^20. **Outcome: `M_MAX = 3` at tier 18; `UNIFORM` is not needed.**

**The gate (controller ruling, 2026-10-11).** The target is **tier 18 only**: never 19, never 20.
Tier 18 is what a 48 GB laptop proves (≈ 33 GB measured), and the private multisig's privacy rests on
users proving their own auth proofs.

- Plan Task 8 measures `M = 3` (cycles, Poseidon2 permutations, then one Production prove with peak
  RSS and `mem_log_height`).
- **If it fits tier 18:** `M_MAX = 3` and the gate is met.
- **If it does not:** `M_MAX = 2` at tier 18. Update `msauth.rs` `M_MAX`, the guest constant and
  `MSAUTH_WORDS`, and re-run the `msauth` suite. A 2-of-3 policy then needs only 2 signatures, so it
  still works; 3-of-5 waits for 3b.
- **Phase 3b, a `UNIFORM` op,** is recorded as the lever back to `M_MAX = 3`. It is rejection sampling
  in the chip: 3 words in, 4 candidates per row, a running output counter, conditional writes.
  - It takes `ExpandA` from ≈ 30 k to ≈ 1 k (−28 k per verify), so `M = 3` ≈ 169 k.
  - It is a second row semantics in the table: about +40 columns, a data-dependent write address, and
    a "full" flag. That is enough new soundness surface for its own spec and cheating suite.
- Adding 19 to `TIERS` is **not** an option (ruling).

## 5. Soundness pitfalls and the cheating suite (question 5)

**Method (pre-flight ruling 1; phase 4's `d95aa5e` method).** A forgery that dies only because
the trace is inconsistent somewhere else proves nothing about the defence it is named for. So every
AIR-level test is built with a `#[doc(hidden)]` forge hook, `tables::modq::forge_block`. The hook
takes a block that is honest except for the targeted lie and makes it consistent everywhere else:

- it recomputes `K` and `D` for every row it touches;
- it re-propagates the lie through the later stages' `MODQ_WIRE` values and the block's memory writes;
- it returns the forged witness, its `RangeCounts` and its memory accesses.

`machine::build_traces_forged` then rebuilds the range and memory traces from that forged witness.
Each test asserts both directions. **With only the targeted defence switched off**, through
`#[doc(hidden)] ModqAirWithout(Some(Defence::X))` (never reachable from `chips()`), the forgery is
accepted. **With it on**, the forgery is rejected. That pins each defence as necessary and as the
thing doing the work. The defences that live outside the modq AIR are the memory table's strict
`(addr, ts)` order and the cpu's `MODQ` lookup. Their tests switch nothing off; instead they show the
forgery passes the modq AIR (the standalone harness with a permissive memory twin) and dies in the
full machine.

| pitfall | defence (`Defence::…` switched off for the "accepted" half) | test (`tests/cheating.rs` unless noted) |
|---|---|---|
| forged butterfly output | identity 2, plus the wire or memory consumer | `modq_forged_butterfly_output_is_rejected` |
| non-canonical output `O + q` (with `K − 1`), on a stage-7 row, its memory write rebuilt to `O + q` | `D` limbs (`Defence::Canonical`). **Priority** | `modq_non_canonical_output_is_rejected` |
| wrong ζ (a self-consistent block computed with ζ_{k+1}) | preprocessed `ZF` is in the verifier key | `modq_wrong_zeta_block_is_rejected` (built by `modq_trace_with_zetas`) |
| input `≥ 2^24` (unchecked range) | `U_L`/`V_L`/`W_L` `RANGE8` | `modq_input_limb_out_of_range_is_rejected`; emulator: `modq_refuses_a_coefficient_of_2_pow_24` (`tests/modq.rs`) |
| chip reads a value memory never held | `MEMORY` balance | `modq_memory_read_mismatch_is_rejected` |
| tampered hand-off between stages (a swapped `U`/`V` pair, every later stage recomputed from the swap) | `MODQ_WIRE` balance (`Defence::Wire`). **Priority** | `modq_wire_value_swap_is_rejected` |
| `DOT4` accumulator not carried, or not started at 0 | rule 4 | `modq_dot_carry_tamper_is_rejected` |
| `MSUB4` broadcast `ĉ` changed mid-coefficient | rule 4 | `modq_msub_broadcast_tamper_is_rejected` |
| op confusion (an `INTT` block claiming `NTT`) | `A1` decomposition and `MODQ` key | `modq_op_bit_flip_is_rejected` |
| padding block made real | `MODQ` entry no cpu row asks for | `modq_padding_block_made_real_is_rejected` |
| `SYS_MODQ` row with no `modq` table | `MODQ` bus has no provider | `modq_row_without_a_modq_table_is_rejected` |
| declared height outside `[10, 20]` (`min(t + 10, 20)` is 20 at every tier in `TIERS`, so the flat cap is the binding one) | `check_declared_heights_with_modq` before any key | `modq_heights_outside_the_flat_range_are_rejected_before_any_key` (9 and 21) |
| **aliasing**: two operands read at one `ts` from one address (a `DOT4` with `\|A − B\| < 4`; `MSUB4` ranges not pairwise disjoint) | the memory table's strict `(addr, ts)` order makes it unprovable, so the emulator refuses it (`ModqAlias`) so that every admitted run is provable. Read/write overlap is legal, because reads precede writes | `modq_refuses_overlapping_dot_operands`, `modq_refuses_msub_aliasing` (`tests/modq.rs`) |
| reserved `a1` bits, or `A`/`B` set on a transform | rule 1 / `ModqArgs` | `modq_refuses_reserved_bits` (`tests/modq.rs`) |
| **AIR-level:** a `DOT4` with `\|A − B\| < 4`, spliced past the emulator (`modq::call_unchecked`), with its memory rebuilt | the memory table's strict `(addr, ts)` order (outside the modq AIR) | `modq_overlapping_dot_operands_die_on_strict_order` |
| **AIR-level:** an `a1` with a reserved bit set (bit 5), the cpu row and register carrying it | the `A1` decomposition (`Defence::A1Decomposition`) | `modq_reserved_a1_bit_is_rejected` |
| **AIR-level:** an `NTT` with `A ≠ 0` | canonical args `T·A = 0` (`Defence::CanonicalArgs`) | `modq_ntt_with_nonzero_a_is_rejected` |
| pointer near `2^30` | cpu cubic rule; `MODQ_PTR_LIMIT` | `modq_refuses_a_base_past_the_limit` (`tests/modq.rs`) |
| centred `z` canonicalised before `chknorm` | review; the KAT suite's `‖z‖∞` cases through `HostModq` | `malformed_signatures_agree_with_the_crate` over three backends (`tests/dilithium.rs`) |

**Height leaks `M` (pre-flight ruling 3).** A run with fewer active slots makes fewer calls: 18 / 36
/ 54 → `modq_log_height` 15 / 16 / 16. That is a shape leak exactly like the keccak table's (99 /
198 / 297 permutations → 12 / 13 / 14), the memory table's and the tier's. So the `msauth` prover
**pins the tier** to `tier(M_MAX)` (`prove(…, Some(tier))`) and floors every variable height to its
`M_MAX` value. That needs new prover-only floors, each with the verifier unchanged, because idle
padding verifies:

- `ProveOptions::min_modq_log_height`
- `ProveOptions::min_keccak_log_height`
- `ProveOptions::min_mem_log_height` (missing today; `mem_log_height` is `max(t + 2, needed)`)

The program, input and public heights are already fixed by the guest and `MSAUTH_WORDS`.
**Fullnode admission must pin all heights:** the tier and the program, input, keccak, sha256, modq,
public and mem heights of `hc_auth_multisig` are compared exactly, not bounded. A proof with any other
height is refused even though it would verify. Every multisig spend, **1-of-N included, pays
`M_MAX`'s tier.**

## 6. Fork impact (question 6)

- **Constraint set.** The cpu gains one column and one lookup, so every verifier key's `common` digest
  moves. That includes every chip-free shape: `tests/verifier_key.rs`'s four pins, plus a fifth
  shape, "tier 10, one modq block". Program digests `hc` do not move. **It ships only with a chain
  cut.**
- **Verifier-key tuple.** It grows from 6 to 7: `(tier, program, input, keccak, sha256, modq,
  public)`. The API is additive, so source-compatible callers (recursion, the fullnode patch) keep
  compiling:
  - `chips`, `check_declared_heights`, `Machine::log_ext_degrees`, `Machine::verifier_key`,
    `gas::gas_max` and `max_constraint_degrees` keep their exact signatures and delegate with
    `modq_log_height = 0`.
  - New `*_with_modq` siblings take the eighth argument.
  - `sync-zkvm.sh`'s exact-signature anchor on `verifier_key` therefore still matches.
- **`Proof`.** It gains `modq_log_height: u8` after `sha256_log_height`. Postcard adds 1 byte to every
  proof, and old proofs do not decode (the cut again).
- **Size of chip-free proofs:** +1 byte of header, plus one cpu column (8 B × 80 queries plus out-of-
  domain values), plus at most one LogUp group, ≈ **+1 KB (+0.07% of 1.37 MB)**. Constraint set 8
  measured +2 KB for 5 columns and 4 lookups.
- **Size of chip-bearing proofs:** about 107 opened base columns (64 main, 16 preprocessed, ≈ 27 aux)
  × 80 queries × 8 B, plus quotient and out-of-domain values: **≈ +75 KB** at Production FRI. Keccak's
  2 711 columns cost +1.91 MB, about 0.7 KB per column.
- **Gas.** `MODQ_GAS = 168`: 1 024 × (59 + 16) = 76 800 committed cells, at the ≈ 460 cells per gas
  that `KECCAK` (192) and `SHA256` (64) imply. `gas_max_with_modq` adds `(2^mlh / 1024)·167`.
- **Recursion.** No source change: `chips(tier, k, s)` is untouched, and a modq-bearing proof's extra
  instance fails `InnerShape::matches` on `degree_bits`. But the inner cpu width moves, so
  `verify_rv32.digest`, `tests/pins.json`, `inner_vk_digest` and the row and tier literals all move.
  That is exactly the set rVM phase 4's Task 5 re-pins.
  - **Merge phase 4 into this branch, then re-pin once.** Use `git merge` of `feat/rvm-phase4-spans`,
    or of `origin/main` once phase 4 is on it. **Never rebase:** the branch carries merge `26f547e`
    (circuits `feat/scan-compact` `56b7061`, the fullnode `CIRCUITS_PIN` base), which must survive.
  - Circuits `main` may lag phase 4, so check that it is there before assuming it.
  - Pins that can be re-recorded on the laptop: every non-ignored recursion test, plus
    `recursion/tests/profile.rs:103` `where_the_rows_go` (ignored; one ≈ 100 s Production proof).
  - Pins that **stay stale until a 256 GB machine exists:** `recursion/tests/tree_measure.rs:117`
    `production_leaf_l2` and `:154` `production_rv32r_over_the_leaf_proves`.
  - **If any recursion tier moves, stop and report.** One cpu column should move rows, not tiers.
- **Fullnode re-vendor**, at the cut:
  1. `deploy/sync-zkvm.sh` rsyncs `src/modq.rs`, `src/tables/modq.rs` and `tests/modq.rs`. Keep
     `tests/modq.rs` free of `dilithium-core`.
  2. Add `pub mod modq;` by hand to the hand-maintained `crates/randprotocol-zkvm/src/lib.rs`.
  3. The `verifier_key` anchor and the `notes::domain` patch need no change. Assert it.
  4. `ZkExecutor::decode_and_check` keeps the modq-free calls, so a modq-bearing proof is refused
     until multisig phase 4 switches the auth-proof path to the `*_with_modq` calls.
  5. In `crates/randprotocol-zkvm/src/executor.rs`, add `const NO_MODQ: u8 = 0;` beside `NO_KECCAK`
     and `NO_SHA256` (lines 67–71). Every non-multisig program record pins `modq_log_height == 0`,
     next to the keccak/sha256 checks at lines 167–170.
  6. `ProveOptions::pad_absent_hash_tables` **does not** pad the modq table. It stays a hash-table
     option, and a chip-free proof keeps `modq_log_height = 0`. Only the explicit
     `min_modq_log_height` floor declares an idle modq table.
  7. `TIERS` itself does not change (ruling). The client-side users of `TIERS` to re-check at the
     re-vendor are `clients/core/crates/wallet-core/src/lib.rs` and the vendored
     `randprotocol-client/src/main.rs` and `randprotocol-rvm/src/machine.rs` under
     `clients/core/vendor/fullnode`. They only need the new `Proof` field and the re-pinned keys.
  8. Re-pin `CIRCUITS_PIN` (it lives in the fullnode), the verifier-key digests and
     `aggregate_program_digest`. Mirror `MODQ_GAS` in the fee schedule.

### 6.1 Shared files, for merge planning

New:
- `research/src/modq.rs`
- `research/src/tables/modq.rs`
- `research/tests/modq.rs`
- `guests-compiled/dilithium-core/src/ring.rs`

Edited, all append-only at the end of their lists:

| file | change |
|---|---|
| `research/src/isa.rs` | `SYS_MODQ = 8`, `MODQ_*` constants |
| `research/src/emulator.rs` | `Syscall::Modq`, `ModqCall`, `CycleEvent::modq: Option<Box<ModqCall>>` (boxed; touches every `CycleEvent` literal the compiler flags, today in `emulator.rs`, `tables/memory.rs`, `tables/sha256.rs`, `machine.rs`, `tests/{cheating,emulator,sha256}.rs`), four `ExecError`s, the handler |
| `research/src/tables/mod.rs` | `pub mod modq`, `bus::MODQ`, `bus::MODQ_WIRE` (appended after `BLIND`, the catalogue's last entry) |
| `research/src/tables/cpu.rs` | `SYS_MODQ`, `SELECTORS`, six rule edits, the trace arm |
| `research/src/tables/memory.rs` | chain `modq` accesses |
| `research/src/machine.rs` | `Chip::Modq`, `chips_with_modq`, `Traces`, `Proof`, heights, key, verify, `build_traces`, `ProveOptions`, errors |
| `research/src/gas.rs` | |
| `research/src/lib.rs` | |
| `research/src/asm.rs` | `ops::call_modq` |
| `research/src/dilithium_host.rs` | `HostModq` |

Also edited: `guest-sdk/src/lib.rs`, `guests-compiled/dilithium-core/src/{lib,verify,poly,fips202}.rs`,
`guests-compiled/{dilithium-verify,msauth}/src/main.rs` and both `.bin`s, `research/docs/{01,02,04,05}`,
and parent spec §7 (7 → 8).

**rVM phase 4** (`feat/rvm-phase4-spans`) edits only `recursion/` and its docs, so there is no textual
overlap. The overlap is in the pinned artefacts above. **Phase 2** (`msauth`, this branch, active)
shares `guests-compiled/msauth` and `research/tests/msauth.rs`, so the plan's Tasks 6–8 start after
phase 2's last commit.

## 7. Risks

1. **The tier-18 gate (§4.3).** At the central estimate, `M = 3` sits inside tier 18 with no
   margin. Ruling: tier 18 only. A miss means `M_MAX = 2`, with `UNIFORM` deferred to phase 3b.
2. **Hard fork, and sequencing.** This rides a chain cut, after phase 4, and costs one recursion
   re-pin.
3. **Estimate error.** The 79 k is a profile plus per-loop arithmetic, not a build. Task 8 replaces
   it.
4. **`MODQ_WIRE` is the first intra-table permutation bus in `research`.** Its balance argument (§3.4,
   rule 5) and `modq_wire_value_swap_is_rejected` are the review's first stop. Option (b), per-layer
   calls through `MEMORY`, is the fallback with the same row count.
