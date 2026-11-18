# Harness cost: what a guest pays around the program it runs

ZKVM-117 (2026-11-18). For the two flagship transfers the contract is the minority of the proof:
the harness around it sets the tier. This note records what was measured, what was done without
touching the constraint set, and the design of the two syscalls that would do the rest — which
**are not built**: they change the AIR, so they belong to the next constraint-set bump.

## The tape costs 8.00 cycles a word

Two documents disagreed: `docs/04-guests.md` said the sBPF guest reads its public tape at "~15.8
cycles per word, about 430 K" for the SPL Token ELF, and `sbpf2rv/README.md` measured 302 881
cycles for both tapes at 8.05 a word. Re-measured on the emulator with the committed `sbpf.bin`
(`rand-guest run`, a 48-byte empty instruction on the private tape and an all-zero "ELF" of
growing length on the public one, which the loader refuses, so nothing but the read varies):

| ELF bytes on the public tape | words read | cycles | marginal cycles per word |
|---|---|---|---|
| 0 | 0 | 62 666 | |
| 4 000 | 1 000 | 70 681 | 8.02 |
| 54 300 | 13 575 | 171 281 | 8.00 |
| 108 600 | 27 150 | 279 881 | 8.00 |

So the README was right and `04-guests.md` was stale: **8.00 cycles a word**, about 217 K for the SPL Token ELF's 27 151 words — a third of
the interpreter's 685 749-cycle transfer, not "well over half". `04-guests.md` is corrected.

The loop is one `ecall` (`READ_PUBLIC`, 1 row), the index bookkeeping and four byte stores per
word; nothing guest-side takes it below a handful of cycles a word, because each word crosses
into the machine through its own syscall row.

## Done without the AIR: a translated image carries its program

An `sbpf2rv` image has the program's code in it, so everything else it took from the ELF at run
time was the read-only data the code may load and two addresses. Those are now in the image too
(`sbpf_core::baked`, `sbpf2rv::shim::baked_c`), and the image reads no ELF, loads none and guards
none. Measured on the SPL Token `Transfer` of 250 (emulator, same vector):

| | cycles | tier | public tape |
|---|---|---|---|
| interpreter `sbpf.bin` | 685 749 | 20 | 27 152 words (the ELF, then the sysvar block) |
| translated, ELF on the tape (ZKVM-116) | 753 424 | 20 | 27 152 words |
| translated, program in the image (ZKVM-117) | 298 598 | 20 | 1 word (the sysvar block; 16 with sysvars) |
| … and no zeroing of the sBPF stack and heap | **249 422** | 20 | 1 word |

The tier column is what `rand-guest run` prints (`Tier::for_workload`: cycles plus digest rows;
16, 18 or 20). The transfer's 249 422 cycles are under tier 18's 262 143 and it is still sized
tier 20 once its digest rows are counted; thirteen of the fifteen SPL Token vectors measured in
`sbpf2rv/README.md` (every `MintTo`, `Burn`, `InitializeAccount3`, `GetAccountDataSize`, and the
failing transfers) do land in tier 18, where all fifteen were tier 20. The issue's acceptance
names "tier 19 or lower" for the transfer; this machine's tiers step from 20 to 18, and the
transfer is a few thousand rows short of 18. No proof was made at either tier.

What went: reading the ELF (about 217 K), `elf::load` (about 177 K), the ELF guard's hash of the
loaded program (about 73 K), and — because a guest's `.bss` is zero and the image makes one call —
the zeroing of the sBPF stack and heap (about 49 K). What it costs: the data prologue, 2.8 program
words (and cycles) per word of read-only data — 2 124 for SPL Token's 2 848 bytes — against the
65 535-word program cap, and the program's own instruction bytes are not readable unless the
image is built with `--text-in-image` (`sbpf2rv/README.md`, accepted divergence #3).

What binds the program now: `hc`, alone. The public tape carries only the sysvars, so
`Machine::verify_public` is given 1 or 16 words and the chain needs no ELF to check a proof of a
translated program. The public output is unchanged — the same eight words the interpreter
publishes for the same instruction.

What is left in a translated SPL transfer is the instruction itself: reading its 10 458 words
(84 K at 8.00 a word), `check_region`'s zero scan of the realloc headroom and the digests (about
104 K and 45 K in `sbpf2rv/README.md`'s 2026-09-18 stage split, not re-profiled). All
three are consequences of the aligned serialization format's 10 240 bytes of zero padding per
account, which the program's own entrypoint skips.

## Not built: a bulk public-read syscall (constraint-set change)

**What.** `READ_PUBLIC_BULK ptr n idx`: copy public words `idx .. idx + n` to memory words
`ptr .. ptr + n`. Today a guest pays one cpu row per word for the `ecall` and four to seven more
for the loop around it; the bulk form pays one cpu row for the call and one *table* row per word.

**Rows.** A new `public_copy` table, the shape of the Poseidon2 chip's absorb rows: one row per
word carrying `(clk, ptr + i, idx + i, word)`, with

- a memory write of `word` at `ptr + i` on the memory bus, at the call's clock (the same
  many-writes-at-one-clock discipline the `POSEIDON2` rows use for their in-place digest);
- a lookup `(idx + i, word)` into the `public` witness table on the existing `PUBLIC_READ` bus —
  the bus `H_PUB`'s digest rows already bind, so no new binding argument is needed;
- a running counter `i` from 0 to `n − 1` with a boundary constraint tying the first row to the
  cpu's call `(clk, ptr, idx, n)` on a new `PUBLIC_COPY` bus and the last row to `i = n − 1`.

The cpu side is one row: opcode selector, the three arguments range-checked (`ptr < 2^30`,
`n ≤ 2^16` so a call fits a table of known maximum height), and the send on `PUBLIC_COPY`.

**Gas.** `3 + n`, by the rule the other chips follow (rows the call adds).

**What it buys.** The interpreter's 217 K for the ELF becomes about 27 K rows in a table that is
not the cpu table, so the cpu height — which is what sets the tier — drops by about 190 K. For
`sbpf.bin`'s transfer that is 686 K → about 496 K: still tier 20, because `elf::load` (174 K) and
the instruction's own cost remain. It is the private tape that would need the same treatment
(`READ_INPUT_BULK` against the salted `H_IN`) to move the instruction's 84 K.

**Cheating tests it needs.** A copy row whose word is not the public word at that index; a copy
that skips or repeats an index; a copy whose row count is not `n`; a write at a clock other than
the call's; a call with `idx + n` past `n_pub` (must be unsatisfiable, as a single read is).

## Not built: a looped Merkle-verify syscall (constraint-set change)

**What.** `MERKLE_VERIFY leaf_ptr path_ptr depth index root_ptr`: verify a whole authentication
path — `depth` sibling digests at `path_ptr`, direction bits from `index` — in one call, writing
nothing and trapping (unsatisfiable) on a mismatch, or writing the computed root for the caller to
compare. Today a storage walk is `depth` separate `POSEIDON2` calls with the guest shuffling 16
words between them: the ERC-20 transfer's four walks are 132 calls at about 207 cycles, 27 300 of
its 66 235 translated cycles.

**Rows.** No new hashing, but a new row kind in the Poseidon2 table: a two-to-one compression
(the rVM's chip in `recursion/` has one; this machine's sponge rows are the starting point). The
call adds, per level, one compression row whose *input* is chained to the previous row's *output*
inside the table (a transition constraint on the eight digest columns,
selected by a new `IS_PATH` flag) instead of going back to the cpu through memory; the sibling is
read from memory at `path_ptr + 8·level` on the memory bus; the direction bit is a boolean column
whose weighted sum over the path is constrained to `index`. The cpu sees one row. The rVM's
phase-4 Merkle spans (`recursion/`) are the same idea and the place to borrow the argument from,
as the issue says.

**Gas.** `3 + 3·depth` (one compression's rows per level), against `depth × (3 + 3·4)` plus about
190 cycles of guest glue a level today.

**What it buys.** The ERC-20 transfer's four depth-33 walks: about 27 300 cycles → about 4 × 102.
The translated transfer goes from 66 235 to about 39 000 — under tier 16's cap is the claim to
check when it is built, not a measurement.

**Cheating tests it needs.** A path row whose input is not the previous output; a direction bit
that does not match `index`; a sibling that is not the memory word; a path shorter or longer than
`depth`; a root exposed from a row other than the last.

## Order

Both syscalls change the constraint set and every verifier key, so they ship together in one
bump with the EVM-side items of ZKVM-117; nothing here depends on them.
