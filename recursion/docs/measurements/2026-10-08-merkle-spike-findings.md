# Merkle-span row cuts — priced (2026-10-08, circuits main 71e1a04, production, 80 queries)

Baseline (tests/profile.rs, unmodified): 585 686 cpu rows (tier 20), 54 515 perms; input_root 248 151 (97 987 reloads),
commit_root 120 640 (35 840 reloads); 176 283 reloads in total; live_max 25 of r1..r25 (r26..r31 scratch). Gate: tier 19 ≤ 524 287 (−61 399).

## Reload anatomy
A spilled handle is reloaded into a scratch register at every use and never re-homed (builder.rs `replay` Mat arm,
`claim` evicts farthest-next-use). Every Ptr is a holder register + compile-time delta; SPONGE/COMPRESS/POSEIDON2 take
register-only addresses → an offset FADDI per use. The tape for all 80 queries is read up front, so buffer holders spill.
input_root /query: hash-scratch base 504.6 reloads; opening/path holders ≈516; cap holders 84; index bits 120.
commit_root /query: cap holders 144; index bits 142; path holders 116; scratch base 46.
Per op: bit-driven COMPRESS 3.94 rows each; commit COMPRESS 3.90; SPONGE block 3.91; cap check 88 rows/round × 14 rounds/query ≈ 98k.
No rows are stored only to be sponged (HINTN already hints openings into sponge buffers); STOREs are scratch management.

## Candidates (Δ rows from 585 686; each built and run on the real fixture, honest proof accepted)
| # | candidate | rows | Δ | alone crosses? | consensus surface |
|---|---|---:|---:|---|---|
| a | allocator re-homing (reload into a real register when nearer than the farthest resident; no re-home inside if_eq; in loops only body-defined values) | 439 432 | −146 254 | yes | program digests only |
| a′ | pin hash-scratch base in r25 | 541 918 | −43 768 | no | digests only |
| b | COMPRESS absolute immediate sibling address | 557 225 | −28 461 | no | ISA + cpu AIR (B_REG) + digests |
| b′ | SPONGE absolute immediate source address | 516 408 | −69 278 | yes | ISA + cpu AIR + digests |
| c | path-level precompile (priced) | ≈530–536k | ≈−50…−56k | no | ISA + cpu + poseidon2 AIR |
| d1 | cap select by register-offset LOAD (off = 4·b0 + 8·b1), Cut E1's ruled pattern | 513 994 | −71 692 | yes | digests only |
| d2 | no digest copies (walk compresses over the leaf in place) | 566 625 | −19 061 | no | digests only |

Combinations: d1+d2 494 933; a+d1 386 698; **a+d1+d2 (software only) 367 339 (tier 19, 156 948 headroom)**; a+b+b′ 389 164; everything 317 315.
a+d1+d2 also: REG accesses 1 290 039 → 817 303 (REG table 2^21 → 2^20); RAM 1 723 112 (2^21); perms unchanged (poseidon2 2^16);
Test profile 169 366 → 114 449 (tier 18 → 17); loop overhead 274 → 318; production aggregates projected N=1 ≈ 368k (tier 19), N=2 ≈ 735k (tier 20), N=3 ≈ 1.10M (tier 21; ≈ 952k tier 20 with b+b′).
Validation of a+d1+d2 in the spike: dsl, allocator, emulator, cheating 96/96 pass; precompiles one expected failure under d2 (reads the old `out`); aggregate suite only the row pins fail; a real aggregate proved and verified with the re-homing allocator.

Recommendation: software-only package d1 → a → d2; b+b′ later as its own ISA/AIR change (lever for production N=3); do not build c.
Scratch: spike.patch, runs/*.log, profile.log, spike.log, tests_sw.log in this directory.
