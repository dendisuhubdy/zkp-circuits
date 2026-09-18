# evm2rv

`evm2rv` translates EVM runtime bytecode (what `solc --bin-runtime` prints) into C over
`evm-rt/`. `rand-guest build` then compiles that C into a zkVM image. The image takes the same
input vector as the EVM interpreter guest (`guests-compiled/bin/evm.bin`) and publishes the same
eight output words. It just runs the contract natively instead of interpreting it opcode by
opcode.

The design spec is `docs/superpowers/specs/2026-09-18-evm-to-rv32-translator-design.md`. Every
ruling is in the task briefs and reports under `.superpowers/sdd/2026-09-18-evm2rv-translator/`.

There are two translation stages. Both give the same results and the same gas.

| stage | source | what it does | flag |
|---|---|---|---|
| one | `src/emit.rs` | every opcode over `evm-rt`'s memory stack | `--stage 1` |
| two | `src/lift.rs` | each block's words in C locals, constants folded at translation | `--stage 2` (the default) |

Each stage is a different program, so each has its own `hc`.

## Walkthrough: the ERC-20, end to end

Every command below was run from the root of a `circuits` checkout, and the output shown is its
real output. Long output is cut where marked `...`.

### 0. The toolchain

The pins are Rust 1.98.1, clang 23.1.1 and the `cc` crate 1.4.6. `hc` depends on all three.

```
$ /opt/homebrew/opt/llvm/bin/clang --version | head -1
Homebrew clang version 23.1.1
```

On macOS, `brew install llvm` gives this clang. Build the two tools once:

```
$ (cd evm2rv && cargo +1.98.1 build --release)
$ (cd rand-guest && cargo +1.98.1 build --release)
```

### 1. The bytecode

`evm2rv` takes **runtime** bytecode: the code that lives at the contract's address after
deployment. It does not take creation code. Creation code runs the constructor once and returns
the runtime code. A proof here is of one call to a deployed contract, so the constructor never
runs. The state it would have written is part of the pre-state instead, as storage witnesses.

To get runtime bytecode from Solidity:

```
solc --optimize --optimize-runs 200 --evm-version shanghai --bin-runtime MyToken.sol
```

The last line of output is the hex. Save it as `mytoken.hex`. Use `--evm-version shanghai`:
newer targets emit `MCOPY` and other Cancun opcodes, which trap here.

`solc` is not installed on the machine these numbers come from. The committed ERC-20
(`guests-compiled/evm/contracts/erc20.runtime.hex`, 1 296 bytes) was compiled once with solc
**0.8.37** (`0.8.37+commit.f401782d`), with exactly the flags above.
`guests-compiled/evm/contracts/SOLC.md` names the binary and its sha256.
`guests-compiled/evm/contracts/build.sh` recompiles it and diffs the result when a solc is on
`PATH`.

### 2. Translate

```
$ evm2rv/target/release/evm2rv guests-compiled/evm/contracts/erc20.runtime.hex --out evm2rv/target/erc20 --chain-id 12
1296 code bytes: 74 blocks, 798 opcodes, 51 jumpdests (stage 2)
CHAINID is the constant 12
no trapping opcodes present
wrote evm2rv/target/erc20 (crate erc20-runtime): contract.c, Cargo.toml, Cargo.lock, build.rs, src/main.rs, shim.ld
```

- A `.hex` file is read as hex text. Any other extension is read as raw bytes.
- `--out` must be inside a circuits checkout, because `rand-guest build` needs one.
- `--chain-id N` is the value `CHAINID` returns, baked into the C. It is required when the code
  contains `CHAINID`. This ERC-20 does not, so the flag changes nothing here: `hc` is the same with
  or without it.
- Any trapping opcode is listed as a warning, with its pc.

`contract.c` is the translated contract. It ends with the code guard (see "Trust" below):

```
$ tail -7 evm2rv/target/erc20/contract.c
   from. Before any of the code above runs, the shim hashes the input vector's code the same way and
   refuses any other (OutOfBounds, status 2, gas_used 0). */
const uint32_t *evm_code_digest(void);
const uint32_t *evm_code_digest(void) {
    static const uint32_t d[8] = {0xf679280fu, 0x86c10e83u, 0x7e8f1f39u, 0xa2377de3u, 0x8a2e282fu, 0xc54cad42u, 0xddfaf009u, 0x7d28a8afu};
    return d;
}
```

### 3. Build the image

```
$ rand-guest/target/release/rand-guest build evm2rv/target/erc20 --max-words 65535
...
warning: erc20-runtime@0.1.0: evm2rv: clang Homebrew clang version 23.1.1 (/opt/homebrew/opt/llvm/bin/clang)
    Finished `release` profile [optimized] target(s) in 3.50s
11686 words against a cap of 65535 (fits); 0 ecall(s) with a non-static a7
OK
wrote evm2rv/target/erc20/image.bin and its .sha256 (11686 words, hc a0feae92a7311c9562495717100eb7aea71270a38ed435d06dc31387e0ea8ff6, program id f074c4eb834cf01886a8241b6a2e0caf6e1cee5327fee6cb1a1a37436607280d)
```

`--max-words 65535` is needed: the default cap is 4 096 words. The build refuses any clang other
than 23.1.1. `RAND_GUEST_CLANG_UNPINNED=1` builds anyway, with a warning that `hc` will not match
published images.

### 4. Run a transfer

The input vector is the interpreter's: the code, the calldata, the caller and other environment
words, the gas limit, the pre-state root, and one storage witness per slot the call touches. This
example prints the parity test's `transfer` (ALICE sends BOB 250 of her 1 000) as 921 words. It
also has `approve` and `transferFrom`.

```
$ (cd evm2rv && cargo +1.98.1 run -q --release --example erc20_vector -- transfer > target/transfer.words)
921 input words
$ rand-guest/target/release/rand-guest run evm2rv/target/erc20/image.bin --input $(cat evm2rv/target/transfer.words)
out[0] = 1
out[1] = 513227413
out[2] = 3087537901
out[3] = 995619457
out[4] = 4004100029
out[5] = 234390638
out[6] = 3262201797
out[7] = 3842361427
cycles 66235
tier 18
```

`out[0]` is the status: 1 success, 0 revert, 2 exceptional halt. `out[1..8]` is the `EVM_OUT`
digest over the code hash, both state roots, the return data and the logs.

### 5. The same eight words as the interpreter

The interpreter guest, on the same input:

```
$ rand-guest/target/release/rand-guest run guests-compiled/bin/evm.bin --input $(cat evm2rv/target/transfer.words)
out[0] = 1
out[1] = 513227413
out[2] = 3087537901
out[3] = 995619457
out[4] = 4004100029
out[5] = 234390638
out[6] = 3262201797
out[7] = 3842361427
cycles 121638
tier 18
```

The interpreter run natively on the host (the tests' oracle):

```
$ (cd evm2rv && cargo +1.98.1 run -q --release --example erc20_vector -- transfer --expected)
out[0] = 1
out[1] = 513227413
...
out[7] = 3842361427
interpreter (native): status 1, Return, gas_used 29956
```

The check, as one command:

```
$ diff <(rand-guest/target/release/rand-guest run evm2rv/target/erc20/image.bin --input $(cat evm2rv/target/transfer.words) | grep '^out') \
       <(rand-guest/target/release/rand-guest run guests-compiled/bin/evm.bin --input $(cat evm2rv/target/transfer.words) | grep '^out') \
  && echo "the eight words are identical"
the eight words are identical
```

| | translated (stage two) | interpreter (`evm.bin`) |
|---|---:|---:|
| eight output words | identical | identical |
| cycles | 66 235 | 121 638 |
| tier | 18 | 18 |
| program words | 11 686 | 18 009 |

`tests/parity.rs` runs this and seven more vectors under both stages, and also checks `gas_used`
and the halt through a second build that reports them.

### 6. Deploy (not run here)

```
$ rand-guest/target/release/rand-guest info evm2rv/target/erc20/image.bin
form: image container
text 11147 words at 0x10000; data 408 words (205 non-zero) at 0x1ae2c; prologue 539 words; program 11686 words from base_pc 0xf794
hc a0feae92a7311c9562495717100eb7aea71270a38ed435d06dc31387e0ea8ff6
program id f074c4eb834cf01886a8241b6a2e0caf6e1cee5327fee6cb1a1a37436607280d
11686 words against a cap of 4096: does not fit
```

The fullnode wallet deploys an image with:

```
rand program deploy evm2rv/target/erc20/image.bin
```

It prints the program id, the word count and `hc`, then checks the chain's program cap before it
proves anything. The image is 11 686 words. Chain 12 runs the default cap of 4 096 words, so this
deploy is refused there. It needs a chain whose genesis sets `max_program_words` high enough, for
example `rand-node genesis ... --max-program-words 65535` (fullnode `docs/cli.md`). The cap is part
of the genesis hash, so it cannot be raised on an existing chain.

## Trust

A verifier checks a translated contract in two steps:

1. **`hc == translate(bytecode)`.** Re-run `evm2rv` on the published bytecode with the same
   `--stage` and `--chain-id`, rebuild with the pinned toolchain (Rust 1.98.1, clang 23.1.1,
   `cc` 1.4.6), and compare `hc`. The generated crate pins `cc` exactly and carries its own
   `Cargo.lock`. The build refuses any other clang unless told otherwise.
2. **The code guard.** The translated logic is baked into the image, so `hc` binds it. But
   `CODECOPY` and `CODESIZE` read the input vector's code. Without a check, one `hc` could run with
   code bytes the caller chose. So `contract.c` carries a digest of the source bytecode
   (`guard::code_digest`: the `POSEIDON2` sponge over the code's length and its bytes), and the
   shim hashes the input vector's code the same way before any translated code runs. Any other
   code is refused the way the interpreter's `pre_halt` stops a call before it starts: status 2,
   `gas_used` 0, halt `OutOfBounds`. So `hc` binds the code too.

The `EVM_OUT` digest also binds `keccak256` of the input vector's code, as the interpreter's
does. The chain does not record the source bytecode or its hash; a verifier who wants to check
`hc` needs the bytecode from the contract's author.

What the guard costs, on the transfer (measured):

| | before the guard | with the guard | cost |
|---|---:|---:|---:|
| stage one cycles | 79 203 | 80 211 | +1 008 |
| stage two cycles | 65 227 | 66 235 | +1 008 |
| program words, either stage | 15 637 / 11 519 | 15 804 / 11 686 | +167 |

Why `POSEIDON2` and not Keccak: the harness hashes the code with Keccak for `EVM_OUT`, but only
after the contract has run. Reusing that hash would mean changing `evm-core`, which would move
the pinned `evm.bin`. So the guard hashes once more, with the cheaper coprocessor hash:

| guard hash (stage two transfer) | added cycles |
|---|---:|
| Keccak-256 of the code | +8 798 |
| `POSEIDON2`, plain copy loop | +2 720 |
| `POSEIDON2`, eight-word copy (shipped) | +1 008 |

A code one byte different from the source is refused in 30 344 cycles (stage one) or 30 418
(stage two), tier 16. `tests/guard.rs` also runs 16 381- and 24 575-byte codes, which need a
second `POSEIDON2` call.

## The observable contract

What must match the interpreter is the status, the eight output words and `gas_used`. The halt
kind is not public, and it may differ. Three divergences are accepted:

1. **The halt kind.** Static gas is charged once at the head of each block. A block that would
   halt midway for another reason can halt `OutOfGas` at its head instead, or the reverse. Both are
   status 2 with `gas_used` equal to the limit, so nothing observable changes.
2. **The translation runs a little more than the interpreter.** The interpreter traps on
   `CHAINID`, `ORIGIN` and every call. The translation implements `CHAINID` and `ORIGIN`, and runs
   calls to the precompiles (addresses 1 to 9). A call on too shallow a stack underflows at the
   block head where the interpreter traps; both are status 2.
3. **The code guard.** Given code other than its source, the interpreter would run it. The
   translation refuses it (status 2, `gas_used` 0).

## Environment opcodes

| opcode | translation |
|---|---|
| `ADDRESS`, `CALLER`, `CALLVALUE`, `CALLDATASIZE`, `CODESIZE` | from the input vector, as the interpreter reads them |
| `CHAINID` | the `--chain-id` constant, baked in, so `hc` binds it; 2 gas |
| `ORIGIN` | `CALLER` (one call, no relayer); 2 gas |
| `GASPRICE`, `COINBASE`, `TIMESTAMP`, `NUMBER`, `PREVRANDAO`, `GASLIMIT`, `SELFBALANCE`, `BASEFEE`, `BLOCKHASH` | trap (status 2), as in the interpreter |

The nine block-context opcodes trap until there is a design for binding them. A private input
word is bound only to the salted `H_IN`, which a verifier cannot open, so it could not carry a
block fact a prover could not forge. Binding them needs a chain decision on which block a proof is
checked against. Until then, contracts that read the time or the block number (a permit deadline,
for example) trap.

## Calls and precompiles

- All four call opcodes (`CALL`, `CALLCODE`, `DELEGATECALL`, `STATICCALL`) run a precompile when
  the target is 1 to 9, with Shanghai gas. Any other target traps, as in the interpreter.
- A nonzero value on `CALL` or `CALLCODE` traps: there is no balance model.
- `modexp`'s base and modulus are capped at 1 024 bytes each. Past the cap, an affordable call
  halts `OutOfBounds`. The exponent is not capped.
- `RETURNDATASIZE` and `RETURNDATACOPY` read a real return-data buffer in a contract that calls.

All nine are software. Measured with one known answer each (`evm-rt/test/rv32-precompiles`):

| precompile | vector | cycles | fits 2^20? |
|---|---|---:|---|
| 1 ecrecover | ValidKey | 14 510 525 | no |
| 2 sha256 | "abc" / 200 bytes | 2 791 / 5 289 | yes |
| 3 ripemd160 | "abc" | 12 195 | yes |
| 4 identity | 100 bytes | 4 498 | yes |
| 5 modexp | nagydani-1-square / -1-pow0x10001 | 122 332 / 874 548 | yes |
| 5 modexp | eip_example1 (256-bit) | 11 170 118 | no |
| 5 modexp | nagydani-5-pow0x10001 (1 024-byte) | 55 076 950 | no |
| 6 bn256 add | chfast1 | 978 262 | yes, just |
| 7 bn256 mul | chfast1 | 3 060 669 | no |
| 8 bn256 pairing | 1 pair / 2 pairs | 1 853 656 212 / 2 019 000 469 | no |
| 9 blake2f | 12 rounds | 14 493 | yes (up to about 1 800 rounds) |

The ones over 2^20 cycles are correct but cannot be proven today. They are the coprocessor
backlog: ecrecover, bn256 mul, the pairing, modexp past small operands, and blake2f past about
1 800 rounds.

## Cycles against the interpreter

Measured with `rand-guest run` on the vectors `tests/parity.rs` and `tests/precompiles.rs` pin,
with the code guard in. Tier in parentheses.

| vector | interpreter | stage one | stage two |
|---|---:|---:|---:|
| `transfer(BOB, 250)` | 121 638 (18) | 80 211 (18) | **66 235** (18) |
| `approve(BOB, 5)` | 85 645 (18) | 56 261 (16) | **48 119** (16) |
| `transferFrom(ALICE, BOB, 100)` | 161 434 (18) | 110 074 (18) | **88 824** (18) |
| transfer of 5 000 of 1 000 (reverts) | 88 092 (18) | 54 256 (16) | 46 830 (16) |
| transfer, out of gas at 100 | 49 504 (16) | 32 831 (16) | 32 382 (16) |
| transfer, out of gas at 20 000 | 103 736 (18) | 67 815 (18) | 57 427 (16) |
| transfer, out of gas at 29 955 | 120 235 (18) | 78 553 (18) | 65 038 (18) |
| sha256 + ecrecover, underfunded | traps | 22 626 (16) | 21 562 (16) |

| program | words | hc |
|---|---:|---|
| interpreter (`evm.bin`) | 18 009 | `7e1aea2b…854c08` |
| ERC-20, stage one | 15 804 | `9cdb79e7f05d53f6503f0eb777bb0c2356d29cab516a0378864802e42fd048c8` |
| ERC-20, stage two | 11 686 | `a0feae92a7311c9562495717100eb7aea71270a38ed435d06dc31387e0ea8ff6` |
| sha256 + ecrecover contract, stage one | 15 858 | `c8f00a09…f946fd` |
| sha256 + ecrecover contract, stage two | 15 630 | `011120cf…058c33` |

Stage two runs the three ERC-20 calls in 54.5% (`transfer`), 56.2% (`approve`) and 55.0%
(`transferFrom`) of the interpreter's cycles. Stage one takes 65.7 to 68.2%.

**The transfer stays at tier 18.** The tier bound is total rows (cycles plus digest rows: one per
four program words, one per four input words, and the public-input digest) at or under 65 535,
plus a separate Poseidon2 budget (`rand-guest/src/main.rs:244-248`). The transfer's 66 235 cycles
plus 3 155 digest rows are 69 390 total, 3 855 over tier 16's 65 535; its 3 908 Poseidon2
permutations are well under tier 16's 8 192, so cycles, not Poseidon2, keep it at tier 18.

### Where the cycles go

The harness is the code both images share: decoding the input, verifying each storage witness,
the ABI's own `keccak256` calls, and the output digest. The split below was measured on the
transfer with a one-off tool (Tasks 7 and 8; not committed): `llvm-nm` symbol ranges over each
cycle's pc, with each `memcpy`/`memset`/`memcmp` call charged to its caller. It was measured
before the code guard.

| transfer, before the guard | total | contract | harness | unclassified |
|---|---:|---:|---:|---:|
| stage one | 79 203 | 39 839 | 38 920 | 444 |
| stage two | 65 227 | 25 789 | 38 920 | 518 |

Stage two cuts the contract's own execution by 35%. The guard adds 1 008 cycles to the harness,
so the harness is now about 39 928 of stage two's 66 235 cycles: **about 60% of a transfer**. No
translation work can go below that floor.

## Proving

**Not yet proven on a 48 GB laptop.** A proof of the stage-one transfer (Task 7, before the
guard) was run once, with `Machine::new(FriProfile::Test).prove`, and the OS killed it:

| run | wall time | peak memory | result |
|---|---:|---:|---|
| stage-one transfer, tier 18 | 1 015.76 s | 24 706 367 488 bytes (24.7 GB) | SIGKILL, no proof |

No stage-two proof and no `evm.bin` proof were attempted. Both are deferred to a machine with at
least 64 GB. `tests/proof.rs` holds the two `#[ignore]`d tests, each with its exact command. The
prover is unchanged; this is a memory gap, not a correctness gap.

## Tests

`cargo +1.98.1 test --release` in this directory: 70 tests, plus the 2 ignored proofs.

| file | what |
|---|---|
| `blocks.rs` | the jumpdest rule, block splitting, static gas, stack bounds |
| `emit.rs` | the emitted C and the shim's files, for both stages |
| `lift.rs` | stage two's lifting: text tests, directed hazards, the 4 KiB frame cap |
| `opcodes.rs` | 34 directed opcode edges, both stages, and again under stage two with every push laundered |
| `parity.rs` | the ERC-20's 8 vectors, both stages, against `evm.bin` and the native interpreter; the hc pins; the guard refusing a one-byte change |
| `precompiles.rs` | a sha256 + ecrecover contract, end to end |
| `fuzz.rs` | 10 000 random programs, plain and opaque, both stages, against the interpreter; a sample through the real pipeline |
| `guard.rs` | the code guard's digest, and long codes through the real pipeline |
| `toolchain.rs` | the clang pin and its override |
