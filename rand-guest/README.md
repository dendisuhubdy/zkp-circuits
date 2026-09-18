# rand-guest

The Rand zkVM toolchain: one binary from a guest's source to the image the chain deploys.
`build` compiles a guest directory (Rust or C) with the fixed flags every guest needs, `check`
runs the machine's own decoder over the result and refuses anything the circuit could not accept,
`pack` wraps a bare ELF into the image container, `run` executes an image on the emulator, and
`info` reports what a built image is without running it. `guests-compiled/README.md` is the
committed guests' side of this; this file is the tool's.

Run from this directory (`cd rand-guest`) with the pinned toolchain: `cargo +1.98.1 run -- <cmd>
…`, or build once and use the binary directly.

## The five subcommands

### `build` — compile a guest directory to a packed image, checking it on the way

    cargo +1.98.1 run -- build ../guests-compiled/evm --out ../guests-compiled/bin/evm.bin --max-words 65535

Rust is the default language; `--lang c` drives clang instead (see "The C path" below). Writes
the image and its `<out>.sha256` pin (the same form `pack` writes), then prints the checker's
report. Exits non-zero — after still writing the image — if `check` rejects the result.

`fib.bin` and `keccak256.bin` are **never rebuilt over**: they are legacy flat pins (see "The two
image forms"), `build` only writes the container form, and replacing either would break every
test that loads it with `from_flat_binary`. They are checked instead, by `rand-guest/tests/build.rs`
(program equality against a fresh build into a temporary directory) and by `info`. `build`
refuses outright to write over an existing `--out` that is not an image container, naming it.

### `check` — the ISA report over an ELF or an image

    cargo +1.98.1 run -- check ../guests-compiled/bin/evm.bin --max-words 65535

Takes either form (`pack`s an ELF on the way in); prints every finding, one per line, then a
summary line and `OK` or `REJECTED`.

### `pack` — pack an ELF into the image container

    cargo +1.98.1 run -- pack path/to/guest.elf --out guest.bin

Also writes `guest.bin.sha256`, the pin format `guests-compiled/bin/*.bin.sha256` uses.

### `run` — run an image on the emulator with the given inputs

    cargo +1.98.1 run -- run ../guests-compiled/bin/fib.bin --input 20 --tier 10

Prints each output word, the cycle count, and the smallest tier the run fits (mirroring
`Machine::prove_salted`'s tier pick, not cycles alone — the Poseidon2 table is a second,
independent constraint); with `--tier t`, also whether the run fits tier `t`, with both budgets
(`tier 10: fits (cycles 146 of 1023, Poseidon2 permutations 10 of 128)` for `fib(20)`). A run that fits no tier
says so with both counts. A trap prints `trap: <the emulator's error>` (it carries no pc) and
exits 2.

### `info` — words, hc, the cap

    cargo +1.98.1 run -- info ../guests-compiled/bin/evm.bin

Reports the on-disk form, the text/data/prologue word counts (image containers) or just the word
count (flat binaries), the program digest `hc`, the chain's program id, and whether the program
fits `--max-words`. The two identities are different hashes of the same `(base_pc, words)`: `hc`
is the circuit's Poseidon2 digest a proof is verified against; the program id is fullnode's
`program_id`, `blake3("rand-program" ‖ base_pc ‖ words)`, the key a deployed program is stored and
called under. `build` prints both too.

## Flags

| subcommand | flag | default | what it does |
|---|---|---|---|
| `build` | `<dir>` (positional) | — | the guest directory |
| `build` | `--lang rust\|c` | `rust` | which compiler drives the build |
| `build` | `--ld <path>` | the one `.ld` in `<dir>`, else `guest-sdk/guest.ld` | the linker script, relative to `<dir>` as the former Makefiles wrote it |
| `build` | `--out <path>` | `<dir>/image.bin` | where the packed image is written |
| `build` | `--max-words <n>` | `4096` | the cap `check` measures the built image against |
| `check` | `<file>` (positional) | — | an ELF or an image |
| `check` | `--max-words <n>` | `4096` | the cap |
| `pack` | `<elf>` (positional) | — | the ELF to pack |
| `pack` | `--out <path>` | `<elf>` with a `.bin` extension | where the image (and its `.sha256`) are written |
| `run` | `<image>` (positional) | — | a packed image or a legacy flat binary |
| `run` | `--input <u32>...` | none | private input words, bound to `H_IN` (`READ_INPUT`) |
| `run` | `--public <u32>...` | none | public input words, bound to `H_PUB` (`READ_PUBLIC`) |
| `run` | `--tier <t>` | none | also report whether the run fits tier `t` (10, 12, …, 20) |
| `info` | `<image>` (positional) | — | a packed image or a legacy flat binary |
| `info` | `--max-words <n>` | `4096` | the cap the report is measured against |

`--lang` and `--ld` apply to `build` only, for both languages: a C guest's own `.ld` (if it has
one) is found and used exactly like a Rust guest's, by the same `find_ld`. A guest with a data
segment needs its own `.ld` with `ORIGIN` raised past the loader's `li`/`sw` prologue (`evm.ld`,
`sbpf.ld`: `guest.ld` with the origin moved) — `rand-guest` picks the one `.ld` file it finds in
the guest's own directory, and refuses to guess if there is more than one (`--ld` names it then).

## What `check` rejects

Every text word goes through the machine's own decoder (`Instr::decode`), so a guest that passes
cannot fail in-circuit for an encoding, syscall-number, or layout reason. It refuses:

- a 16-bit (RVC) encoding — the machine decodes only 32-bit RV32IM (`Compressed`)
- an opcode, funct, or shift amount outside what the machine implements (`Undecodable`)
- `FENCE`/`FENCE.I` — no memory-ordering instructions in this machine (`Fence`)
- a CSR instruction — no CSRs in this machine (`Csr`)
- `EBREAK` — traps are not modelled (`Ebreak`)
- an `ecall` whose `a7` is statically known (a preceding `li a7, n` in straight-line code) but
  names no syscall the machine implements (`Syscall`); an `ecall` whose `a7` is *not* statically
  known — set by anything other than `li`, or reached after a branch — is counted separately
  (`unresolved_ecalls`) rather than rejected, since the checker cannot know what it will be at
  run time
- more words than `--max-words`, counted the way the loader would count them — text plus the
  data prologue it synthesises, never estimated from the data word count, since an `li` is one
  word or two depending on the constant and the base register resets periodically (`Cap`)
- a text base that is not word-aligned (`Layout`)

## What `check` does not check

The spec's §4.3 and §4.5 are deferred (`docs/superpowers/specs/2026-09-18-rand-guest-toolchain-design.md`
says why); in practice the linker, the packer and the loader cover them:

- **Layout beyond the text base.** Only the text base's alignment is checked. Sections inside
  `RAM`, unresolved relocations and the entry point are the linker's (an overflowed region or an
  unresolved symbol fails the link; `guest.ld` says `ENTRY(_start)`); the data span is built from
  the sections themselves; a misaligned or wrapping base, data overlapping the text and a prologue
  with no room below the text are refused by the loader. Nothing checks the 64 KiB stack
  reservation against `RAM`'s `LENGTH`, or a stack that outgrows it into `.bss` at run time.
- **Alignment of constant addresses.** No load or store address is folded; the compiler's
  `-unaligned-scalar-mem` is the guarantee, and a misaligned address computed at run time is a
  trap `run` reports.
- **`a7` past a branch target.** The syscall rule tracks the last `li a7, n` in straight-line code
  and forgets it at every branch or jump *instruction* — but not at a branch *target*, which the
  checker does not compute. Code reached by a jump into the middle of a block, after an `li a7`
  that the jumping path never executed, is judged with that `li`'s value. The compilers set `a7`
  immediately before each `ecall`, so this does not arise in practice, but a hand-written or
  translated text could hide an unimplemented syscall number from the check this way (the machine
  still traps on it at run time).
- **What a syscall does with its arguments** — pointers, lengths, input indices. Those are run-time
  values; `run` reports the trap.

## The cap: `--max-words` and its default

The default, `4096`, is the fullnode's deploy cap today. Both loaders (`Program::from_flat_image`,
`Program::from_flat_binary`) refuse anything over **65 535** words outright (`LoadError::TooLong`)
regardless of `--max-words` — the hard ceiling the v0.4 chain is expected to raise the deploy cap
to. The two committed interpreters are already over the default: `evm.bin` is 18 009 words and
`sbpf.bin` is bigger still, so building or checking either needs `--max-words 65535` — as
`rand-guest/tests/build.rs` passes it, and as a developer building `evm` or `sbpf` by hand must
pass it too, there being no build script that does it for them (`guests-compiled/README.md`'s
own example command shows it). `fib`, `keccak256`, and `c-fib` all fit comfortably under 4096.

## The two image forms

`build` and `pack` always write the **image container** (`IMAGE_MAGIC` header, `Program::from_flat_image`):
a text span, a data span with its own base, and the loader's own `li`/`sw` prologue that writes
the data words at load time. `evm.bin` and `sbpf.bin` are committed and gated in this form, byte
for byte.

`fib.bin` and `keccak256.bin` are **legacy flat binaries** — headerless, no data segment, predating
this toolchain, loaded at the fixed `ORIGIN` `guest-sdk/guest.ld` gives every guest, `0x1000`
(`Program::from_flat_binary(0x1000, …)`). `build` still only knows how to emit the container form
for them, so rebuilding them does not reproduce their committed bytes; see "Byte/program identity"
below for what is actually pinned instead. Every subcommand that loads an image (`check`, `run`,
`info`) tries the container form first and falls back to the flat one on a bare `Magic` mismatch,
so callers never need to say which one they have.

## The C path

`build --lang c` compiles every `.c` file in the guest directory (sorted, so link order does not
depend on the directory's) plus this crate's own `start.S` and `rt.c`, with `rust-lld` linking
against the same `guest.ld` the Rust guests use. Prerequisites:

- a clang that targets `riscv32`: either Homebrew's LLVM (`brew install llvm` — Apple's system
  clang has no RISC-V backend) at its default path, or any other clang set via `$CLANG`
- `rustup +1.98.1 component add llvm-tools`, for `rust-lld` — the same linker the Rust guests use,
  found in the pinned toolchain's own sysroot, so a C guest needs no separate linker installed

`rt.c` is the C runtime. `-ffreestanding -fno-builtin` stop clang *recognising* library
functions, not *emitting* calls to them: a struct copy still becomes a `memcpy` call, a large zero
initialiser a `memset`, and a 64-bit `/` or `%` by a runtime value a call to `__udivdi3`,
`__umoddi3`, `__divdi3` or `__moddi3` (RV32IM divides 32-bit values only). `rt.c` defines those
eight — `memcpy`, `memmove`, `memset`, `memcmp` and the four division helpers, as byte loops and
shift-subtract division that call nothing themselves — and is linked into every C guest. The link
uses `--gc-sections` over `-ffunction-sections` objects, so only what a guest calls reaches its
image (`c-fib` is still 25 words). They are slow; copy and divide in words in a hot loop.

A C guest writes `#include "guest.h"` for the syscall wrappers (`rand_read_input`,
`rand_read_public`, `rand_write_output`, `rand_poseidon2`, `rand_keccak`,
`rand_sha256_compress`, `rand_halt`) and needs no `_start` of its own — both are written into the
guest's `target/rand-guest/` and put on the include path, so a C guest directory is its own
source and nothing else. Because of that, `build --lang c` refuses a guest directory that already
has its own `guest.h` or `start.S`. The two fail silently in different ways: a local `guest.h`
would shadow the toolchain's copy, since `#include "guest.h"`'s quote form searches the including
file's own directory before the `-I` path; a local `start.S` would not be compiled at all — `build_c`
only globs `.c` files — so the guest's intended entry point would be silently dropped in favour of
the bundled one.

## Byte/program identity for the committed guests

`fib`, `keccak256`, `evm`, and `sbpf` are the four guests pinned in `guests-compiled/bin/` (each
`<name>.bin` with a `<name>.bin.sha256`), and `rand-guest/tests/build.rs` gates all four on every
run. `evm` and `sbpf` are image containers: rebuilding must reproduce the committed bytes exactly,
checked by comparing SHA-256 hashes. `fib` and `keccak256` are the legacy flat-binary pins: since
`build` always writes the container form, the byte gate does not apply to them; instead the test
compares the *program* the freshly built image loads to against the program the committed flat
binary loads to — same `base_pc`, same `words`, same `digest()` (`hc`). `c-fib`, the C path's
guest, is not one of the four pins; it exists to exercise `--lang c` end to end and is checked
functionally (build, check, run to the same `fib(20) = 6765` the Rust `fib` guest gives), not
pinned.
