# Compiled guests

Built with the toolchain, never by hand — for example, after an `evm-core` change:

    cd rand-guest && cargo run -- build ../guests-compiled/evm --out ../guests-compiled/bin/evm.bin --max-words 65535

That writes `bin/evm.bin` and `bin/evm.bin.sha256` together. `--max-words 65535` is needed for
`evm` and `sbpf`: both interpreter guests are far over the chain's default 4096-word cap
(`rand-guest/README.md`'s "The cap"), which is a genesis parameter on the v0.4 chain, not yet
raised for either of them.

**`evm.bin` and `evm-v1.bin` are one source.** `guests-compiled/evm` and `guests-compiled/evm-v1`
both include `evm/src/guest.rs`; the second builds `evm-core` with its `storage-v1` feature
(storage layout 1, a depth-32 tree) and the first without (layout 2, depth 64). After an
`evm-core` change both are rebuilt:

    cd rand-guest && cargo run -- build ../guests-compiled/evm-v1 --out ../guests-compiled/bin/evm-v1.bin --max-words 65535

`research/docs/04-guests.md`'s "Storage layouts and program versions" says what the two are for.

**`fib.bin` and `keccak256.bin` are never rebuilt over.** They are legacy flat pins (below) and
`build` only writes the image container, so a rebuild into `bin/` would replace a file two repos
load with `from_flat_binary` by one they cannot; `rand-guest build` refuses to write over them.
They are checked instead: by `rand-guest/tests/build.rs`, which builds both into a temporary
directory and compares the programs, and by `rand-guest info`.

`rand-guest build` compiles with the pinned toolchain and the fixed flags, checks the ELF
against the machine, packs the image and prints its `hc`. `bin/<guest>.bin.sha256` pins each
image; `rand-guest/tests/build.rs` rebuilds all six and compares. A guest with a data segment
links with its own `.ld` (`evm.ld`, `sbpf.ld`: `guest.ld` with `ORIGIN` raised for the
prologue), which `rand-guest` finds by itself.

## The two shapes the six pins have

Six images are pinned in `bin/` (`*.bin.sha256`): `fib`, `keccak256`, `evm`, `sbpf`,
`dilithium-verify` and `msauth`.

`evm.bin`, `sbpf.bin`, `dilithium-verify.bin` and `msauth.bin` are image containers (`docs/01-isa.md`'s "The image container"):
`rand-guest build` packs every guest into this form, header and all, and `rand-guest/tests/build.rs`
gates them byte for byte against the committed `.bin`.

`fib.bin` and `keccak256.bin` are legacy flat binaries — headerless, no data segment, predating
the image container and the toolchain — pinned as they are and loaded with
`Program::from_flat_binary(0x1000, …)` in two repos (`research/src/guests.rs` here, and again in
`fullnode`). `rand-guest build` still emits the container form for them, since that is the one
thing the tool knows how to write; the byte gate for this pair is therefore program equality, not
image bytes — `rand-guest/tests/build.rs` compares `base_pc`, `words` and `digest()` between the
image it built and the committed flat binary rather than diffing bytes. `rand-guest`'s loader
(`info`, `check`, `run`) accepts both forms.
