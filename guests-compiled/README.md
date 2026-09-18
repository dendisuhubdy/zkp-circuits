# Compiled guests

Built with the toolchain, never by hand:

    cd rand-guest && cargo run -- build ../guests-compiled/<guest> --out ../guests-compiled/bin/<guest>.bin

`rand-guest build` compiles with the pinned toolchain and the fixed flags, checks the ELF
against the machine, packs the image and prints its `hc`. `bin/<guest>.bin.sha256` pins each
image; `rand-guest/tests/build.rs` rebuilds all four and compares. A guest with a data segment
links with its own `.ld` (`evm.ld`, `sbpf.ld`: `guest.ld` with `ORIGIN` raised for the
prologue), which `rand-guest` finds by itself.

## The two shapes the four pins have

`evm.bin` and `sbpf.bin` are image containers (`docs/01-isa.md`'s "The image container"):
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
