# guest-sdk

The Rust side of a Rand zkVM guest: the syscall wrappers, the entry point (`_start`), the panic
handler and the linker script (`guest.ld`). `no_std`, `riscv32im-unknown-none-elf` only. The C
twin is `rand-guest/guest.h`. Guests are built with `rand-guest build` and nothing else
(`rand-guest/README.md`).

## What a guest can do

| | |
|---|---|
| `read_input(i)`, `read_input_words(base, &mut dst)` | private input words, bound to the proof's salted `H_IN` |
| `read_public(i)` | public input words, bound to the unsalted `H_PUB` a verifier recomputes |
| `write_output(slot, word)` | one of eight public output words; each slot at most once |
| `halt()` | ends the run; **a halted run is a provable run** |
| `refuse()`, `require!(cond)` | ends the run in a trap, which has no proof: the way to reject |
| `poseidon2_len(&mut buf, n)` | the length-bound Poseidon2 sponge; `unsafe poseidon2(ptr, n)` is the unpadded one the protocol's own digests use |
| `keccak256(&bytes)`, `keccak(&mut state)` | Keccak-256, and the bare permutation |
| `sha256(&bytes)`, `sha256_compress(&mut buf)` | SHA-256, and the bare compression |
| `SyscallRing`, `SyscallKeccak` (feature `dilithium`) | Dilithium2's ring arithmetic over the `MODQ` coprocessor |

The ABI behind each is `research/docs/01-isa.md`, "Syscall ABI".

## A worked example

A guest that proves "I know a secret whose hash is this public digest, and its first word is at
most a public limit" without revealing the secret.

`Cargo.toml` (copy `guests-compiled/fib/Cargo.toml`'s `[profile.release]` and `[workspace]`
tables as they are):

```toml
[package]
name = "limit-guest"
version = "0.1.0"
edition = "2021"

[dependencies]
guest-sdk = { path = "../../guest-sdk" }
```

`src/main.rs`:

```rust
#![no_std]
#![no_main]
use guest_sdk::{halt, poseidon2_len, read_input_words, read_public, require, write_output};

#[no_mangle]
pub extern "C" fn main() -> ! {
    // Private: the four-word secret. Public: the limit, then the eight-word digest.
    let mut buf = [0u32; 8];
    read_input_words(0, &mut buf[..4]);
    let first = buf[0];
    let limit = read_public(0);

    // The statement. A false one must leave no proof: `require!`, never `assert!`.
    require!(first <= limit);
    let digest = poseidon2_len(&mut buf, 4);
    let mut i = 0;
    while i < 8 {
        require!(digest[i] == read_public(1 + i as u32));
        i += 1;
    }

    write_output(0, 1);
    halt();
}
```

Build, run and look at it (from `rand-guest/`, with the guest in `guests-compiled/limit/`):

```text
cargo +1.98.1 run -- build ../guests-compiled/limit
cargo +1.98.1 run -- run ../guests-compiled/limit/image.bin --input 5 6 7 8 --public 10 <the eight digest words>
cargo +1.98.1 run -- profile ../guests-compiled/limit/image.bin \
    --elf ../guests-compiled/limit/target/riscv32im-unknown-none-elf/release/limit-guest \
    --input 5 6 7 8 --public 10 <the eight digest words>
```

A run whose statement is false prints `refused: …` and exits 2; `Machine::prove` returns the same
error and no proof. The digest words are `rand_zkvm::hash::sponge_hash_len(&[5, 6, 7, 8])` on the
host.

## Rules that are easy to get wrong

- **Reject with `refuse()` / `require!`.** A panic — `assert!`, `unwrap`, an out-of-range index,
  an overflow check — runs the panic handler, which writes `out[7] = 0xdeadbeef` and *halts*, so
  the run still proves. `rand-guest build` rejects a guest that links the panic machinery unless
  `--allow-panic` is passed (`rand-guest/README.md`, "Rejecting").
- **Private or public is a privacy decision.** A digest the guest declares over `read_input` words
  is bound to nothing a verifier can check; over `read_public` words it is.
- **`poseidon2` does not pad.** `[a]` and `[a, 0]` hash the same; use `poseidon2_len` for anything
  whose length can vary.
- **The stack is 64 KiB and unchecked.** `rand-guest run` reports the depth a run reached and
  warns past the reserved size.
- **The guest must live inside a circuits checkout** (`rand-guest build` finds `guest-sdk/` by
  walking up), and the SDK cannot be built for the host, so guest logic that should be unit-tested
  belongs in a separate `no_std` crate the guest depends on.
- **Do not insert lines into `src/lib.rs`.** Panic locations carry its line numbers into a guest's
  `.rodata`, which `hc` binds; new code goes in a new module named at the end of the file, as
  `refuse.rs` is.
