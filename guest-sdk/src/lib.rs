//! Syscall wrappers and the guest entry point for RV32IM binaries this machine can load and
//! prove (`Program::from_flat_binary`, `research/src/isa.rs`). Every wrapper matches
//! `research/docs/01-isa.md`'s syscall ABI exactly: syscall number in `a7`, first argument in
//! `a0`, a second argument (only `POSEIDON2` and `POSEIDON2_LEN` need one) in `a1`, a returned
//! value in `a0`.
#![no_std]

#[cfg(not(target_arch = "riscv32"))]
compile_error!("guest-sdk only builds for riscv32im-unknown-none-elf");

const SYS_HALT: u32 = 0;
const SYS_WRITE_OUTPUT: u32 = 1;
const SYS_READ_INPUT: u32 = 2;
const SYS_POSEIDON2: u32 = 3;
const SYS_KECCAK: u32 = 4;
const SYS_SHA256: u32 = 5;
const SYS_READ_PUBLIC: u32 = 6;
const SYS_POSEIDON2_LEN: u32 = 7;
/// `research/src/isa.rs`'s `POSEIDON2_MAX_WORDS`.
const POSEIDON2_MAX_WORDS: usize = 4096;

/// SHA-256's initial hash value `H(0)` (FIPS 180-4 §5.3.3), the chaining state `sha256` starts
/// from; `research/src/sha256.rs::IV` is the same table host-side.
const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Returns private input word `idx` — bound, since milestone 4.1, to the proof's `H_IN`
/// commitment (`research/docs/03-privacy.md`): two calls with the same `idx` are guaranteed
/// to return the same word, and `idx >= n_in` (the number of words the caller committed) can
/// never be satisfied at all.
#[inline(always)]
pub fn read_input(idx: u32) -> u32 {
    let out: u32;
    unsafe { // SAFETY: `READ_INPUT` reads no guest memory and writes only `a0` (`lateout`), leaving every other register and all memory as they were (`research/src/emulator.rs`'s ecall arm; `research/docs/01-isa.md`, "Syscall ABI").
        core::arch::asm!(
            "ecall",
            in("a7") SYS_READ_INPUT,
            in("a0") idx,
            lateout("a0") out,
            options(nostack),
        );
    }
    out
}

/// Returns **public** input word `idx` — committed to the proof's unsalted `H_PUB`
/// (`pv::PUB0..7`), which anyone holding the words recomputes and checks
/// (`Machine::verify_public`). Use this for data the chain sees anyway (a program image, a
/// codehash, calldata): a digest the guest *declares* over these words is sound, where the
/// same declaration over `read_input` words would be bound to nothing.
/// `idx >= n_pub` can never be satisfied.
#[inline(always)]
pub fn read_public(idx: u32) -> u32 {
    let out: u32;
    unsafe { // SAFETY: `READ_PUBLIC` reads no guest memory and writes only `a0` (`lateout`), leaving every other register and all memory as they were — `READ_INPUT`'s twin.
        core::arch::asm!(
            "ecall",
            in("a7") SYS_READ_PUBLIC,
            in("a0") idx,
            lateout("a0") out,
            options(nostack),
        );
    }
    out
}

#[inline(always)]
pub fn write_output(slot: u32, word: u32) {
    unsafe { // SAFETY: `WRITE_OUTPUT` reads `a0`/`a1` and writes no register and no guest memory; a bad or repeated slot makes the run unprovable, not undefined.
        core::arch::asm!(
            "ecall",
            in("a7") SYS_WRITE_OUTPUT,
            in("a0") slot,
            in("a1") word,
            options(nostack),
        );
    }
}

/// `ptr`: a 4-byte-aligned pointer to `n` words hashed in place with the `POSEIDON2` sponge,
/// `ptr..ptr+8` overwritten with the digest. `n <= 4096` (`isa::POSEIDON2_MAX_WORDS`).
///
/// **The sponge does not pad, so it is not injective over variable-length input** (audit
/// ZKH-3). It starts from the zero state and *overwrites* lanes with each 4-word chunk, so within
/// the first chunk a trailing zero word and an absent one are the same: `[a]` and `[a, 0]` (and
/// `[a, 0, 0]`, `[a, 0, 0, 0]`) hash identically. If the length of what you hash can vary — a
/// short id, an amount, a variable-length record — put the length in the message (`[n, w0, ..]`)
/// or hash a fixed-length encoding, and give each use its own domain-tag word, as the note layer
/// does (`research/docs/01-isa.md`, "`POSEIDON2` does not pad") — or use `poseidon2_len`, whose
/// sponge binds the length itself (a different hash of the same words, HCS-4).
///
/// The syscall takes a **word address** in `a0` (`research/docs/01-isa.md`'s `MEM_ADDR`
/// convention), so this divides the byte pointer by 4. Fixed in M4.2: the doc comment always
/// said word address but the body passed the byte pointer straight through, so a compiled guest
/// calling this would have hashed the words at four times the intended address. No committed
/// guest binary calls `poseidon2` (`fib.bin` does not), so no binary changes with this fix.
///
/// # Safety
///
/// The syscall reads `n` words at `ptr` and overwrites 8 there, so `ptr` must be 4-byte aligned and
/// valid for reads of `n` words and writes of 8, with nothing else reading or writing those words
/// for the duration of the call, and `n <= 4096`. (R4-b: this used to be a safe fn over the
/// caller's raw pointer. It stays a raw-pointer `unsafe fn` rather than taking a slice because the
/// two chained-digest callers in `evm2rv`/`sbpf2rv`'s shims hash in place over a `static` buffer,
/// and a checked slice API would add code to the pinned images; `poseidon2_len` is the safe
/// slice-taking API.)
#[inline(always)]
pub unsafe fn poseidon2(ptr: *mut u32, n: usize) {
    debug_assert!((ptr as u32) % 4 == 0);
    unsafe { // SAFETY: the syscall writes no register, reads `n` words and overwrites 8 at `ptr`; the caller upholds this fn's `# Safety` contract for exactly that range.
        core::arch::asm!(
            "ecall",
            in("a7") SYS_POSEIDON2,
            in("a0") (ptr as u32) / 4,
            in("a1") n as u32,
            options(nostack),
        );
    }
}

/// Hashes `buf[..n]` with the **length-bound** Poseidon2 sponge — the `POSEIDON2_LEN` syscall
/// (HCS-4, the next constraint set; `research/src/hash.rs`'s `sponge_hash_len`) — writes the 8-word
/// (lo/hi) digest over `buf[..8]` and returns it. The sponge starts with `n` in its capacity, so
/// `[a]` and `[a, 0]` differ and the empty message is not the zero digest: prefer this to
/// `poseidon2` for anything whose length can vary.
///
/// Safe: `buf` is a live, exclusively borrowed, 4-aligned buffer, and the call panics (the panic
/// handler halts with the sentinel output) unless it covers both what the syscall reads (`n` words)
/// and what it writes (8 words), with `n <= 4096`.
#[inline(always)]
pub fn poseidon2_len(buf: &mut [u32], n: usize) -> [u32; 8] {
    assert!(n <= buf.len() && buf.len() >= 8 && n <= POSEIDON2_MAX_WORDS);
    unsafe { // SAFETY: the syscall writes no register, reads `buf[..n]` and overwrites `buf[..8]`; the assert above keeps both inside `buf`, which `&mut` makes 4-aligned, valid and unaliased for the whole call.
        core::arch::asm!(
            "ecall",
            in("a7") SYS_POSEIDON2_LEN,
            in("a0") (buf.as_mut_ptr() as u32) / 4,
            in("a1") n as u32,
            options(nostack),
        );
    }
    let mut out = [0u32; 8];
    out.copy_from_slice(&buf[..8]);
    out
}

/// `state`: 50 words (200 bytes) holding a Keccak-f[1600] state — lane `i`'s low word at `2i`, its
/// high word at `2i+1` — permuted in place by one call. The syscall takes a **word** address in
/// `a0`, so this divides the array's byte address by 4, the same convention as `poseidon2`.
///
/// R4-b: this took a raw pointer and was a safe fn over it; the array reference makes the contract
/// the type's (4-aligned, 50 words, exclusively borrowed), with the same machine code at every call.
#[inline(always)]
pub fn keccak(state: &mut [u32; 50]) {
    unsafe { // SAFETY: the syscall writes no register and permutes the 50 words at `state` in place; `&mut [u32; 50]` is exactly 50 valid, 4-aligned, unaliased words for the whole call.
        core::arch::asm!(
            "ecall",
            in("a7") SYS_KECCAK,
            in("a0") (state.as_mut_ptr() as u32) / 4,
            options(nostack),
        );
    }
}

/// Keccak-256 (the Ethereum variant: rate 136 bytes, `0x01` domain padding) as a software
/// sponge over the `KECCAK` syscall — the permutation is the chip's, the padding and absorption
/// are the guest's. `research/tests/keccak.rs` transcribes this loop and checks it against the
/// host `keccak::keccak256` at every block boundary.
///
/// A message whose length is an exact multiple of 136 (zero included) still needs a whole extra
/// all-padding block; the loop gets that from `take == 0` on its final pass, since `last` is set
/// by `take < 136` rather than by exhausting the message.
pub fn keccak256(msg: &[u8]) -> [u8; 32] {
    let mut state = [0u32; 50];
    let mut block = [0u8; 136];
    let mut off = 0;
    loop {
        let take = core::cmp::min(136, msg.len() - off);
        block.fill(0);
        block[..take].copy_from_slice(&msg[off..off + take]);
        let last = take < 136;
        if last { block[take] ^= 0x01; block[135] ^= 0x80; }
        for i in 0..34 { state[i] ^= u32::from_le_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]); }
        keccak(&mut state);
        off += take;
        if last { break; }
    }
    let mut out = [0u8; 32];
    for i in 0..8 { out[4 * i..4 * i + 4].copy_from_slice(&state[i].to_le_bytes()); }
    out
}

/// `buf`: 24 words (96 bytes) holding one SHA-256 compression's argument — the 512-bit message
/// block as sixteen big-endian-valued words at `0..16`, the chaining state `H` at `16..24`. One
/// call compresses them, writing `H + f(H, W)` back over words `16..24` and leaving the block
/// untouched. The syscall takes a **word** address in `a0`, so this divides the array's byte
/// address by 4, the same convention as `keccak`.
///
/// R4-b: this took a raw pointer and was a safe fn over it; the array reference makes the contract
/// the type's, with the same machine code at every call.
#[inline(always)]
pub fn sha256_compress(buf: &mut [u32; 24]) {
    unsafe { // SAFETY: the syscall writes no register, reads the 24 words at `buf` and overwrites words `16..24`; `&mut [u32; 24]` is exactly 24 valid, 4-aligned, unaliased words for the whole call.
        core::arch::asm!(
            "ecall",
            in("a7") SYS_SHA256,
            in("a0") (buf.as_mut_ptr() as u32) / 4,
            options(nostack),
        );
    }
}

/// SHA-256 (FIPS 180-4) as a software Merkle-Damgård loop over the `SHA256` syscall — the
/// compression is the chip's, the padding and the chaining are the guest's, exactly as
/// `keccak256` splits its sponge. One 24-word buffer serves the whole message: words `16..24`
/// hold the running state across calls, words `0..16` are overwritten with each block.
///
/// `research/tests/sha256.rs` transcribes this loop and checks it against the host
/// `sha256::sha256` at every block-boundary case.
pub fn sha256(msg: &[u8]) -> [u8; 32] {
    let mut buf = [0u32; 24];
    buf[16..].copy_from_slice(&SHA256_IV);
    let mut block = [0u8; 64];
    let mut off = 0;
    // Every whole 64-byte block of the message itself.
    while msg.len() - off >= 64 {
        block.copy_from_slice(&msg[off..off + 64]);
        compress_bytes(&mut buf, &block);
        off += 64;
    }
    // The tail: `rest < 64` leftover bytes, the `0x80` terminator, then eight zero bytes and the
    // big-endian bit length — in this same block if the terminator left room for them (`rest <
    // 56`), in one further all-padding block if it did not.
    let rest = msg.len() - off;
    block.fill(0);
    block[..rest].copy_from_slice(&msg[off..]);
    block[rest] = 0x80;
    if rest >= 56 {
        compress_bytes(&mut buf, &block);
        block.fill(0);
    }
    block[56..].copy_from_slice(&(msg.len() as u64).wrapping_mul(8).to_be_bytes());
    compress_bytes(&mut buf, &block);

    let mut out = [0u8; 32];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&buf[16 + i].to_be_bytes());
    }
    out
}

/// Packs `block`'s 64 bytes into `buf[0..16]` big-endian — the word order `SYS_SHA256` reads them
/// in — and compresses `buf` in place.
fn compress_bytes(buf: &mut [u32; 24], block: &[u8; 64]) {
    for i in 0..16 {
        buf[i] = u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
    }
    sha256_compress(buf);
}

// Deviation from the brief's literal `options(nostack, noreturn)`: on this bare-metal target
// rustc unconditionally treats the IR block after a `noreturn` asm! as `unreachable` and lowers
// that to a genuine trap instruction (LLVM encodes it as `csrrw x0, cycle, x0` = 0xc0001073,
// disassembling as `unimp`) — confirmed by comparing `--emit=llvm-ir` output run through `llc`
// directly (no trap, `-trap-unreachable` cl::opt defaults false there) against the same IR
// compiled through `cargo`/rustc's own TargetMachine construction (trap present regardless of
// `-C llvm-args=-trap-unreachable=false`, which has no effect since rustc sets this field on
// the LLVM TargetOptions struct directly rather than consulting that command-line flag). That
// trailing SYSTEM-opcode word is not `ECALL`/`EBREAK`, so `Instr::decode` correctly rejects it
// (`LoadError::Decode { err: Opcode(115), .. }`) — extending the decoder to accept CSR
// instructions is out of scope for this task. Dropping `noreturn` and giving the compiler a
// real backward branch instead removes the need for rustc to synthesize `unreachable` at all:
// the function still never returns, but now because it loops, not because LLVM promises it.
#[inline(always)]
pub fn halt() -> ! {
    unsafe { // SAFETY: `HALT` reads only `a7` and ends execution: nothing after the ecall runs, so no register or memory the compiler relies on is observed afterwards; the `loop {}` below is the `!` the type needs, never reached.
        core::arch::asm!(
            "ecall",
            in("a7") SYS_HALT,
            options(nostack),
        );
    }
    loop {}
}

/// A panicking guest halts with output slot 7 set to a fixed sentinel, rather than looping
/// forever or executing whatever undefined instruction `core::panic` would otherwise fall
/// through to (there is no `abort`/`unreachable` intrinsic lowering safe on this target
/// without one).
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    write_output(7, 0xdead_beef);
    halt();
}

// `_start`: sets `sp` to the linker-provided `__stack_top` (`guest.ld`) and calls the guest's
// own `main`. `la`/`call` lower to `auipc`+`addi`/`auipc`+`jalr` — both RV32I, both in this
// machine's decoder — no pseudo-instruction here needs an extension the target lacks.
core::arch::global_asm!(
    ".section .text._start",
    ".global _start",
    "_start:",
    "    la sp, __stack_top",
    "    call main",
    // Defense in depth: if `main` ever returns instead of calling `halt()` itself, halt here
    // rather than falling into whatever bytes follow in `.text`.
    "    li a7, 0",
    "    ecall",
);
