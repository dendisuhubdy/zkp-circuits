//! Syscall wrappers and the guest entry point for RV32IM binaries this machine can load and
//! prove (`Program::from_flat_binary`, `research/src/isa.rs`). Every wrapper matches
//! `research/docs/01-isa.md`'s syscall ABI exactly: syscall number in `a7`, first argument in
//! `a0`, a second argument (only `POSEIDON2` needs one) in `a1`, a returned value in `a0`.
#![no_std]

#[cfg(not(target_arch = "riscv32"))]
compile_error!("guest-sdk only builds for riscv32im-unknown-none-elf");

const SYS_HALT: u32 = 0;
const SYS_WRITE_OUTPUT: u32 = 1;
const SYS_READ_INPUT: u32 = 2;
const SYS_POSEIDON2: u32 = 3;
const SYS_KECCAK: u32 = 4;

/// Returns private input word `idx` — bound, since milestone 4.1, to the proof's `H_IN`
/// commitment (`research/docs/03-privacy.md`): two calls with the same `idx` are guaranteed
/// to return the same word, and `idx >= n_in` (the number of words the caller committed) can
/// never be satisfied at all.
#[inline(always)]
pub fn read_input(idx: u32) -> u32 {
    let out: u32;
    unsafe {
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

#[inline(always)]
pub fn write_output(slot: u32, word: u32) {
    unsafe {
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
/// The syscall takes a **word address** in `a0` (`research/docs/01-isa.md`'s `MEM_ADDR`
/// convention), so this divides the byte pointer by 4. Fixed in M4.2: the doc comment always
/// said word address but the body passed the byte pointer straight through, so a compiled guest
/// calling this would have hashed the words at four times the intended address. No committed
/// guest binary calls `poseidon2` (`fib.bin` does not), so no binary changes with this fix.
#[inline(always)]
pub fn poseidon2(ptr: *mut u32, n: usize) {
    debug_assert!((ptr as u32) % 4 == 0);
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") SYS_POSEIDON2,
            in("a0") (ptr as u32) / 4,
            in("a1") n as u32,
            options(nostack),
        );
    }
}

/// `ptr`: a 4-byte-aligned pointer to 50 words (200 bytes) holding a Keccak-f[1600] state —
/// lane `i`'s low word at `2i`, its high word at `2i+1` — permuted in place by one call. The
/// syscall takes a **word** address in `a0`, so this divides the byte pointer by 4, the same
/// convention as `poseidon2`.
#[inline(always)]
pub fn keccak(ptr: *mut u32) {
    debug_assert!((ptr as u32) % 4 == 0);
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") SYS_KECCAK,
            in("a0") (ptr as u32) / 4,
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
        keccak(state.as_mut_ptr());
        off += take;
        if last { break; }
    }
    let mut out = [0u8; 32];
    for i in 0..8 { out[4 * i..4 * i + 4].copy_from_slice(&state[i].to_le_bytes()); }
    out
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
    unsafe {
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
