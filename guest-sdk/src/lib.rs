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

/// `ptr`: a **word address** (already divided by 4, `research/docs/01-isa.md`'s `MEM_ADDR`
/// convention), pointing at `n` words to hash in place with the `POSEIDON2` sponge, `ptr..
/// ptr+8` overwritten with the digest. `n <= 4096` (`isa::POSEIDON2_MAX_WORDS`).
#[inline(always)]
pub fn poseidon2(ptr: *mut u32, n: usize) {
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") SYS_POSEIDON2,
            in("a0") ptr as u32,
            in("a1") n as u32,
            options(nostack),
        );
    }
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
