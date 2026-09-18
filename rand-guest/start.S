/* `_start`, byte for byte `guest-sdk/src/lib.rs`'s `global_asm!`: sets `sp` to the
 * linker-provided `__stack_top` (`guest-sdk/guest.ld`) and calls the guest's own `main`. `la`
 * and `call` lower to `auipc`+`addi` and `auipc`+`jalr` — both RV32I, both in this machine's
 * decoder. If `main` ever returns instead of calling `rand_halt()` itself, the `li`/`ecall`
 * below halt here rather than falling into whatever bytes follow in `.text`. */
    .section .text._start
    .global _start
_start:
    la sp, __stack_top
    call main
    li a7, 0
    ecall
