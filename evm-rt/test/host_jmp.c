/* The host's `evm_rt_enter`/`evm_rt_unwind`: libc's setjmp, which the runtime itself may not use
 * (it is freestanding; on RV32 `evm_rt.c` carries its own). The same contract as the RV32 one:
 * run `entry`, treat a normal return as STOP, come back here from any `evm_halt`. */
#include <setjmp.h>
#include "../evm_rt.h"

#if !(defined(__riscv) && __riscv_xlen == 32)
static jmp_buf host_jb;

uint32_t evm_rt_enter(void (*entry)(void)) {
    if (setjmp(host_jb) == 0) {
        entry();
        evm_halt(EVM_HALT_STOP, 0);
    }
    return evm_halt_code;
}

void evm_rt_unwind(void) { longjmp(host_jb, 1); }
#endif
