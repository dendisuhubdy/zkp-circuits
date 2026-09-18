/* The runtime's state and calls (see evm_rt.h). Each call is the matching arm of
 * `interp.rs`'s `Interpreter::step`, or one of its helpers (`mem`, `copy_to_memory`,
 * `read_padded`, `len_arg`, `charge`), with the same checks in the same order. */
#include "evm_rt.h"

u256 evm_stack[STACK_LIMIT];
uint32_t evm_sp;
uint64_t evm_gas;
uint64_t evm_gas_limit;
uint8_t evm_memory[MAX_MEMORY_BYTES] __attribute__((aligned(4)));
uint32_t evm_msize;

const uint8_t *evm_code;
uint32_t evm_code_len;
const uint8_t *evm_calldata;
uint32_t evm_calldata_len;

u256 evm_address;
u256 evm_caller;
u256 evm_callvalue;

void *evm_tree;
void *evm_host;

uint8_t evm_ret[MAX_RETURN_BYTES];
uint32_t evm_ret_len;

evm_log_t evm_logs[MAX_LOGS];
uint32_t evm_n_logs;

uint32_t evm_halt_code;
uint32_t evm_halt_arg;

/* ---- lifecycle ---- */

uint32_t evm_rt_init(const uint8_t *code, uint32_t code_len, const uint8_t *calldata,
                     uint32_t calldata_len, uint64_t gas_limit) {
    uint32_t pre = EVM_HALT_OK;
    if (code_len > MAX_CODE_BYTES || calldata_len > MAX_CALLDATA_BYTES) pre = EVM_HALT_OUT_OF_BOUNDS;
    /* Capped, as `Interpreter::new` caps its slices (nothing past a cap is ever read). */
    evm_code = code;
    evm_code_len = code_len > MAX_CODE_BYTES ? MAX_CODE_BYTES : code_len;
    evm_calldata = calldata;
    evm_calldata_len = calldata_len > MAX_CALLDATA_BYTES ? MAX_CALLDATA_BYTES : calldata_len;
    /* Every byte the last run could have written is below its msize (the `dirty_mem` rule); a
     * fresh .bss needs nothing cleared. */
    for (uint32_t i = 0; i < evm_msize; i++) evm_memory[i] = 0;
    evm_msize = 0;
    evm_sp = 0;
    evm_gas = gas_limit;
    evm_gas_limit = gas_limit;
    evm_ret_len = 0;
    evm_n_logs = 0;
    evm_halt_code = EVM_HALT_OK;
    evm_halt_arg = 0;
    return pre;
}

uint64_t evm_gas_used(void) { return evm_gas_limit - evm_gas; }

void evm_halt(uint32_t halt_code, uint32_t arg) {
    evm_halt_code = halt_code;
    evm_halt_arg = arg;
    /* Every exceptional halt consumes the whole limit; only STOP/RETURN/REVERT leave gas. */
    if (halt_code != EVM_HALT_STOP && halt_code != EVM_HALT_RETURN && halt_code != EVM_HALT_REVERT)
        evm_gas = 0;
    evm_rt_unwind();
}

/* ---- gas and memory ---- */

void evm_charge(uint64_t g) {
    if (g > evm_gas) evm_halt(EVM_HALT_OUT_OF_GAS, 0);
    evm_gas -= g;
}

/* Bytes rounded up to whole words (`words`). */
static uint64_t words(uint64_t bytes) { return (bytes + 31) / 32; }

/* `expansion_cost`: 3w + floor(w^2 / 512). w <= 2048, so w^2 fits a u32 — no 64-bit division. */
static uint32_t expansion_cost(uint32_t w) { return G_MEMORY * w + w * w / 512; }

/* `len_arg`: a byte count past the memory is out of bounds, never a gas charge. */
static void len_arg(uint32_t len) {
    if (len > MAX_MEMORY_BYTES) evm_halt(EVM_HALT_OUT_OF_BOUNDS, 0);
}

uint32_t evm_mexpand(uint32_t offset, uint32_t len) {
    if (len == 0) return 0;
    uint64_t end = (uint64_t)offset + len; /* no u32 wrap */
    if (end > MAX_MEMORY_BYTES) evm_halt(EVM_HALT_OUT_OF_BOUNDS, 0);
    uint32_t w = (uint32_t)words(end);
    uint32_t want = w * 32;
    if (want > evm_msize) {
        evm_charge(expansion_cost(w) - expansion_cost(evm_msize / 32));
        evm_msize = want;
    }
    return offset;
}

void evm_mload(uint32_t off, u256 *r) {
    uint32_t start = evm_mexpand(off, 32);
    u256_from_be_bytes(r, evm_memory + start);
}

void evm_mstore(uint32_t off, const u256 *v) {
    uint32_t start = evm_mexpand(off, 32);
    u256_to_be_bytes(evm_memory + start, v);
}

void evm_mstore8(uint32_t off, uint32_t b) {
    uint32_t start = evm_mexpand(off, 1);
    evm_memory[start] = (uint8_t)b;
}

/* `read_padded`: the offset widened so an offset near UINT32_MAX cannot wrap. */
void evm_calldataload(uint32_t off, u256 *r) {
    uint8_t b[32];
    for (uint32_t i = 0; i < 32; i++) {
        uint64_t s = (uint64_t)off + i;
        b[i] = s < evm_calldata_len ? evm_calldata[s] : 0;
    }
    u256_from_be_bytes(r, b);
}

/* `copy_to_memory`. */
static void copy_to_memory(uint32_t dst, uint32_t src, uint32_t len, const uint8_t *from,
                           uint32_t from_len) {
    len_arg(len);
    evm_charge(G_COPY_WORD * words(len));
    uint32_t start = evm_mexpand(dst, len);
    for (uint32_t i = 0; i < len; i++) {
        uint64_t s = (uint64_t)src + i;
        evm_memory[start + i] = s < from_len ? from[s] : 0;
    }
}

void evm_copy_calldata(uint32_t dst, uint32_t src, uint32_t len) {
    copy_to_memory(dst, src, len, evm_calldata, evm_calldata_len);
}

void evm_copy_code(uint32_t dst, uint32_t src, uint32_t len) {
    copy_to_memory(dst, src, len, evm_code, evm_code_len);
}

void evm_copy_returndata(uint32_t dst, uint32_t src, uint32_t len) {
    (void)dst;
    (void)src;
    if (len != 0) evm_halt(EVM_HALT_TRAP, 0x3e);
}

/* ---- KECCAK256, EXP, LOGn, storage ---- */

void evm_keccak(uint32_t off, uint32_t len, u256 *r) {
    len_arg(len);
    evm_charge(G_KECCAK256 + G_KECCAK256_WORD * words(len));
    uint32_t start = evm_mexpand(off, len);
    uint8_t d[32];
    evm_keccak256(evm_host, evm_memory + start, len, d);
    u256_from_be_bytes(r, d);
}

void evm_exp(u256 *r, const u256 *base, const u256 *e) {
    evm_charge(G_EXP + (uint64_t)G_EXP_BYTE * u256_byte_len(e));
    u256_exp(r, base, e);
}

void evm_log(uint32_t n_topics, uint32_t off, uint32_t len, const u256 *topics) {
    evm_charge(G_LOG + (uint64_t)G_LOG_TOPIC * n_topics);
    len_arg(len);
    /* The data is dropped but still paid for and bounds-checked. */
    evm_charge((uint64_t)G_LOG_DATA * len);
    evm_mexpand(off, len);
    if (evm_n_logs == MAX_LOGS) evm_halt(EVM_HALT_OUT_OF_BOUNDS, 0);
    evm_log_t *log = &evm_logs[evm_n_logs];
    log->n_topics = n_topics;
    for (uint32_t i = 0; i < MAX_TOPICS; i++) {
        if (i < n_topics) {
            log->topics[i] = topics[n_topics - 1 - i];
        } else {
            for (int k = 0; k < 8; k++) log->topics[i].l[k] = 0;
        }
    }
    evm_n_logs++;
}

void evm_storage_load(const u256 *slot, u256 *r) {
    uint32_t out[8];
    uint32_t code = evm_sload(evm_tree, evm_host, slot->l, out);
    if (code != 0) evm_halt(code, 0);
    for (int i = 0; i < 8; i++) r->l[i] = out[i];
}

void evm_storage_store(const u256 *slot, const u256 *value) {
    /* The cost needs the pre-value, so the witness is read (and verified) first. */
    u256 prev;
    evm_storage_load(slot, &prev);
    evm_charge(u256_is_zero(&prev) && !u256_is_zero(value) ? G_SSTORE_SET : G_SSTORE_RESET);
    uint32_t code = evm_sstore(evm_tree, evm_host, slot->l, value->l);
    if (code != 0) evm_halt(code, 0);
}

/* ---- RETURN / REVERT ---- */

static void set_return(uint32_t off, uint32_t len) {
    len_arg(len);
    if (len > MAX_RETURN_BYTES) evm_halt(EVM_HALT_OUT_OF_BOUNDS, 0);
    uint32_t start = evm_mexpand(off, len);
    for (uint32_t i = 0; i < len; i++) evm_ret[i] = evm_memory[start + i];
    evm_ret_len = len;
}

void evm_return(uint32_t off, uint32_t len) {
    set_return(off, len);
    evm_halt(EVM_HALT_RETURN, 0);
}

void evm_revert(uint32_t off, uint32_t len) {
    set_return(off, len);
    evm_halt(EVM_HALT_REVERT, 0);
}

/* ---- the non-local exit, RV32 ----
 *
 * A minimal setjmp/longjmp over what the ILP32 calling convention makes callee-saved: ra, sp and
 * s0-s11 (the machine has no float registers). `evm_rt_enter` is the only frame that ever calls
 * `evm_rt_setjmp`, and it stays live for the whole run, so the jump always lands in a live frame.
 * A host build supplies its own pair over libc (test/host_jmp.c). */
#if defined(__riscv) && __riscv_xlen == 32
__attribute__((returns_twice)) int evm_rt_setjmp(uint32_t *buf);
__attribute__((noreturn)) void evm_rt_longjmp(uint32_t *buf, int v);

__asm__(".section .text.evm_rt_setjmp,\"ax\",@progbits\n"
        ".globl evm_rt_setjmp\n"
        ".type evm_rt_setjmp,@function\n"
        ".p2align 2\n"
        "evm_rt_setjmp:\n"
        "  sw ra, 0(a0)\n  sw sp, 4(a0)\n  sw s0, 8(a0)\n  sw s1, 12(a0)\n"
        "  sw s2, 16(a0)\n  sw s3, 20(a0)\n  sw s4, 24(a0)\n  sw s5, 28(a0)\n"
        "  sw s6, 32(a0)\n  sw s7, 36(a0)\n  sw s8, 40(a0)\n  sw s9, 44(a0)\n"
        "  sw s10, 48(a0)\n  sw s11, 52(a0)\n"
        "  li a0, 0\n"
        "  ret\n"
        ".size evm_rt_setjmp, .-evm_rt_setjmp\n"
        ".section .text.evm_rt_longjmp,\"ax\",@progbits\n"
        ".globl evm_rt_longjmp\n"
        ".type evm_rt_longjmp,@function\n"
        ".p2align 2\n"
        "evm_rt_longjmp:\n"
        "  lw ra, 0(a0)\n  lw sp, 4(a0)\n  lw s0, 8(a0)\n  lw s1, 12(a0)\n"
        "  lw s2, 16(a0)\n  lw s3, 20(a0)\n  lw s4, 24(a0)\n  lw s5, 28(a0)\n"
        "  lw s6, 32(a0)\n  lw s7, 36(a0)\n  lw s8, 40(a0)\n  lw s9, 44(a0)\n"
        "  lw s10, 48(a0)\n  lw s11, 52(a0)\n"
        "  seqz a0, a1\n"
        "  add a0, a0, a1\n" /* setjmp's second return is never 0 */
        "  ret\n"
        ".size evm_rt_longjmp, .-evm_rt_longjmp\n"
        ".text\n");

static uint32_t evm_rt_jmp[14];

uint32_t evm_rt_enter(void (*entry)(void)) {
    if (evm_rt_setjmp(evm_rt_jmp) == 0) {
        entry();
        evm_halt(EVM_HALT_STOP, 0); /* running off the end is STOP */
    }
    return evm_halt_code;
}

void evm_rt_unwind(void) { evm_rt_longjmp(evm_rt_jmp, 1); }
#endif
