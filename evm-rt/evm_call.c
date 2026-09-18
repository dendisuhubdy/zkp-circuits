/* The call family's runtime (evm_rt.h, "calls"): `evm_call` over the precompiles (precompiles.h)
 * and the return-data buffer. In a file of its own, apart from evm_rt.c, so that a contract that
 * makes no call links none of it — not even these globals, which LLVM's global merging would
 * otherwise pack together with evm_rt.c's and so move a call-free contract's image (the pinned
 * ERC-20 hc). */
#include "evm_rt.h"
#include "precompiles.h"

/* `Interpreter::len_arg`, as evm_rt.c has it: a byte count past the memory is out of bounds. */
static void len_arg(uint32_t len) {
    if (len > MAX_MEMORY_BYTES) evm_halt(EVM_HALT_OUT_OF_BOUNDS, 0);
}

/* A precompile's output (at most PC_OUT_MAX bytes, identity's copy of a memory range) is written
 * straight into the buffer. */
_Static_assert(MAX_MEMORY_BYTES <= PC_OUT_MAX && PC_OUT_MAX <= EVM_RETURNDATA_MAX,
               "the return-data buffer must hold any precompile output, and that any memory range");

uint8_t evm_rdata[EVM_RETURNDATA_MAX];
uint32_t evm_rdata_len;
uint32_t evm_rdata_live;

void evm_calls_begin(void) {
    evm_rdata_len = 0;
    evm_rdata_live = 0;
}

void evm_copy_returndata_buf(uint32_t dst, uint32_t src, uint32_t len) {
    if (!evm_rdata_live) {
        evm_copy_returndata(dst, src, len);
        return;
    }
    if ((uint64_t)src + len > evm_rdata_len) evm_halt(EVM_HALT_OUT_OF_BOUNDS, 0);
    /* evm_rt.c's `copy_to_memory`, over the buffer (in bounds, so no padding). */
    len_arg(len);
    evm_charge(G_COPY_WORD * ((len + 31ull) / 32));
    uint32_t start = evm_mexpand(dst, len);
    for (uint32_t i = 0; i < len; i++) evm_memory[start + i] = evm_rdata[src + i];
}

/* The word as a u64 when it fits, else UINT64_MAX (only compared against a smaller u64). */
static uint64_t sat_u64(const u256 *v) {
    for (int i = 2; i < 8; i++)
        if (v->l[i]) return UINT64_MAX;
    return (uint64_t)v->l[1] << 32 | v->l[0];
}

void evm_call(uint32_t op, u256 *a, uint64_t gas_after) {
    int has_value = op == 0xf1 || op == 0xf2;
    uint32_t n = has_value ? 7 : 6;
    const u256 *gas = &a[n - 1], *addr = &a[n - 2];
    /* The low 160 bits: limbs 0..4. */
    uint32_t target = addr->l[0];
    if (addr->l[1] | addr->l[2] | addr->l[3] | addr->l[4] || target < PC_FIRST || target > PC_LAST)
        evm_halt(EVM_HALT_TRAP, op);
    if (has_value && !u256_is_zero(&a[4])) evm_halt(EVM_HALT_TRAP, op);
    uint32_t in_off = u256_sat_u32(&a[3]), in_len = u256_sat_u32(&a[2]);
    uint32_t ret_off = u256_sat_u32(&a[1]), ret_len = u256_sat_u32(&a[0]);
    uint64_t requested = sat_u64(gas);

    evm_charge(EVM_CALL_WARM_ACCESS);
    len_arg(in_len);
    len_arg(ret_len);
    uint32_t in_start = evm_mexpand(in_off, in_len);
    uint32_t ret_start = evm_mexpand(ret_off, ret_len);
    uint64_t left = evm_gas + gas_after; /* the EVM's remaining gas here */
    uint64_t pass = left - left / 64;
    if (requested < pass) pass = requested;

    evm_rdata_live = 1;
    evm_rdata_len = 0;
    const uint8_t *in = evm_memory + in_start;
    uint64_t cost = evm_precompile_gas(target, in, in_len);
    uint32_t ok = 0;
    if (cost <= pass) {
        /* Affordable, so the call consumes at least `cost` whatever the precompile does: its cost
         * on success, the gas passed (>= cost) on failure. When the counter cannot pay that, the
         * run is out of gas either way; halt before running the precompile, so an out-of-gas run
         * never spends the precompile's cycles first. */
        if (cost > evm_gas) evm_halt(EVM_HALT_OUT_OF_GAS, 0);
        uint32_t out_len = 0;
        uint32_t r = evm_precompile_run(target, in, in_len, evm_rdata, &out_len);
        if (r == PC_TOO_BIG) evm_halt(EVM_HALT_OUT_OF_BOUNDS, 0);
        if (r == PC_OK) {
            ok = 1;
            evm_charge(cost);
            evm_rdata_len = out_len;
            uint32_t k = ret_len < out_len ? ret_len : out_len;
            for (uint32_t i = 0; i < k; i++) evm_memory[ret_start + i] = evm_rdata[i];
        }
    }
    if (!ok) evm_charge(pass);
    u256_from_u32(&a[0], ok);
}
