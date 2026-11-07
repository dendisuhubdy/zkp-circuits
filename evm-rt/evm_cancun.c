/* The post-Shanghai opcodes' runtime (see evm_rt.h): MCOPY and transient storage, each the
 * matching arm of `interp.rs`'s `Interpreter::step` with the same checks in the same order, and
 * the table `transient.rs` keeps. A file of its own so that `evm_rt.c`'s object, and so every
 * image built from a contract without these opcodes, is exactly what it was. */
#include "evm_rt.h"

/* ---- MCOPY ---- */

void evm_mcopy(uint32_t dst, uint32_t src, uint32_t len) {
    /* `len_arg`, then the word gas, as `copy_to_memory` orders them. */
    if (len > MAX_MEMORY_BYTES) evm_halt(EVM_HALT_OUT_OF_BOUNDS, 0);
    evm_charge((uint64_t)G_COPY_WORD * ((len + 31u) / 32u));
    if (len == 0) return;
    /* Both ranges are inside the memory once the farther one is: `evm_mexpand` bounds it (a
     * saturated offset is past every bound) and charges the expansion. */
    evm_mexpand(dst > src ? dst : src, len);
    uint8_t *m = evm_memory;
    if (dst < src) {
        for (uint32_t i = 0; i < len; i++) m[dst + i] = m[src + i];
    } else if (dst > src) {
        for (uint32_t i = len; i > 0; i--) m[dst + i - 1] = m[src + i - 1];
    }
}

/* ---- TLOAD / TSTORE ---- */

static u256 evm_tkeys[MAX_TRANSIENT_SLOTS];
static u256 evm_tvals[MAX_TRANSIENT_SLOTS];
static uint32_t evm_tn;

void evm_transient_begin(void) { evm_tn = 0; }

/* The entry holding `key`, or MAX_TRANSIENT_SLOTS. */
static uint32_t tfind(const u256 *key) {
    for (uint32_t i = 0; i < evm_tn; i++) {
        if (u256_eq_p(&evm_tkeys[i], key)) return i;
    }
    return MAX_TRANSIENT_SLOTS;
}

void evm_tload(const u256 *key, u256 *r) {
    uint32_t i = tfind(key);
    if (i == MAX_TRANSIENT_SLOTS) {
        u256_from_u32(r, 0);
    } else {
        *r = evm_tvals[i];
    }
}

void evm_tstore(const u256 *key, const u256 *value) {
    uint32_t i = tfind(key);
    if (i != MAX_TRANSIENT_SLOTS) {
        evm_tvals[i] = *value;
        return;
    }
    if (u256_is_zero(value)) return;
    if (evm_tn == MAX_TRANSIENT_SLOTS) evm_halt(EVM_HALT_OUT_OF_BOUNDS, 0);
    evm_tkeys[evm_tn] = *key;
    evm_tvals[evm_tn] = *value;
    evm_tn++;
}

/* CLZ (EIP-7939), `U256::clz`: 256 - bit_len. Here rather than in u256.c, so a contract without
 * CLZ links none of it and its image (and hc) is what it was before the post-Shanghai opcodes. */
void u256_clz(u256 *r, const u256 *a) { u256_from_u32(r, 256 - u256_bit_len(a)); }
