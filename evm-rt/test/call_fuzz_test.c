/* `evm_call` fuzzed against a per-op EVM gas model (Task 6, ruling 3): random call opcodes,
 * targets (the nine precompiles, non-precompiles, addresses with bits above 160), values, regions
 * with offsets and lengths near MAX_MEMORY_BYTES and saturated ones, a prior msize, requested gas
 * from zero to 2^256 - 1, the gas left and `gas_after`.
 *
 * The model is the EVM at the call, one step at a time, with the EVM's own gas (the counter plus
 * `gas_after`, the static gas the block head has already taken for the ops after the call):
 *
 *   a target outside 1..9 (low 160 bits), or a value on CALL/CALLCODE: status 2 (the trap);
 *   100 for the warm access; a length past the memory, or a region ending past it: status 2
 *   (interp.rs's OutOfBounds); the expansion to the larger of the two regions' ends;
 *   pass = min(requested, left - left/64) — the 63/64 rule;
 *   RequiredGas <= pass and a valid input: the cost is consumed, the flag is 1, the return data is
 *   the output; otherwise the gas passed is consumed, the flag is 0, the return data is empty;
 *   and then the ops after the call still need `gas_after`: less than that left is status 2.
 *
 * On success the counter must be exactly what the model has left minus `gas_after` (gas
 * conservation), and the flag, the return-data length and — for identity — the bytes must match;
 * on status 2 gas_used is the whole limit. RequiredGas is written out here from the EIPs for every
 * precompile but modexp, whose EIP-2565 formula is evm_precompile_gas's own (checked against
 * go-ethereum's vectors in precompiles_test.c); validity is decided from the input's shape: the
 * inputs to 6, 7 and 8 are either all zero (the points at infinity: valid) or random (invalid but
 * with negligible probability), blake2f's by its length and final flag. */
#include <string.h>
#include "test.h"
#include "../precompiles.h"

extern int t_real_keccak;

static uint64_t rng_s;
static uint64_t rnd(void) {
    rng_s += 0x9e3779b97f4a7c15ull;
    uint64_t z = rng_s;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}
static uint64_t below(uint64_t n) { return rnd() % n; }

static uint64_t words(uint64_t b) { return (b + 31) / 32; }
static uint64_t expansion(uint64_t w) { return 3 * w + w * w / 512; }

static uint32_t op_;
static u256 *args_;
static uint64_t after_;
static void b_call(void) { evm_call(op_, args_, after_); }

/* An offset operand: small mostly; near the end of memory, at it, past it, or saturated. */
static uint64_t pick_off(uint64_t len) {
    switch (below(24)) {
    case 0: { /* just inside: the region ends at the last byte, or a byte or two before it */
        uint64_t end = MAX_MEMORY_BYTES - below(3);
        return len <= end ? end - len : 0;
    }
    case 1: return len <= MAX_MEMORY_BYTES ? MAX_MEMORY_BYTES - len + below(3) : MAX_MEMORY_BYTES;
    case 2: return below(MAX_MEMORY_BYTES);
    case 3: return 0xffffffffull;
    case 4: case 5: case 6: return below(4096);
    default: return below(256);
    }
}
/* A length operand: small mostly; the precompile's own sizes; the whole memory, one past it,
 * or saturated. */
static uint64_t pick_len(uint32_t target) {
    switch (below(24)) {
    case 0: return MAX_MEMORY_BYTES - below(2);
    case 1: return MAX_MEMORY_BYTES + below(2);
    case 2: return 0xffffffffull;
    case 3: case 4: case 5: case 6: return 0;
    case 7: case 8: case 9: return target == 9 ? 213 : 192 * below(3);
    default: return below(300);
    }
}
/* An operand word: the value, or anything at or above 2^32 when `v` is 0xffffffff (saturated). */
static u256 word(uint64_t v) {
    u256 r;
    u256_from_u64(&r, v);
    if (v == 0xffffffffull && below(2)) r.l[5] = 1; /* 2^160 + 2^32 - 1: saturates the same */
    return r;
}

/* RequiredGas, from the EIPs (modexp: evm_precompile_gas, see the file comment). */
static uint64_t model_cost(uint32_t t, const uint8_t *in, uint64_t len) {
    switch (t) {
    case 1: return 3000;
    case 2: return 60 + 12 * words(len);
    case 3: return 600 + 120 * words(len);
    case 4: return 15 + 3 * words(len);
    case 5: return evm_precompile_gas(5, in, (uint32_t)len);
    case 6: return 150;
    case 7: return 6000;
    case 8: return 45000 + 34000 * (len / 192);
    default: return len == 213 ? ((uint64_t)in[0] << 24 | (uint64_t)in[1] << 16 | (uint64_t)in[2] << 8 | in[3]) : 0;
    }
}
static int all_zero(const uint8_t *p, uint64_t n) {
    for (uint64_t i = 0; i < n; i++)
        if (p[i]) return 0;
    return 1;
}
/* 1 valid, 0 invalid (the call fails), 2 the runtime's modexp cap (OutOfBounds when affordable). */
static int model_valid(uint32_t t, const uint8_t *in, uint64_t len) {
    switch (t) {
    case 6: case 7: return all_zero(in, len);
    case 8: return len % 192 == 0 && all_zero(in, len);
    case 9: return len == 213 && in[212] <= 1;
    case 5: {
        uint8_t h[96];
        memset(h, 0, 96);
        memcpy(h, in, len < 96 ? len : 96);
        uint64_t bl = 0, ml = 0;
        for (int i = 0; i < 32; i++) {
            if (i < 24 && (h[i] || h[64 + i])) return 2; /* a length >= 2^64: past the cap */
            if (i >= 24) { bl = bl << 8 | h[i]; ml = ml << 8 | h[64 + i]; }
        }
        if (bl == 0 && ml == 0) return 1;
        return bl > PC_MODEXP_MAX_BYTES || ml > PC_MODEXP_MAX_BYTES ? 2 : 1;
    }
    default: return 1;
    }
}
static uint64_t model_out_len(uint32_t t, uint64_t len) {
    switch (t) {
    case 2: case 3: case 8: return 32;
    case 4: return len;
    case 6: case 7: case 9: return 64;
    default: return UINT64_MAX; /* ecrecover (0 or 32), modexp (the modulus length): not modelled */
    }
}

static int one(int it) {
    static const uint32_t ops[4] = {0xf1, 0xf2, 0xf4, 0xfa};
    uint32_t op = ops[below(4)];
    int has_value = op == 0xf1 || op == 0xf2;
    /* target: a precompile mostly (modexp and the pairing rarely: the pairing's final
     * exponentiation is seconds on the host), else a trap. */
    uint32_t t;
    uint64_t tr = below(100);
    if (tr < 6) t = (uint32_t)(10 + below(1000));
    else if (tr < 7) t = 0;
    else if (tr < 9) t = 8;
    else if (tr < 25) t = 5;
    else {
        static const uint32_t cheap[7] = {1, 2, 3, 4, 6, 7, 9};
        t = cheap[below(7)];
    }
    u256 addr;
    u256_from_u32(&addr, t);
    if (below(20) == 0) addr.l[5 + below(3)] = (uint32_t)rnd() | 1; /* bits above 160: ignored */
    int value = has_value && below(20) == 0;

    uint64_t in_len = pick_len(t), ret_len = pick_len(t);
    uint64_t in_off = pick_off(in_len), ret_off = pick_off(ret_len);
    /* The gas: the EVM's total at the call, split between the counter and gas_after. */
    uint64_t total;
    switch (below(4)) {
    case 0: total = below(400); break;
    case 1: total = below(8000); break;
    case 2: total = below(60000); break;
    default: total = below(2000000); break;
    }
    uint64_t after = below(3) ? below(total + 1) : 0;
    u256 req;
    switch (below(6)) {
    case 0: u256_from_u32(&req, 0); break;
    case 1: u256_from_u64(&req, below(200)); break;
    case 2: u256_from_u64(&req, below(20000)); break;
    case 3: memset(&req, 0xff, sizeof req); break;
    case 4: u256_from_u64(&req, 0); req.l[2] = 1; break; /* 2^64 */
    default: u256_from_u64(&req, rnd() >> (below(64))); break;
    }

    /* The run's state: memory prefilled, a prior msize, the input shaped for its target. */
    CHECK(evm_rt_init((const uint8_t *)"", 0, (const uint8_t *)"", 0, total) == EVM_HALT_OK);
    evm_calls_begin();
    evm_gas -= after;
    uint32_t msize_w0 = (uint32_t)below(3) * (uint32_t)below(64);
    evm_msize = msize_w0 * 32;
    for (uint32_t i = 0; i < MAX_MEMORY_BYTES; i += 8) {
        uint64_t r = rnd();
        memcpy(evm_memory + i, &r, 8);
    }
    int in_ok = in_len > 0 && in_len <= MAX_MEMORY_BYTES && in_off + in_len <= MAX_MEMORY_BYTES;
    if (in_ok) {
        uint8_t *in = evm_memory + in_off;
        if ((t >= 6 && t <= 8) && below(2)) memset(in, 0, in_len);
        if (t == 9 && in_len >= 4) { in[0] = in[1] = in[2] = 0; in[3] = (uint8_t)below(40); }
        if (t == 9 && in_len == 213 && below(2)) in[212] = (uint8_t)below(2);
        if (t == 5 && in_len >= 96) {
            memset(in, 0, 96);
            in[31] = (uint8_t)below(40);
            in[63] = (uint8_t)below(40);
            in[95] = (uint8_t)below(40);
            if (below(8) == 0) { in[30] = 0x04; in[31] = 0x01; } /* base 1025: the cap */
        }
    }
    uint8_t in_copy[512];
    uint64_t in_keep = in_ok ? (in_len < sizeof in_copy ? in_len : sizeof in_copy) : 0;
    if (in_ok) memcpy(in_copy, evm_memory + in_off, in_keep);

    /* Push the operands (the deepest first). */
    evm_sp = 2;
    u256 *a = &evm_stack[evm_sp];
    evm_stack[evm_sp++] = word(ret_len);
    evm_stack[evm_sp++] = word(ret_off);
    evm_stack[evm_sp++] = word(in_len);
    evm_stack[evm_sp++] = word(in_off);
    if (has_value) {
        u256_from_u32(&evm_stack[evm_sp], value ? 1 + (uint32_t)below(100) : 0);
        evm_sp++;
    }
    evm_stack[evm_sp++] = addr;
    evm_stack[evm_sp++] = req;
    op_ = op;
    args_ = a;
    after_ = after;

    /* ---- the model ---- */
    int status; /* 1, or 2 */
    uint64_t left = total, consumed = 0;
    int ok = 0;
    uint64_t out_len = 0;
    if (t < 1 || t > 9 || value) {
        status = 2;
    } else if (left < 100) {
        status = 2;
    } else {
        left -= 100;
        int oob = in_len > MAX_MEMORY_BYTES || ret_len > MAX_MEMORY_BYTES ||
                  (in_len && in_off + in_len > MAX_MEMORY_BYTES) ||
                  (ret_len && ret_off + ret_len > MAX_MEMORY_BYTES);
        uint64_t w = msize_w0;
        if (!oob) {
            if (in_len && words(in_off + in_len) > w) w = words(in_off + in_len);
            if (ret_len && words(ret_off + ret_len) > w) w = words(ret_off + ret_len);
        }
        uint64_t mcost = expansion(w) - expansion(msize_w0);
        if (oob || left < mcost) {
            status = 2;
        } else {
            left -= mcost;
            uint64_t pass = left - left / 64;
            uint64_t rq = UINT64_MAX; /* anything past a u64 exceeds any gas */
            if ((req.l[2] | req.l[3] | req.l[4] | req.l[5] | req.l[6] | req.l[7]) == 0)
                rq = (uint64_t)req.l[1] << 32 | req.l[0];
            if (rq < pass) pass = rq;
            const uint8_t *in = in_len ? evm_memory + in_off : evm_memory;
            uint64_t cost = model_cost(t, in, in_len);
            int valid = model_valid(t, in, in_len);
            if (cost <= pass && valid == 2) {
                status = 2; /* the runtime's cap (or out of gas before it) */
            } else {
                if (cost <= pass && valid == 1) {
                    consumed = cost;
                    ok = 1;
                    out_len = model_out_len(t, in_len);
                } else {
                    consumed = pass;
                }
                left -= consumed;
                status = left < after ? 2 : 1;
            }
        }
    }

    /* ---- the runtime ---- */
    uint32_t h = evm_rt_enter(b_call);
    int bad = 0;
    if (status == 2) {
        bad |= h == EVM_HALT_STOP;
        bad |= evm_gas_used() != total;
        if (t >= 1 && t <= 9 && !value && h == EVM_HALT_TRAP) bad = 1;
    } else {
        bad |= h != EVM_HALT_STOP;
        bad |= evm_gas != left - after;
        bad |= args_[0].l[0] != (uint32_t)ok || !u256_hi_zero(&args_[0]) || args_[0].l[1] != 0;
        if (out_len != UINT64_MAX) bad |= evm_rdata_len != out_len;
        if (!ok) bad |= evm_rdata_len != 0;
        if (ok && t == 4) {
            bad |= memcmp(evm_rdata, in_copy, in_keep) != 0;
            uint64_t c = ret_len < in_len ? ret_len : in_len;
            if (c > in_keep) c = in_keep;
            if (c) bad |= memcmp(evm_memory + ret_off, in_copy, c) != 0;
        }
    }
    if (bad) {
        fprintf(stderr,
                "call fuzz %d: op %#x target %u value %d in %llu+%llu ret %llu+%llu msize %u total "
                "%llu after %llu req.l0 %u: model status %d left %llu ok %d; runtime halt %u gas %llu "
                "used %llu flag %u rdata %u\n",
                it, op, t, value, (unsigned long long)in_off, (unsigned long long)in_len,
                (unsigned long long)ret_off, (unsigned long long)ret_len, msize_w0,
                (unsigned long long)total, (unsigned long long)after, req.l[0], status,
                (unsigned long long)left, ok, h, (unsigned long long)evm_gas,
                (unsigned long long)evm_gas_used(), args_[0].l[0], evm_rdata_len);
    }
    CHECK(!bad);
    return status;
}

int call_fuzz_tests(void) {
    t_real_keccak = 1;
    rng_s = 0x63616c6cull; /* a fixed seed */
    int n[3] = {0, 0, 0};
    for (int it = 0; it < 20000; it++) n[one(it)]++;
    t_real_keccak = 0;
    printf("call fuzz: 20000 calls, %d completed, %d exceptional\n", n[1], n[2]);
    return 0;
}
