/* The runtime's half of `research/tests/sbpf_rt.rs`'s differential test: reads cases on stdin, runs
 * each through sbpf-rt, and prints what happened in the same text the Rust side prints for
 * `sbpf-core`'s `Memory`/`syscalls::dispatch` over the same regions — so the two outputs must be
 * byte-identical. Host only (libc, stdio); links test/host_glue.c.
 *
 * A case (one token per line, numbers decimal or 0x-hex, byte strings as hex or `-` for empty):
 *
 *   case
 *   text <hex>        text_va <u64>
 *   rodata <hex>      rodata_va <u64>
 *   input <hex>
 *   ld <addr> <size> | st <addr> <size> <v> | sys <hash> <r1> <r2> <r3> <r4> <r5>   (any number)
 *   end
 *
 * The stack and heap start zeroed and the allocator's cursor at 0 (`Vm::new`). The ops run in order
 * until one halts. Printed per op: `ok <r0>` (a load's value; 0 for a store) or
 * `halt <code> <arg>`; then `input <hex>`, `stack <fnv1a64>`, `heap <fnv1a64>`, `heap_used <n>`.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../sbpf_rt.h"

static uint8_t text[1 << 16], rodata[1 << 16], input[1 << 16];
static uint8_t stack[SBPF_STACK_BYTES], heap[SBPF_HEAP_BYTES];

static size_t unhex(uint8_t *out, const char *h) {
    if (strcmp(h, "-") == 0) return 0;
    size_t n = strlen(h) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(h + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
    return n;
}

static uint64_t fnv(const uint8_t *p, size_t n) {
    uint64_t h = 0xcbf29ce484222325ull;
    for (size_t i = 0; i < n; i++) h = (h ^ p[i]) * 0x100000001b3ull;
    return h;
}

static uint64_t num(const char *s) { return strtoull(s, NULL, 0); }

static uint64_t op_ld(uint64_t a, uint64_t n, uint64_t c, uint64_t d, uint64_t e) {
    (void)c, (void)d, (void)e;
    return sbpf_load(a, (uint32_t)n);
}
static uint64_t op_st(uint64_t a, uint64_t n, uint64_t v, uint64_t d, uint64_t e) {
    (void)d, (void)e;
    sbpf_store(a, (uint32_t)n, v);
    return 0;
}
static uint32_t sys_hash;
static uint64_t op_sys(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e) {
    return sbpf_syscall(sys_hash, a, b, c, d, e);
}

int main(void) {
    static char line[1 << 18];
    int halted = 0;
    while (fgets(line, sizeof line, stdin)) {
        char *tok[8] = {0};
        int nt = 0;
        for (char *t = strtok(line, " \n"); t && nt < 8; t = strtok(NULL, " \n")) tok[nt++] = t;
        if (nt == 0) continue;
        const char *k = tok[0];
        if (!strcmp(k, "case")) {
            memset(stack, 0, sizeof stack);
            memset(heap, 0, sizeof heap);
            memset(&sbpf_r, 0, sizeof sbpf_r);
            sbpf_r.text = text;
            sbpf_r.rodata = rodata;
            sbpf_r.stack = stack;
            sbpf_r.heap = heap;
            sbpf_r.input = input;
            sbpf_rt_reset();
            halted = 0;
        } else if (!strcmp(k, "text")) {
            sbpf_r.text_len = (uint32_t)unhex(text, tok[1]);
        } else if (!strcmp(k, "text_va")) {
            sbpf_r.text_va = num(tok[1]);
        } else if (!strcmp(k, "rodata")) {
            sbpf_r.rodata_len = (uint32_t)unhex(rodata, tok[1]);
        } else if (!strcmp(k, "rodata_va")) {
            sbpf_r.rodata_va = num(tok[1]);
        } else if (!strcmp(k, "input")) {
            sbpf_r.input_len = (uint32_t)unhex(input, tok[1]);
        } else if (!strcmp(k, "ld") || !strcmp(k, "st") || !strcmp(k, "sys")) {
            if (halted) continue;
            uint64_t r0 = 0;
            uint32_t code;
            if (!strcmp(k, "ld")) {
                code = sbpf_rt_enter(op_ld, num(tok[1]), num(tok[2]), 0, 0, 0, &r0);
            } else if (!strcmp(k, "st")) {
                code = sbpf_rt_enter(op_st, num(tok[1]), num(tok[2]), num(tok[3]), 0, 0, &r0);
            } else {
                sys_hash = (uint32_t)num(tok[1]);
                code = sbpf_rt_enter(op_sys, num(tok[2]), num(tok[3]), num(tok[4]), num(tok[5]),
                                     num(tok[6]), &r0);
            }
            if (code == SBPF_HALT_EXIT) {
                printf("ok %llu\n", (unsigned long long)r0);
            } else {
                printf("halt %u %llu\n", code, (unsigned long long)sbpf_halt_arg);
                halted = 1;
            }
        } else if (!strcmp(k, "end")) {
            printf("input ");
            if (sbpf_r.input_len == 0) printf("-");
            for (uint32_t i = 0; i < sbpf_r.input_len; i++) printf("%02x", input[i]);
            printf("\nstack %016llx\nheap %016llx\nheap_used %u\n",
                   (unsigned long long)fnv(stack, sizeof stack), (unsigned long long)fnv(heap, sizeof heap),
                   sbpf_heap_used);
        }
    }
    return 0;
}
