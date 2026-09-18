// The host test harness: one binary runs every suite — from evm-rt/, `cc -o t test/*.c *.c && ./t`.
#ifndef EVM_RT_TEST_H
#define EVM_RT_TEST_H
#include <stdio.h>
#include "../evm_rt.h"

void t_check(int ok, const char *file, int line, const char *what);
#define CHECK(c) t_check(!!(c), __FILE__, __LINE__, #c)
#define CHECK_EQ_U64(a, b)                                                                     \
    do {                                                                                       \
        unsigned long long t_a_ = (a), t_b_ = (b);                                             \
        if (t_a_ != t_b_) fprintf(stderr, "  %s = %llu, %s = %llu\n", #a, t_a_, #b, t_b_);     \
        CHECK(t_a_ == t_b_);                                                                   \
    } while (0)

/* Hex, big-endian, no 0x, any length up to 64 digits. */
u256 t_hex(const char *s);
int t_eq(const u256 *a, const u256 *b);
void t_print(const char *label, const u256 *a);

int u256_tests(void);
int mem_tests(void);
int precompile_tests(void);
int call_tests(void);
int call_fuzz_tests(void);
int precompile_fuzz_tests(void);
#endif
