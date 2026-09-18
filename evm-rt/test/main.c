#include <string.h>
#include "test.h"

static int failed, passed;

void t_check(int ok, const char *file, int line, const char *what) {
    if (ok) {
        passed++;
    } else {
        failed++;
        if (failed <= 50) fprintf(stderr, "FAIL %s:%d: %s\n", file, line, what);
    }
}

u256 t_hex(const char *s) {
    u256 r;
    memset(&r, 0, sizeof r);
    size_t n = strlen(s);
    for (size_t i = 0; i < n; i++) {
        char c = s[n - 1 - i];
        uint32_t d = (c >= '0' && c <= '9') ? (uint32_t)(c - '0')
                   : (c >= 'a' && c <= 'f') ? (uint32_t)(c - 'a' + 10)
                                            : (uint32_t)(c - 'A' + 10);
        r.l[i / 8] |= d << (4 * (i % 8));
    }
    return r;
}

int t_eq(const u256 *a, const u256 *b) { return memcmp(a, b, sizeof *a) == 0; }

void t_print(const char *label, const u256 *a) {
    fprintf(stderr, "  %s = 0x", label);
    for (int i = 7; i >= 0; i--) fprintf(stderr, "%08x", a->l[i]);
    fprintf(stderr, "\n");
}

int main(void) {
    u256_tests();
    mem_tests();
    printf("evm-rt: %d passed, %d failed\n", passed, failed);
    return failed != 0;
}
