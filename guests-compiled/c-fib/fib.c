/* The C twin of `guests-compiled/fib`: reads `n` from input slot 0 and writes `fib(n)` to output
 * slot 0. Built by `rand-guest build --lang c guests-compiled/c-fib`, which supplies `guest.h`
 * and `_start`, so this directory holds nothing but the guest itself. */
#include "guest.h"

static uint32_t fib(uint32_t n) {
    uint32_t a = 0, b = 1;
    for (uint32_t i = 0; i < n; i++) {
        uint32_t c = a + b;
        a = b;
        b = c;
    }
    return a;
}

void main(void) {
    rand_write_output(0, fib(rand_read_input(0)));
    rand_halt();
}
