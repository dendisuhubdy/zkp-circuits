#![no_std]
#![no_main]

use guest_sdk::{halt, read_input, write_output};

fn fib(n: u32) -> u32 {
    let (mut a, mut b) = (0u32, 1u32);
    for _ in 0..n {
        let c = a.wrapping_add(b);
        a = b;
        b = c;
    }
    a
}

/// Reads `n` from input slot 0, writes `fib(n)` to output slot 0 — the same function
/// `guests::fib` computes by hand-assembled loop (`research/src/guests.rs`), so the two are
/// directly comparable in Step 4's test.
#[no_mangle]
pub extern "C" fn main() -> ! {
    let n = read_input(0);
    write_output(0, fib(n));
    halt();
}
