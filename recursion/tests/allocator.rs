//! Regression tests for the two latent register-allocator miscompilations of issue #63
//! (randprotocol/fullnode#63, R62-DSL-1 and R62-DSL-2): control-flow shapes where the replay's
//! straight-line view of the buffer disagreed with what the emitted program executes. Each test
//! accepts exactly two outcomes — the program computes what its DSL source says, or the build is
//! refused with the allocator's own message. What it must never do is compile to a program that
//! computes something else.
use std::panic::{catch_unwind, AssertUnwindSafe};

use p3_field::PrimeCharacteristicRing;
use recursion::dsl::{Builder, Checkpoints};
use recursion::emulator::execute;
use recursion::isa::{Program, F};

/// Build with `f`; `Some(program)` if the builder accepts it, `None` if it refuses the shape with
/// a panic naming `refusal` (any other panic is a test failure).
fn built_or_refused(refusal: &str, f: impl FnOnce() -> Program) -> Option<Program> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(p) => Some(p),
        Err(e) => {
            let msg = e
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            assert!(msg.contains(refusal), "the build panicked, but not with the allocator's refusal: {msg}");
            None
        }
    }
}

fn publics(p: &Program) -> Vec<F> {
    execute(p, &[], 100_000).unwrap().public
}

/// R62-DSL-1: a pre-loop handle read in the body had its last use clamped to the `LoopEnd`
/// marker and its register freed there — but `counted_loop_mem`'s back edge (the counter's
/// reload and decrement) is emitted after that marker and claimed the freed register, so from
/// the second iteration the body read the counter instead of the value. Was `[7, 3, 2]`.
#[test]
fn a_loop_mem_back_edge_never_clobbers_a_pre_loop_handle_the_body_reads() {
    let mut b = Builder::new(Checkpoints::Off);
    let x = b.constant(F::from_u64(7));
    let cell = b.alloc_absolute(1);
    let n = b.constant(F::from_u64(3));
    b.counted_loop_mem(cell, n, |b| {
        b.public(x);
    });
    let got = publics(&b.finish());
    assert_eq!(got, vec![F::from_u64(7); 3], "the loop body read a clobbered pre-loop handle");
}

/// R62-DSL-1, the eviction variant: with every allocatable register holding a handle that is
/// live after the loop, the back edge's reload must evict one. Its spill `STORE` sat inside the
/// loop, so the second iteration re-ran it from a register that by then held the counter, and
/// the handle came back from its cell as the counter. The loop invariant ran at `LoopEnd`,
/// before the back edge, and saw nothing.
#[test]
fn a_loop_mem_back_edge_eviction_is_refused_or_correct() {
    let want: Vec<F> = (1..=25u64).map(|k| F::from_u64(100 + k)).collect();
    let p = built_or_refused("counted_loop: the body moved handle", || {
        let mut b = Builder::new(Checkpoints::Off);
        let vals: Vec<_> = (1..=25u64).map(|k| b.constant(F::from_u64(100 + k))).collect();
        let cell = b.alloc_absolute(1);
        let n = b.constant(F::from_u64(3));
        b.counted_loop_mem(cell, n, |_| {});
        for v in &vals {
            b.public(*v);
        }
        b.finish()
    });
    if let Some(p) = p {
        assert_eq!(publics(&p), want, "a spill in the loop's back edge re-ran from a reused register");
    }
}
