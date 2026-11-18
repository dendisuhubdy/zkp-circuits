//! Rejecting a statement: [`refuse`] and [`require!`](crate::require) (ZKVM-106).
//!
//! **A halt is a provable run, whatever came before it.** A guest that decides its inputs are
//! wrong must therefore not halt, and must not panic either: the SDK's default panic handler
//! writes a marker (`out[7] = 0xdeadbeef`) and *halts*, so a failed `assert!`, an out-of-bounds
//! index, an overflow check or an `unwrap` on `None` ends in a proof like any other, and only a
//! verifier that looks at `out[7]` can tell. [`refuse`] is the way to reject: it ends the run in a
//! trap, and a trapped run has no proof.
//!
//! This file is a module of its own, and `lib.rs` names it on its last lines, so that adding it
//! moved no line of `lib.rs`: the panic `Location`s the compiler puts in a guest's `.rodata` carry
//! `lib.rs` line numbers, the image container carries `.rodata`, and `hc` binds it. The six
//! published images are unchanged (`rand-guest/tests/build.rs`).

use crate::read_input;

/// The private-input index [`refuse`] reads. No run can have this many private input words — the
/// input table of the largest tier is far below `2^32 - 1` rows — so the read is out of range in
/// every execution, which the emulator reports as `ExecError::InputIndex(0xffff_ffff)` and the
/// constraints cannot satisfy (`research/docs/01-isa.md`, `READ_INPUT`: "`idx >= n_in` cannot be
/// satisfied at all"; `research/tests/cheating.rs` forges the read and is refused).
pub const REFUSE_INDEX: u32 = u32::MAX;

/// Ends the run in a trap, so that **no proof of this execution exists**. The one way a guest
/// rejects: use it wherever the statement being proved is false — a bad signature, an amount over
/// a balance, a malformed input — in place of `panic!`, `assert!` and `unwrap`, which halt (module
/// comment). Outputs written before the call do not matter: nothing is published without a proof.
///
/// `rand-guest run` prints a refusal as `refused`, and `rand-guest build` refuses a guest that
/// still links the panic machinery (`rand-guest/README.md`, "Rejecting").
#[inline(always)]
pub fn refuse() -> ! {
    read_input(REFUSE_INDEX);
    // Never reached: the read above cannot succeed. A loop rather than a promise to the compiler,
    // for `halt`'s reason (an `unreachable` lowers to a word the machine does not decode).
    loop {}
}

/// `require!(cond)` is `if !cond { refuse() }`: the guest's `assert!`, except that a false
/// condition leaves no proof where a failed `assert!` leaves a halted, provable run.
///
/// ```ignore
/// require!(amount <= balance);
/// ```
#[macro_export]
macro_rules! require {
    ($cond:expr $(,)?) => {
        if !($cond) {
            $crate::refuse()
        }
    };
}
