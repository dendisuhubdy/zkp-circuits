//! Task 7 (stage one): one real proof of the translated ERC-20 `transfer`, and — if it fits the
//! same resource budget — the same vector on the interpreter's own guest (`evm.bin`), so the
//! README can compare proof times directly. `research/tests/backend.rs:44-61` shows the
//! `Machine::prove`/`verify` API these two tests use; nothing here touches a GPU backend.
//!
//! Both are `#[ignore]`d: proving is heavy (the notes' limits are about 24 GB and about 45
//! minutes), so they are run once each, by hand, under `/usr/bin/time -l`, never as part of an
//! ordinary `cargo test`.

mod common;

use common::{build_shim, root};
use evm_core::u256::U256;
use rand_zkvm::evm::{erc20_transfer, ALICE, BOB};
use rand_zkvm::isa::Program;
use rand_zkvm::machine::{FriProfile, Machine};

/// The transfer-250-of-1000 vector (`parity.rs`'s `transfer_250`): the same call every other
/// Task 4-7 cycle count and pin is measured on.
fn transfer_words() -> Vec<u32> {
    erc20_transfer(
        ALICE,
        BOB,
        U256::from_u32(250),
        &[(ALICE, U256::from_u32(1000))],
    )
    .input_words()
}

/// Proves and verifies the translated ERC-20's `transfer` under the test FRI profile.
///
/// Run once, measured:
///
/// ```text
/// cd evm2rv && /usr/bin/time -l cargo +1.98.1 test --release --test proof \
///     the_translated_erc20_transfer_proves_and_verifies -- --ignored --exact --nocapture
/// ```
#[test]
#[ignore]
fn the_translated_erc20_transfer_proves_and_verifies() {
    let base = root().join("evm2rv/target/proof");
    let (image, hc) = build_shim(
        &root().join("guests-compiled/evm/contracts/erc20.runtime.hex"),
        &base.join("erc20"),
        "erc20-evm2rv-proof",
        false,
    );
    eprintln!("proving the translated ERC-20 (hc {hc})");
    let program = Program::from_flat_image(&std::fs::read(&image).unwrap()).unwrap();
    let inputs = transfer_words();
    let m = Machine::new(FriProfile::Test);
    let t0 = std::time::Instant::now();
    let (proof, exec) = m.prove(&program, &inputs, &[], None).expect("prove");
    let t_prove = t0.elapsed();
    eprintln!(
        "proved: {} cycles, tier {}, {:.1}s",
        exec.cycles(),
        proof.tier.0,
        t_prove.as_secs_f64()
    );
    let t1 = std::time::Instant::now();
    m.verify(&program.digest(), &proof).expect("verify");
    eprintln!("verified: {:.3}s", t1.elapsed().as_secs_f64());
}

/// Proves and verifies the interpreter's own guest (`guests-compiled/bin/evm.bin`) on the same
/// `transfer` vector, so the README can compare proof times directly with the translated program.
/// Only run if the translated program's proof fit the notes' budget (about 24 GB, about 45
/// minutes) — the interpreter is the larger program (18 009 words against 15 637) and costs more
/// cycles (121 638 against 79 203), so it is the one more likely to miss it.
///
/// Run once, measured:
///
/// ```text
/// cd evm2rv && /usr/bin/time -l cargo +1.98.1 test --release --test proof \
///     evm_bin_proves_and_verifies_the_same_transfer -- --ignored --exact --nocapture
/// ```
#[test]
#[ignore]
fn evm_bin_proves_and_verifies_the_same_transfer() {
    let image = root().join("guests-compiled/bin/evm.bin");
    let program = Program::from_flat_image(&std::fs::read(&image).unwrap()).unwrap();
    let inputs = transfer_words();
    let m = Machine::new(FriProfile::Test);
    let t0 = std::time::Instant::now();
    let (proof, exec) = m.prove(&program, &inputs, &[], None).expect("prove");
    let t_prove = t0.elapsed();
    eprintln!(
        "proved: {} cycles, tier {}, {:.1}s",
        exec.cycles(),
        proof.tier.0,
        t_prove.as_secs_f64()
    );
    let t1 = std::time::Instant::now();
    m.verify(&program.digest(), &proof).expect("verify");
    eprintln!("verified: {:.3}s", t1.elapsed().as_secs_f64());
}
