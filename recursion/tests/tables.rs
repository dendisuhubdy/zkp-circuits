//! Per-table unit tests: the memory table (Task 3), and later tables as they land (Tasks 4–5, 8).
mod common;

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;
use recursion::emulator::MemAccess;
use recursion::isa::F;
use recursion::tables::memory::{col, memory_trace, REGISTER_BASE};
use recursion::tables::range::RangeCounts;

fn read(addr: u64, ts: u32, value: u64) -> MemAccess {
    MemAccess { addr, ts, value: F::from_u64(value), is_write: false }
}
fn write(addr: u64, ts: u32, value: u64) -> MemAccess {
    MemAccess { addr, ts, value: F::from_u64(value), is_write: true }
}

fn cell(t: &p3_matrix::dense::RowMajorMatrix<F>, row: usize, c: usize) -> F {
    t.get(row, c).unwrap()
}

#[test]
fn the_trace_sorts_by_addr_then_ts_and_read_after_write_holds() {
    // Deliberately unsorted: the builder sorts.
    let accesses = vec![
        write(100, 0, 42),
        write(REGISTER_BASE + 3, 0, 7),
        read(100, 16, 42),
        write(REGISTER_BASE + 3, 16, 9),
        read(REGISTER_BASE + 3, 32, 9),
        read(5, 48, 0), // first touch of a fresh address reads zero
    ];
    let mut counts = RangeCounts::default();
    let t = memory_trace(&accesses, 16, &mut counts);
    let mut last = (0u64, 0u64);
    for i in 0..6 {
        let addr = cell(&t, i, col::ADDR).as_canonical_u64();
        let ts = cell(&t, i, col::TS).as_canonical_u64();
        assert!((addr, ts) > last, "rows are sorted by (addr, ts)");
        last = (addr, ts);
        assert_eq!(cell(&t, i, col::IS_REAL), F::ONE);
    }
    // Row 0 is addr 5 (fresh read of zero), then 100, then the register cell.
    assert_eq!(cell(&t, 0, col::ADDR).as_canonical_u64(), 5);
    assert_eq!(cell(&t, 0, col::VALUE), F::ZERO);
    assert_eq!(cell(&t, 1, col::ADDR).as_canonical_u64(), 100);
    assert_eq!(cell(&t, 1, col::IS_WRITE), F::ONE);
    assert_eq!(cell(&t, 2, col::VALUE), F::from_u64(42));
    assert_eq!(cell(&t, 2, col::IS_WRITE), F::ZERO);
    assert_eq!(cell(&t, 3, col::ADDR).as_canonical_u64(), REGISTER_BASE + 3);
    // The delta limbs recompose the AIR's own key arithmetic (research's audit-ZM2 lesson):
    // the key is the address itself, and the delta is (key_n - key_l - 1) on an address change.
    let mut limb_sum = |i: usize| -> u64 {
        (0..4).map(|k| cell(&t, i, col::D0 + k).as_canonical_u64() << (8 * k)).sum::<u64>()
    };
    // Row 0 (addr 5) -> row 1 (addr 100): changed, delta = 100 - 5 - 1 = 94.
    assert_eq!(cell(&t, 0, col::ADDR_CHANGED), F::ONE);
    assert_eq!(limb_sum(0), 94);
    // Row 1 -> row 2: same address, ts 0 -> 16, delta = 15.
    assert_eq!(cell(&t, 1, col::ADDR_CHANGED), F::ZERO);
    assert_eq!(limb_sum(1), 15);
    // DIFF_INV is the inverse of the key difference on a change, zero otherwise.
    let diff = F::from_u64(100 - 5);
    assert_eq!(cell(&t, 0, col::DIFF_INV) * diff, F::ONE);
    assert_eq!(cell(&t, 1, col::DIFF_INV), F::ZERO);
}

#[test]
#[should_panic(expected = "two accesses to the same address at the same timestamp")]
fn a_same_address_same_timestamp_pair_is_a_builder_error() {
    let accesses = vec![write(7, 0, 1), read(7, 0, 1)];
    let mut counts = RangeCounts::default();
    memory_trace(&accesses, 4, &mut counts);
}

#[test]
#[should_panic(expected = "read does not match last write")]
fn a_read_that_disagrees_with_the_last_write_is_a_builder_error() {
    let accesses = vec![write(7, 0, 1), read(7, 8, 2)];
    let mut counts = RangeCounts::default();
    memory_trace(&accesses, 4, &mut counts);
}

#[test]
#[should_panic(expected = "first read of a fresh address must be zero")]
fn a_nonzero_first_touch_is_a_builder_error() {
    let accesses = vec![read(7, 0, 9)];
    let mut counts = RangeCounts::default();
    memory_trace(&accesses, 4, &mut counts);
}

#[test]
fn register_and_ram_histories_split_by_address_class() {
    // What `build_traces` (Task 6) does: each instance's trace is built from its own class.
    let accesses = vec![
        write(REGISTER_BASE + 1, 0, 11),
        write(300, 0, 22),
        read(REGISTER_BASE + 1, 16, 11),
        read(300, 16, 22),
    ];
    let is_reg = |a: &MemAccess| a.addr >= REGISTER_BASE;
    let regs: Vec<MemAccess> = accesses.iter().copied().filter(|a| is_reg(a)).collect();
    let ram: Vec<MemAccess> = accesses.iter().copied().filter(|a| !is_reg(a)).collect();
    let mut counts = RangeCounts::default();
    let rt = memory_trace(&regs, 4, &mut counts);
    let mt = memory_trace(&ram, 4, &mut counts);
    assert!(cell(&rt, 0, col::ADDR).as_canonical_u64() >= REGISTER_BASE);
    assert!(cell(&mt, 0, col::ADDR).as_canonical_u64() < REGISTER_BASE);
    assert_eq!(cell(&rt, 1, col::VALUE), F::from_u64(11));
    assert_eq!(cell(&mt, 1, col::VALUE), F::from_u64(22));
}
