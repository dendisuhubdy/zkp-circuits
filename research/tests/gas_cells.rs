//! ZKVM-202 (fullnode #167): what one gas buys, in committed trace cells, for every priced row kind.
//! `docs/07-gas.md` has the method and the table this prints (`--nocapture`).
//!
//! Gas is meant to track prover cost, and the weights in `gas.rs` are enforced by the cpu AIR
//! (`w_next`), so they cannot move without a constraint-set bump. This file does not move them. It
//! measures them: table widths from the real chips and the real packed LogUp contexts, rows per
//! operation from an emulator run of a probe guest (cross-checked against the trace generator's own
//! real rows), gas from `gas::row_gas`. An operation whose cells per gas is more than 15 % away from
//! a plain cycle's fails the test unless it is on `KNOWN_MISPRICED`, with its measured ratio and the
//! weight that would fix it; an entry that is in fact inside the band fails too, so the list is
//! emptied in the commit that re-weights at the next constraint set.
mod common;

use p3_air::BaseAir;
use p3_field::{BasedVectorSpace, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use rand_zkvm::asm::{ops::*, Assembler};
use rand_zkvm::emulator::{execute, CycleEvent, Execution, Syscall};
use rand_zkvm::gas::{gas_max_with_modq, gas_of, row_gas, KECCAK_GAS, MODQ_GAS, POSEIDON2_ABSORB_GAS, SHA256_GAS};
use rand_zkvm::isa::{BranchCond, Program};
use rand_zkvm::machine::{build_traces_salted, chips_with_modq, Challenge, Chip, FriProfile, Machine, Tier, Val};
use rand_zkvm::modq::{Args, Op};
use rand_zkvm::tables::{keccak, memory, modq, poseidon2, sha256};

/// How far an operation's cells per gas may sit from a plain cycle's.
const BAND: f64 = 0.15;
/// How tightly a `KNOWN_MISPRICED` ratio is pinned.
const PIN: f64 = 0.005;

/// An operation the count shows outside the band, kept because the weights are constraint-enforced
/// and the owner's October ruling was not to cut a chain for them. `ratio` is its cells per gas over
/// a plain cycle's (above 1: under-priced); `weight` is the row's total gas that brings it to 1.0,
/// `round(cells / slot)`. Empty this list in the commit that changes `gas.rs` and `w_next`.
struct Mispriced { op: &'static str, ratio: f64, weight: u64 }
const KNOWN_MISPRICED: [Mispriced; 6] = [
    Mispriced { op: "poseidon2 absorb", ratio: 1.243, weight: 4 },
    Mispriced { op: "digest prefix", ratio: 1.243, weight: 4 },
    Mispriced { op: "keccak", ratio: 0.697, weight: 134 },
    Mispriced { op: "sha256", ratio: 0.769, weight: 49 },
    Mispriced { op: "modq dot4", ratio: 1.572, weight: 264 },
    Mispriced { op: "modq msub4", ratio: 1.814, weight: 305 },
];

// ---- widths --------------------------------------------------------------------------------------

/// One table's columns, in base-field cells per row.
#[derive(Clone, Copy, Debug)]
struct Width {
    /// The table's own main-trace columns (`Chip::table_width`).
    main: usize,
    /// The preprocessed columns (committed once per key, opened by every proof).
    pre: usize,
    /// The LogUp-terminal blind's columns (`tables::blind`), appended to every main trace.
    blind: usize,
    /// The permutation (LogUp) trace: one accumulator and one fraction column per packed lookup
    /// context, each an extension element, committed flattened to the base field.
    aux: usize,
    /// The quotient chunks, likewise flattened. Not trace; reported as a sensitivity only.
    quotient: usize,
}

/// Which columns a count takes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Method {
    /// The method of record: every committed trace cell — main, blind, preprocessed, LogUp.
    Trace,
    /// The 17 November review's: main and preprocessed only.
    MainPre,
    /// `Trace` without the preprocessed columns (a proof does not recommit them).
    NoPre,
    /// `Trace` plus the quotient chunks.
    WithQuotient,
    /// The October audit's: what a proof commits itself — main, blind, LogUp and the quotient
    /// chunks, without the preprocessed columns.
    PerProof,
}

impl Width {
    fn cells(&self, m: Method) -> usize {
        match m {
            Method::Trace => self.main + self.blind + self.pre + self.aux,
            Method::MainPre => self.main + self.pre,
            Method::NoPre => self.main + self.blind + self.aux,
            Method::WithQuotient => self.main + self.blind + self.pre + self.aux + self.quotient,
            Method::PerProof => self.main + self.blind + self.aux + self.quotient,
        }
    }
}

struct Widths { cpu: Width, alu: Width, memory: Width, poseidon2: Width, keccak: Width, sha256: Width, modq: Width }

/// Every width from the machine itself, at tier 10 with all three optional tables declared (a
/// chip's columns and its packed lookups do not depend on the tier or on any height): the main and
/// preprocessed widths from the `Chip`'s `BaseAir`, the blind as the difference between the chip's
/// width and its table's, the LogUp width from the verifier key's packed lookup contexts — the
/// permutation trace `LogUpGadget::generate_permutation` builds is `contexts + 1` extension columns
/// wide — and the quotient chunk count from `get_log_num_quotient_chunks`, as the prover calls it.
fn widths() -> Widths {
    let (tier, klh, slh, mlh) = (Tier(10), 7, 7, modq::MIN_LOG_HEIGHT);
    let machine = Machine::new(FriProfile::Test);
    let key = machine.verifier_key_with_modq(tier, 7, 7, klh, slh, mlh, 7);
    let degrees = machine.log_ext_degrees_with_modq(tier, 7, 7, klh, slh, mlh, 7, tier.min_mem_log_height());
    let chips = chips_with_modq(tier, klh, slh, mlh);
    assert_eq!(chips.len(), key.lookups.len());
    let ext = <Challenge as BasedVectorSpace<Val>>::DIMENSION;
    let gadget = p3_lookup::LogUpGadget::new();
    let of = |want: fn(&Chip) -> bool| -> Width {
        let i = chips.iter().position(want).expect("the chip is in the batch");
        let (chip, lookups) = (&chips[i], &key.lookups[i]);
        assert!(!lookups.is_empty(), "every table carries the blind's two messages, so every table has a permutation trace");
        let log_chunks = p3_batch_stark::symbolic::get_log_num_quotient_chunks::<Val, Challenge, Chip, p3_lookup::LogUpGadget>(
            chip,
            p3_air::symbolic::AirLayout::from_air(chip),
            1usize << (degrees[i] - 1),
            lookups,
            1,
            &gadget,
        );
        Width {
            main: chip.table_width(),
            pre: BaseAir::<Val>::preprocessed_width(chip),
            blind: BaseAir::<Val>::width(chip) - chip.table_width(),
            aux: (lookups.len() + 1) * ext,
            quotient: (1usize << log_chunks) * ext,
        }
    };
    Widths {
        cpu: of(|c| matches!(c, Chip::Cpu(_))),
        alu: of(|c| matches!(c, Chip::Alu(_))),
        memory: of(|c| matches!(c, Chip::Memory(_))),
        poseidon2: of(|c| matches!(c, Chip::Poseidon2(..))),
        keccak: of(|c| matches!(c, Chip::Keccak(..))),
        sha256: of(|c| matches!(c, Chip::Sha256(..))),
        modq: of(|c| matches!(c, Chip::Modq(..))),
    }
}

// ---- rows per operation ----------------------------------------------------------------------------

/// The table a syscall's chip rows land in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ChipTable { None, Poseidon2, Keccak, Sha256, Modq }

/// What one priced row costs in rows: its own cpu row (and with it the tier's slot, below), the
/// block it pulls into its chip's table, and the memory rows that chip sends for it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Rows { gas: u64, table: ChipTable, chip_rows: usize, chip_mem_rows: usize }

/// The rows the tier provisions behind one cpu row whatever the row does: `alu` ALU rows and `mem`
/// memory rows (`Tier::alu_height`, `Tier::min_mem_log_height`).
#[derive(Clone, Copy, Debug)]
struct Slot { alu: usize, mem: usize }

fn slot() -> Slot {
    let s = |t: Tier| Slot { alu: t.alu_height() / t.cpu_height(), mem: (1usize << t.min_mem_log_height()) / t.cpu_height() };
    let first = s(Tier(rand_zkvm::machine::TIERS[0]));
    for t in rand_zkvm::machine::TIERS {
        let x = s(Tier(t));
        assert_eq!((x.alu, x.mem), (first.alu, first.mem), "the slot is the same at every tier");
    }
    first
}

const ARENA_WORDS: u32 = 0x1000;
const NTT: Args = Args { op: Op::Ntt, out: 0, a: 0, b: 0 };
const INTT: Args = Args { op: Op::Intt, out: 0, a: 0, b: 0 };
const DOT4: Args = Args { op: Op::Dot4, out: 8, a: 0, b: 4 };
const MSUB4: Args = Args { op: Op::Msub4, out: 0, a: 8, b: 4 };

/// The probe: fill nine polys of an arena (as `common::modq_program`), then one call of every priced
/// syscall — a 12-word `POSEIDON2` (three absorb rows), a `KECCAK`, a `SHA256`, and the four `MODQ` ops.
fn probe() -> Program {
    let arena_bytes = 4 * ARENA_WORDS as i32;
    let mut a = Assembler::new(0);
    a.extend(li(5, arena_bytes));
    a.extend(li(6, 0));
    a.extend(li(7, 9 * 256));
    a.extend(li(8, 3));
    a.extend(li(9, 7001));
    a.label("fill");
    a.push(sw(5, 8, 0));
    a.push(addi(5, 5, 4));
    a.push(add(8, 8, 9));
    a.push(addi(6, 6, 1));
    a.branch(BranchCond::Ne, 6, 7, "fill");
    for args in [NTT, INTT, DOT4, MSUB4] {
        a.extend(call_modq(ARENA_WORDS, args.encode()));
    }
    a.extend(call_poseidon2(0x4000, 12));
    a.extend(call_keccak(0x5000));
    a.extend(call_sha256(0x6000));
    a.extend(halt());
    a.assemble()
}

/// The priced kind of a cycle, and the rows it pulls in, read off the event.
fn rows_of(ev: &CycleEvent) -> (&'static str, Rows) {
    let gas = row_gas(ev);
    let r = |table, chip_rows, chip_mem_rows| Rows { gas, table, chip_rows, chip_mem_rows };
    if ev.hash_row.as_ref().is_some_and(|h| h.is_absorb()) {
        return ("poseidon2 absorb", r(ChipTable::Poseidon2, poseidon2::BLOCK, 0));
    }
    match ev.sys {
        Some(Syscall::Keccak { .. }) => ("keccak", r(ChipTable::Keccak, keccak::BLOCK, ev.keccak_accesses.len())),
        Some(Syscall::Sha256 { .. }) => ("sha256", r(ChipTable::Sha256, sha256::BLOCK, ev.sha256_accesses.len())),
        Some(Syscall::Modq { a1, .. }) => {
            let name = match Args::decode(a1).expect("the emulator ran it").op {
                Op::Ntt => "modq ntt",
                Op::Intt => "modq intt",
                Op::Dot4 => "modq dot4",
                Op::Msub4 => "modq msub4",
            };
            (name, r(ChipTable::Modq, modq::BLOCK, ev.modq.as_ref().expect("a modq row carries its call").accesses.len()))
        }
        _ => ("plain cycle", r(ChipTable::None, 0, 0)),
    }
}

/// Every priced kind, in print order, with its rows: measured on the probe's events, each kind
/// required to be uniform (every row of a kind weighs and pulls the same). The digest-prefix row is
/// not an event — the prefix precedes the first cycle — so its gas is `gas_of` over no events divided
/// by the prefix's row count, and its permutation is checked against the poseidon2 trace below.
fn measure(p: &Program, e: &Execution) -> Vec<(&'static str, Rows)> {
    let mut seen: Vec<(&'static str, Rows)> = Vec::new();
    for ev in &e.events {
        let (name, rows) = rows_of(ev);
        match seen.iter().find(|(n, _)| *n == name) {
            Some((_, r)) => assert_eq!(*r, rows, "{name}: every row of a kind costs the same"),
            None => seen.push((name, rows)),
        }
    }
    let prefix = p.digest_rows() + rand_zkvm::hash::input_digest_row_count(0) + rand_zkvm::hash::public_digest_row_count(0);
    let prefix_gas = gas_of(p, &[], &[], &[]);
    assert_eq!(prefix_gas % prefix as u64, 0);
    seen.push(("digest prefix", Rows { gas: prefix_gas / prefix as u64, table: ChipTable::Poseidon2, chip_rows: poseidon2::BLOCK, chip_mem_rows: 0 }));
    const ORDER: [&str; 9] = ["plain cycle", "poseidon2 absorb", "digest prefix", "keccak", "sha256", "modq ntt", "modq intt", "modq dot4", "modq msub4"];
    ORDER.iter().map(|n| *seen.iter().find(|(m, _)| m == n).unwrap_or_else(|| panic!("the probe has no {n} row"))).collect()
}

// ---- cells -----------------------------------------------------------------------------------------

fn slot_cells(w: &Widths, s: Slot, m: Method) -> usize { w.cpu.cells(m) + s.alu * w.alu.cells(m) + s.mem * w.memory.cells(m) }

fn chip_width(w: &Widths, t: ChipTable) -> Option<&Width> {
    match t { ChipTable::None => None, ChipTable::Poseidon2 => Some(&w.poseidon2), ChipTable::Keccak => Some(&w.keccak), ChipTable::Sha256 => Some(&w.sha256), ChipTable::Modq => Some(&w.modq) }
}

/// The cells behind a syscall's chip block and the memory rows the chip sends — without the cpu
/// row's own slot.
fn chip_cells(w: &Widths, r: &Rows, m: Method) -> usize {
    chip_width(w, r.table).map_or(0, |c| r.chip_rows * c.cells(m)) + r.chip_mem_rows * w.memory.cells(m)
}

/// Everything the row causes: its slot and its chip's cells.
fn cells(w: &Widths, s: Slot, r: &Rows, m: Method) -> usize { slot_cells(w, s, m) + chip_cells(w, r, m) }

/// Cells per gas over a plain cycle's.
fn ratio(w: &Widths, s: Slot, r: &Rows, m: Method) -> f64 { cells(w, s, r, m) as f64 / r.gas as f64 / slot_cells(w, s, m) as f64 }

/// The row weight that brings the ratio to 1.0.
fn fair_weight(w: &Widths, s: Slot, r: &Rows, m: Method) -> u64 { (cells(w, s, r, m) as f64 / slot_cells(w, s, m) as f64).round() as u64 }

fn real_rows(m: &RowMajorMatrix<Val>, is_real: usize) -> usize { (0..m.height()).filter(|&r| m.values[r * m.width() + is_real].as_canonical_u64() == 1).count() }

struct Measured { program: Program, exec: Execution, widths: Widths, slot: Slot, ops: Vec<(&'static str, Rows)> }

fn measured() -> Measured {
    let program = probe();
    let exec = execute(&program, &[], &[], 100_000).unwrap();
    assert!(exec.halted);
    let ops = measure(&program, &exec);
    Measured { program, exec, widths: widths(), slot: slot(), ops }
}

// ---- the tests -------------------------------------------------------------------------------------

/// The row model against the trace generator: the probe's traces hold exactly the real rows the
/// per-operation counts add up to, and no cycle overruns its slot.
#[test]
fn the_row_counts_are_what_the_trace_generator_lays_down() {
    let Measured { program: p, exec: e, slot: s, ops, .. } = measured();
    let prefix = p.digest_rows() + rand_zkvm::hash::input_digest_row_count(0) + rand_zkvm::hash::public_digest_row_count(0);
    let tier = Tier::for_cycles(e.cycles() + prefix).unwrap();
    let t = build_traces_salted(&p, &[], &[], [0; 4], &e, tier, gas_max_with_modq(tier, keccak::MIN_LOG_HEIGHT.max(7), sha256::MIN_LOG_HEIGHT.max(7), modq::MIN_LOG_HEIGHT + 2)).unwrap();

    let count = |name: &str| e.events.iter().filter(|ev| rows_of(ev).0 == name).count();
    let rows = |name: &str| ops.iter().find(|(n, _)| *n == name).unwrap().1;
    // One block per call in each chip's table.
    assert_eq!(real_rows(t.keccak.as_ref().unwrap(), keccak::col::IS_REAL), count("keccak") * rows("keccak").chip_rows);
    assert_eq!(real_rows(t.sha256.as_ref().unwrap(), sha256::col::IS_REAL), count("sha256") * rows("sha256").chip_rows);
    let modq_calls: usize = ["modq ntt", "modq intt", "modq dot4", "modq msub4"].iter().map(|n| count(n)).sum();
    assert_eq!(modq_calls, 4);
    assert_eq!(real_rows(t.modq.as_ref().unwrap(), modq::col::IS_REAL), modq_calls * modq::BLOCK);
    // One permutation per absorb row and per digest-prefix row.
    assert_eq!(real_rows(&t.poseidon2, poseidon2::col::IS_REAL), (count("poseidon2 absorb") + prefix) * poseidon2::BLOCK);
    // The memory table: every cpu-sent access, plus what each chip sends for its calls.
    let cpu_sent: usize = e.events.iter().map(|ev| ev.accesses.len()).sum();
    let chip_sent: usize = e.events.iter().map(|ev| rows_of(ev).1.chip_mem_rows).sum();
    assert_eq!(real_rows(&t.memory, memory::col::IS_REAL), cpu_sent + chip_sent);
    // The slot is a capacity: no cycle sends more memory accesses or ALU rows than it holds.
    assert_eq!(e.events.iter().map(|ev| ev.accesses.len()).max().unwrap(), s.mem);
    assert!(e.events.iter().all(|ev| ev.alu.len() <= s.alu));
    assert_eq!(t.cpu.height(), tier.cpu_height());
    assert_eq!(t.alu.height(), s.alu * tier.cpu_height());
    // The modq chip's memory rows, against what its documented traffic comes to (`tables/modq.rs`,
    // "The chip's memory traffic"): a transform reads 256 words and writes 256; `DOT4` reads two
    // spans of four polys and writes one poly; `MSUB4` reads two spans and one poly, writes four.
    let n = rand_zkvm::modq::N;
    assert_eq!(rows("modq ntt").chip_mem_rows, 2 * n);
    assert_eq!(rows("modq intt").chip_mem_rows, 2 * n);
    assert_eq!(rows("modq dot4").chip_mem_rows, (4 + 4 + 1) * n);
    assert_eq!(rows("modq msub4").chip_mem_rows, (4 + 4 + 1 + 4) * n);
}

/// The table, and the band.
#[test]
fn cells_per_gas_is_within_the_band_or_on_the_list() {
    let Measured { widths: w, slot: s, ops, .. } = measured();
    let m = Method::Trace;

    println!("\ncolumns per row (base-field cells)        main  blind   pre  logup | trace | quotient");
    for (name, x) in [("cpu", &w.cpu), ("alu", &w.alu), ("memory", &w.memory), ("poseidon2", &w.poseidon2), ("keccak", &w.keccak), ("sha256", &w.sha256), ("modq", &w.modq)] {
        println!("  {name:<38} {:>5} {:>6} {:>5} {:>6} | {:>5} | {:>8}", x.main, x.blind, x.pre, x.aux, x.cells(m), x.quotient);
    }
    let unit = slot_cells(&w, s, m);
    println!("slot: 1 cpu + {} alu + {} memory rows = {unit} cells\n", s.alu, s.mem);
    println!("{:<18} {:>4} {:>4} {:>5} {:>10} {:>6} {:>9} {:>5} {:>10} {:>6} {:>7}", "op", "cpu", "alu", "mem", "chip rows", "+mem", "cells", "gas", "cells/gas", "ratio", "fair w");
    let mut failures = Vec::new();
    for (name, r) in &ops {
        let (c, q) = (cells(&w, s, r, m), ratio(&w, s, r, m));
        let fair = fair_weight(&w, s, r, m);
        println!("{name:<18} {:>4} {:>4} {:>5} {:>10} {:>6} {c:>9} {:>5} {:>10.1} {q:>6.3} {fair:>7}", 1, s.alu, s.mem, r.chip_rows, r.chip_mem_rows, r.gas, c as f64 / r.gas as f64);
        let inside = (q - 1.0).abs() <= BAND;
        match KNOWN_MISPRICED.iter().find(|k| k.op == *name) {
            None if !inside => failures.push(format!("{name}: ratio {q:.3} is outside ±{BAND} and not on KNOWN_MISPRICED (weight {fair} would bring it to 1.0)")),
            None => {}
            Some(_) if inside => failures.push(format!("{name}: ratio {q:.3} is inside the band — take it off KNOWN_MISPRICED")),
            Some(k) => {
                if (q - k.ratio).abs() > PIN { failures.push(format!("{name}: measured ratio {q:.3}, pinned {}", k.ratio)); }
                if fair != k.weight { failures.push(format!("{name}: fair weight {fair}, pinned {}", k.weight)); }
                let fixed = c as f64 / k.weight as f64 / unit as f64;
                if (fixed - 1.0).abs() > BAND { failures.push(format!("{name}: the pinned weight {} leaves ratio {fixed:.3}", k.weight)); }
            }
        }
    }
    for k in &KNOWN_MISPRICED {
        if !ops.iter().any(|(n, _)| *n == k.op) { failures.push(format!("KNOWN_MISPRICED names {}, which is not a priced op", k.op)); }
    }

    println!("\nratio by method            trace  main+pre(17 Nov)  no-pre  +quotient  per-proof(Oct)");
    for (name, r) in &ops {
        let nov = if r.gas == 1 { 1.0 } else { chip_cells(&w, r, Method::MainPre) as f64 / r.gas as f64 / slot_cells(&w, s, Method::MainPre) as f64 };
        println!("{name:<24} {:>7.3} {nov:>17.3} {:>7.3} {:>10.3} {:>15.3}", ratio(&w, s, r, m), ratio(&w, s, r, Method::NoPre), ratio(&w, s, r, Method::WithQuotient), ratio(&w, s, r, Method::PerProof));
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// The two earlier counts, reproduced from the same widths and rows, so the doc's account of why
/// they differ is checked rather than asserted.
#[test]
fn the_earlier_counts_are_reproduced() {
    let Measured { widths: w, slot: s, ops, .. } = measured();
    let rows = |name: &str| ops.iter().find(|(n, _)| *n == name).unwrap().1;

    // 17 November: main + preprocessed columns only, and an operation's cells are its chip block and
    // the chip's memory rows — the cpu row's own slot is left out of the numerator.
    let m = Method::MainPre;
    assert_eq!(slot_cells(&w, s, m), 459);
    let nov = |name: &str| chip_cells(&w, &rows(name), m);
    assert_eq!((nov("keccak"), nov("sha256"), nov("modq ntt"), nov("modq dot4"), nov("modq msub4")), (87_952, 30_848, 82_944, 104_448, 116_736));
    let nov_ratio = |name: &str| nov(name) as f64 / rows(name).gas as f64 / 459.0;
    assert!((nov_ratio("modq dot4") - 1.35).abs() < 0.005 && (nov_ratio("modq msub4") - 1.51).abs() < 0.005);

    // October: the cells a proof commits itself — main, blind, LogUp and quotient chunks, no
    // preprocessed columns — with the cpu row's slot in the numerator.
    let m = Method::PerProof;
    assert_eq!(slot_cells(&w, s, m), 760);
    let oct = |name: &str| (ratio(&w, s, &rows(name), m) * 100.0).round() / 100.0;
    assert_eq!((oct("modq dot4"), oct("modq msub4"), oct("keccak"), oct("sha256")), (1.49, 1.77, 0.61, 0.69));

    // `gas.rs`'s own derivation of `MODQ_GAS`: the chip block alone at 460 cells per gas, plus the row.
    let block = rows("modq ntt").chip_rows * w.modq.cells(Method::MainPre);
    assert_eq!(block, 76_800);
    assert_eq!((block as f64 / 460.0).round() as u64 + 1, MODQ_GAS);
    assert_eq!((KECCAK_GAS, SHA256_GAS, POSEIDON2_ABSORB_GAS), (192, 64, 3), "the weights this file measures; ZKVM-202 does not move them");
}

// ---- msauth under the proposed weights -------------------------------------------------------------

/// The private-multisig guest (Dilithium2 verification, `guests::compiled::msauth`) at `k` active
/// signers of a three-signer policy, on the emulator only — the fixture of `tests/msauth.rs`.
fn msauth_run(k: usize) -> (Program, Vec<u32>, Execution) {
    use crystals_dilithium::dilithium2::Keypair;
    use rand_zkvm::msauth::{msauth_inputs, signer_tree, signing_message, Slot, M_MAX};
    const BINDING: [u32; 8] = [11, 22, 33, 44, 55, 66, 77, 88];
    let kps: Vec<Keypair> = (0..M_MAX).map(|i| Keypair::generate(Some(&{ let mut s = [i as u8 + 1; 32]; s[31] = 0; s })).unwrap()).collect();
    let pks: Vec<[u8; 1312]> = kps.iter().map(|k| k.public.to_bytes()).collect();
    let (_, paths) = signer_tree(&pks);
    let slots: Vec<Slot> = (0..k).map(|i| Slot { index: i as u32, pk: pks[i], sig: kps[i].sign(&signing_message(&BINDING)), path: paths[i] }).collect();
    let input = msauth_inputs(&[5; 8], &[6; 8], 1, &slots);
    let p = rand_zkvm::guests::compiled::msauth();
    let e = execute(&p, &input, &BINDING, Tier(22).max_cycles()).unwrap();
    assert!(e.halted);
    (p, input, e)
}

/// The header ceiling `gas::gas_max_with_modq` would compute at these weights: each term is the most
/// its row kind can add, so the modq term takes the heaviest op's weight.
fn ceiling(tier: Tier, klh: u8, mlh: u8, absorb: u64, keccak_w: u64, modq_max: u64) -> u64 {
    ((1u64 << tier.0) - 1) + (absorb - 1) * (1u64 << (tier.0 - 3)) + (keccak_w - 1) * ((1u64 << klh) / keccak::BLOCK as u64) + (modq_max - 1) * ((1u64 << mlh) / modq::BLOCK as u64)
}

/// What `msauth` costs today and what it would cost at the proposed weights, for `M = 1, 2, 3`.
/// Nothing but the gas moves: a tier is chosen by cycles and Poseidon2 permutations and a table's
/// height by its rows, none of which a weight touches, so the pinned shape (tier 18, keccak 14,
/// modq 16, memory 20) holds as it is. The pinned gas word is the header ceiling, and that does move.
#[test]
fn msauth_under_the_proposed_weights() {
    use rand_zkvm::msauth::{MSAUTH_TIER, PINNED_KECCAK_LOG_HEIGHT, PINNED_MODQ_LOG_HEIGHT};
    let Measured { widths: w, slot: s, ops, .. } = measured();
    let fair = |name: &str| fair_weight(&w, s, &ops.iter().find(|(n, _)| *n == name).unwrap().1, Method::Trace);
    let today = |name: &str| ops.iter().find(|(n, _)| *n == name).unwrap().1.gas;
    // Two re-weightings: every priced row at ratio 1.0, and the MODQ ops alone.
    let all = |name: &str| fair(name);
    let modq_only = |name: &str| if name.starts_with("modq") { fair(name) } else { today(name) };

    println!("\nmsauth (tier {}, pinned keccak {PINNED_KECCAK_LOG_HEIGHT} / modq {PINNED_MODQ_LOG_HEIGHT})", MSAUTH_TIER.0);
    println!("{:>2} {:>8} {:>7} {:>7} {:>5} {:>5} {:>5} {:>6} | {:>9} {:>10} {:>9}", "M", "cycles", "prefix", "absorb", "kecc", "ntt", "intt", "dot4", "gas today", "modq-only", "all ops");
    let mut got = Vec::new();
    for k in 1..=3usize {
        let (p, input, e) = msauth_run(k);
        let prefix = p.digest_rows() + rand_zkvm::hash::input_digest_row_count(input.len()) + rand_zkvm::hash::public_digest_row_count(8);
        let count = |name: &str| e.events.iter().filter(|ev| rows_of(ev).0 == name).count();
        let gas = |weight: &dyn Fn(&str) -> u64| prefix as u64 * weight("digest prefix") + e.events.iter().map(|ev| weight(rows_of(ev).0)).sum::<u64>();
        let now = gas(&today);
        assert_eq!(now, gas_of(&p, &input, &[11, 22, 33, 44, 55, 66, 77, 88], &e.events), "the per-kind weights are the meter's");
        assert_eq!(count("modq msub4"), k, "one MSUB4 per signature");
        assert!(e.cycles() + prefix <= MSAUTH_TIER.max_cycles());
        println!("{k:>2} {:>8} {prefix:>7} {:>7} {:>5} {:>5} {:>5} {:>6} | {now:>9} {:>10} {:>9}", e.cycles() + prefix, count("poseidon2 absorb"), count("keccak"), count("modq ntt"), count("modq intt"), count("modq dot4"), gas(&modq_only), gas(&all));
        got.push((count("keccak"), count("modq ntt"), count("modq intt"), count("modq dot4"), count("modq msub4"), now, gas(&modq_only), gas(&all)));
    }
    let heaviest = |weight: &dyn Fn(&str) -> u64| ["modq ntt", "modq intt", "modq dot4", "modq msub4"].iter().map(|n| weight(n)).max().unwrap();
    let ceil = |weight: &dyn Fn(&str) -> u64| ceiling(MSAUTH_TIER, PINNED_KECCAK_LOG_HEIGHT, PINNED_MODQ_LOG_HEIGHT, weight("poseidon2 absorb"), weight("keccak"), heaviest(weight));
    let ceilings = (ceil(&today), ceil(&modq_only), ceil(&all));
    println!("header ceiling (the pinned gas word): today {}, modq-only {}, all ops {}", ceilings.0, ceilings.1, ceilings.2);
    assert_eq!(ceilings.0, gas_max_with_modq(MSAUTH_TIER, PINNED_KECCAK_LOG_HEIGHT, 0, PINNED_MODQ_LOG_HEIGHT));
    for g in &got {
        assert!(g.5 <= ceilings.0 && g.6 <= ceilings.1 && g.7 <= ceilings.2, "a run never passes its header's ceiling");
    }
    // Per signature: 9 NTT, 4 INTT, 4 DOT4, 1 MSUB4 and 99 Keccak permutations; then the gas, pinned
    // (the fixture is seeded): today's, with the MODQ ops re-weighted, with every op re-weighted.
    let pinned = [(111_217, 112_063, 108_057), (216_576, 218_268, 208_623), (321_575, 324_113, 308_829)];
    for (i, g) in got.iter().enumerate() {
        let k = i + 1;
        assert_eq!((g.0, g.1, g.2, g.3, g.4), (99 * k, 9 * k, 4 * k, 4 * k, k), "M = {k}");
        assert_eq!((g.5, g.6, g.7), pinned[i], "M = {k}");
    }
    assert_eq!(ceilings, (436_159, 444_927, 447_999));
}
