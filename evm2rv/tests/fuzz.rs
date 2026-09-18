//! Task 6: differential fuzzing of the translation against the interpreter over every Shanghai
//! opcode the translation implements.
//!
//! **The corpus** is `evm2rv::gen::case(seed)` for the fixed seeds `0..N` (N = 10 000, or
//! `EVM2RV_FUZZ_CASES`): random programs over every opcode in `gen::OPS`, with loops, branches,
//! dynamic jumps, dead code, storage witnesses, random calldata and gas limits cut at random points
//! below what the program needs (`gen`'s module docs). Each is translated (`emit::translate`) and
//! compiled for the host with evm-rt into one library (`common/host.rs`: the Rust FFI for storage
//! and Keccak, UBSan on), then run through `run_call_with_executor` exactly as the shim runs it,
//! over the same input vector the interpreter (`run_call_with`) runs.
//!
//! **Compared** (ruling 2): the eight public words (the status, and the digest that binds the
//! return data, the logs and the post-state root) and `gas_used`. Never the halt kind: charging
//! static gas at the block head legitimately changes which exceptional halt a failing block
//! reports.
//!
//! **Not compared** (ruling 3; the choice is the harness's): a case in which a call reached a
//! precompile. The generator does emit the call family — to non-precompiles, where the
//! interpreter's trap is kept and the full comparison applies, and to precompiles, where the
//! interpreter (which traps on every call) is no oracle; the harness recognises those runs by the
//! runtime's `evm_rdata_live` and counts them apart. `evm_call` and the precompiles are fuzzed on
//! their own terms in evm-rt's host suite (`test/call_fuzz_test.c`, `test/precompile_fuzz_test.c`),
//! and the return-data buffer after a call here, against a model
//! (`the_return_data_buffer_matches_a_model_after_a_call`).
//!
//! **CHAINID and ORIGIN** (ruling 5): the interpreter traps on both, so the interpreter runs the
//! same program with each replaced by `CALLER` (`Case::interp_code`), with the caller equal to
//! the chain id the translation bakes in; `chainid_is_the_translation_time_constant` checks the
//! constant on its own.
//!
//! **Coverage** (ruling 5): every opcode the translation implements is executed at least 100 times
//! across the corpus (counted in the translated code), and so are dynamic bad jumps. The test
//! prints the per-opcode table.
//!
//! **Reproducing a failure:** each is printed with its seed, its code and calldata as hex, its
//! gas limit and both outcomes; `EVM2RV_FUZZ_SEED=<seed>` runs that one case alone.
//!
//! `a_sample_runs_through_the_real_pipeline` (ruling 1) takes cases from the same corpus, loops
//! included, through `evm2rv`, `rand-guest build` and `rand-guest run`, so the host build cannot
//! drift from the target build.

mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Instant;

use common::{build_shim, host, root, run_out_of_cycles};
use evm2rv::blocks::static_gas;
use evm2rv::emit::{translate, Options};
use evm2rv::gen::{case, non_trapping, Case, Gas};
use evm_core::abi::{run_call_with, Workspace};
use evm_core::ffi::HALT_INVALID;
use evm_core::interp::{Halt, Outcome};
use evm_core::u256::U256;
use rand_zkvm::evm::{EvmCall, HostRef, SparseTree};

/// The number of cases: 10 000, or `EVM2RV_FUZZ_CASES`.
fn n_cases() -> u64 {
    std::env::var("EVM2RV_FUZZ_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000)
}

/// The seeds: `0..n_cases()`, or the one `EVM2RV_FUZZ_SEED` names.
fn seeds() -> Vec<u64> {
    match std::env::var("EVM2RV_FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        Some(s) => vec![s],
        None => (0..n_cases()).collect(),
    }
}

/// The interpreter's call for `c`: its code is `interp_code` (CHAINID and ORIGIN as CALLER).
fn call_of(c: &Case) -> EvmCall {
    let mut tree = SparseTree::new();
    for (s, v) in &c.storage {
        tree.insert(*s, *v);
    }
    EvmCall {
        code: c.interp_code(),
        calldata: c.calldata.clone(),
        address: c.address,
        caller: c.caller,
        callvalue: c.callvalue,
        gas_limit: c.gas_limit,
        tree,
        touched: c.touched.clone(),
    }
}

/// The index of the gas-limit word in `c`'s input vector.
fn gas_word(c: &Case) -> usize {
    1 + c.code.len().div_ceil(4) + 1 + c.calldata.len().div_ceil(4) + 24
}

/// `c`'s input vector at its final gas limit, and the interpreter's words and outcome on it.
fn interpret(c: &Case, ws: &mut Workspace) -> (Vec<u32>, [u32; 8], Outcome) {
    let mut words = call_of(c).input_words();
    let gi = gas_word(c);
    assert_eq!(
        words[gi] as u64, c.gas_limit,
        "seed {}: the gas word",
        c.seed
    );
    let run = |w: &[u32], ws: &mut Workspace| {
        run_call_with(&mut HostRef, ws, |k| w[k as usize], w.len() as u32)
    };
    let (mut out, mut o) = run(&words, ws);
    if c.gas != Gas::Full {
        let used = o.gas_used;
        words[gi] = match c.gas {
            Gas::Fraction(f) => used * f as u64 / 65_536,
            Gas::Minus(k) => used.saturating_sub(k),
            Gas::Full => unreachable!(),
        } as u32;
        (out, o) = run(&words, ws);
    }
    (words, out, o)
}

fn translate_case(c: &Case) -> String {
    translate(
        &c.code,
        &Options {
            chain_id: c.chain_id,
        },
    )
    .unwrap_or_else(|e| panic!("seed {}: {e}", c.seed))
    .c
}

/// One divergence, printable.
fn report(
    c: &Case,
    words: &[u32],
    want: &([u32; 8], Outcome),
    got: &([u32; 8], Outcome),
) -> String {
    format!(
        "seed {} (EVM2RV_FUZZ_SEED={}):\n  code {}\n  calldata {}\n  gas limit {}, chain id {:?}\n  interpreter: status {} halt {:?} gas_used {} ret {}\n  translation: status {} halt {:?} gas_used {} ret {}\n  words {:?} / {:?}\n  input words {}",
        c.seed,
        c.seed,
        hex::encode(&c.code),
        hex::encode(&c.calldata),
        words[gas_word(c)],
        c.chain_id,
        want.0[0],
        want.1.halt,
        want.1.gas_used,
        hex::encode(&want.1.ret[..want.1.ret_len]),
        got.0[0],
        got.1.halt,
        got.1.gas_used,
        hex::encode(&got.1.ret[..got.1.ret_len]),
        want.0,
        got.0,
        words.len(),
    )
}

#[test]
fn the_translation_matches_the_interpreter_on_the_fuzz_corpus() {
    let t0 = Instant::now();
    let seeds = seeds();
    let cases: Vec<Case> = seeds.iter().map(|&s| case(s)).collect();
    let cs: Vec<String> = cases.iter().map(translate_case).collect();
    let t_gen = t0.elapsed();
    let t1 = Instant::now();
    let name = match seeds.as_slice() {
        [one] => format!("fuzz-seed-{one}"),
        _ => format!("fuzz-{}", seeds.len()),
    };
    let lib = host::build(&name, &cs);
    let t_build = t1.elapsed();

    let t2 = Instant::now();
    let mut ws = Box::new(Workspace::ZERO);
    let mut failures: Vec<String> = Vec::new();
    let mut n_failed = 0usize;
    let mut excluded = 0usize;
    let mut status = [0usize; 3];
    let mut halts: BTreeMap<String, usize> = BTreeMap::new();
    let (mut chain, mut loops, mut call_bytes, mut dead_call_bytes, mut cuts) = (0, 0, 0, 0, 0);
    for (i, c) in cases.iter().enumerate() {
        let (words, want_w, want_o) = interpret(c, &mut ws);
        let (got_w, got_o, extra) = lib.run_words(&mut HostRef, i, &words);
        if extra.reached_precompile {
            assert!(
                matches!(want_o.halt, Halt::Trap(0xf1 | 0xf2 | 0xf4 | 0xfa)),
                "seed {}: a run that reached a precompile must have trapped the interpreter on \
                 CALL/CALLCODE/DELEGATECALL/STATICCALL, got {:?}",
                c.seed,
                want_o.halt,
            );
            excluded += 1;
            continue;
        }
        status[want_w[0] as usize] += 1;
        *halts.entry(format!("{:?}", want_o.halt)).or_default() += 1;
        chain += c.chain_id.is_some() as usize;
        loops += (c.tags.loops > 0) as usize;
        call_bytes += c.tags.call_byte as usize;
        dead_call_bytes += (c.tags.dead_call_byte && !c.tags.call_step) as usize;
        cuts += (c.gas != Gas::Full) as usize;
        if want_w != got_w || want_o.gas_used != got_o.gas_used {
            n_failed += 1;
            if failures.len() < 20 {
                failures.push(report(c, &words, &(want_w, want_o), &(got_w, got_o)));
            }
        }
    }
    let t_run = t2.elapsed();

    let compared = cases.len() - excluded;
    eprintln!(
        "fuzz: {} cases, {} compared, {} excluded (a call reached a precompile), {} diverged",
        cases.len(),
        compared,
        excluded,
        n_failed
    );
    eprintln!(
        "fuzz: status success {} / revert {} / exceptional {}; halts {:?}",
        status[1], status[0], status[2], halts
    );
    eprintln!(
        "fuzz: with loops {loops}, with CHAINID {chain}, with a call-family byte {call_bytes} ({dead_call_bytes} in dead code only), gas cut below the need {cuts}"
    );
    eprintln!(
        "fuzz: timings: generate + translate {:.1}s, host build {:.1}s, run {:.1}s",
        t_gen.as_secs_f64(),
        t_build.as_secs_f64(),
        t_run.as_secs_f64()
    );
    for f in &failures {
        eprintln!("DIVERGENCE {f}");
    }
    assert_eq!(
        n_failed, 0,
        "{n_failed} divergences (the first are printed above)"
    );

    // Coverage, over the whole corpus (the excluded cases' executions too).
    let cov = lib.coverage();
    let mut table = String::from("fuzz: executed per opcode (translated code):\n");
    for (k, op) in non_trapping().into_iter().enumerate() {
        table.push_str(&format!(
            "  {:02x} {:<14} {:>8}",
            op,
            evm2rv::emit::mnemonic(op),
            cov[op as usize]
        ));
        if k % 4 == 3 {
            table.push('\n');
        }
    }
    eprintln!("{table}");
    eprintln!(
        "fuzz: dynamic bad jumps executed {}",
        lib.dynamic_bad_jumps()
    );
    if seeds.len() >= 10_000 {
        let thin: Vec<String> = non_trapping()
            .into_iter()
            .filter(|&o| cov[o as usize] < 100)
            .map(|o| format!("{} ({})", evm2rv::emit::mnemonic(o), cov[o as usize]))
            .collect();
        assert!(thin.is_empty(), "executed fewer than 100 times: {thin:?}");
        assert!(lib.dynamic_bad_jumps() >= 100, "dynamic bad jumps");
    }
}

// ---- CHAINID -------------------------------------------------------------------------------

/// `CHAINID` pushes the `--chain-id` constant, whatever the caller: the interpreter traps on it,
/// so this is checked on its own (ruling 5). `CHAINID, PUSH0, MSTORE, PUSH1 32, PUSH0, RETURN`
/// returns it as a word, for 2 + 2 + 3 + 3 (one word of memory) + 3 + 2 gas; the same with
/// `ORIGIN` returns the caller.
#[test]
fn chainid_is_the_translation_time_constant() {
    let ids = [0u64, 1, 5, 0xffff_ffff, 1 << 32, 1 << 63, u64::MAX];
    let code_of = |op: u8| vec![op, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3];
    let mut cs: Vec<String> = ids
        .iter()
        .map(|&id| {
            translate(&code_of(0x46), &Options { chain_id: Some(id) })
                .unwrap()
                .c
        })
        .collect();
    cs.push(translate(&code_of(0x32), &Options::default()).unwrap().c);
    let lib = host::build("chainid", &cs);
    let caller = U256([0x1234_5678, 0x9abc_def0, 7, 0, 0x8000_0000, 0, 0, 0]);
    let run = |i: usize, code: Vec<u8>| {
        let call = EvmCall {
            code,
            calldata: vec![],
            address: U256::from_u32(0xc0de),
            caller,
            callvalue: U256::ZERO,
            gas_limit: 100_000,
            tree: SparseTree::new(),
            touched: vec![],
        };
        let (w, o, _) = lib.run_words(&mut HostRef, i, &call.input_words());
        (w, o)
    };
    for (i, &id) in ids.iter().enumerate() {
        let (w, o) = run(i, code_of(0x46));
        assert_eq!((w[0], o.gas_used), (1, 15), "chain id {id}");
        assert_eq!(
            o.ret[..32],
            U256::from_u64(id).to_be_bytes(),
            "chain id {id}"
        );
    }
    let (w, o) = run(ids.len(), code_of(0x32));
    assert_eq!((w[0], o.gas_used), (1, 15), "ORIGIN");
    assert_eq!(o.ret[..32], caller.to_be_bytes(), "ORIGIN is CALLER");
}

// ---- the return-data buffer after a call -----------------------------------------------------

/// A model of one template contract (ruling 4): copy `input` into memory from calldata, optionally
/// RETURNDATACOPY before any call (the interpreter's rule), call identity or sha256 (any of the
/// four call opcodes), optionally a second call that fails (which empties the buffer), then
/// RETURNDATASIZE and RETURNDATACOPY(dst, src, len) (EIP-211), store the flags and the size, and
/// RETURN the first 1024 bytes of memory. The model is the EVM's rules written out step by step,
/// the gas included; the translated contract (run on the host) must produce exactly its status,
/// return data and gas_used.
struct Model {
    code: Vec<u8>,
    gas: u64,
    msize_words: u64,
    mem: Vec<u8>,
    halt: Option<Halt>,
}

impl Model {
    fn new() -> Model {
        Model {
            code: Vec::new(),
            gas: 1_000_000,
            msize_words: 0,
            mem: vec![0; 1024],
            halt: None,
        }
    }
    fn op(&mut self, b: u8) {
        self.code.push(b);
        if self.halt.is_none() {
            self.gas -= static_gas(b);
        }
    }
    fn push(&mut self, v: &U256) {
        let be = v.to_be_bytes();
        self.code.push(0x7f);
        self.code.extend_from_slice(&be);
        if self.halt.is_none() {
            self.gas -= 3;
        }
    }
    fn push_u(&mut self, v: u64) {
        self.push(&U256::from_u64(v));
    }
    fn expand(&mut self, end: u64) {
        let w = end.div_ceil(32);
        if w > self.msize_words {
            let cost = |w: u64| 3 * w + w * w / 512;
            self.gas -= cost(w) - cost(self.msize_words);
            self.msize_words = w;
        }
    }
    fn halt(&mut self, h: Halt) {
        if self.halt.is_none() {
            self.halt = Some(h);
        }
    }
}

/// The saturating u32 an operand becomes (`u256_sat_u32`).
fn sat(v: &U256) -> u64 {
    if v.fits_u32() {
        v.low_u32() as u64
    } else {
        u32::MAX as u64
    }
}

#[test]
fn the_return_data_buffer_matches_a_model_after_a_call() {
    let mut r = evm2rv::gen::Rng::new(0x2e7d);
    let mut models: Vec<(Model, Vec<u8>)> = Vec::new();
    let big_src = [
        U256::from_u64(u32::MAX as u64),
        U256::MAX,
        U256::from_u64(1 << 32),
    ];
    for _ in 0..2000 {
        let mut m = Model::new();
        let k = r.range(0, 200);
        let input = r.bytes(k as usize);
        // CALLDATACOPY(0, 0, k)
        m.push_u(k);
        m.push_u(0);
        m.push_u(0);
        m.op(0x37);
        m.gas -= 3 * k.div_ceil(32);
        if k > 0 {
            m.expand(k);
        }
        m.mem[..k as usize].copy_from_slice(&input);
        // RETURNDATACOPY before any call: a zero length is a no-op wherever it points, any other
        // traps (the interpreter's rule, kept until the first call).
        if r.chance(300) {
            let len = if r.chance(700) { 0 } else { r.range(1, 8) };
            let src = if r.chance(500) {
                r.pick(&big_src)
            } else {
                U256::from_u64(r.below(64))
            };
            m.push_u(len);
            m.push(&src);
            m.push_u(r.below(1024));
            m.op(0x3e);
            if len != 0 {
                m.halt(Halt::Trap(0x3e));
            }
        }
        let calls = [0xf1u8, 0xf2, 0xf4, 0xfa];
        let mut buffer: Vec<u8> = Vec::new();
        let mut flags: Vec<u64> = Vec::new();
        let n_calls = if r.chance(400) { 2 } else { 1 };
        for n in 0..n_calls {
            let op = r.pick(&calls);
            let addr = if r.chance(500) { 4u64 } else { 2 };
            let ret_off = 256 + r.below(64);
            let ret_len = r.range(0, 64);
            // The second call fails (gas 0 requested), emptying the buffer.
            let req = if n == 1 {
                U256::ZERO
            } else {
                match r.below(3) {
                    0 => U256::MAX,
                    1 => U256::from_u64(r.range(200, 5000)),
                    _ => U256::from_u64(r.range(0, 100)),
                }
            };
            m.push_u(ret_len);
            m.push_u(ret_off);
            m.push_u(k);
            m.push_u(0);
            if matches!(op, 0xf1 | 0xf2) {
                m.push_u(0);
            }
            m.push_u(addr);
            m.push(&req);
            m.op(op);
            if m.halt.is_some() {
                continue;
            }
            // 100 (warm), the regions' expansion, then all but one 64th.
            m.gas -= 100;
            if k > 0 {
                m.expand(k);
            }
            if ret_len > 0 {
                m.expand(ret_off + ret_len);
            }
            let left = m.gas;
            let pass = (left - left / 64).min(if req.fits_u32() {
                req.low_u32() as u64
            } else {
                u64::MAX
            });
            let (cost, out) = if addr == 4 {
                (15 + 3 * k.div_ceil(32), m.mem[..k as usize].to_vec())
            } else {
                (
                    60 + 12 * k.div_ceil(32),
                    rand_zkvm::sha256::sha256(&m.mem[..k as usize]).to_vec(),
                )
            };
            if cost <= pass {
                m.gas -= cost;
                let c = (ret_len as usize).min(out.len());
                let at = ret_off as usize;
                m.mem[at..at + c].copy_from_slice(&out[..c]);
                buffer = out;
                flags.push(1);
            } else {
                m.gas -= pass;
                buffer.clear();
                flags.push(0);
            }
            // The flag: kept on the stack for the store below.
        }
        // RETURNDATASIZE, then RETURNDATACOPY(dst, src, len) over the buffer (EIP-211).
        m.op(0x3d);
        let dst = 512 + r.below(256);
        let (src, len) = match r.below(6) {
            0 => (U256::from_u64(buffer.len() as u64 + r.range(1, 8)), 0), // zero length past the end
            1 => (r.pick(&big_src), r.below(3)),                           // a saturated source
            2 => (U256::from_u64(r.below(40)), r.range(1, 40)),            // may run past the end
            _ => {
                let s = r.below(buffer.len() as u64 + 1);
                (U256::from_u64(s), r.below(buffer.len() as u64 - s + 1))
            }
        };
        m.push_u(len);
        m.push(&src);
        m.push_u(dst);
        m.op(0x3e);
        if m.halt.is_none() {
            let s = sat(&src);
            if s + len > buffer.len() as u64 || !src.fits_u32() {
                m.halt(Halt::OutOfBounds);
            } else {
                m.gas -= 3 * len.div_ceil(32);
                if len > 0 {
                    m.expand(dst + len);
                }
                let (d, s) = (dst as usize, s as usize);
                m.mem[d..d + len as usize].copy_from_slice(&buffer[s..s + len as usize]);
            }
        }
        // MSTORE the size at 800, each flag at 832, 864; RETURN(0, 1024).
        m.push_u(800);
        m.op(0x52);
        if m.halt.is_none() {
            m.expand(832);
            m.mem[800..832].copy_from_slice(&U256::from_u64(buffer.len() as u64).to_be_bytes());
        }
        for (j, f) in flags.iter().enumerate().rev() {
            let at = 832 + 32 * j as u64;
            m.push_u(at);
            m.op(0x52);
            if m.halt.is_none() {
                m.expand(at + 32);
                m.mem[at as usize..at as usize + 32]
                    .copy_from_slice(&U256::from_u64(*f).to_be_bytes());
            }
        }
        m.push_u(1024);
        m.push_u(0);
        m.op(0xf3);
        if m.halt.is_none() {
            m.expand(1024);
            m.halt(Halt::Return);
        }
        models.push((m, input));
    }
    let cs: Vec<String> = models
        .iter()
        .map(|(m, _)| translate(&m.code, &Options::default()).unwrap().c)
        .collect();
    let lib = host::build("returndata-model", &cs);
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    for (i, (m, input)) in models.iter().enumerate() {
        let call = EvmCall {
            code: m.code.clone(),
            calldata: input.clone(),
            address: U256::from_u32(0xc0de),
            caller: U256::from_u32(0xca11),
            callvalue: U256::ZERO,
            gas_limit: 1_000_000,
            tree: SparseTree::new(),
            touched: vec![],
        };
        let (w, o, _) = lib.run_words(&mut HostRef, i, &call.input_words());
        let halt = m.halt.expect("every model halts");
        *tally.entry(format!("{halt:?}")).or_default() += 1;
        let ctx = || format!("model {i}: code {}", hex::encode(&m.code));
        if halt == Halt::Return {
            assert_eq!(w[0], 1, "{}", ctx());
            assert_eq!(o.gas_used, 1_000_000 - m.gas, "{}", ctx());
            assert_eq!(&o.ret[..o.ret_len], &m.mem[..], "{}", ctx());
        } else {
            assert_eq!((w[0], o.gas_used), (2, 1_000_000), "{}: {halt:?}", ctx());
        }
    }
    eprintln!("return-data model: {} contracts, {tally:?}", models.len());
}

// ---- the real pipeline ----------------------------------------------------------------------

/// The sample: the first corpus cases (by seed) that make no call, keep their code short and
/// finish in the interpreter within a small gas budget, with loops among them — at least 50, at
/// least 10 with loops.
fn sample() -> &'static Vec<Case> {
    static S: OnceLock<Vec<Case>> = OnceLock::new();
    S.get_or_init(|| {
        let mut ws = Box::new(Workspace::ZERO);
        let mut out: Vec<Case> = Vec::new();
        let mut with_loops = 0;
        for seed in 0.. {
            let c = case(seed);
            if c.tags.call_byte || c.code.len() > 700 || c.touched.len() > 3 {
                continue;
            }
            let (_, _, o) = interpret(&c, &mut ws);
            if o.gas_used > 60_000 && o.status() != 2 {
                continue;
            }
            if c.tags.loops > 0 {
                with_loops += 1;
            } else if out.len() >= 50 {
                continue;
            }
            out.push(c);
            if out.len() >= 56 && with_loops >= 12 {
                break;
            }
        }
        out
    })
}

/// One image for the whole sample: the evm2rv CLI writes the shim crate for one of the cases, and
/// its `contract.c` becomes every sampled case's translation (`evm_entry` renamed per case) with an
/// `evm_entry` that picks the one whose code the input vector carries (by length and FNV-1a hash:
/// a table of the codes themselves would not fit the loader's data prologue). The shim, its
/// build.rs, the runtime, the flags, rand-guest build and rand-guest run are the real ones; only
/// the dispatch is the test's.
fn sample_c(cases: &[Case]) -> String {
    let fnv = |b: &[u8]| {
        b.iter().fold(0x811c_9dc5u32, |h, &x| {
            (h ^ x as u32).wrapping_mul(0x0100_0193)
        })
    };
    let mut keys: Vec<(usize, u32)> = cases
        .iter()
        .map(|c| (c.code.len(), fnv(&c.interp_code())))
        .collect();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), cases.len(), "two sampled codes share a key");
    let mut s = String::from("#include <stdint.h>\n#include \"evm_rt.h\"\n\n");
    for (i, c) in cases.iter().enumerate() {
        let t = translate_case(c)
            .replace("void evm_entry(void)", &format!("void evm_entry_{i}(void)"))
            .replace("#include <stdint.h>\n#include \"evm_rt.h\"\n", "");
        s.push_str(&t);
    }
    s.push_str("void evm_entry(void);\nvoid evm_entry(void) {\n    uint32_t h = 0x811c9dc5u;\n    for (uint32_t i = 0; i < evm_code_len; i++) h = (h ^ evm_code[i]) * 0x01000193u;\n");
    for (i, c) in cases.iter().enumerate() {
        s.push_str(&format!(
            "    if (evm_code_len == {}u && h == {:#x}u) evm_entry_{i}();\n",
            c.code.len(),
            fnv(&c.interp_code())
        ));
    }
    s.push_str("    evm_halt(EVM_HALT_INVALID, 0);\n}\n");
    s
}

/// Ruling 1: a sample of the corpus through `evm2rv`, `rand-guest build` and `rand-guest run`
/// (the default image: the eight public words; the emit-outcome image: the status, the digest's
/// first five words, the halt and gas_used). The interpreter's words must match on every case.
#[test]
fn a_sample_runs_through_the_real_pipeline() {
    let cases = sample();
    let with_loops = cases.iter().filter(|c| c.tags.loops > 0).count();
    assert!(
        cases.len() >= 50 && with_loops >= 10,
        "{} / {with_loops}",
        cases.len()
    );
    let base = root().join("evm2rv/target/fuzz-pipeline");
    std::fs::create_dir_all(&base).unwrap();
    let t = Instant::now();
    let mut images = Vec::new();
    for (sub, outcome) in [("plain", false), ("outcome", true)] {
        let dir = base.join(sub);
        let first = base.join("first.bin");
        // (The CLI takes no --chain-id through `build_shim`: the first case without CHAINID.)
        let cli = cases.iter().find(|c| c.chain_id.is_none()).unwrap();
        std::fs::write(&first, &cli.code).unwrap();
        // The CLI writes the crate (and a single-contract contract.c, which the build below
        // replaces); `build_shim` runs evm2rv, patches emit-outcome in, and builds.
        let _ = build_shim(&first, &dir, &format!("fuzz-sample-{sub}"), outcome);
        std::fs::write(dir.join("contract.c"), sample_c(cases)).unwrap();
        let o = common::scrubbed(common::rand_guest())
            .arg("build")
            .arg(&dir)
            .arg("--out")
            .arg(dir.join("image.bin"))
            .args(["--max-words", "65535"])
            .output()
            .unwrap();
        assert!(
            o.status.success(),
            "rand-guest build: {}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        eprintln!(
            "sample {sub}: {}",
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .find(|l| l.starts_with("wrote"))
                .unwrap_or("")
        );
        images.push(dir.join("image.bin"));
    }
    let t_build = t.elapsed();
    let mut ws = Box::new(Workspace::ZERO);
    let mut ran = 0;
    let mut ran_loops = 0;
    let mut too_long = 0;
    let t = Instant::now();
    for c in cases {
        let (words, want, o) = interpret(c, &mut ws);
        if run_out_of_cycles(&images[0], &words).is_some() {
            too_long += 1;
            continue;
        }
        let got = run_words(&images[0], &words);
        assert_eq!(got, want, "seed {}: the eight public words", c.seed);
        let dbg = run_words(&images[1], &words);
        assert_eq!(
            dbg[..6],
            want[..6],
            "seed {}: status and digest words 0..4",
            c.seed
        );
        assert_eq!(dbg[7] as u64, o.gas_used, "seed {}: gas_used", c.seed);
        assert!(
            (dbg[6] & 0xff) != HALT_INVALID || matches!(o.halt, Halt::Invalid),
            "seed {}: dbg[6] reports EVM_HALT_INVALID ({:#x}) but the interpreter's halt is {:?}",
            c.seed,
            dbg[6],
            o.halt,
        );
        ran += 1;
        ran_loops += (c.tags.loops > 0) as usize;
    }
    eprintln!(
        "sample: {ran} cases ({ran_loops} with loops) through rand-guest run, {too_long} past the 2^20 cycles; build {:.1}s, runs {:.1}s",
        t_build.as_secs_f64(),
        t.elapsed().as_secs_f64()
    );
    assert!(
        ran >= 50 && ran_loops >= 10,
        "{ran} ran, {ran_loops} with loops"
    );
}

fn run_words(image: &Path, words: &[u32]) -> [u32; 8] {
    common::run(image, words).0
}
