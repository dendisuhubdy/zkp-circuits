//! The post-Shanghai opcodes end to end: real `solc` 0.8.37 output for `--evm-version cancun` and
//! `--evm-version osaka`, translated by `evm2rv` and run on the emulator against the interpreter,
//! exactly as `tests/parity.rs` holds the ERC-20.
//!
//! * `guests-compiled/evm/contracts/cancun.runtime.hex` (`Cancun.sol`): a counter behind a
//!   reentrancy lock in **transient storage** (`uint256 transient locked`, so `TLOAD`/`TSTORE`) and
//!   a `bytes.concat` that solc lowers to **`MCOPY`**.
//! * `guests-compiled/evm/contracts/osaka.runtime.hex` (`Osaka.sol`): `lz(x)`, an inline-assembly
//!   **`CLZ`**.
//!
//! For every vector, both stages' default images publish the interpreter's eight words (the
//! native oracle `EvmCall::expected` and the committed `evm.bin` on the same emulator), and their
//! `emit-outcome` builds report the interpreter's halt and `gas_used`. The bytecode is decoded by
//! `blocks` with the new opcodes as ordinary ops, and `warnings` names nothing outside solc's CBOR
//! metadata trailer (which is never executed, and whose bytes may happen to decode as a trapping
//! opcode): nothing in either contract's code traps.
//!
//! `build.sh` next to the fixtures re-runs solc and diffs against the committed hex.

mod common;

use std::path::PathBuf;
use std::sync::OnceLock;

use common::{build_shim, encoded_halt, root, run, run_tier, STAGES};
use evm2rv::blocks::{blocks, warnings};
use evm2rv::emit::Stage;
use evm_core::interp::Halt;
use evm_core::u256::U256;
use rand_zkvm::evm::{abi_call, selector, EvmCall, SparseTree, ALICE, TOKEN};

#[derive(Clone, Copy)]
enum Contract {
    Cancun,
    Osaka,
}

impl Contract {
    fn name(self) -> &'static str {
        match self {
            Contract::Cancun => "cancun",
            Contract::Osaka => "osaka",
        }
    }

    fn hex_path(self) -> PathBuf {
        root().join(format!(
            "guests-compiled/evm/contracts/{}.runtime.hex",
            self.name()
        ))
    }

    fn code(self) -> Vec<u8> {
        hex::decode(std::fs::read_to_string(self.hex_path()).unwrap().trim()).unwrap()
    }
}

struct Images {
    plain: PathBuf,
    outcome: PathBuf,
}

fn images(c: Contract, stage: Stage) -> &'static Images {
    static CELLS: [OnceLock<Images>; 4] = [const { OnceLock::new() }; 4];
    let k = (c as usize) * 2 + matches!(stage, Stage::Two) as usize;
    CELLS[k].get_or_init(|| {
        let base = root().join("evm2rv/target/parity");
        let dir = format!("{}-stage{}", c.name(), k % 2 + 1);
        let name = format!("{}-evm2rv", c.name());
        let (plain, _) = build_shim(&c.hex_path(), &base.join(&dir), &name, false, stage);
        let (outcome, _) =
            build_shim(&c.hex_path(), &base.join(format!("{dir}-outcome")), &name, true, stage);
        Images { plain, outcome }
    })
}

/// The interpreter (natively and as `evm.bin`) against both stages' images, as `parity.rs`'s
/// `check`. Returns the oracle's `gas_used`.
fn check(c: Contract, name: &str, call: &EvmCall, want_status: u32) -> u64 {
    let words = call.input_words();
    let (want, o, _post) = call.expected();
    assert_eq!(want[0], want_status, "{name}: the oracle's own status");
    let (interp, interp_cycles, _) = run_tier(&root().join("guests-compiled/bin/evm.bin"), &words);
    assert_eq!(interp, want, "{name}: evm.bin disagrees with the native interpreter");
    let mut cycles = [0usize; 2];
    for (k, stage) in STAGES.into_iter().enumerate() {
        let Images { plain, outcome } = images(c, stage);
        let (got, cy, _) = run_tier(plain, &words);
        assert_eq!(got, want, "{name} ({stage:?}): the eight public words");
        let (dbg, _) = run(outcome, &words);
        assert_eq!(dbg[..6], want[..6], "{name} ({stage:?}): status and digest words");
        assert_eq!(dbg[6], encoded_halt(&o), "{name} ({stage:?}): halt ({:?})", o.halt);
        assert_eq!(dbg[7] as u64, o.gas_used, "{name} ({stage:?}): gas_used");
        cycles[k] = cy;
    }
    eprintln!(
        "{name}: status {} halt {:?} gas_used {} — cycles: interpreter {interp_cycles}, stage one {}, stage two {}",
        want[0], o.halt, o.gas_used, cycles[0], cycles[1]
    );
    o.gas_used
}

/// `bump(bytes)`'s calldata: the ABI head (offset 0x20), the length, the bytes zero-padded.
fn bump_calldata(data: &[u8]) -> Vec<u8> {
    let mut cd = selector("bump(bytes)").to_vec();
    cd.extend_from_slice(&U256::from_u32(0x20).to_be_bytes());
    cd.extend_from_slice(&U256::from_u32(data.len() as u32).to_be_bytes());
    cd.extend_from_slice(data);
    cd.resize(cd.len() + (32 - data.len() % 32) % 32, 0);
    cd
}

/// A call to the Cancun contract with the counter (storage slot 0) at `counter`, witnessed.
fn cancun_call(calldata: Vec<u8>, counter: u32) -> EvmCall {
    let mut tree = SparseTree::new();
    if counter != 0 {
        tree.insert(U256::ZERO, U256::from_u32(counter));
    }
    EvmCall {
        code: Contract::Cancun.code(),
        calldata,
        address: TOKEN,
        caller: ALICE,
        callvalue: U256::ZERO,
        gas_limit: 1_000_000,
        tree,
        touched: vec![U256::ZERO],
    }
}

fn osaka_call(x: U256) -> EvmCall {
    EvmCall {
        code: Contract::Osaka.code(),
        calldata: abi_call("lz(uint256)", &[x]),
        address: TOKEN,
        caller: ALICE,
        callvalue: U256::ZERO,
        gas_limit: 100_000,
        tree: SparseTree::new(),
        touched: vec![],
    }
}

/// The warnings in the code proper, before the CBOR metadata trailer (its length is the last two
/// bytes, big-endian, and excludes them).
fn code_warnings(code: &[u8]) -> Vec<evm2rv::blocks::Warning> {
    let n = code.len();
    let trailer = u16::from_be_bytes([code[n - 2], code[n - 1]]) as usize + 2;
    warnings(code)
        .into_iter()
        .filter(|w| match w {
            evm2rv::blocks::Warning::Trap { pc, .. } | evm2rv::blocks::Warning::Call { pc, .. } => {
                *pc < n - trailer
            }
            _ => true,
        })
        .collect()
}

fn has(code: &[u8], op: u8) -> usize {
    blocks(code)
        .iter()
        .flat_map(|b| b.ops.iter())
        .filter(|o| o.opcode == op)
        .count()
}

#[test]
fn the_fixtures_use_the_new_opcodes_and_nothing_traps() {
    let cancun = Contract::Cancun.code();
    assert_eq!(cancun.len(), 657);
    assert_eq!(has(&cancun, 0x5e), 2, "MCOPY");
    assert_eq!(has(&cancun, 0x5c), 2, "TLOAD");
    assert_eq!(has(&cancun, 0x5d), 2, "TSTORE");
    assert!(code_warnings(&cancun).is_empty(), "{:?}", code_warnings(&cancun));
    let osaka = Contract::Osaka.code();
    assert_eq!(has(&osaka, 0x1e), 1, "CLZ");
    assert!(code_warnings(&osaka).is_empty(), "{:?}", code_warnings(&osaka));
}

/// `bump` under the lock: TLOAD/TSTORE of the transient slot, the counter's SLOAD/SSTORE, and
/// `bytes.concat`'s MCOPYs — a short string (one word each way), 40 bytes (two words, an
/// unaligned tail) and nothing at all.
#[test]
fn bump_matches_the_interpreter() {
    check(Contract::Cancun, "bump 41, 5 bytes", &cancun_call(bump_calldata(b"hello"), 41), 1);
    let forty: Vec<u8> = (1..=40).collect();
    check(Contract::Cancun, "bump 0, 40 bytes", &cancun_call(bump_calldata(&forty), 0), 1);
    check(Contract::Cancun, "bump 7, empty", &cancun_call(bump_calldata(&[]), 7), 1);
}

/// `isLocked()` reads the transient slot in a fresh call: empty, so false. `counter()` reads
/// storage only.
#[test]
fn views_match_the_interpreter() {
    let mut locked = cancun_call(abi_call("isLocked()", &[]), 0);
    locked.touched = vec![];
    let (out, o, _) = locked.expected();
    assert_eq!((out[0], o.ret_len), (1, 32));
    assert!(o.ret[..32].iter().all(|&b| b == 0), "a fresh call is unlocked");
    check(Contract::Cancun, "isLocked", &locked, 1);
    check(Contract::Cancun, "counter", &cancun_call(abi_call("counter()", &[]), 9), 1);
}

/// A non-zero `callvalue` to the non-payable `bump` reverts before the lock; malformed calldata
/// (a length past the data) reverts in the decoder.
#[test]
fn reverts_match_the_interpreter() {
    let mut paid = cancun_call(bump_calldata(b"x"), 1);
    paid.callvalue = U256::ONE;
    check(Contract::Cancun, "bump with value", &paid, 0);
    let mut bad = bump_calldata(b"x");
    bad[4 + 32 + 31] = 0xff;
    check(Contract::Cancun, "bump, length past the data", &cancun_call(bad, 1), 0);
}

/// Out of gas at limits around `bump`'s own use, including one short — the last charge fails — and
/// the exact amount.
#[test]
fn out_of_gas_matches_the_interpreter() {
    let call = || cancun_call(bump_calldata(&(1..=40).collect::<Vec<u8>>()), 3);
    let used = call().expected().1.gas_used;
    for gas in [50u64, 300, used - 1] {
        let mut c = call();
        c.gas_limit = gas;
        assert_eq!(c.expected().1.halt, Halt::OutOfGas, "gas {gas}");
        check(Contract::Cancun, &format!("bump out of gas at {gas}"), &c, 2);
    }
    let mut exact = call();
    exact.gas_limit = used;
    check(Contract::Cancun, &format!("bump at exactly {used}"), &exact, 1);
}

/// `lz(x)` through CLZ: zero is 256, the top bit set is 0, and values between.
#[test]
fn clz_matches_the_interpreter() {
    let mut top = U256::ZERO;
    top.0[7] = 0x8000_0000;
    for (x, want) in [
        (U256::ZERO, 256u32),
        (U256::ONE, 255),
        (U256::from_u32(0x1_0000), 239),
        (top, 0),
        (U256::MAX, 0),
    ] {
        let call = osaka_call(x);
        let (_, o, _) = call.expected();
        assert_eq!(&o.ret[..32], &U256::from_u32(want).to_be_bytes(), "lz({x:?})");
        check(Contract::Osaka, &format!("lz = {want}"), &call, 1);
    }
}
