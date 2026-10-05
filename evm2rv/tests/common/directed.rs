//! Directed parity cases: a hand-assembled bytecode with its pinned `(status, gas_used)` and, for
//! a success, its return data, run through the interpreter (the oracle) and through both stages of
//! the translation built for the host (`common/host.rs`). The three must agree on the eight public
//! words and `gas_used`, and the oracle must give the pins — so a pin that is wrong fails here on
//! its own, and a translation that disagrees with the interpreter fails on the case's name.
//!
//! As in `tests/opcodes.rs`, each case also runs a second time under stage two with every push
//! laundered ([`launder`]): stage two folds constant operands at translation, so without that twin
//! an edge would be exercised by the interpreter's own `U256` and never reach `u256.c`. The twin
//! is held to the interpreter over the same laundered code (the eight words, `gas_used`) and to
//! the case's status; its return data is the pin's unless the case says it moves (`CODECOPY`,
//! `CODESIZE`, `PC`, `GAS`, `MSIZE` read things laundering changes).

use evm2rv::emit::{translate, Options, Stage};
use evm_core::abi::{run_call_with, Workspace};
use evm_core::u256::U256;
use rand_zkvm::evm::{EvmCall, HostRef, SparseTree};

use super::{host, launder, STAGES};

/// PUSH0, MSTORE, PUSH1 32, PUSH0, RETURN: the top of the stack returned as one word. 13 gas on
/// untouched memory (2 + 3 + 3 for the first word + 3 + 2 + 0), 10 once memory holds a word.
pub const TAIL: &str = "5f5260205ff3";

/// One case. Build one with [`Directed::new`] and the setters.
#[derive(Clone, Debug)]
pub struct Directed {
    pub name: String,
    pub code: Vec<u8>,
    pub calldata: Vec<u8>,
    pub callvalue: u64,
    pub gas_limit: u64,
    /// The pre-state: `(slot, value)` pairs in the storage tree.
    pub storage: Vec<(u64, u64)>,
    /// The slots a witness is supplied for.
    pub touched: Vec<U256>,
    pub status: u32,
    pub gas: u64,
    /// The exact return data, when pinned.
    pub ret: Option<Vec<u8>>,
    /// The number of logs, when pinned.
    pub logs: Option<usize>,
    /// Run the laundered twin (off for a case laundering would change: a tight gas limit, the
    /// stack limit, a truncated push).
    pub launder: bool,
    /// The laundered twin returns the pinned data too.
    pub ret_stable: bool,
}

/// `hex`, spaces allowed, decoded.
pub fn bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex.replace(' ', "")).unwrap_or_else(|e| panic!("{hex}: {e}"))
}

/// A 32-byte word with `v` in its low bytes.
pub fn word(v: u64) -> Vec<u8> {
    U256::from_u64(v).to_be_bytes().to_vec()
}

/// The all-ones word.
pub fn max_word() -> Vec<u8> {
    vec![0xff; 32]
}

impl Directed {
    /// A case over `code` (hex, spaces allowed), no calldata, a 100 000 gas limit, with its
    /// expected status and `gas_used`.
    pub fn new(name: impl Into<String>, code: &str, status: u32, gas: u64) -> Directed {
        Directed {
            name: name.into(),
            code: bytes(code),
            calldata: vec![],
            callvalue: 0,
            gas_limit: 100_000,
            storage: vec![],
            touched: vec![],
            status,
            gas,
            ret: None,
            logs: None,
            launder: true,
            ret_stable: true,
        }
    }
    pub fn code_bytes(mut self, code: Vec<u8>) -> Directed {
        self.code = code;
        self
    }
    pub fn calldata(mut self, hex: &str) -> Directed {
        self.calldata = bytes(hex);
        self
    }
    pub fn calldata_bytes(mut self, b: Vec<u8>) -> Directed {
        self.calldata = b;
        self
    }
    pub fn callvalue(mut self, v: u64) -> Directed {
        self.callvalue = v;
        self
    }
    /// A gas limit other than 100 000: the laundered twin is skipped (its pushes cost more).
    pub fn gas_limit(mut self, g: u64) -> Directed {
        self.gas_limit = g;
        self.launder = false;
        self
    }
    pub fn storage(mut self, slot: u64, value: u64) -> Directed {
        self.storage.push((slot, value));
        self
    }
    pub fn touched(mut self, slot: u64) -> Directed {
        self.touched.push(U256::from_u64(slot));
        self
    }
    /// A witness for a full-word slot, given as limbs.
    pub fn touched_word(mut self, limbs: [u32; 8]) -> Directed {
        self.touched.push(U256(limbs));
        self
    }
    /// The returned word: `v` in the low bytes of one 32-byte word.
    pub fn ret_word(mut self, v: u64) -> Directed {
        self.ret = Some(word(v));
        self
    }
    /// The return data, as hex.
    pub fn ret_hex(mut self, hex: &str) -> Directed {
        self.ret = Some(bytes(hex));
        self
    }
    pub fn ret_bytes(mut self, b: Vec<u8>) -> Directed {
        self.ret = Some(b);
        self
    }
    pub fn logs(mut self, n: usize) -> Directed {
        self.logs = Some(n);
        self
    }
    pub fn no_launder(mut self) -> Directed {
        self.launder = false;
        self
    }
    /// The laundered twin's return data is not the pin's.
    pub fn ret_moves(mut self) -> Directed {
        self.ret_stable = false;
        self
    }

    fn call(&self, code: Vec<u8>) -> EvmCall {
        let mut tree = SparseTree::new();
        for &(s, v) in &self.storage {
            tree.insert(U256::from_u64(s), U256::from_u64(v));
        }
        EvmCall {
            code,
            calldata: self.calldata.clone(),
            address: U256::from_u32(0xc0de),
            caller: U256::from_u32(0xca11),
            callvalue: U256::from_u64(self.callvalue),
            gas_limit: self.gas_limit,
            tree,
            touched: self.touched.clone(),
        }
    }
}

fn opts(stage: Stage) -> Options {
    Options {
        chain_id: None,
        stage,
    }
}

/// Every case through the interpreter and both stages (and the laundered twin under stage two),
/// in one host library named `lib_name` (unique per test, so the cache keys do not collide).
pub fn run_directed(lib_name: &str, cases: &[Directed]) {
    assert!(!cases.is_empty());
    // Each case at stage one, then at stage two, then every laundering twin at stage two.
    let mut cs: Vec<String> = STAGES
        .iter()
        .flat_map(|&stage| {
            cases
                .iter()
                .map(move |c| translate(&c.code, &opts(stage)).unwrap().c)
        })
        .collect();
    let laundered: Vec<Option<Vec<u8>>> = cases
        .iter()
        .map(|c| c.launder.then(|| launder(&c.code)))
        .collect();
    let mut twin_index = Vec::with_capacity(cases.len());
    for l in &laundered {
        match l {
            Some(code) => {
                twin_index.push(Some(cs.len()));
                cs.push(translate(code, &opts(Stage::Two)).unwrap().c);
            }
            None => twin_index.push(None),
        }
    }
    let lib = host::build(lib_name, &cs);
    let mut ws = Box::new(Workspace::ZERO);
    let mut table = String::new();
    let n = cases.len();
    for (i, c) in cases.iter().enumerate() {
        let call = c.call(c.code.clone());
        let words = call.input_words();
        let (want, o) = run_call_with(
            &mut HostRef,
            &mut ws,
            |k| words[k as usize],
            words.len() as u32,
        );
        let hexret = hex::encode(&o.ret[..o.ret_len]);
        table.push_str(&format!(
            "{}: status {} halt {:?} gas {} logs {} ret {hexret}\n",
            c.name, want[0], o.halt, o.gas_used, o.n_logs
        ));
        // The oracle gives the pins.
        assert_eq!(want[0], c.status, "{}: status (interpreter)", c.name);
        assert_eq!(o.gas_used, c.gas, "{}: gas_used pin (interpreter)", c.name);
        if let Some(ret) = &c.ret {
            assert_eq!(
                hexret,
                hex::encode(ret),
                "{}: return data pin (interpreter)",
                c.name
            );
        }
        if let Some(logs) = c.logs {
            assert_eq!(o.n_logs, logs, "{}: logs pin (interpreter)", c.name);
        }
        // Both stages agree with it.
        for (k, stage) in STAGES.iter().enumerate() {
            let (got, t, _) = lib.run_words(&mut HostRef, k * n + i, &words);
            assert_eq!(got, want, "{} ({stage:?}): the eight words", c.name);
            assert_eq!(t.gas_used, o.gas_used, "{} ({stage:?}): gas_used", c.name);
            assert_eq!(
                &t.ret[..t.ret_len],
                &o.ret[..o.ret_len],
                "{} ({stage:?}): return data",
                c.name
            );
            assert_eq!(t.n_logs, o.n_logs, "{} ({stage:?}): logs", c.name);
            for (a, b) in t.logs[..t.n_logs].iter().zip(&o.logs[..o.n_logs]) {
                assert_eq!(a.n_topics, b.n_topics, "{} ({stage:?}): a log's topics", c.name);
                assert_eq!(a.topics, b.topics, "{} ({stage:?}): a log's topics", c.name);
            }
        }
        // The laundered twin, against the interpreter over the laundered code.
        let (Some(code), Some(idx)) = (&laundered[i], twin_index[i]) else {
            continue;
        };
        let call = c.call(code.clone());
        let words = call.input_words();
        let (want, o) = run_call_with(
            &mut HostRef,
            &mut ws,
            |k| words[k as usize],
            words.len() as u32,
        );
        let (got, t, _) = lib.run_words(&mut HostRef, idx, &words);
        assert_eq!(got, want, "{} (laundered, Two): the eight words", c.name);
        assert_eq!(
            t.gas_used, o.gas_used,
            "{} (laundered, Two): gas_used",
            c.name
        );
        assert_eq!(want[0], c.status, "{} (laundered): status", c.name);
        if let (Some(ret), true) = (&c.ret, c.ret_stable) {
            assert_eq!(
                hex::encode(&o.ret[..o.ret_len]),
                hex::encode(ret),
                "{} (laundered): return data",
                c.name
            );
        }
    }
    eprintln!("{table}");
}
