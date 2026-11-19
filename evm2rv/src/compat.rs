//! The EVM compatibility table (ZKVM-121): what each of the 256 opcode bytes and each precompile
//! address does on the two paths a contract can take into the zkVM, and how its gas compares with
//! mainnet's.
//!
//! - **the interpreter**: `evm-core` (`guests-compiled/evm-core/src/interp.rs`), the program in
//!   `guests-compiled/bin/evm.bin`;
//! - **a translation**: this crate's output over `evm-rt`, at either stage.
//!
//! The table is data ([`opcode`], [`precompile`], [`CAPS`]); [`markdown`] renders it as
//! `evm2rv/COMPATIBILITY.md`, and [`check`] is the pre-flight scan behind `evm2rv check`.
//! Nothing here is read by the translator: it is a description, and `tests/compat.rs` is what
//! holds it to the code. That test runs every opcode byte through the interpreter and through a
//! translation at both stages and compares the halt with this table, compares the static gas with
//! `interp.rs`'s, runs the gas rules marked [`Gas::Differs`] and calls every precompile address
//! listed. The committed Markdown is compared with [`markdown`]'s output.

use std::fmt::Write as _;

use evm_core::interp::{
    MAX_CALLDATA_BYTES, MAX_CODE_BYTES, MAX_LOGS, MAX_MEMORY_BYTES, MAX_RETURN_BYTES,
    MAX_TRANSIENT_SLOTS, STACK_LIMIT,
};
use evm_core::storage::MAX_WITNESSES;

use crate::blocks;
use crate::emit::mnemonic;

/// What one path does with an opcode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Behaviour {
    /// Implemented: it runs, whatever its operands (it can still halt for the EVM's own reasons:
    /// a stack fault, a bad jump, out of gas, a cap).
    Runs,
    /// Implemented for some operands only; with any other it halts `Trap(op)`. The condition is
    /// the entry's [`Opcode::note`].
    RunsIf,
    /// Not implemented: always halts `Trap(op)` (status 2, the whole gas limit consumed).
    Traps,
    /// `0xfe`, the EVM's designated invalid opcode: halts `Invalid` (status 2).
    Invalid,
    /// A byte no accepted fork assigns an opcode to: halts `Trap(op)` (status 2), which is what
    /// an undefined opcode does on mainnet too (an exceptional halt consuming all gas).
    Undefined,
}

impl Behaviour {
    fn word(self) -> &'static str {
        match self {
            Behaviour::Runs => "runs",
            Behaviour::RunsIf => "runs if",
            Behaviour::Traps => "traps",
            Behaviour::Invalid => "invalid",
            Behaviour::Undefined => "undefined",
        }
    }
}

/// How an opcode's gas compares with mainnet's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gas {
    /// The same figure and the same rule as mainnet.
    Same,
    /// A different rule; the entry's `gas_rule` says how.
    Differs,
    /// Nothing is charged because nothing runs (a trap, `INVALID`, an undefined byte): the halt
    /// consumes the whole limit, as an exceptional halt does on mainnet.
    None,
}

/// One opcode byte's row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opcode {
    pub byte: u8,
    /// The mnemonic; `None` for an undefined byte.
    pub name: Option<String>,
    pub interp: Behaviour,
    pub xlat: Behaviour,
    /// Why it traps, the condition of a [`Behaviour::RunsIf`], or how the two paths differ.
    /// Empty when there is nothing to say.
    pub note: &'static str,
    /// The part of the cost that does not depend on the operands (`blocks::static_gas`, which
    /// `tests/blocks.rs` holds equal to `interp.rs`'s table on every byte the interpreter runs).
    pub static_gas: u64,
    pub gas: Gas,
    /// The whole gas rule in words, and for [`Gas::Differs`] what mainnet does instead.
    pub gas_rule: String,
}

/// The opcode's mnemonic. `emit::mnemonic`'s, except for the two blob opcodes: that function
/// names the ops in the emitted C's comments and has no name for `BLOBHASH` or `BLOBBASEFEE`
/// (they print as `UNDEFINED_0x49`/`0x4a` there), though both are opcodes the code traps on by
/// name (`blocks::BLOCK_CTX_TRAPS`).
pub fn name(op: u8) -> String {
    match op {
        0x49 => "BLOBHASH".into(),
        0x4a => "BLOBBASEFEE".into(),
        _ => mnemonic(op),
    }
}

// The dynamic figures the rules below quote. `interp.rs` keeps its `G_*` constants private, so
// these are a second copy; `tests/compat.rs` runs each rule and checks the gas used against them.
/// `EXP`: 10, plus this for every byte of the exponent.
pub const EXP_BASE: u64 = 10;
pub const EXP_PER_BYTE: u64 = 50;
/// `KECCAK256`: 30, plus 6 for every 32-byte word hashed.
pub const KECCAK_BASE: u64 = 30;
pub const KECCAK_PER_WORD: u64 = 6;
/// `SLOAD`, every time.
pub const SLOAD: u64 = 2_100;
/// `SSTORE` of a non-zero value to a slot whose current value is zero.
pub const SSTORE_SET: u64 = 20_000;
/// Every other `SSTORE`.
pub const SSTORE_RESET: u64 = 2_900;
/// `TLOAD` and `TSTORE`.
pub const TRANSIENT: u64 = 100;
/// `LOGn`: 375, plus 375 a topic, plus 8 a byte of data.
pub const LOG_BASE: u64 = 375;
pub const LOG_PER_TOPIC: u64 = 375;
pub const LOG_PER_BYTE: u64 = 8;
/// The copies: 3 for every 32-byte word copied, on top of the static 3.
pub const COPY_PER_WORD: u64 = 3;
/// A call to a precompile, before the precompile's own gas (`evm_rt.h`'s `EVM_CALL_WARM_ACCESS`).
pub const CALL_ACCESS: u64 = 100;

/// Memory expansion to `words` 32-byte words: `3w + w²/512`.
pub const fn memory_cost(words: u64) -> u64 {
    3 * words + words * words / 512
}

const MEM: &str = "memory expansion";
const NO_BLOCK_CTX: &str =
    "block context: no public value binds a block fact to the proof, so a prover could supply any";
const NO_ACCOUNTS: &str =
    "one contract per proof: there is no account state beyond this contract's storage";
const NO_CREATE: &str = "one contract per proof: there is no second code or storage to create";
const CALL_NOTE: &str = "a translation runs it when the target is a precompile (addresses 1 to 9) \
     and, for CALL and CALLCODE, the value is zero; any other target or a non-zero value traps. \
     The interpreter traps on every call";

/// The row for `byte`.
pub fn opcode(byte: u8) -> Opcode {
    use Behaviour::*;
    let s = blocks::static_gas(byte);
    // (interp, xlat, note, gas, rule): `rule` empty means "the static figure and nothing else".
    let (interp, xlat, note, gas, rule): (Behaviour, Behaviour, &str, Gas, String) = match byte {
        0x00 => (Runs, Runs, "", Gas::Same, "0".into()),
        0x0a => (
            Runs,
            Runs,
            "",
            Gas::Same,
            format!("{EXP_BASE} + {EXP_PER_BYTE} per byte of the exponent"),
        ),
        0x01..=0x09 | 0x0b | 0x10..=0x1e => (Runs, Runs, "", Gas::Same, String::new()),
        0x20 => (
            Runs,
            Runs,
            "",
            Gas::Same,
            format!("{KECCAK_BASE} + {KECCAK_PER_WORD} per word + {MEM}"),
        ),
        0x30 | 0x33 | 0x34 | 0x35 | 0x36 | 0x38 => (Runs, Runs, "", Gas::Same, String::new()),
        0x32 => (
            Traps,
            Runs,
            "a translation pushes CALLER (one call, no relayer); the interpreter traps",
            Gas::Same,
            String::new(),
        ),
        0x37 | 0x39 => (
            Runs,
            Runs,
            "",
            Gas::Same,
            format!("{s} + {COPY_PER_WORD} per word + {MEM}"),
        ),
        0x3d => (
            Runs,
            Runs,
            "0 in the interpreter (no call is ever made); in a translation, the length of the \
             last precompile call's output",
            Gas::Same,
            String::new(),
        ),
        0x3e => (
            RunsIf,
            RunsIf,
            "a zero length always runs. A non-zero length traps in the interpreter, and in a \
             translation until a precompile call has been made; after one it copies from that \
             call's output (reading past its end halts OutOfBounds)",
            Gas::Same,
            format!("{s} + {COPY_PER_WORD} per word + {MEM}"),
        ),
        0x46 => (
            Traps,
            Runs,
            "a translation pushes the constant given as --chain-id (required at translation, \
             bound by the image hash); the interpreter traps",
            Gas::Same,
            String::new(),
        ),
        0x3a => (
            Traps,
            Traps,
            "transaction context: no public value binds the gas price to the proof",
            Gas::None,
            String::new(),
        ),
        0x47 => (
            Traps,
            Traps,
            "there is no balance model: the contract's storage is the only state",
            Gas::None,
            String::new(),
        ),
        0x40..=0x45 | 0x48..=0x4a => (Traps, Traps, NO_BLOCK_CTX, Gas::None, String::new()),
        0x31 | 0x3b | 0x3c | 0x3f => (Traps, Traps, NO_ACCOUNTS, Gas::None, String::new()),
        0x50 | 0x56..=0x5b | 0x5f..=0x9f => (Runs, Runs, "", Gas::Same, String::new()),
        0x51..=0x53 => (Runs, Runs, "", Gas::Same, format!("{s} + {MEM}")),
        0x54 => (
            Runs,
            Runs,
            "needs a storage witness for the slot in the input (NoWitness otherwise)",
            Gas::Differs,
            format!(
                "{} every time. Mainnet: 2 100 for the first access to a slot in a \
                 transaction (cold), 100 after (warm); there is no access list here",
                thousands(SLOAD)
            ),
        ),
        0x55 => (
            Runs,
            Runs,
            "needs a storage witness for the slot in the input (NoWitness otherwise)",
            Gas::Differs,
            format!(
                "{} when the slot's current value is zero and the new one is not, \
                 else {}, decided on the current value alone. Mainnet (EIP-2200, \
                 2929, 3529): the cost depends on the original, current and new value (100 for a \
                 no-op or a slot already written), adds 2 100 on a cold slot, refunds a clear, \
                 and fails when 2 300 gas or less is left. Here: no refund, no cold surcharge, \
                 no 100-gas case, no 2 300 check",
                thousands(SSTORE_SET),
                thousands(SSTORE_RESET)
            ),
        ),
        0x5c | 0x5d => (
            Runs,
            Runs,
            "at most 16 distinct keys given a non-zero value in one call; one more halts \
             OutOfBounds",
            Gas::Same,
            String::new(),
        ),
        0x5e => (
            Runs,
            Runs,
            "",
            Gas::Same,
            format!("{s} + {COPY_PER_WORD} per word + {MEM}"),
        ),
        0xa0..=0xa4 => (
            Runs,
            Runs,
            "the topics are bound by the public output; the data is bounds-checked and paid for, \
             then dropped. At most 8 logs in one call; one more halts OutOfBounds",
            Gas::Same,
            format!(
                "{LOG_BASE} + {LOG_PER_TOPIC} per topic + {LOG_PER_BYTE} per byte of data + {MEM}"
            ),
        ),
        0xf0 | 0xf5 => (Traps, Traps, NO_CREATE, Gas::None, String::new()),
        0xf1 | 0xf2 | 0xf4 | 0xfa => (
            Traps,
            RunsIf,
            CALL_NOTE,
            Gas::Same,
            format!(
                "{CALL_ACCESS} + {MEM} + the precompile's gas (see the precompile table). At \
                 most all but one 64th of the gas left is passed; a call that fails consumes \
                 what was passed"
            ),
        ),
        0xf3 | 0xfd => (
            Runs,
            Runs,
            "at most 1 024 bytes of return data; more halts OutOfBounds",
            Gas::Same,
            MEM.into(),
        ),
        0xfe => (Invalid, Invalid, "", Gas::None, String::new()),
        0xff => (
            Traps,
            Traps,
            "one contract per proof: there is no account to delete and no balance to move",
            Gas::None,
            String::new(),
        ),
        _ => (Undefined, Undefined, "", Gas::None, String::new()),
    };
    let gas_rule = match gas {
        Gas::None => String::new(),
        _ if rule.is_empty() => s.to_string(),
        _ => rule,
    };
    Opcode {
        byte,
        name: (interp != Undefined).then(|| name(byte)),
        interp,
        xlat,
        note,
        static_gas: s,
        gas,
        gas_rule,
    }
}

/// All 256 rows, in byte order.
pub fn opcodes() -> Vec<Opcode> {
    (0..=255u8).map(opcode).collect()
}

/// One precompile address's row. The interpreter traps on every call, so there is one column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Precompile {
    pub address: u32,
    pub name: &'static str,
    /// The fork that put it on mainnet.
    pub since: &'static str,
    /// `Runs` or `Traps` (a call to it halts `Trap(op)` with the calling opcode).
    pub xlat: Behaviour,
    pub gas: Gas,
    pub gas_rule: &'static str,
    /// The precompile's gas for an empty input when a call with an empty input succeeds; `None`
    /// when it fails (and so consumes the gas passed) or the address traps. `tests/compat.rs`
    /// checks it.
    pub empty_input_gas: Option<u64>,
    pub note: &'static str,
}

/// The addresses the table lists: 1 to 0x11 and 0x100, which is every precompile address mainnet
/// has assigned up to Osaka.
pub const PRECOMPILE_ADDRESSES: [u32; 18] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x100,
];

const TOO_MANY_CYCLES: &str = "runs, but in software it takes more cycles than the largest tier \
     holds (evm2rv/README.md, \"Calls and precompiles\"), so a call to it cannot be proved today";

/// The row for precompile `address`, or `None` when the table does not list it (a call to any
/// unlisted address traps: it is another contract).
pub fn precompile(address: u32) -> Option<Precompile> {
    use Behaviour::{Runs, Traps};
    let row = |name, since, xlat, gas, gas_rule, empty_input_gas, note| Precompile {
        address,
        name,
        since,
        xlat,
        gas,
        gas_rule,
        empty_input_gas,
        note,
    };
    let missing = |name, since| {
        row(
            name,
            since,
            Traps,
            Gas::None,
            "",
            None,
            "not implemented: a call traps like a call to any other contract",
        )
    };
    Some(match address {
        1 => row("ecrecover", "Frontier", Runs, Gas::Same, "3 000", Some(3_000), TOO_MANY_CYCLES),
        2 => row("sha256", "Frontier", Runs, Gas::Same, "60 + 12 per word", Some(60), ""),
        3 => row("ripemd160", "Frontier", Runs, Gas::Same, "600 + 120 per word", Some(600), ""),
        4 => row("identity", "Frontier", Runs, Gas::Same, "15 + 3 per word", Some(15), ""),
        5 => row(
            "modexp",
            "Byzantium",
            Runs,
            Gas::Differs,
            "EIP-2565 (Berlin): at least 200. Osaka's repricing (EIP-7883) and its 1 024-byte \
             input bound (EIP-7823) are not applied",
            Some(200),
            "base and modulus are capped at 1 024 bytes each: past that an affordable call halts \
             OutOfBounds. Past small operands it exceeds the largest tier's cycles",
        ),
        6 => row("bn256 add", "Byzantium", Runs, Gas::Same, "150 (EIP-1108)", Some(150), ""),
        7 => row(
            "bn256 mul",
            "Byzantium",
            Runs,
            Gas::Same,
            "6 000 (EIP-1108)",
            Some(6_000),
            TOO_MANY_CYCLES,
        ),
        8 => row(
            "bn256 pairing",
            "Byzantium",
            Runs,
            Gas::Same,
            "45 000 + 34 000 per pair (EIP-1108)",
            Some(45_000),
            TOO_MANY_CYCLES,
        ),
        9 => row(
            "blake2f",
            "Istanbul",
            Runs,
            Gas::Same,
            "1 per round (EIP-152)",
            None,
            "the input must be exactly 213 bytes, or the call fails",
        ),
        0x0a => missing("KZG point evaluation", "Cancun"),
        0x0b => missing("BLS12-381 G1 add", "Prague"),
        0x0c => missing("BLS12-381 G1 MSM", "Prague"),
        0x0d => missing("BLS12-381 G2 add", "Prague"),
        0x0e => missing("BLS12-381 G2 MSM", "Prague"),
        0x0f => missing("BLS12-381 pairing check", "Prague"),
        0x10 => missing("BLS12-381 map Fp to G1", "Prague"),
        0x11 => missing("BLS12-381 map Fp2 to G2", "Prague"),
        0x100 => missing("P256VERIFY", "Osaka"),
        _ => return None,
    })
}

/// Every listed precompile, in address order.
pub fn precompiles() -> Vec<Precompile> {
    PRECOMPILE_ADDRESSES
        .iter()
        .map(|&a| precompile(a).expect("a listed address"))
        .collect()
}

/// A fixed capacity: exceeding it is `Halt::OutOfBounds` (status 2), never out-of-gas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cap {
    pub what: &'static str,
    pub limit: usize,
    pub unit: &'static str,
    pub note: &'static str,
}

/// The fixed caps, from `evm-core`'s own constants.
pub const CAPS: [Cap; 8] = [
    Cap {
        what: "memory",
        limit: MAX_MEMORY_BYTES,
        unit: "bytes",
        note: "a range that ends past it halts OutOfBounds; mainnet would charge expansion gas",
    },
    Cap {
        what: "calldata",
        limit: MAX_CALLDATA_BYTES,
        unit: "bytes",
        note: "a longer input is refused before anything runs (gas used 0)",
    },
    Cap {
        what: "return data (RETURN, REVERT)",
        limit: MAX_RETURN_BYTES,
        unit: "bytes",
        note: "",
    },
    Cap {
        what: "logs in one call",
        limit: MAX_LOGS,
        unit: "logs",
        note: "",
    },
    Cap {
        what: "transient storage (TSTORE)",
        limit: MAX_TRANSIENT_SLOTS,
        unit: "distinct keys",
        note: "keys that have been given a non-zero value; one more halts OutOfBounds",
    },
    Cap {
        what: "storage witnesses in one call",
        limit: MAX_WITNESSES,
        unit: "slots",
        note: "the slots a call may read or write; an input with more is refused before anything \
               runs, and a slot touched without a witness halts NoWitness",
    },
    Cap {
        what: "code",
        limit: MAX_CODE_BYTES,
        unit: "bytes",
        note: "EIP-170's limit, as on mainnet; longer code is refused before anything runs",
    },
    Cap {
        what: "stack",
        limit: STACK_LIMIT,
        unit: "words",
        note: "the EVM's own limit, as on mainnet: StackOverflow, not OutOfBounds",
    },
];

// ---------------------------------------------------------------------------------------------
// The pre-flight scan.

/// How serious a [`Finding`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// The interpreter traps here and a translation runs it (`CHAINID`, `ORIGIN`).
    InterpreterOnly,
    /// It traps for some operands (the call family, `RETURNDATACOPY`).
    MayTrap,
    /// It always traps, on both paths.
    Traps,
}

/// One opcode occurrence `evm2rv check` reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub pc: usize,
    pub opcode: u8,
    pub name: String,
    pub severity: Severity,
    pub interp: Behaviour,
    pub xlat: Behaviour,
    /// The table's note for the opcode.
    pub reason: &'static str,
}

/// What [`check`] found.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Report {
    /// Set when the code is over [`MAX_CODE_BYTES`]: nothing in it runs, and nothing else is
    /// reported.
    pub code_too_large: Option<usize>,
    /// Every occurrence of an opcode that traps, may trap, or runs on one path only, in code
    /// order.
    pub findings: Vec<Finding>,
    /// Occurrences of bytes no fork assigns (they halt on mainnet too). Data embedded in the code
    /// (solc's metadata, constants after the last `STOP`/`INVALID`) is disassembled like code,
    /// so these are usually data.
    pub undefined: usize,
    /// How many opcodes whose gas differs from mainnet's (`SLOAD`, `SSTORE`) the code has.
    pub gas_differs: usize,
}

impl Report {
    /// Something in the code always traps in a translation (or the code is too large).
    pub fn traps(&self) -> bool {
        self.code_too_large.is_some()
            || self.findings.iter().any(|f| f.severity == Severity::Traps)
    }

    /// Something in the code traps for some operands in a translation.
    pub fn may_trap(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::MayTrap)
    }

    /// Something in the code traps in the interpreter, always or for some operands.
    pub fn interpreter_traps(&self) -> bool {
        self.code_too_large.is_some() || !self.findings.is_empty()
    }
}

/// Disassemble `code` linearly (`PUSHn` immediates skipped, so push data is never read as an
/// opcode) and report every occurrence the table says traps, may trap or differs between the two
/// paths. It is a scan, not a reachability analysis: an opcode in dead code or in data is
/// reported like any other.
pub fn check(code: &[u8]) -> Report {
    let mut r = Report::default();
    if code.len() > MAX_CODE_BYTES {
        r.code_too_large = Some(code.len());
        return r;
    }
    let mut pc = 0;
    while pc < code.len() {
        let op = code[pc];
        let row = opcode(op);
        let severity = match (row.interp, row.xlat) {
            (Behaviour::Traps, Behaviour::Traps) => Some(Severity::Traps),
            (_, Behaviour::RunsIf) => Some(Severity::MayTrap),
            (Behaviour::Traps, Behaviour::Runs) => Some(Severity::InterpreterOnly),
            _ => None,
        };
        if let Some(severity) = severity {
            r.findings.push(Finding {
                pc,
                opcode: op,
                name: name(op),
                severity,
                interp: row.interp,
                xlat: row.xlat,
                reason: row.note,
            });
        }
        if row.interp == Behaviour::Undefined {
            r.undefined += 1;
        }
        if row.gas == Gas::Differs {
            r.gas_differs += 1;
        }
        pc += if (0x60..=0x7f).contains(&op) {
            1 + (op - 0x5f) as usize
        } else {
            1
        };
    }
    r
}

// ---------------------------------------------------------------------------------------------
// The published table.

/// `1234567` as `1 234 567`, the way the repo's docs write figures.
pub fn thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

/// The family a row is folded into in the Markdown (consecutive bytes that differ only in their
/// index), or `None` for a row of its own.
fn family(o: &Opcode) -> Option<&'static str> {
    match o.byte {
        0x60..=0x7f => Some("PUSH"),
        0x80..=0x8f => Some("DUP"),
        0x90..=0x9f => Some("SWAP"),
        0xa0..=0xa4 => Some("LOG"),
        _ if o.interp == Behaviour::Undefined => Some(""),
        _ => None,
    }
}

fn behaviour_cell(b: Behaviour) -> String {
    match b {
        Behaviour::Runs => "runs".into(),
        Behaviour::RunsIf => "**runs if** (note)".into(),
        Behaviour::Traps => "**traps**".into(),
        other => other.word().into(),
    }
}

fn opcode_rows(out: &mut String) {
    let rows = opcodes();
    let mut i = 0;
    while i < rows.len() {
        let first = &rows[i];
        let fam = family(first);
        let mut j = i;
        if fam.is_some() {
            while j + 1 < rows.len()
                && family(&rows[j + 1]) == fam
                && rows[j + 1].interp == first.interp
                && rows[j + 1].xlat == first.xlat
                && rows[j + 1].gas == first.gas
                && rows[j + 1].gas_rule == first.gas_rule
                && rows[j + 1].note == first.note
            {
                j += 1;
            }
        }
        let last = &rows[j];
        let bytes = if i == j {
            format!("`{:#04x}`", first.byte)
        } else {
            format!("`{:#04x}`–`{:#04x}`", first.byte, last.byte)
        };
        let name = match (&first.name, &last.name) {
            (None, _) => "—".to_string(),
            (Some(a), Some(b)) if i != j => format!("`{a}`–`{b}`"),
            (Some(a), _) => format!("`{a}`"),
        };
        let gas = match first.gas {
            Gas::None => "—".to_string(),
            Gas::Same => format!("same: {}", first.gas_rule),
            Gas::Differs => format!("**different**: {}", first.gas_rule),
        };
        writeln!(
            out,
            "| {bytes} | {name} | {} | {} | {gas} | {} |",
            behaviour_cell(first.interp),
            behaviour_cell(first.xlat),
            first.note
        )
        .unwrap();
        i = j + 1;
    }
}

/// `evm2rv/COMPATIBILITY.md`, whole. `tests/compat.rs` fails when the committed file differs;
/// regenerate with `EVM2RV_COMPAT_REGEN=1 cargo +1.98.1 test --test compat`.
pub fn markdown() -> String {
    let rows = opcodes();
    let count = |f: &dyn Fn(&Opcode) -> bool| rows.iter().filter(|o| f(o)).count();
    let both_run = count(&|o| o.interp == Behaviour::Runs && o.xlat == Behaviour::Runs);
    let cond = count(&|o| o.interp == Behaviour::RunsIf || o.xlat == Behaviour::RunsIf);
    let xlat_only = count(&|o| o.interp == Behaviour::Traps && o.xlat == Behaviour::Runs);
    let both_trap = count(&|o| o.interp == Behaviour::Traps && o.xlat == Behaviour::Traps);
    let invalid = count(&|o| o.interp == Behaviour::Invalid);
    let undefined = count(&|o| o.interp == Behaviour::Undefined);
    let differs = count(&|o| o.gas == Gas::Differs);

    let mut s = String::new();
    s.push_str(
        "<!-- GENERATED by evm2rv/src/compat.rs (`compat::markdown`) — do not edit.\n     \
         Regenerate: (cd evm2rv && EVM2RV_COMPAT_REGEN=1 cargo +1.98.1 test --test compat).\n     \
         tests/compat.rs fails when this file differs from what the module generates, and holds\n     \
         the module to the code: it runs every opcode byte on both paths. -->\n\n",
    );
    s.push_str("# EVM compatibility\n\n");
    s.push_str(
        "What the zkVM's EVM guest runs, opcode by opcode and precompile by precompile, and how \
         its gas compares with Ethereum mainnet's. This file is the one place that says it; the \
         other docs link here.\n\n",
    );
    s.push_str("## The target\n\n");
    s.push_str(
        "**Today the guest is a single-contract EVM with a documented subset. It is not \
         mainnet-equivalent, and its gas is not mainnet gas.** A contract author should assume \
         nothing beyond the tables below.\n\n",
    );
    s.push_str(
        "- **One contract per proof.** A proof is one call into one contract's code against that \
         contract's storage. There is no second account: a call to another contract, `CREATE`, \
         `CREATE2`, `SELFDESTRUCT`, `BALANCE` and the `EXTCODE*` opcodes trap. So a router, a \
         proxy, or a token calling a pool does not run.\n\
         - **A subset.** The opcodes of Shanghai that one contract needs, plus `MCOPY`, `TLOAD`, \
         `TSTORE` (Cancun) and `CLZ` (Osaka). No block context (`TIMESTAMP`, `NUMBER`, …). The \
         precompiles stop at Shanghai's nine, and only in a translation.\n\
         - **Gas is a counter, not mainnet gas.** Most opcodes cost what they cost on mainnet. \
         Storage does not: there is no warm/cold access list, no refund and no 2 300-gas check \
         (the `SLOAD` and `SSTORE` rows). `gas_used` counts execution only: nothing is charged \
         before the first opcode (no 21 000 intrinsic gas, no calldata gas). Gas parity with \
         Ethereum is not a goal of the current design.\n\
         - **Fixed caps.** Memory, calldata, return data, logs, transient keys and storage \
         witnesses each have a fixed size (the caps table). Exceeding one is the exceptional halt \
         `OutOfBounds`, not out-of-gas.\n\n",
    );
    s.push_str(
        "**Open design question: multi-contract.** Whether the guest should run calls between \
         contracts inside one proof has not been decided, and this file does not decide it. The \
         sketch on the table (ZKVM-121): the code and the storage witnesses of every callee on \
         the input tape, a call stack in the harness, gas shared across frames, starting with \
         `STATICCALL` to another contract's view function. Until that is decided and built, the \
         first bullet above stands.\n\n",
    );
    s.push_str("## Two paths, three outcomes\n\n");
    s.push_str(
        "A contract reaches the zkVM one of two ways, and the tables have a column for each:\n\n\
         - **interpreter**: `evm-core`, the program `guests-compiled/bin/evm.bin`. It takes any \
         bytecode as input.\n\
         - **translation**: `evm2rv` turns one contract's bytecode into its own program. Both \
         stages (`--stage 1`, `--stage 2`) behave the same; they differ in cycles only.\n\n\
         Every run ends with a status: 1 success (`STOP`, `RETURN`), 0 revert, 2 an exceptional \
         halt. A **trap** is the exceptional halt `Trap(op)`: status 2, the whole gas limit \
         consumed, no state change, no logs. The proof is still produced; it says the call was \
         invalid. `evm2rv check <bytecode>` lists the opcodes in a contract that trap, before \
         anything is built or proved.\n\n",
    );
    writeln!(
        s,
        "Of the 256 opcode bytes: {both_run} run on both paths, {cond} run for some operands \
         only, {xlat_only} run in a translation and trap in the interpreter, {both_trap} trap on \
         both, {invalid} is `INVALID`, and {undefined} are undefined. {differs} have gas that \
         differs from mainnet's.\n"
    )
    .unwrap();

    s.push_str("## Opcodes\n\n");
    s.push_str(
        "The gas column is the whole rule; \"memory expansion\" is `3w + w²/512` for `w` words, \
         charged on growth, as on mainnet. An undefined byte halts `Trap(op)`, which is what an \
         undefined opcode does on mainnet (an exceptional halt).\n\n",
    );
    s.push_str("| byte | opcode | interpreter | translation | gas against mainnet | note |\n");
    s.push_str("|---|---|---|---|---|---|\n");
    opcode_rows(&mut s);

    s.push_str("\n## Precompiles\n\n");
    s.push_str(
        "Reached by `CALL`, `CALLCODE`, `DELEGATECALL` or `STATICCALL` to the address, in a \
         translation only: **the interpreter traps on every call.** A call costs 100 (the warm \
         access) plus memory expansion plus the precompile's gas. Any address not listed here is \
         another contract, and a call to it traps.\n\n",
    );
    s.push_str("| address | precompile | on mainnet since | translation | gas against mainnet | note |\n");
    s.push_str("|---|---|---|---|---|---|\n");
    for p in precompiles() {
        let gas = match p.gas {
            Gas::None => "—".to_string(),
            Gas::Same => format!("same: {}", p.gas_rule),
            Gas::Differs => format!("**different**: {}", p.gas_rule),
        };
        writeln!(
            s,
            "| `{:#04x}` | {} | {} | {} | {gas} | {} |",
            p.address,
            p.name,
            p.since,
            behaviour_cell(p.xlat),
            p.note
        )
        .unwrap();
    }

    s.push_str("\n## Fixed caps\n\n");
    s.push_str(
        "Each is a fixed-size array in the guest. Exceeding one halts `OutOfBounds` (status 2, \
         the whole gas limit consumed) unless the row says otherwise. It is not reported as \
         out-of-gas, and it is not a distinct halt per cap. None is configurable.\n\n",
    );
    s.push_str("| what | limit | note |\n|---|---|---|\n");
    for c in CAPS {
        writeln!(
            s,
            "| {} | {} {} | {} |",
            c.what,
            thousands(c.limit as u64),
            c.unit,
            c.note
        )
        .unwrap();
    }

    s.push_str("\n## Where the two paths differ\n\n");
    s.push_str(
        "A translation must give the interpreter's status, public output and `gas_used` for the \
         same call. Three differences are accepted (evm2rv/README.md, \"The observable \
         contract\"):\n\n\
         1. **The halt kind.** A translation charges a basic block's static gas once, at the \
         block's head. A block that would halt midway for another reason can halt `OutOfGas` at \
         its head instead, or the reverse. Both are status 2 with `gas_used` equal to the limit.\n\
         2. **A translation runs a little more.** `CHAINID` (the `--chain-id` constant), `ORIGIN` \
         (= `CALLER`) and calls to precompiles 1 to 9 run in a translation and trap in the \
         interpreter. A call on too shallow a stack underflows at the block head where the \
         interpreter traps; both are status 2.\n\
         3. **The code guard.** A translation refuses any code but the one it was translated \
         from (status 2, `gas_used` 0); the interpreter runs whatever code it is given.\n\n",
    );
    s.push_str("## Cycles\n\n");
    s.push_str(
        "What each opcode costs the interpreter in zkVM cycles is measured in \
         [CYCLES.md](CYCLES.md).\n",
    );
    s
}
