//! What a run did, for a guest author (ZKVM-119): symbols from the guest's ELF, where a trap
//! happened, where the cycles went, and how deep the stack got. All of it reads the emulator's own
//! record of the run (`rand_zkvm::emulator`), so it describes exactly the execution a proof would
//! be of; none of it is seen by the prover.

use crate::elf;
use anyhow::Result;
use rand_zkvm::emulator::{Execution, HashRow, Syscall, Trap, SPACE_REG};
use rand_zkvm::isa::{Instr, Program};
use std::collections::HashMap;
use std::fmt::Write as _;

/// The symbols of a linked guest that name code, sorted by address.
#[derive(Clone, Debug, Default)]
pub struct Symbols {
    /// `(start, size, demangled name)`; `size` is 0 for a label with no extent (`_start`).
    syms: Vec<(u32, u32, String)>,
}

impl Symbols {
    /// From a guest ELF's symbol table; an ELF without one gives no symbols. Mapping symbols
    /// (`$x…`, `$d…`), assembler-local labels (`.L…`) and linker-script symbols (`__stack_top`) are
    /// not code a reader would recognise and are left out.
    pub fn from_elf(elf_bytes: &[u8]) -> Result<Self> {
        let text: Vec<(u32, u32)> = elf::read_sections(elf_bytes)?
            .into_iter()
            .filter(|s| s.alloc && s.progbits && s.name.starts_with(".text"))
            .map(|s| (s.addr, s.addr.saturating_add(s.size)))
            .collect();
        let mut syms: Vec<(u32, u32, String)> = elf::read_symbols(elf_bytes)?
            .unwrap_or_default()
            .into_iter()
            .filter(|s| !s.name.starts_with('$') && !s.name.starts_with('.') && text.iter().any(|(a, b)| s.value >= *a && s.value < *b))
            .map(|s| (s.value, s.size, format!("{:#}", rustc_demangle::demangle(&s.name))))
            .collect();
        // At one address a sized (function) symbol is the better name than a bare label.
        syms.sort_by(|a, b| (a.0, std::cmp::Reverse(a.1), &a.2).cmp(&(b.0, std::cmp::Reverse(b.1), &b.2)));
        syms.dedup_by_key(|s| s.0);
        Ok(Self { syms })
    }

    pub fn is_empty(&self) -> bool {
        self.syms.is_empty()
    }

    /// The index of the symbol `pc` falls in: the last one starting at or before it, unless that
    /// one has an extent and `pc` is past it.
    fn index(&self, pc: u32) -> Option<usize> {
        let i = self.syms.partition_point(|s| s.0 <= pc).checked_sub(1)?;
        let (start, size, _) = &self.syms[i];
        (*size == 0 || pc - start < *size).then_some(i)
    }

    /// The symbol `pc` falls in and the offset into it.
    pub fn lookup(&self, pc: u32) -> Option<(&str, u32)> {
        self.index(pc).map(|i| (self.syms[i].2.as_str(), pc - self.syms[i].0))
    }

    /// `0x… (name+0x…)`, or the bare address when no symbol covers it.
    pub fn place(&self, pc: u32) -> String {
        match self.lookup(pc) {
            Some((name, 0)) => format!("{pc:#x} ({name})"),
            Some((name, off)) => format!("{pc:#x} ({name}+{off:#x})"),
            None => format!("{pc:#x}"),
        }
    }
}

/// A trap, placed: the pc with its symbol, the cycle, the address at fault when the error carries
/// one, and with `history` the instructions that led there.
pub fn describe_trap(trap: &Trap, program: &Program, symbols: &Symbols, history: bool) -> String {
    use rand_zkvm::emulator::ExecError as E;
    let mut s = String::new();
    let _ = writeln!(s, "  at pc {} after {} cycles", symbols.place(trap.pc), trap.cycle);
    match trap.error {
        E::Misaligned(a) => { let _ = writeln!(s, "  faulting address {a:#x} (a misaligned load or store)"); }
        E::BadPc(a) => { let _ = writeln!(s, "  faulting address {a:#x} (no instruction there: a jump outside the program)"); }
        E::Poseidon2Ptr(a) | E::KeccakPtrOutOfRange(a) | E::Sha256PtrOutOfRange(a) | E::ModqPtrOutOfRange(a) => {
            let _ = writeln!(s, "  faulting address: word {a:#x} (byte {:#x}), the syscall's pointer", (a as u64) * 4);
        }
        E::ModqCoefficient { addr, value } => { let _ = writeln!(s, "  faulting address: word {addr:#x} (byte {:#x}), holding {value:#x}", (addr as u64) * 4); }
        _ => {}
    }
    if symbols.is_empty() {
        let _ = writeln!(s, "  (no symbols: pass --elf <the linked ELF> to name the function)");
    }
    if history {
        let _ = writeln!(s, "  the last {} instructions, oldest first:", trap.recent.len());
        for pc in &trap.recent {
            let what = program.instr_at(*pc).map(|i| format!("{i:?}")).unwrap_or_else(|| "(no instruction)".into());
            let _ = writeln!(s, "    {}  {what}", symbols.place(*pc));
        }
    }
    s
}

/// How far the stack pointer went: the top `_start` loads into `sp` and the lowest value `sp`
/// held afterwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StackUse {
    pub top: u32,
    pub lowest: u32,
}

impl StackUse {
    pub fn depth(&self) -> u32 {
        self.top.saturating_sub(self.lowest)
    }
}

/// The stack use of a finished run, or `None` if the guest never set `sp`. The top is what `sp`
/// holds once its first run of consecutive writes ends (`la sp, __stack_top` is two instructions,
/// and the first leaves an intermediate value). A host-side reading of the register writes; the
/// machine itself has no stack limit, which is why an overflow is silent.
pub fn stack_use(exec: &Execution) -> Option<StackUse> {
    let mut top: Option<u32> = None;
    let mut settled = false;
    let mut lowest = u32::MAX;
    for e in &exec.events {
        let write = e.accesses.iter().find(|a| a.space == SPACE_REG && a.addr == 2 && a.is_write).map(|a| a.value);
        match write {
            Some(v) if !settled => top = Some(v),
            Some(v) => lowest = lowest.min(v),
            None if top.is_some() => settled = true,
            None => {}
        }
    }
    top.map(|top| StackUse { top, lowest: lowest.min(top) })
}

/// Where a run's cycles went.
#[derive(Clone, Debug, Default)]
pub struct Profile {
    pub cycles: u64,
    /// Cycles by the function the row's pc is in (self time), largest first. A syscall's rows are
    /// its caller's. `None` is code no symbol covers.
    pub functions: Vec<(Option<String>, u64)>,
    /// Per syscall: name, calls, cpu rows (more than one per call only for the Poseidon2 pair).
    pub syscalls: Vec<(&'static str, u64, u64)>,
    /// `a;b;c count` lines: cycles by call stack, for a flamegraph.
    pub folded: Vec<(String, u64)>,
}

fn syscall_name(s: &Syscall) -> &'static str {
    match s {
        Syscall::Halt => "HALT",
        Syscall::WriteOutput { .. } => "WRITE_OUTPUT",
        Syscall::ReadInput { .. } => "READ_INPUT",
        Syscall::ReadPublic { .. } => "READ_PUBLIC",
        Syscall::Poseidon2 { .. } => "POSEIDON2",
        Syscall::Poseidon2Len { .. } => "POSEIDON2_LEN",
        Syscall::Keccak { .. } => "KECCAK",
        Syscall::Sha256 { .. } => "SHA256",
        Syscall::Modq { .. } => "MODQ",
    }
}

const RA: u32 = 1;
const T0: u32 = 5;

/// The profile of a finished run. Call stacks are followed by the calling convention: a `jal` or
/// `jalr` that links (`rd` is `ra` or `t0`) is a call, a `jalr` through a link register that does
/// not link is a return, and any other jump that lands on the first instruction of another
/// function is a tail call. Code built without that convention still gets exact per-function
/// totals; only its stacks are approximate.
pub fn profile(exec: &Execution, symbols: &Symbols) -> Profile {
    const UNKNOWN: usize = usize::MAX;
    let name = |i: usize| if i == UNKNOWN { "[unknown]".to_string() } else { symbols.syms[i].2.clone() };
    let sym = |pc: u32| symbols.index(pc).unwrap_or(UNKNOWN);
    let mut by_fn: HashMap<usize, u64> = HashMap::new();
    let mut sys: Vec<(&'static str, u64, u64)> = Vec::new();
    let mut stacks: HashMap<Vec<usize>, u64> = HashMap::new();
    let mut stack: Vec<usize> = Vec::new();
    let mut last_sys: Option<usize> = None;
    for e in &exec.events {
        let here = sym(e.pc);
        if stack.is_empty() {
            stack.push(here);
        }
        *by_fn.entry(here).or_default() += 1;
        *stacks.entry(stack.clone()).or_default() += 1;
        // A Poseidon2 call is a row group at one pc: the ecall row, then absorb and write-back
        // rows that are the same call.
        let continuation = matches!(e.hash_row, Some(HashRow::Absorb { .. }) | Some(HashRow::WriteOut { .. }));
        if continuation {
            if let Some(i) = last_sys {
                sys[i].2 += 1;
            }
            continue;
        }
        if let Some(s) = &e.sys {
            let n = syscall_name(s);
            let i = sys.iter().position(|x| x.0 == n).unwrap_or_else(|| {
                sys.push((n, 0, 0));
                sys.len() - 1
            });
            sys[i].1 += 1;
            sys[i].2 += 1;
            last_sys = Some(i);
        }
        let links = |rd: u32| rd == RA || rd == T0;
        match e.instr {
            Instr::Jal { rd, .. } | Instr::Jalr { rd, .. } if links(rd) => stack.push(sym(e.next_pc)),
            Instr::Jalr { rd: 0, rs1, .. } if links(rs1) => {
                if stack.len() > 1 {
                    stack.pop();
                }
            }
            Instr::Jal { rd: 0, .. } | Instr::Jalr { rd: 0, .. } => {
                let to = sym(e.next_pc);
                if to != here && to != UNKNOWN && symbols.syms[to].0 == e.next_pc {
                    *stack.last_mut().unwrap() = to;
                }
            }
            _ => {}
        }
    }
    let mut functions: Vec<(Option<String>, u64)> = by_fn.into_iter().map(|(i, n)| ((i != UNKNOWN).then(|| name(i)), n)).collect();
    functions.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    sys.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(b.0)));
    let mut folded: Vec<(String, u64)> = stacks.into_iter().map(|(st, n)| (st.iter().map(|i| name(*i).replace(';', ":")).collect::<Vec<_>>().join(";"), n)).collect();
    folded.sort();
    Profile { cycles: exec.events.len() as u64, functions, syscalls: sys, folded }
}
