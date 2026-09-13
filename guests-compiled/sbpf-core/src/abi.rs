//! The input layout and the public output digest: everything between the machine's
//! `READ_INPUT`/`WRITE_OUTPUT` syscalls and the interpreter. [`run_call`] is the whole guest —
//! decode the input vector, load, run, produce the eight output words — so the binary Task 6
//! commits is a wrapper around this one function.
//!
//! # The input vector
//!
//! `READ_INPUT` word indices, in order, byte strings packed four per word little-endian and
//! zero-padded:
//!
//! ```text
//! [n_elf, elf bytes…, n_input, input bytes…]
//! ```
//!
//! # The public output
//!
//! `out0 = status` and `out1..out7` = words 0..6 of
//!
//! ```text
//! hash(SBPF_OUT, [program_hash(8) ‖ input_hash(8) ‖ output_hash(8)])
//! ```
//!
//! — 24 words through the domain-tagged Poseidon2 sponge, a 224-bit binding of the program, the
//! instruction it was given and the state it left behind. `program_hash = sha256(elf bytes)`,
//! `input_hash = sha256(serialized input as passed to the program)`, and `output_hash` is
//! [`output_hash`] over the accounts. Each 32-byte digest is packed into eight words as
//! `word[i] = LE(bytes[4i..4i+4])`, and all three go through the chip, which is what puts the
//! SHA-256 table on the exit test's own path.
//!
//! The status word is the plan's: `1` = the program returned `r0 == 0`, `0` = it returned something
//! else (a `ProgramError`, whose code is *not* published — the seven digest words are spoken for),
//! `2` = an exceptional halt. A status other than 1 binds the **pre**-state as the output hash:
//! nothing happened. [`run_call_with`] is the one place that rule lives, and it enforces it by
//! hashing the account region once before the run and reusing that digest, so a failed run cannot
//! publish a state change it made part-way through and then abandoned.
//!
//! # The guest pattern
//!
//! The whole run's state — the decoded input (272 KiB) plus the 32 KiB stack and 32 KiB heap — is
//! one [`Workspace`], which the guest keeps in `.bss` and lends out. Nothing here is ever a stack
//! local: the guest's stack is 64 KiB (`guest-sdk/guest.ld`) and a `Workspace` is five times that.
//! This crate is `#![forbid(unsafe_code)]`, so the `static mut` cell is the guest binary's (M4.3's
//! `evm` guest does the same):
//!
//! ```ignore
//! static mut W: Workspace = Workspace::ZERO;          // all-zero, so `.bss`: no image bytes
//!
//! #[no_mangle]
//! pub extern "C" fn main() -> ! {
//!     let w = unsafe { &mut *core::ptr::addr_of_mut!(W) };
//!     // READ_INPUT past the committed input length is unsatisfiable in-circuit (M4.1's `H_IN`),
//!     // so the machine itself is the guest's bound and `u32::MAX` is the honest `len` here.
//!     let out = run_call(&mut Syscalls, w, guest_sdk::read_input, u32::MAX);
//!     for (slot, word) in out.iter().enumerate() {
//!         guest_sdk::write_output(slot as u32, *word);
//!     }
//!     guest_sdk::halt()
//! }
//! ```

use crate::elf;
use crate::interp::{Halt, Vm};
use crate::memory::{Memory, HEAP_BYTES, STACK_BYTES};
use crate::{dhash, hash_words, sha256, Host, Sha256};

/// The largest ELF the input vector may carry (the plan's number).
pub const MAX_ELF_BYTES: usize = 262_144;
/// The largest serialized instruction the input vector may carry.
pub const MAX_INPUT_BYTES: usize = 16_384;
/// `notes::domain::SBPF_OUT`, mirrored here so the guest and the host agree without a dependency.
pub const SBPF_OUT_DOMAIN: u32 = 14;

/// Accounts [`output_hash`] can walk. Solana's own per-transaction limit is 64; a serialized input
/// claiming more is walked only this far, which is a deterministic answer rather than a panic.
pub const MAX_ACCOUNTS: usize = 64;

/// Bytes of realloc headroom the aligned format leaves after every account's data
/// (`solana_program::entrypoint::MAX_PERMITTED_DATA_INCREASE`).
const MAX_PERMITTED_DATA_INCREASE: usize = 10_240;

/// The marker byte of an account that is not a duplicate of an earlier one.
const NON_DUP_MARKER: u8 = 0xff;

/// Words in the public-output digest's preimage: three eight-word SHA-256 digests.
const OUT_WORDS: usize = 24;

/// Why an input vector is not a call. Every one of these is status 2 with the canonical malformed
/// output ([`run_call_with`]); none is a panic, because every length involved is prover-supplied
/// and a panicking guest aborts without producing a proof at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParseError {
    /// The vector ends before the layout does.
    Truncated,
    /// `n_elf` above [`MAX_ELF_BYTES`].
    ElfTooLong,
    /// `n_input` above [`MAX_INPUT_BYTES`].
    InputTooLong,
}

/// Reads the input vector through a `read(idx) -> u32` closure, so the same code runs on the host
/// (over a slice) and in the guest (over the `READ_INPUT` syscall).
///
/// `len` is how many words the reader can supply. A read at or past it is **not** attempted — the
/// closure is never called out of range — and sets the truncation flag instead. In the guest `len`
/// is `u32::MAX`: a `READ_INPUT` beyond the length committed to `H_IN` cannot be satisfied by any
/// witness, so the machine refuses an overrun before this ever could.
pub struct InputCursor<F: FnMut(u32) -> u32> {
    read: F,
    pos: u32,
    len: u32,
    truncated: bool,
}

impl<F: FnMut(u32) -> u32> InputCursor<F> {
    pub fn new(read: F, len: u32) -> Self {
        InputCursor { read, pos: 0, len, truncated: false }
    }

    /// The next word, or 0 with the truncation flag set once the vector is exhausted.
    pub fn word(&mut self) -> u32 {
        if self.pos >= self.len {
            self.truncated = true;
            return 0;
        }
        let w = (self.read)(self.pos);
        self.pos += 1;
        w
    }

    /// The next byte string: a length word, then `ceil(n/4)` words unpacked little-endian into
    /// `out[..n]`. Returns `n`, or `None` when `n > out.len()` — a cap the caller maps to its own
    /// [`ParseError`], and which is checked *before* any word of the string is read, so an absurd
    /// length costs nothing.
    pub fn bytes(&mut self, out: &mut [u8]) -> Option<usize> {
        let n = self.word() as usize;
        if n > out.len() {
            return None;
        }
        for i in 0..n.div_ceil(4) {
            let w = self.word().to_le_bytes();
            let chunk = &mut out[4 * i..core::cmp::min(4 * i + 4, n)];
            chunk.copy_from_slice(&w[..chunk.len()]);
        }
        Some(n)
    }

    /// Whether a read ran past the end of the vector.
    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

/// One call's decoded input: the ELF and the serialized instruction, in static buffers. Part of the
/// guest's [`Workspace`], never a value on the stack (272 KiB).
pub struct CallInput {
    pub elf: [u8; MAX_ELF_BYTES],
    pub elf_len: usize,
    pub input: [u8; MAX_INPUT_BYTES],
    pub input_len: usize,
}

impl CallInput {
    /// All zeros: an empty call, and a `const` so a `static` holding one lands in `.bss`.
    pub const ZERO: CallInput = CallInput {
        elf: [0; MAX_ELF_BYTES],
        elf_len: 0,
        input: [0; MAX_INPUT_BYTES],
        input_len: 0,
    };
}

/// All the static state one call needs: the decoded input, the sBPF stack and the sBPF heap — about
/// 336 KiB in one place. The guest keeps exactly one in `.bss` and passes `&mut` into [`run_call`];
/// a host test boxes one. Reusing a workspace is sound: [`decode_input`] resets the two lengths and
/// [`run_call_with`] zeroes the stack and heap, so nothing carries over from a previous call.
pub struct Workspace {
    pub input: CallInput,
    pub stack: [u8; STACK_BYTES],
    pub heap: [u8; HEAP_BYTES],
}

impl Workspace {
    pub const ZERO: Workspace =
        Workspace { input: CallInput::ZERO, stack: [0; STACK_BYTES], heap: [0; HEAP_BYTES] };
}

/// Decodes the input vector into `dst`, in place — the ELF, then the serialized instruction.
///
/// Refuses, rather than trusting, everything the layout leaves to the prover: either length above
/// its cap, and a vector that ends before the layout does. Checked once at the end, as M4.3's
/// `decode_input` is: nothing here branches on anything but a length and a read past the end
/// yields zero, so a truncated vector can only have produced *shorter* fields, never misread ones.
pub fn decode_input<F: FnMut(u32) -> u32>(
    dst: &mut CallInput,
    c: &mut InputCursor<F>,
) -> Result<(), ParseError> {
    dst.elf_len = 0;
    dst.input_len = 0;
    dst.elf_len = c.bytes(&mut dst.elf).ok_or(ParseError::ElfTooLong)?;
    dst.input_len = c.bytes(&mut dst.input).ok_or(ParseError::InputTooLong)?;
    if c.truncated() {
        return Err(ParseError::Truncated);
    }
    Ok(())
}

/// `sha256(for each account in order: lamports ‖ data_len ‖ data)`, each integer eight
/// little-endian bytes — the plan's `output_hash`, over whatever state the serialized input region
/// holds when it is called. Covers every account, writable or not.
///
/// The walk is over the *aligned* format (`solana_program::entrypoint::deserialize`'s layout), and
/// a duplicate account entry re-hashes the account it duplicates, at the position it occupies. Its
/// marker byte is an index into **all** entries seen so far, duplicates included — the same index
/// space `deserialize` pushes into.
///
/// Total by construction: a region that is not a serialized instruction, or that ends before its
/// own account count does, hashes the prefix the walk got through and stops. Both the pre- and the
/// post-state digest of a run go through this same walk, so a malformed region still binds
/// consistently — and a well-formed one is exactly the documented preimage.
pub fn output_hash<H: Host>(h: &mut H, input: &[u8]) -> [u8; 32] {
    let mut s = Sha256::new();
    // Where each entry's lamports and data sit, indexed by its **entry ordinal** — duplicates
    // included. A duplicate's marker byte is an index into the full list of entries seen so far,
    // not into the non-duplicate ones: `solana_program::entrypoint::deserialize` does
    // `accounts.push(accounts[dup_info].clone())` over a `Vec` that already holds its own
    // duplicates, and so does this crate's host twin (`rand_zkvm::sbpf::deserialize_accounts`).
    // Indexing anything else silently hashes the wrong account — `[A, A, B, C, B]`'s last entry
    // carries the byte 2, which is `B` among all entries but `C` among the non-duplicate ones.
    let mut seen = [(0usize, 0usize, 0usize); MAX_ACCOUNTS];
    let mut n_entries = 0usize;

    let mut off = 0usize;
    // Clamped in `u64`: on the 32-bit target a count above `u32::MAX` would otherwise truncate
    // into a small, plausible-looking number instead of being refused.
    let n_accounts = match read_u64(input, 0) {
        Some(n) => {
            off = 8;
            core::cmp::min(n, MAX_ACCOUNTS as u64) as usize
        }
        None => 0,
    };
    for _ in 0..n_accounts {
        let dup = match input.get(off) {
            Some(d) => *d,
            None => break,
        };
        let entry = if dup == NON_DUP_MARKER {
            // marker, is_signer, is_writable, executable, then four bytes of `original_data_len`.
            let key_at = off + 8;
            let lamports_at = key_at + 64;
            let data_len_at = lamports_at + 8;
            let Some(data_len) = read_u64(input, data_len_at) else { break };
            let data_at = data_len_at + 8;
            let Ok(data_len) = usize::try_from(data_len) else { break };
            let Some(data_end) = data_at.checked_add(data_len) else { break };
            if data_end > input.len() {
                break;
            }
            // The realloc headroom, then padding to the next eight-byte boundary, then
            // `rent_epoch`.
            let after = match data_end.checked_add(MAX_PERMITTED_DATA_INCREASE) {
                Some(a) => (a + 7) & !7,
                None => break,
            };
            off = match after.checked_add(8) {
                Some(o) => o,
                None => break,
            };
            (lamports_at, data_at, data_len)
        } else {
            // A duplicate: the index, then seven bytes of padding, and nothing else.
            if dup as usize >= n_entries {
                break;
            }
            let Some(&entry) = seen.get(dup as usize) else { break };
            off += 8;
            entry
        };
        // Every entry is recorded at its own ordinal, so a later duplicate of a duplicate lands on
        // the same account either way.
        if n_entries < MAX_ACCOUNTS {
            seen[n_entries] = entry;
        }
        n_entries += 1;

        let (lamports_at, data_at, data_len) = entry;
        let Some(lamports) = read_u64(input, lamports_at) else { break };
        let Some(data_end) = data_at.checked_add(data_len) else { break };
        if data_end > input.len() {
            break;
        }
        hash_account(h, &mut s, lamports, data_len, &input[data_at..data_end]);
    }
    s.finish(h)
}

fn hash_account<H: Host>(h: &mut H, s: &mut Sha256, lamports: u64, data_len: usize, data: &[u8]) {
    s.update(h, &lamports.to_le_bytes());
    s.update(h, &(data_len as u64).to_le_bytes());
    s.update(h, data);
}

fn read_u64(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off.checked_add(8)?)?;
    Some(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

/// The eight public output words: `out[0] = status`, `out[1..8]` = words 0..6 of
/// `hash(SBPF_OUT, [program_hash ‖ input_hash ‖ output_hash])`.
pub fn public_output<H: Host>(
    h: &mut H,
    status: u32,
    program_hash: &[u8; 32],
    input_hash: &[u8; 32],
    output_hash: &[u8; 32],
) -> [u32; 8] {
    let mut msg = [0u32; OUT_WORDS];
    msg[0..8].copy_from_slice(&hash_words(program_hash));
    msg[8..16].copy_from_slice(&hash_words(input_hash));
    msg[16..24].copy_from_slice(&hash_words(output_hash));
    let d = dhash(h, SBPF_OUT_DOMAIN, &msg);
    let mut out = [0u32; 8];
    out[0] = status;
    out[1..8].copy_from_slice(&d[..7]);
    out
}

/// The whole guest: decode the input vector, load the ELF, run it, produce the eight public output
/// words. See the module docs for the `static mut` pattern and for what `len` means.
pub fn run_call<H: Host, F: FnMut(u32) -> u32>(
    h: &mut H,
    ws: &mut Workspace,
    read: F,
    len: u32,
) -> [u32; 8] {
    run_call_with(h, ws, read, len).0
}

/// [`run_call`] plus the interpreter's own outcome — what a host test needs to check the output
/// against its own idea of the call (`rand_zkvm::sbpf::SbpfCall::expected`). The post-state of the
/// accounts is left in `ws.input.input[..input_len]`, so a caller can deserialize it. The guest
/// uses [`run_call`].
pub fn run_call_with<H: Host, F: FnMut(u32) -> u32>(
    h: &mut H,
    ws: &mut Workspace,
    read: F,
    len: u32,
) -> ([u32; 8], Result<u64, Halt>) {
    let mut c = InputCursor::new(read, len);
    if decode_input(&mut ws.input, &mut c).is_err() {
        // A vector that does not parse is not a call, so there is nothing to bind: the output is
        // the one canonical malformed value — status 2 over three all-zero digests. A verifier
        // recomputing the digest from the program and instruction it meant to run gets something
        // else and rejects the proof, which is the right answer to a prover-supplied vector that is
        // not even well formed.
        let z = [0u8; 32];
        return (public_output(h, 2, &z, &z, &z), Err(Halt::BadElf));
    }
    // Now split the workspace into its fields: the ELF buffer is borrowed by the loaded program for
    // as long as the run lasts, while the instruction region, the stack and the heap are the memory
    // it runs over.
    let Workspace { input: CallInput { elf, elf_len, input, input_len }, stack, heap } = ws;
    let elf_len = *elf_len;
    let input_len = *input_len;

    let program_hash = sha256(h, &elf[..elf_len]);
    let input_hash = sha256(h, &input[..input_len]);
    // The pre-state digest, taken before a single instruction runs: this is what a status of 0 or 2
    // binds, so a run that changed accounts and then failed publishes no change at all.
    let pre_output = output_hash(h, &input[..input_len]);

    // A fresh run gets a zero stack and heap whatever a previous one left behind, so two calls
    // through one workspace cannot differ by what the first one left in a frame — a determinism
    // hazard, since an sBPF program is free to read a stack slot it never wrote.
    //
    // For a guest that runs exactly one call this is 64 KiB of stores the `.bss` image already
    // guarantees (~16 000 RV32 `sw` cycles). If Task 6's tier turns out to be tight, this is the
    // first thing to drop — but only together with a note that a `Workspace` is then single-use.
    stack.fill(0);
    heap.fill(0);

    let result = match elf::load(&mut elf[..elf_len]) {
        Ok(program) => {
            let mem = Memory {
                text: program.text,
                text_va: program.text_va,
                rodata: program.rodata,
                rodata_base: program.rodata_va,
                stack,
                heap,
                input: &mut input[..input_len],
            };
            let mut vm = Vm::new(h, &program, mem);
            vm.run()
        }
        Err(e) => Err(e),
    };

    let status = match result {
        Ok(0) => 1,
        Ok(_) => 0,
        Err(_) => 2,
    };
    let post_output =
        if status == 1 { output_hash(h, &input[..input_len]) } else { pre_output };
    (public_output(h, status, &program_hash, &input_hash, &post_output), result)
}
