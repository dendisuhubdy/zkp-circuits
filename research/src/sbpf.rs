//! The host side of the sBPF guest (M4.4 Task 5): the [`sbpf_core::Host`] implementation the
//! interpreter is generic over, the *aligned* serialized-instruction format Solana's entrypoint
//! deserializes, and the helpers that run `sbpf-core` natively so every opcode, syscall and
//! relocation is unit-tested and differentially tested before anything is proved.
//!
//! `sbpf-core` is `no_std` and cannot depend on this crate, so it carries its own copies of the
//! SHA-256 padding, the domain-tagged sponge wrapper and the output-hash walk. Everything here is
//! the reference those copies are checked against, from the same primitives the guest's syscalls
//! compute (`sha256::compress`, `hash::sponge_hash`).
//!
//! The differential oracle itself — `solana-sbpf` 0.11.1 — lives in `tests/common/sbpf_oracle.rs`
//! rather than here, because it is a dev-dependency and this module is part of the library.

use sbpf_core::abi::{run_call_with, Workspace};
use sbpf_core::elf::Program;
use sbpf_core::interp::{Halt, Vm};
use sbpf_core::isa::{self, Insn};
use sbpf_core::memory::{Memory, HEAP_BYTES, STACK_BYTES};

use crate::hash::sponge_hash;
use crate::sha256;

/// Bytes of realloc headroom the aligned format leaves after every account's data
/// (`solana_program::entrypoint::MAX_PERMITTED_DATA_INCREASE`).
pub const MAX_PERMITTED_DATA_INCREASE: usize = 10_240;

/// The marker byte of an account that is not a duplicate of an earlier one
/// (`solana_program::entrypoint::NON_DUP_MARKER`).
pub const NON_DUP_MARKER: u8 = 0xff;

/// [`sbpf_core::Host`] over this crate's reference primitives: the SHA-256 compression the
/// `SHA256` syscall computes and the Poseidon2 sponge the `POSEIDON2` syscall computes. Every
/// `sbpf-core` function is therefore exercised natively on exactly the arithmetic the guest will
/// see in-circuit.
pub struct HostRef;

impl sbpf_core::Host for HostRef {
    fn sha256_compress(&mut self, words: &mut [u32; 24]) {
        let mut state: [u32; 8] = words[16..24].try_into().unwrap();
        let block: [u32; 16] = words[0..16].try_into().unwrap();
        sha256::compress(&mut state, &block);
        words[16..24].copy_from_slice(&state);
    }

    fn poseidon2(&mut self, words: &mut [u32], n: usize) {
        let digest = sponge_hash(&words[..n]);
        words[..8].copy_from_slice(&digest);
    }
}

// ---- a minimal sBPF assembler, for the hand-written test programs ------------------------------

/// One instruction slot's eight bytes. `dst` and `src` are register numbers; `off` is in slots for
/// a jump and in bytes for a load or store; `imm` is the 32-bit immediate.
pub fn insn(opc: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    isa::encode(Insn { opc, dst, src, off, imm }).to_le_bytes()
}

/// `lddw dst, imm64` — the one two-slot instruction.
pub fn lddw(dst: u8, imm: u64) -> [[u8; 8]; 2] {
    [
        insn(isa::opc::LD_DW_IMM, dst, 0, 0, imm as u32 as i32),
        insn(0, 0, 0, 0, (imm >> 32) as u32 as i32),
    ]
}

/// Flattens slots into a text section.
pub fn asm(insns: &[[u8; 8]]) -> Vec<u8> {
    insns.iter().flatten().copied().collect()
}

// ---- running `sbpf-core` natively -------------------------------------------------------------

/// What one native run produced. `instructions` and `max_depth` are what Task 6 measures the SPL
/// Token `Transfer` with.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Outcome {
    pub result: Result<u64, Halt>,
    pub instructions: u64,
    /// The **deepest** the frame stack got, not the depth it ended at: a run that returns normally
    /// ends at 0, and what the 8 × 4 KiB stack has to be big enough for is the high-water mark
    /// (`Vm::max_call_depth`).
    pub max_depth: usize,
}

/// Runs a bare text section (no ELF, no relocations, entrypoint slot 0) over `input` as the input
/// region. Writes the program makes to the input region are visible to the caller afterwards.
pub fn run_text(text: &[u8], input: &mut [u8]) -> Outcome {
    match Program::from_text(text) {
        Ok(p) => run_program(&p, input),
        Err(e) => Outcome { result: Err(e), instructions: 0, max_depth: 0 },
    }
}

/// Loads `elf` in place and runs it over `input`.
pub fn run_elf(elf: &mut [u8], input: &mut [u8]) -> Outcome {
    match sbpf_core::elf::load(elf) {
        Ok(p) => run_program(&p, input),
        Err(e) => Outcome { result: Err(e), instructions: 0, max_depth: 0 },
    }
}

fn run_program(p: &Program, input: &mut [u8]) -> Outcome {
    let mut stack = vec![0u8; STACK_BYTES].into_boxed_slice();
    let mut heap = vec![0u8; HEAP_BYTES].into_boxed_slice();
    let stack: &mut [u8; STACK_BYTES] = (&mut stack[..]).try_into().unwrap();
    let heap: &mut [u8; HEAP_BYTES] = (&mut heap[..]).try_into().unwrap();
    let mut h = HostRef;
    let mem = Memory {
        text: p.text,
        text_va: p.text_va,
        rodata: p.rodata,
        rodata_base: p.rodata_va,
        stack,
        heap,
        input,
    };
    let mut vm = Vm::new(&mut h, p, mem);
    let result = vm.run();
    Outcome { result, instructions: vm.instructions_executed(), max_depth: vm.max_call_depth() }
}

// ---- the aligned serialized-instruction format -------------------------------------------------

/// One account as the aligned format carries it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Account {
    pub key: [u8; 32],
    pub owner: [u8; 32],
    pub lamports: u64,
    pub data: Vec<u8>,
    pub is_signer: bool,
    pub is_writable: bool,
    pub executable: bool,
    pub rent_epoch: u64,
}

/// The *aligned* input `solana_program::entrypoint::deserialize` reads (M4.4 plan, "Serialized
/// input"):
///
/// ```text
/// u64 n_accounts
/// per account, not a duplicate:
///   u8 0xff, u8 is_signer, u8 is_writable, u8 executable, [u8; 4] original_data_len,
///   [u8; 32] key, [u8; 32] owner, u64 lamports, u64 data_len, data,
///   [u8; 10_240] realloc headroom, padding to an 8-byte boundary, u64 rent_epoch
/// per account, a duplicate of account j:
///   u8 j, [u8; 7] padding
/// u64 instruction_data_len, instruction data, [u8; 32] program_id
/// ```
///
/// An account whose key equals an earlier account's is written as a duplicate, which is what the
/// runtime does (accounts are deduplicated by pubkey).
pub fn serialize_aligned(accounts: &[Account], data: &[u8], program_id: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(accounts.len() as u64).to_le_bytes());
    for (i, a) in accounts.iter().enumerate() {
        if let Some(j) = accounts[..i].iter().position(|b| b.key == a.key) {
            out.push(j as u8);
            out.extend_from_slice(&[0u8; 7]);
            continue;
        }
        out.push(NON_DUP_MARKER);
        out.push(u8::from(a.is_signer));
        out.push(u8::from(a.is_writable));
        out.push(u8::from(a.executable));
        // The `original_data_len` slot. The entrypoint skips it, so it is written as padding.
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&a.key);
        out.extend_from_slice(&a.owner);
        out.extend_from_slice(&a.lamports.to_le_bytes());
        out.extend_from_slice(&(a.data.len() as u64).to_le_bytes());
        out.extend_from_slice(&a.data);
        out.resize(out.len() + MAX_PERMITTED_DATA_INCREASE, 0);
        while out.len() % 8 != 0 {
            out.push(0);
        }
        out.extend_from_slice(&a.rent_epoch.to_le_bytes());
    }
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(program_id);
    out
}

/// [`serialize_aligned`]'s inverse: the accounts in the order the region lists them, a duplicate
/// entry coming back as a copy of the account it duplicates. Panics on a region that is not a
/// serialized instruction; [`try_deserialize_accounts`] is the fallible form, which is what a
/// caller reading a *post*-state should use — a program is free to scribble over its own input
/// region, and the guest's own walk (`sbpf_core::abi::output_hash`) is total for the same reason.
pub fn deserialize_accounts(input: &[u8]) -> Vec<Account> {
    try_deserialize_accounts(input).expect("not a serialized instruction")
}

/// [`deserialize_accounts`], or `None` if the region does not parse.
pub fn try_deserialize_accounts(input: &[u8]) -> Option<Vec<Account>> {
    let n = u64::from_le_bytes(input.get(0..8)?.try_into().ok()?) as usize;
    let mut out: Vec<Account> = Vec::with_capacity(core::cmp::min(n, 64));
    let mut off = 8usize;
    for _ in 0..n {
        let dup = *input.get(off)?;
        if dup != NON_DUP_MARKER {
            out.push(out.get(dup as usize)?.clone());
            off += 8;
            continue;
        }
        let is_signer = *input.get(off + 1)? != 0;
        let is_writable = *input.get(off + 2)? != 0;
        let executable = *input.get(off + 3)? != 0;
        let key: [u8; 32] = input.get(off + 8..off + 40)?.try_into().ok()?;
        let owner: [u8; 32] = input.get(off + 40..off + 72)?.try_into().ok()?;
        let lamports = u64::from_le_bytes(input.get(off + 72..off + 80)?.try_into().ok()?);
        let data_len =
            usize::try_from(u64::from_le_bytes(input.get(off + 80..off + 88)?.try_into().ok()?))
                .ok()?;
        let data = input.get(off + 88..off.checked_add(88)?.checked_add(data_len)?)?.to_vec();
        let after = (off + 88 + data_len).checked_add(MAX_PERMITTED_DATA_INCREASE + 7)? & !7;
        let rent_epoch = u64::from_le_bytes(input.get(after..after.checked_add(8)?)?.try_into().ok()?);
        out.push(Account {
            key,
            owner,
            lamports,
            data,
            is_signer,
            is_writable,
            executable,
            rent_epoch,
        });
        off = after + 8;
    }
    Some(out)
}

/// The instruction data and program id at the end of a serialized region.
pub fn deserialize_instruction(input: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let accounts_end = accounts_span(input);
    let n = u64::from_le_bytes(input[accounts_end..accounts_end + 8].try_into().unwrap()) as usize;
    let data = input[accounts_end + 8..accounts_end + 8 + n].to_vec();
    let id: [u8; 32] =
        input[accounts_end + 8 + n..accounts_end + 8 + n + 32].try_into().unwrap();
    (data, id)
}

/// The offset just past the last account, i.e. where the instruction data's length word begins.
fn accounts_span(input: &[u8]) -> usize {
    let n = u64::from_le_bytes(input[0..8].try_into().unwrap()) as usize;
    let mut off = 8usize;
    for _ in 0..n {
        if input[off] != NON_DUP_MARKER {
            off += 8;
            continue;
        }
        let data_len = u64::from_le_bytes(input[off + 80..off + 88].try_into().unwrap()) as usize;
        off = ((off + 88 + data_len + MAX_PERMITTED_DATA_INCREASE + 7) & !7) + 8;
    }
    off
}

// ---- the whole call, as the guest sees it ------------------------------------------------------

/// One call: the program's ELF and its serialized instruction, the two byte strings the input
/// vector carries.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SbpfCall {
    pub elf: Vec<u8>,
    pub input: Vec<u8>,
}

impl SbpfCall {
    /// `[n_elf, elf bytes…, n_input, input bytes…]`, byte strings four per word little-endian and
    /// zero-padded — `sbpf_core::abi::decode_input`'s layout.
    pub fn input_words(&self) -> Vec<u32> {
        let mut w = Vec::new();
        for bytes in [&self.elf, &self.input] {
            w.push(bytes.len() as u32);
            w.extend(bytes.chunks(4).map(|c| {
                let mut b = [0u8; 4];
                b[..c.len()].copy_from_slice(c);
                u32::from_le_bytes(b)
            }));
        }
        w
    }

    /// The eight public output words, the interpreter's own outcome, and the accounts' post-state —
    /// `sbpf-core` run natively over exactly the input vector the guest will read.
    pub fn expected(&self) -> ([u32; 8], Result<u64, Halt>, Vec<Account>) {
        let words = self.input_words();
        let mut ws = Box::new(Workspace::ZERO);
        let mut h = HostRef;
        let (out, result) =
            run_call_with(&mut h, &mut ws, |i| words[i as usize], words.len() as u32);
        // A program may have scribbled over its own input region, so the post-state is read with
        // the fallible walk: an unparseable region reports no accounts rather than panicking.
        let post = try_deserialize_accounts(&ws.input.input[..ws.input.input_len]).unwrap_or_default();
        (out, result, post)
    }
}

// ---- the SPL Token fixture (M4.4's exit test) --------------------------------------------------

/// The SPL Token program's id, `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` — the account the
/// committed ELF was fetched from (`guests-compiled/sbpf/programs/SPL_TOKEN.md`). The program's
/// entrypoint refuses any other id (`ProgramError::IncorrectProgramId`), so this is part of the
/// fixture, not decoration.
pub const SPL_TOKEN_ID: [u8; 32] = [
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237,
    95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
];

/// The committed SPL Token ELF, exactly as the live program-data account held it.
pub const SPL_TOKEN_ELF: &[u8] =
    include_bytes!("../../guests-compiled/sbpf/programs/spl_token.so");

/// `spl_token::state::Mint::LEN`.
pub const MINT_LEN: usize = 82;
/// `spl_token::state::Account::LEN`.
pub const TOKEN_ACCOUNT_LEN: usize = 165;
/// Where a token account's `amount` sits in its data: `mint(32) ‖ owner(32) ‖ amount(8)`.
pub const TOKEN_AMOUNT_AT: usize = 64;
/// `spl_token::instruction::TokenInstruction::Transfer`'s discriminant.
pub const TRANSFER_TAG: u8 = 3;
/// `spl_token::state::AccountState::Initialized`.
pub const ACCOUNT_STATE_INITIALIZED: u8 = 1;

/// A `COption<Pubkey>`: a four-byte little-endian tag then the 32 bytes, zero-filled for `None`.
/// (`COption` is `solana_program::program_option::COption`, which packs its tag as a `u32` — not
/// Borsh's one byte.)
fn coption_pubkey(out: &mut Vec<u8>, k: Option<[u8; 32]>) {
    out.extend_from_slice(&u32::from(k.is_some()).to_le_bytes());
    out.extend_from_slice(&k.unwrap_or([0u8; 32]));
}

/// A `COption<u64>`: the same four-byte tag then eight bytes.
fn coption_u64(out: &mut Vec<u8>, v: Option<u64>) {
    out.extend_from_slice(&u32::from(v.is_some()).to_le_bytes());
    out.extend_from_slice(&v.unwrap_or(0).to_le_bytes());
}

/// `spl_token::state::Mint`'s 82 packed bytes: `COption<Pubkey> mint_authority`, `u64 supply`,
/// `u8 decimals`, `bool is_initialized`, `COption<Pubkey> freeze_authority`.
pub fn mint_data(mint_authority: Option<[u8; 32]>, supply: u64, decimals: u8) -> Vec<u8> {
    let mut d = Vec::with_capacity(MINT_LEN);
    coption_pubkey(&mut d, mint_authority);
    d.extend_from_slice(&supply.to_le_bytes());
    d.push(decimals);
    d.push(1); // is_initialized
    coption_pubkey(&mut d, None); // freeze_authority: none, so no account is ever frozen
    assert_eq!(d.len(), MINT_LEN);
    d
}

/// `spl_token::state::Account`'s 165 packed bytes: `Pubkey mint`, `Pubkey owner`, `u64 amount`,
/// `COption<Pubkey> delegate`, `u8 state`, `COption<u64> is_native`, `u64 delegated_amount`,
/// `COption<Pubkey> close_authority`.
///
/// `delegate` is `None`, so `process_transfer` falls through to `validate_owner`, which is what
/// makes the owner's signature the thing that authorises the transfer; `is_native` is `None`, so no
/// lamports move; `state` is `Initialized`, without which `Account::unpack` refuses the account.
pub fn token_account_data(mint: [u8; 32], owner: [u8; 32], amount: u64) -> Vec<u8> {
    let mut d = Vec::with_capacity(TOKEN_ACCOUNT_LEN);
    d.extend_from_slice(&mint);
    d.extend_from_slice(&owner);
    d.extend_from_slice(&amount.to_le_bytes());
    coption_pubkey(&mut d, None); // delegate
    d.push(ACCOUNT_STATE_INITIALIZED);
    coption_u64(&mut d, None); // is_native
    d.extend_from_slice(&0u64.to_le_bytes()); // delegated_amount
    coption_pubkey(&mut d, None); // close_authority
    assert_eq!(d.len(), TOKEN_ACCOUNT_LEN);
    d
}

/// A 32-byte key from one byte, so the fixture's accounts are distinguishable and reproducible
/// without a keypair. The last byte is perturbed so no key is a run of one value, which is the
/// shape a bug that compares only a prefix would survive.
fn key(tag: u8) -> [u8; 32] {
    let mut k = [tag; 32];
    k[31] = tag ^ 0x5a;
    k
}

/// M4.4's exit-test fixture: an SPL Token `Transfer` of `amount` from a source account holding
/// `SPL_TRANSFER_SOURCE_BALANCE` to a destination holding `SPL_TRANSFER_DEST_BALANCE`, signed by
/// the accounts' common owner, over the committed SPL Token ELF.
///
/// The accounts are serialized in the order `Transfer` expects — `[source (writable),
/// destination (writable), owner (signer)]` — followed by the mint as a trailing read-only account.
/// `Transfer` itself does not read the mint (`TransferChecked` is the variant that does, and it
/// takes it *between* source and destination), so the mint is here for what the output digest
/// covers rather than for what the program reads: the plan's `output_hash` is over **every** account
/// in the region, writable or not, and a fixture with only writable accounts would not exercise
/// that. It lands in `validate_owner`'s unused `signers` slice, which the non-multisig path ignores.
///
/// `amount` above the source's balance is the failure case the exit test's second half uses:
/// `process_transfer` returns `TokenError::InsufficientFunds` and nothing moves.
pub fn spl_transfer(amount: u64) -> SbpfCall {
    let mint = key(1);
    let owner = key(2);
    let mut data = vec![TRANSFER_TAG];
    data.extend_from_slice(&amount.to_le_bytes());
    let accounts = [
        Account {
            key: key(3),
            owner: SPL_TOKEN_ID,
            lamports: 2_039_280,
            data: token_account_data(mint, owner, SPL_TRANSFER_SOURCE_BALANCE),
            is_signer: false,
            is_writable: true,
            executable: false,
            rent_epoch: u64::MAX,
        },
        Account {
            key: key(4),
            owner: SPL_TOKEN_ID,
            lamports: 2_039_280,
            data: token_account_data(mint, owner, SPL_TRANSFER_DEST_BALANCE),
            is_signer: false,
            is_writable: true,
            executable: false,
            rent_epoch: u64::MAX,
        },
        Account {
            key: owner,
            owner: [0u8; 32], // the system program: an ordinary wallet, not a multisig
            lamports: 1_000_000_000,
            data: Vec::new(),
            is_signer: true,
            is_writable: false,
            executable: false,
            rent_epoch: u64::MAX,
        },
        Account {
            key: mint,
            owner: SPL_TOKEN_ID,
            lamports: 1_461_600,
            data: mint_data(Some(owner), SPL_TRANSFER_SOURCE_BALANCE + SPL_TRANSFER_DEST_BALANCE, 6),
            is_signer: false,
            is_writable: false,
            executable: false,
            rent_epoch: u64::MAX,
        },
    ];
    SbpfCall {
        elf: SPL_TOKEN_ELF.to_vec(),
        input: serialize_aligned(&accounts, &data, &SPL_TOKEN_ID),
    }
}

/// The source token account's balance in [`spl_transfer`]'s fixture.
pub const SPL_TRANSFER_SOURCE_BALANCE: u64 = 1_000_000;
/// The destination token account's balance in [`spl_transfer`]'s fixture.
pub const SPL_TRANSFER_DEST_BALANCE: u64 = 7;
