//! The sBPF guest's ABI (M4.4 Task 5): the *aligned* serialized instruction input
//! `solana_program::entrypoint::deserialize` reads, the three SHA-256 digests that bind a run, and
//! the eight public output words.

mod common;
use common::sbpf_elf_builder::build_elf;

use rand_zkvm::notes;
use rand_zkvm::sbpf::{self, asm, insn, lddw, Account, HostRef};
use sbpf_core::abi;
use sbpf_core::interp::Halt;
use sbpf_core::isa::opc;

const MAX_PERMITTED_DATA_INCREASE: usize = 10_240;

fn account(seed: u8, data_len: usize) -> Account {
    Account {
        key: [seed; 32],
        owner: [seed.wrapping_add(1); 32],
        lamports: 1_000 + u64::from(seed),
        data: (0..data_len).map(|i| (i as u8).wrapping_add(seed)).collect(),
        is_signer: seed % 2 == 0,
        is_writable: seed % 3 == 0,
        executable: false,
        rent_epoch: 0xffff_ffff_ffff_ffff,
    }
}

#[test]
fn serialize_aligned_matches_the_documented_offsets() {
    // Two accounts, the second a duplicate of the first, the first carrying 165 bytes of data (an
    // SPL Token account).
    let a = account(7, 165);
    let ix_data = [1u8, 2, 3, 4, 5, 6, 7, 8, 9];
    let program_id = [0x42u8; 32];
    let buf = sbpf::serialize_aligned(&[a.clone(), a.clone()], &ix_data, &program_id);

    // `u64 n_accounts`.
    assert_eq!(u64::from_le_bytes(buf[0..8].try_into().unwrap()), 2);

    // Account 0, not a duplicate: the 0xff marker, three flag bytes, four bytes of padding (the
    // `original_data_len` slot), the key, the owner, lamports, data_len, the data.
    assert_eq!(buf[8], 0xff);
    assert_eq!(buf[9], u8::from(a.is_signer));
    assert_eq!(buf[10], u8::from(a.is_writable));
    assert_eq!(buf[11], u8::from(a.executable));
    assert_eq!(&buf[12..16], &[0, 0, 0, 0]);
    assert_eq!(&buf[16..48], &a.key);
    assert_eq!(&buf[48..80], &a.owner);
    assert_eq!(u64::from_le_bytes(buf[80..88].try_into().unwrap()), a.lamports);
    assert_eq!(u64::from_le_bytes(buf[88..96].try_into().unwrap()), 165);
    assert_eq!(&buf[96..96 + 165], &a.data[..]);

    // 10 240 bytes of realloc padding, then padding up to an 8-byte boundary (96 + 165 + 10 240 =
    // 10 501, so three bytes), then `u64 rent_epoch`.
    let after_data = 96 + 165;
    let after_realloc = after_data + MAX_PERMITTED_DATA_INCREASE;
    assert_eq!(after_realloc, 10_501);
    assert_eq!(&buf[after_data..after_realloc], &[0u8; MAX_PERMITTED_DATA_INCREASE][..]);
    assert_eq!(&buf[after_realloc..10_504], &[0, 0, 0]);
    assert_eq!(u64::from_le_bytes(buf[10_504..10_512].try_into().unwrap()), a.rent_epoch);

    // Account 1 is a duplicate of account 0: its index, then seven bytes of padding, and nothing
    // else at all.
    assert_eq!(buf[10_512], 0);
    assert_eq!(&buf[10_513..10_520], &[0u8; 7]);

    // Then `u64 data_len`, the instruction data, and the 32-byte program id.
    assert_eq!(u64::from_le_bytes(buf[10_520..10_528].try_into().unwrap()), 9);
    assert_eq!(&buf[10_528..10_537], &ix_data);
    assert_eq!(&buf[10_537..10_569], &program_id);
    assert_eq!(buf.len(), 10_569);

    // And the whole thing round-trips: a duplicate comes back as a copy of what it duplicates.
    let back = sbpf::deserialize_accounts(&buf);
    assert_eq!(back, vec![a.clone(), a]);
}

#[test]
fn serialize_aligned_round_trips_several_shapes() {
    // A zero-length account's data section is empty and its rent epoch is still 8-byte aligned;
    // an account whose data length is already a multiple of 8 needs no boundary padding at all.
    for lens in [vec![0usize], vec![8], vec![1, 7, 8, 9], vec![], vec![165, 82, 0]] {
        let accounts: Vec<Account> =
            lens.iter().enumerate().map(|(i, &n)| account(i as u8, n)).collect();
        let buf = sbpf::serialize_aligned(&accounts, b"ix", &[9u8; 32]);
        // Every account's `rent_epoch` lands on an 8-byte boundary, so the region up to the
        // instruction data is always a whole number of words.
        assert_eq!((buf.len() - 32 - 2) % 8, 0);
        assert_eq!(sbpf::deserialize_accounts(&buf), accounts);
    }
}

#[test]
fn output_hash_covers_lamports_and_data_of_every_account() {
    let mut h = HostRef;
    let a = account(1, 40);
    let b = account(2, 40);
    // `b` is not writable (seed 2 is not a multiple of 3) and must still be covered.
    assert!(!b.is_writable);
    let base = sbpf::serialize_aligned(&[a.clone(), b.clone()], b"ix", &[0u8; 32]);
    let h0 = abi::output_hash(&mut h, &base);

    // One data byte of the writable account changes the hash.
    let mut a2 = a.clone();
    a2.data[7] ^= 1;
    let buf = sbpf::serialize_aligned(&[a2, b.clone()], b"ix", &[0u8; 32]);
    assert_ne!(abi::output_hash(&mut h, &buf), h0);

    // One data byte of the *non-writable* account changes it too.
    let mut b2 = b.clone();
    b2.data[0] ^= 1;
    let buf = sbpf::serialize_aligned(&[a.clone(), b2], b"ix", &[0u8; 32]);
    assert_ne!(abi::output_hash(&mut h, &buf), h0);

    // So do lamports.
    let mut b3 = b.clone();
    b3.lamports += 1;
    let buf = sbpf::serialize_aligned(&[a.clone(), b3], b"ix", &[0u8; 32]);
    assert_ne!(abi::output_hash(&mut h, &buf), h0);

    // The instruction data and the program id are *not* part of the output hash — they are the
    // input, bound by `input_hash` instead.
    let buf = sbpf::serialize_aligned(&[a.clone(), b.clone()], b"other", &[1u8; 32]);
    assert_eq!(abi::output_hash(&mut h, &buf), h0);

    // And it is exactly the documented preimage: per account in order, lamports and data_len as
    // eight little-endian bytes each, then the data.
    let mut msg = Vec::new();
    for acc in [&a, &b] {
        msg.extend_from_slice(&acc.lamports.to_le_bytes());
        msg.extend_from_slice(&(acc.data.len() as u64).to_le_bytes());
        msg.extend_from_slice(&acc.data);
    }
    assert_eq!(h0, rand_zkvm::sha256::sha256(&msg));

    // A duplicate account entry is hashed again, at the position it occupies.
    let buf = sbpf::serialize_aligned(&[a.clone(), a.clone()], b"ix", &[0u8; 32]);
    let mut msg = Vec::new();
    for _ in 0..2 {
        msg.extend_from_slice(&a.lamports.to_le_bytes());
        msg.extend_from_slice(&(a.data.len() as u64).to_le_bytes());
        msg.extend_from_slice(&a.data);
    }
    assert_eq!(abi::output_hash(&mut h, &buf), rand_zkvm::sha256::sha256(&msg));

    // A region that is not a serialized instruction at all yields a digest rather than a panic:
    // the walk stops where the bytes run out. (Both the pre- and post-state hashes go through
    // this same walk, so a run over a malformed region still binds consistently.)
    for junk in [&[][..], &[0xff][..], &[7, 0, 0, 0, 0, 0, 0, 0][..], &[0xff; 200][..]] {
        let _ = abi::output_hash(&mut h, junk);
    }
}

#[test]
fn the_public_output_binds_program_input_and_post_state() {
    let mut h = HostRef;
    let program_hash = rand_zkvm::sha256::sha256(b"an elf");
    let input_hash = rand_zkvm::sha256::sha256(b"an input");
    let out_hash = rand_zkvm::sha256::sha256(b"a post-state");
    let out = abi::public_output(&mut h, 1, &program_hash, &input_hash, &out_hash);

    // `out0` is the status word; `out1..7` are words 0..6 of the domain-tagged Poseidon2 sponge
    // over the 24-word preimage, mirrored here with the host's own `notes::hash`.
    assert_eq!(out[0], 1);
    let mut msg = [0u32; 24];
    for (i, bytes) in [program_hash, input_hash, out_hash].iter().enumerate() {
        for j in 0..8 {
            msg[8 * i + j] = u32::from_le_bytes(bytes[4 * j..4 * j + 4].try_into().unwrap());
        }
    }
    let d = notes::hash(notes::domain::SBPF_OUT, &msg);
    assert_eq!(&out[1..8], &d[..7]);
    assert_eq!(notes::domain::SBPF_OUT, 14);
    assert_eq!(abi::SBPF_OUT_DOMAIN, notes::domain::SBPF_OUT);

    // Every one of the three digests, and the status word, is bound: changing any one changes the
    // output.
    assert_ne!(abi::public_output(&mut h, 0, &program_hash, &input_hash, &out_hash), out);
    assert_ne!(abi::public_output(&mut h, 2, &program_hash, &input_hash, &out_hash), out);
    assert_ne!(abi::public_output(&mut h, 1, &input_hash, &input_hash, &out_hash), out);
    assert_ne!(abi::public_output(&mut h, 1, &program_hash, &out_hash, &out_hash), out);
    assert_ne!(abi::public_output(&mut h, 1, &program_hash, &input_hash, &input_hash), out);
    // The status word is `out0` only: it does not enter the digest, so the low seven words of two
    // runs that differ only in status are the same.
    let zero = abi::public_output(&mut h, 0, &program_hash, &input_hash, &out_hash);
    assert_eq!(&zero[1..], &out[1..]);
}

#[test]
fn the_input_vector_round_trips_through_the_cursor() {
    // `[n_elf, elf bytes…, n_input, input bytes…]`, byte strings four per word little-endian and
    // zero-padded.
    let call = sbpf::SbpfCall { elf: (0..=250u8).collect(), input: b"the input".to_vec() };
    let words = call.input_words();
    assert_eq!(words[0], 251);
    assert_eq!(words[1], u32::from_le_bytes([0, 1, 2, 3]));
    assert_eq!(words.len(), 1 + 251usize.div_ceil(4) + 1 + 9usize.div_ceil(4));
    assert_eq!(words[1 + 251usize.div_ceil(4)], 9);

    let mut ws = Box::new(abi::Workspace::ZERO);
    let mut c = abi::InputCursor::new(|i| words[i as usize], words.len() as u32);
    abi::decode_input(&mut ws.input, &mut c).unwrap();
    assert_eq!(&ws.input.elf[..ws.input.elf_len], &call.elf[..]);
    assert_eq!(&ws.input.input[..ws.input.input_len], &call.input[..]);

    // A vector that ends before the layout does is a parse error, not a panic.
    let mut c = abi::InputCursor::new(|i| words[i as usize], 3);
    assert_eq!(abi::decode_input(&mut ws.input, &mut c), Err(abi::ParseError::Truncated));
    // An ELF or input length above its cap is refused without ever reading that many words.
    let big = [u32::MAX, 0, 0];
    let mut c = abi::InputCursor::new(|i| big[i as usize], 3);
    assert_eq!(abi::decode_input(&mut ws.input, &mut c), Err(abi::ParseError::ElfTooLong));
    let big = [0u32, u32::MAX];
    let mut c = abi::InputCursor::new(|i| big[i as usize], 2);
    assert_eq!(abi::decode_input(&mut ws.input, &mut c), Err(abi::ParseError::InputTooLong));
}

#[test]
fn a_malformed_input_vector_is_status_two_with_a_canonical_digest() {
    let mut h = HostRef;
    let mut ws = Box::new(abi::Workspace::ZERO);
    let words = [7u32, 0];
    let out = abi::run_call(&mut h, &mut ws, |i| words[i as usize], words.len() as u32);
    assert_eq!(out[0], 2);
    // The canonical malformed output: status 2 over three all-zero digests, so a verifier that
    // recomputes the digest from the ELF and input it meant to run gets something else.
    let z = [0u8; 32];
    assert_eq!(out, abi::public_output(&mut h, 2, &z, &z, &z));
}

/// The documented preimage, computed independently of `abi::output_hash`: per **entry** in the
/// order the region lists them (a duplicate entry contributing the account it duplicates),
/// lamports and data_len as eight little-endian bytes each, then the data.
fn expected_output_hash(entries: &[&Account]) -> [u8; 32] {
    let mut msg = Vec::new();
    for a in entries {
        msg.extend_from_slice(&a.lamports.to_le_bytes());
        msg.extend_from_slice(&(a.data.len() as u64).to_le_bytes());
        msg.extend_from_slice(&a.data);
    }
    rand_zkvm::sha256::sha256(&msg)
}

#[test]
fn output_hash_resolves_a_duplicate_against_the_full_entry_list() {
    // A duplicate's marker byte indexes **all** entries seen so far, duplicates included — the
    // index space `solana_program::entrypoint::deserialize` pushes into
    // (`accounts.push(accounts[dup_info].clone())` over a `Vec` that already holds duplicates).
    // Resolving it against the non-duplicate entries instead is silently wrong, and these two
    // shapes are what tell the two apart.
    let mut h = HostRef;
    let (a, b, c) = (account(1, 16), account(2, 24), account(3, 32));

    // `[A, A, B, B]`: the fourth entry's marker is 2. Against the full list that is `B`; against
    // the non-duplicate list there is no index 2 at all, so a walk over that index space runs out
    // and silently hashes a three-entry prefix.
    let buf = sbpf::serialize_aligned(&[a.clone(), a.clone(), b.clone(), b.clone()], b"ix", &[0; 32]);
    assert_eq!(sbpf::deserialize_accounts(&buf), vec![a.clone(), a.clone(), b.clone(), b.clone()]);
    assert_eq!(abi::output_hash(&mut h, &buf), expected_output_hash(&[&a, &a, &b, &b]));
    // And it is genuinely four entries, not the three-entry prefix the bug produced.
    assert_ne!(abi::output_hash(&mut h, &buf), expected_output_hash(&[&a, &a, &b]));

    // `[A, A, B, C, B]`: the fifth entry's marker is 2. Against the full list that is `B`; against
    // the non-duplicate list index 2 is `C` — the wrong account, hashed without any error.
    let buf = sbpf::serialize_aligned(
        &[a.clone(), a.clone(), b.clone(), c.clone(), b.clone()],
        b"ix",
        &[0; 32],
    );
    assert_eq!(
        sbpf::deserialize_accounts(&buf),
        vec![a.clone(), a.clone(), b.clone(), c.clone(), b.clone()]
    );
    assert_eq!(abi::output_hash(&mut h, &buf), expected_output_hash(&[&a, &a, &b, &c, &b]));
    assert_ne!(abi::output_hash(&mut h, &buf), expected_output_hash(&[&a, &a, &b, &c, &c]));

    // A duplicate *of a duplicate* lands on the same account either way: `[A, A, A]`'s third entry
    // carries the byte 1, which is itself a duplicate entry.
    let buf = sbpf::serialize_aligned(&[a.clone(), a.clone(), a.clone()], b"ix", &[0; 32]);
    assert_eq!(abi::output_hash(&mut h, &buf), expected_output_hash(&[&a, &a, &a]));

    // A marker pointing at an entry that does not exist yet (its own ordinal, or beyond) is not a
    // duplicate of anything: the walk stops rather than reading a slot it never filled.
    let mut buf = sbpf::serialize_aligned(&[a.clone(), a.clone()], b"ix", &[0; 32]);
    let dup_at = buf.len() - 32 - 8 - 2 - 8;
    assert_eq!(buf[dup_at], 0, "the second entry's marker byte");
    buf[dup_at] = 1; // its own ordinal
    assert_eq!(abi::output_hash(&mut h, &buf), expected_output_hash(&[&a]));
    buf[dup_at] = 200;
    assert_eq!(abi::output_hash(&mut h, &buf), expected_output_hash(&[&a]));
}

#[test]
fn output_hash_refuses_an_account_count_that_would_truncate() {
    // A count above `u32::MAX` must not be narrowed into a small, plausible-looking number on the
    // 32-bit target: it is clamped in `u64`, so the walk simply runs out of region.
    let mut h = HostRef;
    let a = account(1, 8);
    let mut buf = sbpf::serialize_aligned(&[a.clone()], b"ix", &[0; 32]);
    buf[0..8].copy_from_slice(&(u64::from(u32::MAX) + 2).to_le_bytes());
    // The one real entry is hashed, then the region runs out — never a panic, and never a walk
    // that believed there was exactly one account because the count truncated to 1.
    assert_eq!(abi::output_hash(&mut h, &buf), expected_output_hash(&[&a]));
    buf[0..8].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(abi::output_hash(&mut h, &buf), expected_output_hash(&[&a]));
}

// ---- the whole call: `run_call_with` over a hand-built ELF ------------------------------------

/// The offset of account 0's `lamports` in a serialized region: the count, then the marker, three
/// flag bytes, the `original_data_len` slot, the key and the owner.
const LAMPORTS_AT: i16 = 8 + 8 + 32 + 32;

/// A program that stores `lamports` into account 0 and then does `tail`.
fn lamports_writer(lamports: u64, tail: &[[u8; 8]]) -> Vec<u8> {
    let mut p: Vec<[u8; 8]> = Vec::new();
    p.extend_from_slice(&lddw(2, lamports));
    p.push(insn(opc::ST_DW_REG, 1, 2, LAMPORTS_AT, 0)); // r1 is the input region's base
    p.extend_from_slice(tail);
    asm(&p)
}

/// Runs one whole call the way the guest will: the input vector through `abi::run_call_with`.
fn run(elf: &[u8], input: &[u8]) -> ([u32; 8], Result<u64, Halt>, Vec<u8>) {
    let call = sbpf::SbpfCall { elf: elf.to_vec(), input: input.to_vec() };
    let words = call.input_words();
    let mut ws = Box::new(abi::Workspace::ZERO);
    let mut h = HostRef;
    let (out, result) =
        abi::run_call_with(&mut h, &mut ws, |i| words[i as usize], words.len() as u32);
    (out, result, ws.input.input[..ws.input.input_len].to_vec())
}

#[test]
fn a_successful_run_publishes_status_one_and_the_post_state() {
    let mut h = HostRef;
    let a = account(5, 0);
    let input = sbpf::serialize_aligned(&[a.clone()], b"ix", &[7u8; 32]);
    let elf = build_elf(
        &lamports_writer(999, &[insn(opc::MOV64_IMM, 0, 0, 0, 0), insn(opc::EXIT, 0, 0, 0, 0)]),
        &[],
        &[],
        &[],
        0,
    );

    let (out, result, post) = run(&elf, &input);
    assert_eq!(result, Ok(0));
    assert_eq!(out[0], 1, "r0 == 0 is status 1");

    // The mutation is real and readable back out of the workspace.
    let post_accounts = sbpf::deserialize_accounts(&post);
    assert_eq!(post_accounts[0].lamports, 999);
    assert_ne!(a.lamports, 999, "the fixture would not otherwise prove anything");
    // Everything but the lamports word is untouched.
    let mut expected_post = a.clone();
    expected_post.lamports = 999;
    assert_eq!(post_accounts, vec![expected_post.clone()]);

    // And the digest is over the POST-state, which is not the pre-state.
    let pre_hash = abi::output_hash(&mut h, &input);
    let post_hash = abi::output_hash(&mut h, &post);
    assert_ne!(post_hash, pre_hash);
    assert_eq!(post_hash, expected_output_hash(&[&expected_post]));
    assert_eq!(
        out,
        abi::public_output(
            &mut h,
            1,
            &rand_zkvm::sha256::sha256(&elf),
            &rand_zkvm::sha256::sha256(&input),
            &post_hash,
        )
    );
}

#[test]
fn a_nonzero_return_publishes_status_zero_over_the_pre_state() {
    let mut h = HostRef;
    let a = account(5, 0);
    let input = sbpf::serialize_aligned(&[a.clone()], b"ix", &[7u8; 32]);
    // Mutates the account, *then* returns a `ProgramError`: the effect must not be published.
    let elf = build_elf(
        &lamports_writer(999, &[insn(opc::MOV64_IMM, 0, 0, 0, 42), insn(opc::EXIT, 0, 0, 0, 0)]),
        &[],
        &[],
        &[],
        0,
    );

    let (out, result, post) = run(&elf, &input);
    assert_eq!(result, Ok(42));
    assert_eq!(out[0], 0, "a non-zero r0 is status 0");
    // The run really did change the region — the rule is about what is *bound*, not about undoing.
    assert_eq!(sbpf::deserialize_accounts(&post)[0].lamports, 999);
    let pre_hash = abi::output_hash(&mut h, &input);
    assert_eq!(
        out,
        abi::public_output(
            &mut h,
            0,
            &rand_zkvm::sha256::sha256(&elf),
            &rand_zkvm::sha256::sha256(&input),
            &pre_hash, // the PRE-state
        )
    );
    // The error code itself is not published (the seven digest words are spoken for), so two
    // different non-zero returns are indistinguishable in the output.
    let other = build_elf(
        &lamports_writer(999, &[insn(opc::MOV64_IMM, 0, 0, 0, 43), insn(opc::EXIT, 0, 0, 0, 0)]),
        &[],
        &[],
        &[],
        0,
    );
    let (out_other, result_other, _) = run(&other, &input);
    assert_eq!(result_other, Ok(43));
    // Only because the two ELFs differ do the digests differ; the status word is the same.
    assert_eq!(out_other[0], out[0]);
}

#[test]
fn an_exceptional_halt_publishes_status_two_over_the_pre_state() {
    let mut h = HostRef;
    let a = account(5, 0);
    let input = sbpf::serialize_aligned(&[a.clone()], b"ix", &[7u8; 32]);
    // Mutates the account and *then* halts — a load through r0, which is zero, so address 0. This
    // is the rule that stops a partial effect being published: whatever the program managed to do
    // before it died, the digest says nothing happened.
    let elf = build_elf(
        &lamports_writer(999, &[insn(opc::LD_DW_REG, 3, 0, 0, 0), insn(opc::EXIT, 0, 0, 0, 0)]),
        &[],
        &[],
        &[],
        0,
    );

    let (out, result, post) = run(&elf, &input);
    assert_eq!(result, Err(Halt::AccessViolation(0)));
    assert_eq!(out[0], 2, "an exceptional halt is status 2");
    assert_eq!(sbpf::deserialize_accounts(&post)[0].lamports, 999, "the write did happen");
    let pre_hash = abi::output_hash(&mut h, &input);
    assert_eq!(
        out,
        abi::public_output(
            &mut h,
            2,
            &rand_zkvm::sha256::sha256(&elf),
            &rand_zkvm::sha256::sha256(&input),
            &pre_hash, // the PRE-state, not the mutated region
        )
    );

    // An ELF that does not load at all is status 2 the same way, over the same pre-state.
    let mut broken = elf.clone();
    broken[18] = 0xff; // e_machine
    let (out, result, _) = run(&broken, &input);
    assert_eq!(result, Err(Halt::BadElf));
    assert_eq!(out[0], 2);
    assert_eq!(
        out,
        abi::public_output(
            &mut h,
            2,
            &rand_zkvm::sha256::sha256(&broken),
            &rand_zkvm::sha256::sha256(&input),
            &pre_hash,
        )
    );
}

#[test]
fn the_run_starts_at_the_elf_entrypoint_and_sees_the_whole_input_region() {
    // The guest's `r1` is the input region's base and the region is exactly `input_len` bytes: a
    // program that reads the last byte succeeds and one that reads the next byte halts.
    let a = account(5, 4);
    let input = sbpf::serialize_aligned(&[a], b"ix", &[7u8; 32]);
    let last = (input.len() - 1) as u64;

    let mut p: Vec<[u8; 8]> = Vec::new();
    p.extend_from_slice(&lddw(2, last));
    p.push(insn(opc::ADD64_REG, 1, 2, 0, 0));
    p.push(insn(opc::LD_B_REG, 0, 1, 0, 0));
    p.push(insn(opc::MOV64_IMM, 0, 0, 0, 0));
    p.push(insn(opc::EXIT, 0, 0, 0, 0));
    let (out, result, _) = run(&build_elf(&asm(&p), &[], &[], &[], 0), &input);
    assert_eq!(result, Ok(0));
    assert_eq!(out[0], 1);

    let mut p: Vec<[u8; 8]> = Vec::new();
    p.extend_from_slice(&lddw(2, last + 1));
    p.push(insn(opc::ADD64_REG, 1, 2, 0, 0));
    p.push(insn(opc::LD_B_REG, 0, 1, 0, 0));
    p.push(insn(opc::MOV64_IMM, 0, 0, 0, 0));
    p.push(insn(opc::EXIT, 0, 0, 0, 0));
    let (out, result, _) = run(&build_elf(&asm(&p), &[], &[], &[], 0), &input);
    assert!(matches!(result, Err(Halt::AccessViolation(_))), "{result:?}");
    assert_eq!(out[0], 2);

    // A non-zero entrypoint is honoured: two separate two-slot routines, each with its own `exit`,
    // so entering at slot 0 cannot fall through into the one at slot 2.
    let text = asm(&[
        insn(opc::MOV64_IMM, 0, 0, 0, 1),
        insn(opc::EXIT, 0, 0, 0, 0),
        insn(opc::MOV64_IMM, 0, 0, 0, 0),
        insn(opc::EXIT, 0, 0, 0, 0),
    ]);
    assert_eq!(run(&build_elf(&text, &[], &[], &[], 0), &input).1, Ok(1));
    assert_eq!(run(&build_elf(&text, &[], &[], &[], 2), &input).1, Ok(0));
    // And the status word follows: a non-zero `r0` is status 0, a zero one status 1.
    assert_eq!(run(&build_elf(&text, &[], &[], &[], 0), &input).0[0], 0);
    assert_eq!(run(&build_elf(&text, &[], &[], &[], 2), &input).0[0], 1);
}

#[test]
fn a_workspace_can_be_reused_without_carrying_state_over() {
    // The guest holds one `Workspace` in `.bss`; a host test that runs two calls through one must
    // get the same answers as two fresh ones, or the stack/heap zeroing is not doing its job.
    let a = account(5, 0);
    let input = sbpf::serialize_aligned(&[a], b"ix", &[7u8; 32]);
    // Reads a stack slot it never wrote, so a workspace carrying a previous run's frame would
    // answer differently.
    let leaky = build_elf(
        &asm(&[
            insn(opc::LD_DW_REG, 0, 10, -8, 0),
            insn(opc::EXIT, 0, 0, 0, 0),
        ]),
        &[],
        &[],
        &[],
        0,
    );
    let writer = build_elf(
        &asm(&[
            insn(opc::MOV64_IMM, 2, 0, 0, 0x5eed),
            insn(opc::ST_DW_REG, 10, 2, -8, 0),
            insn(opc::MOV64_IMM, 0, 0, 0, 0),
            insn(opc::EXIT, 0, 0, 0, 0),
        ]),
        &[],
        &[],
        &[],
        0,
    );

    let fresh = run(&leaky, &input);
    assert_eq!(fresh.1, Ok(0), "an unwritten stack slot reads as zero");

    let mut ws = Box::new(abi::Workspace::ZERO);
    let mut h = HostRef;
    for elf in [&writer, &leaky] {
        let call = sbpf::SbpfCall { elf: elf.clone(), input: input.clone() };
        let words = call.input_words();
        let (out, result) =
            abi::run_call_with(&mut h, &mut ws, |i| words[i as usize], words.len() as u32);
        if elf == &leaky {
            assert_eq!(result, Ok(0), "the previous run's frame did not leak into this one");
            assert_eq!(out, fresh.0);
        }
    }
}
