//! The sBPF guest's ABI (M4.4 Task 5): the *aligned* serialized instruction input
//! `solana_program::entrypoint::deserialize` reads, the three SHA-256 digests that bind a run, and
//! the eight public output words.

use rand_zkvm::notes;
use rand_zkvm::sbpf::{self, Account, HostRef};
use sbpf_core::abi;

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
