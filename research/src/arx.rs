//! `Arx8`: the hash every note commitment, nullifier and key in `notes.rs` is built from,
//! written twice — once as plain Rust (the reference), once as an assembler emitter that
//! produces the same function in RV32I for a guest to run under `R_exec`. They are kept in
//! one file, and `tests/viewing.rs` checks them word-for-word against each other, so they
//! cannot drift.
//!
//! **Why an ARX hash at all.** Milestone 1's ISA is RV32I with no multiplier and no hash
//! syscall (`docs/01-isa.md`), so the only hash a guest can afford is one made of adds,
//! xors and rotates. `Arx8` is a 256-bit ChaCha-style permutation (eight 32-bit words, the
//! ChaCha quarter-round, `ROUNDS` rounds of column/cross mixing) run as a sponge with a
//! four-word rate and a four-word capacity. It is a *development stand-in* for the
//! Poseidon2 chip of milestone 3 (`docs/05-roadmap.md`), exactly as `PERM_SEED` is a
//! stand-in for the published Poseidon2 constants: the structure of everything built on it
//! (`notes.rs`, `viewing.rs`, the `transfer` guest) survives the swap unchanged, only the
//! cost per hash changes. Its outputs are 64 bits wide because the machine's words are 32
//! bits and every note field is one or two words; those are development widths, not a
//! security claim (`docs/06-viewing-keys.md`).

use crate::asm::{ops::*, Assembler};
use crate::isa::{BranchCond, REG_RA, REG_ZERO};

/// Four rounds of four quarter-rounds: the same quarter-round density per state word as
/// ChaCha8. Chosen so the `transfer` guest's nine permutations fit gas tier 12
/// (`docs/06-viewing-keys.md` has the cycle budget); production replaces the whole
/// function, not this number.
pub const ROUNDS: usize = 4;
pub const RATE: usize = 4;
const IV: [u32; 2] = [0x5261_6e64, 0x4152_5838]; // "Rand", "ARX8"

/// Fixed domain tags. Every use of the hash has its own tag in the capacity, so a note
/// commitment can never collide with a nullifier or a key even on identical inputs.
pub mod domain {
    pub const NK: u32 = 1;
    pub const PK: u32 = 2;
    pub const NF: u32 = 3;
    pub const CM: u32 = 4;
    pub const OVK: u32 = 5;
    pub const KEM_SEED: u32 = 6;
    pub const TEST: u32 = 0xff;
}

#[inline]
fn qr(s: &mut [u32; 8], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(7);
}

/// One round: two column quarter-rounds, then two that cross the halves.
const SCHEDULE: [[usize; 4]; 4] = [[0, 1, 2, 3], [4, 5, 6, 7], [0, 5, 2, 7], [4, 1, 6, 3]];

pub fn permute(s: &mut [u32; 8]) {
    for _ in 0..ROUNDS {
        for [a, b, c, d] in SCHEDULE { qr(s, a, b, c, d); }
    }
}

/// Initial state: an empty rate, and `(domain, IV, IV, len)` in the capacity. `len` is the
/// message length in words, so zero-padding the last block is unambiguous.
fn init(domain: u32, len: usize) -> [u32; 8] { [0, 0, 0, 0, domain, IV[0], IV[1], len as u32] }

/// Absorbs `blocks(msg.len())` rate-sized blocks, the last one zero-padded — the same loop
/// `emit_hash` runs, so an empty message still costs one permutation on both sides.
fn absorb(s: &mut [u32; 8], msg: &[u32]) {
    for b in 0..blocks(msg.len()) {
        for i in 0..RATE {
            if let Some(w) = msg.get(b * RATE + i) { s[i] ^= w; }
        }
        permute(s);
    }
}

/// Sponge hash of `msg` under `domain`, squeezed to `out.len()` words.
pub fn squeeze(domain: u32, msg: &[u32], out: &mut [u32]) {
    let mut s = init(domain, msg.len());
    absorb(&mut s, msg);
    let mut i = 0;
    while i < out.len() {
        let n = RATE.min(out.len() - i);
        out[i..i + n].copy_from_slice(&s[..n]);
        i += n;
        if i < out.len() { permute(&mut s); }
    }
}

/// The two-word digest every commitment, nullifier and key uses.
pub fn hash(domain: u32, msg: &[u32]) -> [u32; 2] {
    let mut out = [0u32; 2];
    squeeze(domain, msg, &mut out);
    out
}

/// Number of rate-sized blocks a `len`-word message absorbs (at least one).
pub fn blocks(len: usize) -> usize { len.div_ceil(RATE).max(1) }

// ───────────────────────────── guest side ─────────────────────────────

/// Register allocation shared by the emitted routines and their callers.
pub mod reg {
    /// The eight state words live in callee-saved registers s0, s1, s2..s7 (x8, x9, x18..x23).
    pub const STATE: [u32; 8] = [8, 9, 18, 19, 20, 21, 22, 23];
    /// Scratch for rotates; clobbered by `perm`.
    pub const TMP: u32 = 5;      // t0
    /// `hash` keeps its own return address here while it calls `perm`.
    pub const SAVED_RA: u32 = 24; // s8
    pub const PTR: u32 = 6;      // t1
    pub const BLOCKS: u32 = 7;   // t2
    pub const WORD: u32 = 28;    // t3
    /// Arguments to `hash`: message byte address, length in words, domain, block count.
    pub const ARG_PTR: u32 = 10;    // a0
    pub const ARG_LEN: u32 = 11;    // a1
    pub const ARG_DOMAIN: u32 = 12; // a2
    pub const ARG_BLOCKS: u32 = 13; // a3
}

/// `rotl rd, rs, n` as three RV32I instructions; `tmp` is clobbered.
fn rotl(a: &mut Assembler, rd: u32, rs: u32, n: u32, tmp: u32) {
    a.push(slli(tmp, rs, n));
    a.push(srli(rd, rs, 32 - n));
    a.push(or(rd, rd, tmp));
}

fn emit_qr(a: &mut Assembler, s: &[u32; 8], [ia, ib, ic, id]: [usize; 4]) {
    let (ra, rb, rc, rd) = (s[ia], s[ib], s[ic], s[id]);
    a.push(add(ra, ra, rb)); a.push(xor(rd, rd, ra)); rotl(a, rd, rd, 16, reg::TMP);
    a.push(add(rc, rc, rd)); a.push(xor(rb, rb, rc)); rotl(a, rb, rb, 12, reg::TMP);
    a.push(add(ra, ra, rb)); a.push(xor(rd, rd, ra)); rotl(a, rd, rd, 8, reg::TMP);
    a.push(add(rc, rc, rd)); a.push(xor(rb, rb, rc)); rotl(a, rb, rb, 7, reg::TMP);
}

/// Emits the `perm` subroutine at the current position under label `perm`: permutes
/// `reg::STATE` in place, clobbers `reg::TMP`, returns through `ra`. `80 * ROUNDS + 1` instructions.
pub fn emit_perm(a: &mut Assembler) {
    a.label("perm");
    for _ in 0..ROUNDS {
        for sched in SCHEDULE { emit_qr(a, &reg::STATE, sched); }
    }
    a.push(jalr(REG_ZERO, REG_RA, 0));
}

/// Emits the `hash` subroutine under label `hash`. Arguments in `reg::ARG_*`: the message's
/// byte address in RAM (whole words, zero-padded to a multiple of `RATE`), its length in
/// words, the domain tag, and the block count. Leaves the digest in `STATE[0..2]` (the full
/// rate `STATE[0..4]` is valid too). Requires `emit_perm` somewhere in the same program.
pub fn emit_hash(a: &mut Assembler) {
    use reg::*;
    let s = STATE;
    a.label("hash");
    a.push(mv(SAVED_RA, REG_RA));
    for r in &s[..4] { a.push(mv(*r, REG_ZERO)); }
    a.push(mv(s[4], ARG_DOMAIN));
    a.extend(li(s[5], IV[0] as i32));
    a.extend(li(s[6], IV[1] as i32));
    a.push(mv(s[7], ARG_LEN));
    a.push(mv(PTR, ARG_PTR));
    a.push(mv(BLOCKS, ARG_BLOCKS));
    a.label("hash_block");
    a.branch(BranchCond::Eq, BLOCKS, REG_ZERO, "hash_done");
    for i in 0..RATE {
        a.push(lw(WORD, PTR, 4 * i as i32));
        a.push(xor(s[i], s[i], WORD));
    }
    a.push(addi(PTR, PTR, 4 * RATE as i32));
    a.push(addi(BLOCKS, BLOCKS, -1));
    a.jal(REG_RA, "perm");
    a.jal(REG_ZERO, "hash_block");
    a.label("hash_done");
    a.push(jalr(REG_ZERO, SAVED_RA, 0));
}

/// Emits a call: `hash(msg_addr, len, domain)`. The caller has already stored the
/// zero-padded message at `msg_addr`.
pub fn emit_call_hash(a: &mut Assembler, msg_addr: i32, len: usize, domain: u32) {
    use reg::*;
    a.extend(li(ARG_PTR, msg_addr));
    a.extend(li(ARG_LEN, len as i32));
    a.extend(li(ARG_DOMAIN, domain as i32));
    a.extend(li(ARG_BLOCKS, blocks(len) as i32));
    a.jal(REG_RA, "hash");
}

/// Bytes a `len`-word message occupies in RAM once zero-padded to whole blocks.
pub fn padded_bytes(len: usize) -> i32 { (blocks(len) * RATE * 4) as i32 }
