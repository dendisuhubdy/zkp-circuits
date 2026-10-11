#![no_std]
#![no_main]

//! `msauth`: the M-of-N spend-authority relation of the private multisig
//! (`docs/superpowers/specs/2026-10-11-private-multisig-design.md` §4).
//!
//! Private input (`research/src/msauth.rs`'s `msauth_inputs`): `msk` at `0..8`, `salt` at
//! `8..16`, `threshold` at `16`, then `M_MAX` slots of `SLOT` words at `17 + SLOT·s`:
//! `[active, index, pk(328), sig(605), path(32)]`. Public input `0..8`: the transaction binding.
//!
//! Accepted only if `1 <= threshold <= M_MAX`, every `active` is 0 or 1, the active slots carry
//! strictly increasing indices below 16 (so they name distinct members), every active slot's
//! pk opens to one common signer root and its Dilithium2 signature over
//! `"rand-msauth-1" ‖ binding` verifies, and at least `threshold` slots are active. Then
//! `nk = H(NK_MS, msk ‖ H(MS_POLICY, threshold ‖ root))` and output `0..8` is
//! `H(AUTH, nk ‖ salt)`. Anything else panics: the SDK's handler writes `0xdead_beef` to output
//! slot 7 and halts (no output slot is written before the last check).

use dilithium_core::ring::Arena;
use dilithium_core::verify_words_with;
use guest_sdk::{halt, poseidon2, read_input, read_input_words, read_public, write_output, SyscallKeccak, SyscallRing};

/// The ring arena (21 KiB), in `.bss`, shared by the (sequential) signature checks.
static mut ARENA: Arena = Arena::new();
/// The slot's public key and signature, as the words they arrive in (also `.bss`): read once,
/// hashed for `MS_LEAF` and verified from the same words.
static mut PKW: [u32; 328] = [0; 328];
static mut SIGW: [u32; 605] = [0; 605];

const M_MAX: usize = 3;
const SLOT: usize = 967;
const DEPTH: usize = 4;
const N_MAX: u32 = 16;
const AUTH: u32 = 65;
const MS_LEAF: u32 = 66;
const MS_NODE: u32 = 67;
const MS_POLICY: u32 = 68;
const NK_MS: u32 = 69;

/// `H(domain, msg)`: the `POSEIDON2` sponge over `[domain, msg…]`, as `notes::hash` does.
/// Each domain here is used at one fixed length, so the unpadded sponge is unambiguous.
fn h(domain: u32, msg: &[u32], buf: &mut [u32; 330]) -> [u32; 8] {
    buf[0] = domain;
    buf[1..1 + msg.len()].copy_from_slice(msg);
    // SAFETY: `buf` is a live, exclusively borrowed, 4-aligned array of 330 words; the syscall
    // reads `1 + msg.len() <= 330` words (the copy above already bounds it) and writes 8.
    unsafe { poseidon2(buf.as_mut_ptr(), 1 + msg.len()) }
    let mut o = [0u32; 8];
    o.copy_from_slice(&buf[..8]);
    o
}

#[no_mangle]
pub extern "C" fn main() -> ! {
    let mut buf = [0u32; 330];
    let threshold = read_input(16);
    if threshold == 0 || threshold as usize > M_MAX {
        panic!()
    }
    let mut binding = [0u32; 8];
    for i in 0..8 {
        binding[i] = read_public(i as u32);
    }
    let mut msg = [0u8; 45];
    msg[..13].copy_from_slice(b"rand-msauth-1");
    for i in 0..32 {
        msg[13 + i] = (binding[i / 4] >> (8 * (i % 4))) as u8;
    }

    let mut root: Option<[u32; 8]> = None;
    let mut count = 0u32;
    let mut last_index: i32 = -1;
    for s in 0..M_MAX {
        let base = (17 + s * SLOT) as u32;
        let active = read_input(base);
        if active > 1 {
            panic!()
        }
        // An inactive slot contributes nothing and is not counted; every active slot (`1`) runs
        // all of the checks below, so no failing active slot can be skipped.
        if active == 0 {
            continue;
        }
        let index = read_input(base + 1);
        if index >= N_MAX || index as i32 <= last_index {
            panic!()
        }
        last_index = index as i32;
        // SAFETY: single-threaded; these are the only references to PKW / SIGW / ARENA, and they
        // end with this slot's iteration.
        let (pkw, sigw, ar) = unsafe {
            (
                &mut *core::ptr::addr_of_mut!(PKW),
                &mut *core::ptr::addr_of_mut!(SIGW),
                &mut *core::ptr::addr_of_mut!(ARENA),
            )
        };
        read_input_words(base + 2, pkw);
        let mut cur = h(MS_LEAF, pkw, &mut buf);
        for lvl in 0..DEPTH {
            let mut sib = [0u32; 8];
            for i in 0..8 {
                sib[i] = read_input(base + 935 + (lvl * 8 + i) as u32);
            }
            let mut m = [0u32; 16];
            if (index >> lvl) & 1 == 0 {
                m[..8].copy_from_slice(&cur);
                m[8..].copy_from_slice(&sib);
            } else {
                m[..8].copy_from_slice(&sib);
                m[8..].copy_from_slice(&cur);
            }
            cur = h(MS_NODE, &m, &mut buf);
        }
        match root {
            None => root = Some(cur),
            Some(r) if r != cur => panic!(),
            _ => {}
        }
        read_input_words(base + 330, sigw);
        if !verify_words_with(&mut SyscallKeccak, &mut SyscallRing, ar, pkw, &msg, sigw) {
            panic!()
        }
        count += 1;
    }
    // `count >= threshold >= 1` means at least one active slot set `root`.
    if count < threshold {
        panic!()
    }
    let root = root.unwrap_or_else(|| panic!());
    let mut pm = [0u32; 9];
    pm[0] = threshold;
    pm[1..].copy_from_slice(&root);
    let pol = h(MS_POLICY, &pm, &mut buf);
    let mut nm = [0u32; 16];
    for i in 0..8 {
        nm[i] = read_input(i as u32);
    }
    nm[8..].copy_from_slice(&pol);
    let nk = h(NK_MS, &nm, &mut buf);
    let mut cm = [0u32; 16];
    cm[..8].copy_from_slice(&nk);
    for i in 0..8 {
        cm[8 + i] = read_input(8 + i as u32);
    }
    let c = h(AUTH, &cm, &mut buf);
    for i in 0..8 {
        write_output(i as u32, c[i]);
    }
    halt();
}
