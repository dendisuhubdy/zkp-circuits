//! Host model of the private-multisig auth guest: policy hashes, auth
//! commitment, signing message and the fixed private-witness layout.
use crate::notes::{hash, Word8};

pub const AUTH: u32 = 65;
pub const MS_LEAF: u32 = 66;
pub const MS_NODE: u32 = 67;
pub const MS_POLICY: u32 = 68;
pub const NK_MS: u32 = 69;
pub const N_MAX: usize = 16;
pub const DEPTH: usize = 4;
pub const M_MAX: usize = 3;
pub const PK_WORDS: usize = 328;
pub const SIG_WORDS: usize = 605;
pub const SLOT_WORDS: usize = 967;
pub const MSAUTH_WORDS: usize = 17 + M_MAX * SLOT_WORDS;
const _: () = assert!(SLOT_WORDS == 2 + PK_WORDS + SIG_WORDS + 8 * DEPTH);
pub const MSG_PREFIX: &[u8; 13] = b"rand-msauth-1";

fn pack(bytes: &[u8]) -> Vec<u32> {
    debug_assert!(bytes.len() % 4 == 0);
    bytes.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect()
}

fn cat(a: &Word8, b: &Word8) -> [u32; 16] {
    let mut m = [0u32; 16];
    m[..8].copy_from_slice(a);
    m[8..].copy_from_slice(b);
    m
}

pub fn leaf(pk: &[u8; 1312]) -> Word8 {
    hash(MS_LEAF, &pack(pk))
}

/// Root and, per signer, the sibling path from leaf to root. Pads to 16 leaves with zero words.
pub fn signer_tree(pks: &[[u8; 1312]]) -> (Word8, Vec<[Word8; DEPTH]>) {
    assert!(!pks.is_empty() && pks.len() <= N_MAX);
    let mut level: Vec<Word8> = pks.iter().map(leaf).collect();
    level.resize(N_MAX, [0; 8]);
    let mut paths = vec![[[0u32; 8]; DEPTH]; pks.len()];
    for lvl in 0..DEPTH {
        for (i, p) in paths.iter_mut().enumerate() {
            let idx = i >> lvl;
            p[lvl] = level[idx ^ 1];
        }
        level = level.chunks(2).map(|c| hash(MS_NODE, &cat(&c[0], &c[1]))).collect();
    }
    (level[0], paths)
}

pub fn policy(threshold: u32, root: &Word8) -> Word8 {
    let mut m = [0u32; 9];
    m[0] = threshold;
    m[1..].copy_from_slice(root);
    hash(MS_POLICY, &m)
}

pub fn nk(msk: &Word8, policy: &Word8) -> Word8 {
    hash(NK_MS, &cat(msk, policy))
}

pub fn auth_commit(nk: &Word8, salt: &Word8) -> Word8 {
    hash(AUTH, &cat(nk, salt))
}

pub fn signing_message(binding: &[u32; 8]) -> [u8; 45] {
    let mut m = [0u8; 45];
    m[..13].copy_from_slice(MSG_PREFIX);
    for (i, w) in binding.iter().enumerate() {
        m[13 + 4 * i..17 + 4 * i].copy_from_slice(&w.to_le_bytes());
    }
    m
}

#[derive(Clone)]
pub struct Slot {
    pub index: u32,
    pub pk: [u8; 1312],
    pub sig: [u8; 2420],
    pub path: [Word8; DEPTH],
}

/// Fixed-length private witness: `[msk(8), salt(8), threshold, M_MAX slots]`.
/// Slot: `[active=1, index, pk(328), sig(605), path(32)]`; inactive slots are zero.
pub fn msauth_inputs(msk: &Word8, salt: &Word8, threshold: u32, active: &[Slot]) -> Vec<u32> {
    assert!(active.len() <= M_MAX);
    let mut v = Vec::with_capacity(MSAUTH_WORDS);
    v.extend_from_slice(msk);
    v.extend_from_slice(salt);
    v.push(threshold);
    for s in active {
        assert!(s.index < N_MAX as u32);
        v.push(1);
        v.push(s.index);
        v.extend(pack(&s.pk));
        v.extend(pack(&s.sig));
        for n in &s.path {
            v.extend_from_slice(n);
        }
    }
    v.resize(MSAUTH_WORDS, 0);
    debug_assert_eq!(v.len(), MSAUTH_WORDS);
    v
}
