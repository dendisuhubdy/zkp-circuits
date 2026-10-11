use rand_zkvm::msauth::*;
use rand_zkvm::notes::{domain, hash};

#[test]
fn tags_are_node_local_and_distinct() {
    let tags = [AUTH, MS_LEAF, MS_NODE, MS_POLICY, NK_MS];
    for t in tags { assert!(t >= 64 && t != 0xff && t != 64); }
    let mut s = tags.to_vec(); s.sort(); s.dedup(); assert_eq!(s.len(), 5);
    assert!(![domain::NK, domain::PK].iter().any(|d| tags.contains(d)));
}

#[test]
fn the_merkle_path_of_every_signer_reaches_the_root() {
    let pks: Vec<[u8; 1312]> = (0..3u8).map(|i| [i + 1; 1312]).collect();
    let (root, paths) = signer_tree(&pks);
    for (i, pk) in pks.iter().enumerate() {
        let mut cur = leaf(pk);
        for (lvl, sib) in paths[i].iter().enumerate() {
            let mut m = [0u32; 16];
            if (i >> lvl) & 1 == 0 { m[..8].copy_from_slice(&cur); m[8..].copy_from_slice(sib); }
            else { m[..8].copy_from_slice(sib); m[8..].copy_from_slice(&cur); }
            cur = hash(MS_NODE, &m);
        }
        assert_eq!(cur, root);
    }
}

#[test]
fn the_policy_binds_threshold_keys_and_msk() {
    let pks: Vec<[u8; 1312]> = (0..3u8).map(|i| [i + 1; 1312]).collect();
    let (root, _) = signer_tree(&pks);
    let msk = [9u32; 8];
    assert_ne!(nk(&msk, &policy(2, &root)), nk(&msk, &policy(3, &root)));
    assert_ne!(nk(&msk, &policy(2, &root)), nk(&[8u32; 8], &policy(2, &root)));
    let (root2, _) = signer_tree(&pks[..2]);
    assert_ne!(policy(2, &root), policy(2, &root2));
}

#[test]
fn the_witness_has_its_fixed_length_whatever_m() {
    let s = |i| Slot { index: i, pk: [1; 1312], sig: [2; 2420], path: [[0; 8]; DEPTH] };
    assert_eq!(msauth_inputs(&[0; 8], &[0; 8], 1, &[s(0)]).len(), MSAUTH_WORDS);
    assert_eq!(msauth_inputs(&[0; 8], &[0; 8], 2, &[s(0), s(2)]).len(), MSAUTH_WORDS);
}

#[test]
fn the_signing_message_is_prefix_then_binding() {
    let m = signing_message(&[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(&m[..13], b"rand-msauth-1");
    assert_eq!(&m[13..17], &1u32.to_le_bytes());
}
