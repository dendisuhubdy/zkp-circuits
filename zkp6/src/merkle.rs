//! A full binary Merkle tree over commitments, plus the in-circuit path check.
//!
//! ```text
//!                 root
//!               /      \
//!             h01      h23          h_ij = H(left, right)
//!            /   \    /   \
//!          C0    C1  C2    C3       leaves = commitments (zero = empty slot)
//! ```
//!
//! Tornado's contract keeps this tree *incrementally*: it stores one node per
//! level ("filled subtrees") and a ring buffer of the last 30 roots, so a
//! withdrawal proof built against a slightly stale root still verifies. We
//! keep the whole tree in memory since we are simulating.

use crate::hash::{hash2, hash2_gadget};
use crate::{Fr, TREE_DEPTH};
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, select::CondSelectGadget};
use ark_relations::r1cs::SynthesisError;

/// Sibling hashes from leaf to root, and the leaf's position bits
/// (bit i = 1 means "I was the RIGHT child at level i").
#[derive(Clone, Debug)]
pub struct MerklePath {
    pub siblings: [Fr; TREE_DEPTH],
    pub is_right: [bool; TREE_DEPTH],
}

pub struct MerkleTree {
    /// levels[0] = leaves, levels[DEPTH] = [root]
    levels: Vec<Vec<Fr>>,
    next_index: usize,
}

impl MerkleTree {
    pub fn new() -> Self {
        let mut levels = Vec::with_capacity(TREE_DEPTH + 1);
        let mut zero = Fr::from(0u64);
        for d in 0..=TREE_DEPTH {
            levels.push(vec![zero; 1 << (TREE_DEPTH - d)]);
            zero = hash2(zero, zero); // "zero hash" for the next level up
        }
        MerkleTree { levels, next_index: 0 }
    }

    pub fn root(&self) -> Fr {
        self.levels[TREE_DEPTH][0]
    }

    /// Hash at (`level`, `idx`); level 0 = leaves, level DEPTH = root.
    pub fn node(&self, level: usize, idx: usize) -> Fr {
        self.levels[level][idx]
    }

    pub fn len(&self) -> usize {
        self.next_index
    }

    pub fn is_empty(&self) -> bool {
        self.next_index == 0
    }

    /// The inserted leaves in order — what a wallet reconstructs from the
    /// contract's `Deposit(commitment, leafIndex)` event log.
    pub fn leaves(&self) -> &[Fr] {
        &self.levels[0][..self.next_index]
    }

    /// Append a leaf and recompute the DEPTH hashes on its path.
    pub fn insert(&mut self, leaf: Fr) -> usize {
        let idx = self.next_index;
        assert!(idx < 1 << TREE_DEPTH, "tree is full");
        self.levels[0][idx] = leaf;
        let mut i = idx;
        for d in 0..TREE_DEPTH {
            let parent = i / 2;
            let (l, r) = (self.levels[d][parent * 2], self.levels[d][parent * 2 + 1]);
            self.levels[d + 1][parent] = hash2(l, r);
            i = parent;
        }
        self.next_index += 1;
        idx
    }

    pub fn path(&self, mut idx: usize) -> MerklePath {
        let mut siblings = [Fr::from(0u64); TREE_DEPTH];
        let mut is_right = [false; TREE_DEPTH];
        for d in 0..TREE_DEPTH {
            is_right[d] = idx % 2 == 1;
            siblings[d] = self.levels[d][idx ^ 1];
            idx /= 2;
        }
        MerklePath { siblings, is_right }
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Native re-computation of a root from a leaf and its path.
pub fn root_from_path(leaf: Fr, path: &MerklePath) -> Fr {
    let mut cur = leaf;
    for d in 0..TREE_DEPTH {
        cur = if path.is_right[d] { hash2(path.siblings[d], cur) } else { hash2(cur, path.siblings[d]) };
    }
    cur
}

/// In-circuit version. `is_right[d]` is a private Boolean wire; the
/// conditional swap costs 2 constraints per level and hides the position.
pub fn root_gadget(
    leaf: &FpVar<Fr>,
    siblings: &[FpVar<Fr>],
    is_right: &[Boolean<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut cur = leaf.clone();
    for d in 0..TREE_DEPTH {
        let left = FpVar::conditionally_select(&is_right[d], &siblings[d], &cur)?;
        let right = FpVar::conditionally_select(&is_right[d], &cur, &siblings[d])?;
        cur = hash2_gadget(&left, &right)?;
    }
    Ok(cur)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_reconstruct_root() {
        let mut t = MerkleTree::new();
        let leaves: Vec<Fr> = (1..=5u64).map(Fr::from).collect();
        for l in &leaves {
            t.insert(*l);
        }
        for (i, l) in leaves.iter().enumerate() {
            assert_eq!(root_from_path(*l, &t.path(i)), t.root());
        }
        // a wrong leaf does not reconstruct
        assert_ne!(root_from_path(Fr::from(99u64), &t.path(0)), t.root());
    }
}
