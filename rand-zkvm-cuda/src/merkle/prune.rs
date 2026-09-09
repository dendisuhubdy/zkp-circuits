//! Byte-for-byte mirror of p3-merkle-tree 0.7 `pruning.rs::prune_paths` + `walk_frontier`.
use super::Digest;

#[derive(Clone, Copy)]
struct Node { index: usize, lead: usize }

fn total_siblings(levels: usize, arity: &[usize]) -> usize { arity[..levels].iter().map(|a| a - 1).sum() }
const fn sibling_offset(k: usize, lead_pos: usize) -> usize { if k < lead_pos { k } else { k - 1 } }

fn walk_frontier(sorted_unique: &[usize], arity: &[usize], mut visit: impl FnMut(usize, usize, usize, usize)) {
    if sorted_unique.is_empty() { return; }
    let mut nodes: Vec<Node> = sorted_unique.iter().enumerate().map(|(slot, &index)| Node { index, lead: slot }).collect();
    let mut parents: Vec<Node> = Vec::with_capacity(nodes.len());
    for (level, &a) in arity.iter().enumerate() {
        parents.clear();
        let mut i = 0;
        while i < nodes.len() {
            let group = nodes[i].index / a;
            let group_start = group * a;
            let lead = nodes[i].lead;
            let lead_pos = nodes[i].index - group_start;
            let mut member = i;
            for k in 0..a {
                if member < nodes.len() && nodes[member].index == group_start + k { member += 1; } else { visit(level, lead, lead_pos, k); }
            }
            parents.push(Node { index: group, lead });
            i = member;
        }
        std::mem::swap(&mut nodes, &mut parents);
    }
}

/// `paths[i] = (leaf_index, full sibling list level 0 first)`. Returns Plonky3's `sibling_hashes`.
pub fn prune_paths(arity: &[usize], paths: &[(usize, Vec<Digest>)]) -> Vec<Digest> {
    let mut order: Vec<u32> = (0..paths.len() as u32).collect();
    order.sort_unstable_by_key(|&i| paths[i as usize].0);
    order.dedup_by_key(|&mut i| paths[i as usize].0);
    let sorted_unique: Vec<usize> = order.iter().map(|&i| paths[i as usize].0).collect();
    let chunk_base: Vec<usize> = (0..=arity.len()).map(|l| total_siblings(l, arity)).collect();
    let mut out = Vec::new();
    walk_frontier(&sorted_unique, arity, |level, lead, lead_pos, k| {
        let src = &paths[order[lead] as usize].1;
        out.push(src[chunk_base[level] + sibling_offset(k, lead_pos)]);
    });
    out
}
