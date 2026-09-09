//! stdout visualizers.
//!
//! * `print_state` — what a **chain observer** sees: the commitment tree
//!   (leaves from `shield` carry a public sender and value; leaves from a
//!   shielded transfer carry neither), the nullifiers revealed so far, and
//!   the transparent balances next to the shielded pool total.
//! * `render_tree(.., Some(idx))` — what a **wallet** sees while building a
//!   transfer: the same tree with its own leaf, the ancestors on the path,
//!   and the sibling hashes it feeds to the circuit all marked.
//!
//! The tree is depth 8 (256 leaves), so any subtree with no commitments is
//! collapsed into one `∅` line. Empty subtrees still have a real hash (the
//! "zero hash" of that level) and it is shown, since a sibling on a path is
//! usually one of these.

use crate::ledger::{LeafOrigin, Ledger};
use crate::merkle::MerkleTree;
use crate::{Fr, TREE_DEPTH};
use std::fmt::Write;

/// Short hex form of a field element: `0x` + first 10 hex digits + `…`.
pub fn fr(f: &Fr) -> String {
    use ark_ff::{BigInteger, PrimeField};
    let h: String = f.into_bigint().to_bytes_be().iter().map(|b| format!("{b:02x}")).collect();
    format!("0x{}…", &h[..10])
}

/// What the chain can say about leaf `i`.
pub fn leaf_label(l: &Ledger, i: usize) -> String {
    match l.origin(i) {
        LeafOrigin::Shield { from, value } => format!("shielded by {from}, v={value} (public)"),
        LeafOrigin::TxOutput { nullifier, which } => format!("output {which} of tx nf={}, v hidden", fr(nullifier)),
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Role {
    None,
    OnPath,
    Sibling,
}

fn role(level: usize, idx: usize, focus: Option<usize>) -> Role {
    let Some(leaf) = focus else { return Role::None };
    let ancestor = leaf >> level;
    if idx == ancestor {
        Role::OnPath
    } else if level < TREE_DEPTH && idx == ancestor ^ 1 {
        Role::Sibling
    } else {
        Role::None
    }
}

fn marker(r: Role, level: usize) -> String {
    match r {
        Role::None => String::new(),
        Role::OnPath if level == 0 => "   ◀ my note".into(),
        Role::OnPath => "   ◀ on path (recomputed in circuit)".into(),
        Role::Sibling => format!("   ◁ sibling[{level}] (private witness)"),
    }
}

/// Draw the tree, every line prefixed by `indent`. `label(i)` describes
/// leaf `i`; `focus` marks the path from that leaf to the root.
pub fn render_tree(tree: &MerkleTree, indent: &str, label: &dyn Fn(usize) -> String, focus: Option<usize>) -> String {
    let mut out = String::new();
    let cap = 1usize << TREE_DEPTH;
    writeln!(out, "{indent}root {}    depth {TREE_DEPTH}, {}/{cap} leaves filled", fr(&tree.root()), tree.len()).unwrap();
    if tree.is_empty() {
        writeln!(out, "{indent}└── ∅  (no commitments yet — every node is a zero hash)").unwrap();
        return out;
    }
    node(tree, TREE_DEPTH - 1, 0, indent, false, label, focus, &mut out);
    node(tree, TREE_DEPTH - 1, 1, indent, true, label, focus, &mut out);
    out
}

#[allow(clippy::too_many_arguments)]
fn node(
    tree: &MerkleTree,
    level: usize,
    idx: usize,
    prefix: &str,
    is_last: bool,
    label: &dyn Fn(usize) -> String,
    focus: Option<usize>,
    out: &mut String,
) {
    let connector = if is_last { "└── " } else { "├── " };
    let child_prefix = format!("{prefix}{}", if is_last { "    " } else { "│   " });
    let (lo, hi) = (idx << level, (idx + 1) << level);
    let h = fr(&tree.node(level, idx));
    let mark = marker(role(level, idx, focus), level);

    if level == 0 {
        if idx < tree.len() {
            writeln!(out, "{prefix}{connector}leaf {idx:<3} cm = {h}  {}{mark}", label(idx)).unwrap();
        } else {
            writeln!(out, "{prefix}{connector}leaf {idx:<3} ∅ = {h}  (empty slot){mark}").unwrap();
        }
        return;
    }
    if lo >= tree.len() {
        writeln!(out, "{prefix}{connector}∅ {h}  empty subtree, leaves [{lo}, {hi}){mark}").unwrap();
        return;
    }
    writeln!(out, "{prefix}{connector}{h}  leaves [{lo}, {hi}){mark}").unwrap();
    node(tree, level - 1, idx * 2, &child_prefix, false, label, focus, out);
    node(tree, level - 1, idx * 2 + 1, &child_prefix, true, label, focus, out);
}

/// Transparent balances and the shielded pool, with a bar per unit.
pub fn render_balances(l: &Ledger) -> String {
    let mut out = String::new();
    let width = l.transparent.keys().map(|k| k.len()).max().unwrap_or(0).max("shielded pool".len());
    let bar = |n: u64| "█".repeat(n as usize);
    writeln!(out, "    {:<width$}  balance", "t-address").unwrap();
    writeln!(out, "    {}  ───────", "─".repeat(width)).unwrap();
    for (who, bal) in &l.transparent {
        writeln!(out, "    {who:<width$}  {bal:>7}  {}", bar(*bal)).unwrap();
    }
    writeln!(out, "    {}  ───────", "─".repeat(width)).unwrap();
    writeln!(
        out,
        "    {:<width$}  {:>7}  {}  split across {} commitments, {} spent — the chain does not know how",
        "shielded pool",
        l.pool,
        bar(l.pool),
        l.notes(),
        l.nullifiers().len()
    )
    .unwrap();
    out
}

/// The observer's view: tree, nullifiers, balances.
pub fn print_state(l: &Ledger) {
    println!("    ┌ Commitment tree (chain storage)");
    print!("{}", render_tree(l.tree(), "    ", &|i| leaf_label(l, i), None));
    let nfs = l.nullifiers();
    if nfs.is_empty() {
        println!("    nullifiers seen: none");
    } else {
        let list: Vec<String> = nfs.iter().map(fr).collect();
        println!("    nullifiers seen: {}   (H(sk, ρ) — no way to tell which leaf each one spends)", list.join(", "));
    }
    println!("    known roots: {}", l.known_roots());
    println!("    ┌ Balances");
    print!("{}", render_balances(l));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_partial_trees_render() {
        let t = MerkleTree::new();
        assert!(render_tree(&t, "", &|_| "x".into(), None).contains("no commitments yet"));

        let mut t = MerkleTree::new();
        for i in 1..=3u64 {
            t.insert(Fr::from(i));
        }
        let s = render_tree(&t, "", &|i| format!("note{i}"), Some(2));
        assert_eq!(s.matches("cm = ").count(), 3);
        assert!(s.contains("leaf 3   ∅"));
        assert!(s.contains("note2   ◀ my note"));
        assert_eq!(s.matches("◁ sibling").count(), TREE_DEPTH);
        assert!(s.contains("empty subtree, leaves [128, 256)"));
    }
}
