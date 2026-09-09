//! stdout visualizers.
//!
//! Two views of the same contract state:
//!
//! * `print_state` — what a **chain observer** sees: the Merkle tree of
//!   commitments (each leaf tagged with the depositor, because `deposit` is
//!   an ordinary transaction), the nullifier hashes seen so far (which
//!   cannot be mapped back to leaves), and every account balance.
//! * `render_tree(.., Some(idx))` — what the **wallet** sees while building a
//!   proof: the same tree with its own leaf, the ancestors on the path, and
//!   the sibling hashes it feeds into the circuit all marked.
//!
//! The tree is depth 8 (256 leaves), so instead of drawing every node we
//! collapse any subtree with no deposits into one `∅` line. Empty subtrees
//! still have a real hash (the "zero hash" of that level) and it is shown,
//! since that is what a sibling on a path usually is.

use crate::merkle::MerkleTree;
use crate::mixer::Mixer;
use crate::{Fr, TREE_DEPTH};
use std::fmt::Write;

/// Short hex form of a field element: `0x` + first 12 hex digits + `…`.
pub fn fr(f: &Fr) -> String {
    use ark_ff::{BigInteger, PrimeField};
    let h: String = f.into_bigint().to_bytes_be().iter().map(|b| format!("{b:02x}")).collect();
    format!("0x{}…", &h[..12])
}

/// Where a node sits relative to the leaf being proven (if any).
#[derive(Clone, Copy, PartialEq)]
enum Role {
    None,
    /// The leaf itself, or an ancestor of it (the values the circuit recomputes).
    OnPath,
    /// The sibling at some level (a private witness fed to the circuit).
    Sibling,
}

fn role(level: usize, idx: usize, focus: Option<usize>) -> Role {
    let Some(leaf) = focus else { return Role::None };
    let ancestor = leaf >> level; // index of the focus leaf's ancestor at this level
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
        Role::OnPath if level == 0 => "   ◀ my leaf".into(),
        Role::OnPath => "   ◀ on path (recomputed in circuit)".into(),
        Role::Sibling => format!("   ◁ sibling[{level}] (private witness)"),
    }
}

/// Draw the tree, every line prefixed by `indent`. `label(i)` names leaf
/// `i` (the depositor); `focus` marks the path from that leaf to the root.
pub fn render_tree(tree: &MerkleTree, indent: &str, label: &dyn Fn(usize) -> String, focus: Option<usize>) -> String {
    let mut out = String::new();
    let cap = 1usize << TREE_DEPTH;
    writeln!(out, "{indent}root {}    depth {TREE_DEPTH}, {}/{cap} leaves filled", fr(&tree.root()), tree.len()).unwrap();
    if tree.is_empty() {
        writeln!(out, "{indent}└── ∅  (no deposits yet — every node is a zero hash)").unwrap();
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
            writeln!(out, "{prefix}{connector}leaf {idx:<3} C = {h}  deposited by {}{mark}", label(idx)).unwrap();
        } else {
            writeln!(out, "{prefix}{connector}leaf {idx:<3} ∅ = {h}  (empty slot){mark}").unwrap();
        }
        return;
    }
    if lo >= tree.len() {
        // Nothing below here: one line for the whole subtree.
        writeln!(out, "{prefix}{connector}∅ {h}  empty subtree, leaves [{lo}, {hi}){mark}").unwrap();
        return;
    }
    writeln!(out, "{prefix}{connector}{h}  leaves [{lo}, {hi}){mark}").unwrap();
    node(tree, level - 1, idx * 2, &child_prefix, false, label, focus, out);
    node(tree, level - 1, idx * 2 + 1, &child_prefix, true, label, focus, out);
}

/// Account balances + the contract's pool, as a table with a bar per unit.
pub fn render_balances(m: &Mixer) -> String {
    let mut out = String::new();
    let width = m.balances.keys().map(|k| k.len()).max().unwrap_or(0).max("pool (contract)".len());
    let bar = |n: u64| "█".repeat(n as usize);
    writeln!(out, "  {:<width$}  balance", "account").unwrap();
    writeln!(out, "  {}  ───────", "─".repeat(width)).unwrap();
    for (who, bal) in &m.balances {
        writeln!(out, "  {who:<width$}  {bal:>7}  {}", bar(*bal)).unwrap();
    }
    writeln!(out, "  {}  ───────", "─".repeat(width)).unwrap();
    let (d, w) = (m.deposits() as u64, m.withdrawals() as u64);
    writeln!(
        out,
        "  {:<width$}  {:>7}  {}  = {d} deposits − {w} withdrawals, × {} ETH → {} notes still redeemable",
        "pool (contract)",
        m.pool,
        bar(m.pool),
        m.denomination,
        d - w
    )
    .unwrap();
    out
}

/// The observer's view: tree, nullifiers seen, balances.
pub fn print_state(m: &Mixer) {
    println!("  ┌ Merkle tree (contract storage)");
    print!("{}", render_tree(m.tree(), "  ", &|i| m.depositor(i).to_string(), None));
    let spent = m.spent_nullifiers();
    if spent.is_empty() {
        println!("  nullifierHashes seen: none");
    } else {
        let list: Vec<String> = spent.iter().map(fr).collect();
        println!("  nullifierHashes seen: {}   (H(ν) — no way to tell which leaf each one spends)", list.join(", "));
    }
    println!("  known roots: {}   (one per deposit; withdrawals may reference any of them)", m.known_roots());
    println!("  ┌ Balances");
    print!("{}", render_balances(m));
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;

    #[test]
    fn empty_and_partial_trees_render() {
        let t = MerkleTree::new();
        let s = render_tree(&t, "", &|_| "x".into(), None);
        assert!(s.contains("no deposits yet"));

        let mut t = MerkleTree::new();
        for i in 1..=3u64 {
            t.insert(Fr::from(i));
        }
        let s = render_tree(&t, "", &|i| format!("user{i}"), Some(2));
        // three real leaves, one empty slot in the last filled pair
        assert_eq!(s.matches("deposited by").count(), 3);
        assert!(s.contains("leaf 3   ∅"));
        assert!(s.contains("deposited by user2   ◀ my leaf"));
        // one sibling per level
        assert_eq!(s.matches("◁ sibling").count(), TREE_DEPTH);
        // every empty subtree collapses to a single line
        assert!(s.contains("empty subtree, leaves [128, 256)"));
        assert!(!s.contains("leaves [200,"));
    }
}
