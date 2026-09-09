//! stdout visualizers.
//!
//! Monero has no Merkle tree: the chain is a flat list of outputs and each
//! input names a **ring** of them. So the pictures here are:
//!
//! * `render_outputs` — the output set as the chain stores it: one-time key,
//!   commitment, and what is public about its origin (coinbase amounts are
//!   public; transaction outputs reveal nothing). Pass a ring to mark its
//!   members, and the real index to mark the actual spend — the latter is
//!   what only the spending wallet knows.
//! * `render_wallets` — there are no balances on chain. Each wallet scans
//!   every output with its view key, opens the ones it owns, and checks its
//!   own key images against the chain to see which are spent.
//! * `print_state` — outputs + key images + wallets, the observer's view
//!   with the wallets' private view appended.

use crate::keys::Account;
use crate::tx::{Chain, OutputOrigin};
use crate::{hp, pt, Point, Scalar};
use std::fmt::Write;

/// First 4 bytes of a compressed point, as hex.
pub fn short(p: &Point) -> String {
    let b = pt(p);
    format!("{:02x}{:02x}{:02x}{:02x}…", b[0], b[1], b[2], b[3])
}

fn short_bytes(b: &[u8; 32]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}…", b[0], b[1], b[2], b[3])
}

/// Key image I = x·Hp(P) for an output we own. Same formula as `clsag::sign`.
pub fn key_image(one_time_sk: &Scalar, one_time_pk: &Point) -> Point {
    one_time_sk * hp(b"CLSAG_Hp", &[&pt(one_time_pk)])
}

fn origin(o: &OutputOrigin) -> String {
    match o {
        OutputOrigin::Coinbase { amount } => format!("coinbase, v={amount} (public)"),
        OutputOrigin::TxOutput { tx, which } => format!("output {which} of tx #{tx}, v hidden"),
    }
}

/// The output set, one line per output, optionally with a ring overlaid.
pub fn render_outputs(chain: &Chain, indent: &str, ring: Option<&[usize]>, real: Option<usize>) -> String {
    let mut out = String::new();
    writeln!(out, "{indent}{:>3}  {:<13} {:<13} {}", "idx", "one-time P", "commitment C", "origin").unwrap();
    writeln!(out, "{indent}{}  {} {} {}", "───", "─".repeat(13), "─".repeat(13), "─".repeat(28)).unwrap();
    for (i, o) in chain.outputs.iter().enumerate() {
        let in_ring = ring.is_some_and(|r| r.contains(&i));
        let mark = match (in_ring, real == Some(i)) {
            (true, true) => "   ◀ real spend (only the wallet knows)",
            (true, false) => "   ● ring member (decoy)",
            _ => "",
        };
        writeln!(out, "{indent}{i:>3}  {:<13} {:<13} {}{mark}", short(&o.one_time_pk), short(&o.commitment), origin(chain.origin(i))).unwrap();
    }
    out
}

/// Each account scans the chain and reports what it owns and what is spent.
pub fn render_wallets(chain: &Chain, indent: &str, accounts: &[&Account]) -> String {
    let mut out = String::new();
    let width = accounts.iter().map(|a| a.name.len()).max().unwrap_or(0).max(7);
    writeln!(out, "{indent}{:<width$}  {:>6}  {:>6}  status", "account", "output", "amount").unwrap();
    writeln!(out, "{indent}{}  {}  {}  {}", "─".repeat(width), "──────", "──────", "──────────────────────────").unwrap();
    for a in accounts {
        let owned = chain.scan(a);
        let mut unspent = 0;
        for o in &owned {
            let ki = key_image(&o.one_time_sk, &chain.outputs[o.global_index].one_time_pk);
            let spent = chain.key_image_seen(&ki);
            if !spent {
                unspent += o.amount;
            }
            let status = if spent { format!("spent (key image {} on chain)", short(&ki)) } else { "unspent".into() };
            writeln!(out, "{indent}{:<width$}  {:>6}  {:>6}  {status}", a.name, o.global_index, o.amount).unwrap();
        }
        writeln!(out, "{indent}{:<width$}  {:>6}  {:>6}  {}", a.name, "total", unspent, "█".repeat(unspent as usize)).unwrap();
    }
    out
}

/// Observer's view (outputs, key images) followed by each wallet's private view.
pub fn print_state(chain: &Chain, accounts: &[&Account]) {
    println!("    ┌ Output set (chain storage) — {} outputs, {} transactions", chain.outputs.len(), chain.tx_count());
    print!("{}", render_outputs(chain, "    ", None, None));
    let kis = chain.key_images();
    if kis.is_empty() {
        println!("    key images seen: none");
    } else {
        let list: Vec<String> = kis.iter().map(short_bytes).collect();
        println!("    key images seen: {}   (x·Hp(P) — cannot be mapped back to an output)", list.join(", "));
    }
    println!("    ┌ Wallets (each scans with its own view key — the chain holds no balances)");
    print!("{}", render_wallets(chain, "    ", accounts));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::build_tx;

    #[test]
    fn outputs_ring_and_wallets_render() {
        let mut rng = rand::rngs::OsRng;
        let mut chain = Chain::new();
        let alice = Account::new("alice", &mut rng);
        let bob = Account::new("bob", &mut rng);
        for _ in 0..12 {
            chain.mint(&Account::new("x", &mut rng).address(), 7, &mut rng);
        }
        chain.mint(&alice.address(), 10, &mut rng);
        let mine = chain.scan(&alice);
        let tx = build_tx(&chain, &mine, &[(bob.address(), 6), (alice.address(), 3)], 1, &mut rng).unwrap();

        let s = render_outputs(&chain, "", Some(&tx.inputs[0].ring), Some(12));
        assert_eq!(s.matches("● ring member").count(), crate::RING_SIZE - 1);
        assert_eq!(s.matches("◀ real spend").count(), 1);
        assert!(s.contains("12  ") && s.contains("coinbase, v=10 (public)"));

        chain.apply(&tx).unwrap();
        let s = render_outputs(&chain, "", None, None);
        assert!(s.contains("output 0 of tx #0, v hidden"));
        let w = render_wallets(&chain, "", &[&alice, &bob]);
        assert!(w.contains("spent (key image"));
        let total = |who: &str| w.lines().find(|l| l.starts_with(who) && l.contains("total")).unwrap().to_string();
        assert!(total("alice").ends_with("     3  ███"), "{}", total("alice"));
        assert!(total("bob").ends_with("     6  ██████"), "{}", total("bob"));
    }
}
