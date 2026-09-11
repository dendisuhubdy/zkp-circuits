# Phase Z follow-up — 256-bit spend keys Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Widen `notes::SpendKey` from two machine words (64 bits) to eight (256 bits) in `rand_zkvm` (`circuits/research`) before the note layer is vendored into the full node, so that a party's spend authority cannot be recovered by brute force from its public `pk`.

**Architecture:** `nk = H_NK(sk)` and `pk = H_PK(nk)` are both public-ish (every counterparty learns a party's `pk` from the `from` field of the notes it receives). With a 64-bit `sk`, `pk` is a 2^64-work preimage target (two Poseidon2 sponges per guess) — feasible for a well-funded attacker and inconsistent with the chain's ML-KEM-768 / Dilithium2 choices. The fix is mechanical: `SpendKey(Word8)`, the `NK` domain's fixed message length becomes 8 words, the two guests read eight `sk` words instead of two, and every private-input offset after `SK` shifts by six. No AIR, bus or table changes; the guests' `hc` and cycle counts change and are re-measured.

**Tech Stack:** Rust `1.98.1` (`cargo +1.98.1 ...`), Plonky3 `=0.7.0`, no new dependencies.

**Spec:** `../../../fullnode/docs/superpowers/specs/2026-09-11-shielded-pool-design.md` §5 ("Keys: `sk` (spend), `nk` (viewing; derives `pk`, every nullifier, `ovk`, and the ML-KEM-768 decapsulation seed)"). The spec does not state a width; this plan's ruling is 256 bits, matching every other key in §5. Also binding: `research/AGENTS.md` ("one fixed message length per hash domain", "docs carry measured numbers").

## Global Constraints

- Every cargo invocation is `cargo +1.98.1 ...`, run from `research/`.
- No new AIR table, bus, column or syscall. Only `notes.rs`, `guests.rs`, the tests and docs change.
- One fixed message length per hash domain: `domain::NK`'s message becomes exactly 8 words (was 2). Every other domain is unchanged.
- Docs carry measured numbers: the `transfer` and `bundle` rows in `docs/06-viewing-keys.md` and `docs/04-guests.md` (program words, cycles, digest rows, input-digest rows, tier) are re-measured with the exact commands named below, never edited by hand.
- Commit style: `research: <area> — <what>`.

## File structure

```
research/
  src/notes.rs        [edit] SpendKey(Word8); input::* and bundle_input::* offsets; transfer_inputs/bundle_inputs copy 8 sk words; module doc
  src/guests.rs       [edit] transfer(): NK hash over 8 sk words; bundle(): same
  tests/viewing.rs    [edit] a_viewing_key_cannot_spend / measured-numbers test: new numbers
  tests/bundle.rs     [edit] measured-numbers test: new numbers
  docs/06-viewing-keys.md  [edit] "Widths" paragraph, measured tables
  docs/04-guests.md        [edit] bundle/transfer rows
```

---

### Task 1: `SpendKey` is eight words

**Files:**
- Modify: `research/src/notes.rs` (the `SpendKey` struct near line 105, `mod input` near line 239, `mod bundle_input` near line 307, `transfer_inputs` near line 268, `bundle_inputs` near line 419, module doc comment)
- Modify: `research/src/guests.rs` (`transfer()` where it loads `input::SK` and `input::SK + 1`, near line 331; `bundle()` where it loads `bi::SK` and `bi::SK + 1`, near line 496)
- Modify: `research/tests/viewing.rs`, `research/tests/bundle.rs` (measured-number assertions only)
- Modify: `research/docs/06-viewing-keys.md`, `research/docs/04-guests.md`

**Interfaces:**
- Produces: `pub struct SpendKey(pub Word8)`; `SpendKey::random()` fills all eight words; `input::SK` and `bundle_input::SK` are 8-word fields at offset 0; `input::COUNT = 302`; `bundle_input::COUNT = 612`.
- Consumers (unchanged signatures): `SpendKey::viewing_key()`, `transfer_inputs(..)`, `bundle_inputs(..)`, `expected_outputs(..)`, `expected_bundle_outputs(..)`.

- [ ] **Step 1: Write the failing test**

Append to `research/tests/viewing.rs`:

```rust
#[test]
fn spend_keys_are_256_bits_and_nk_hashes_all_eight_words() {
    use rand_zkvm::notes::{hash, domain, SpendKey};
    let sk = SpendKey::random();
    assert_eq!(sk.0.len(), 8);
    // Two keys differing only in the last word must derive different viewing keys: the
    // whole 256-bit key is hashed, not a 64-bit prefix.
    let mut other = sk;
    other.0[7] ^= 1;
    assert_ne!(sk.viewing_key(), other.viewing_key());
    assert_eq!(sk.viewing_key().nk, hash(domain::NK, &sk.0));
    // The private-input layouts start with the eight sk words.
    assert_eq!(rand_zkvm::notes::input::IN_FROM, 8);
    assert_eq!(rand_zkvm::notes::input::COUNT, 302);
    assert_eq!(rand_zkvm::notes::bundle_input::IN1_FROM, 8);
    assert_eq!(rand_zkvm::notes::bundle_input::COUNT, 612);
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo +1.98.1 test --release --test viewing spend_keys_are_256_bits -- --nocapture`
Expected: compile error (`sk.0.len()` is 2; `input::COUNT` is 296) or assertion failure.

- [ ] **Step 3: Widen the key and shift the layouts in `notes.rs`**

Replace the `SpendKey` definition and `random()`:

```rust
/// The spend authority. Never leaves the wallet; the guest reads it through `READ_INPUT`.
/// Eight words (256 bits), like every other key: `pk = H_PK(H_NK(sk))` is known to every
/// counterparty (the `from` field of a received note), so a shorter `sk` would be a
/// brute-force target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendKey(pub Word8);

impl SpendKey {
    pub fn random() -> Self {
        let mut rng = rand::rng();
        SpendKey(std::array::from_fn(|_| rng.next_u32()))
    }
    /// The full viewing key: everything the party can see, nothing it can spend.
    pub fn viewing_key(&self) -> ViewingKey { ViewingKey { nk: hash(domain::NK, &self.0) } }
}
```

Replace `mod input`:

```rust
pub mod input {
    use super::DEPTH;
    pub const SK: usize = 0;          // 8 words
    pub const IN_FROM: usize = 8;     // 8 words
    pub const IN_AMOUNT_LO: usize = 16;
    pub const IN_AMOUNT_HI: usize = 17;
    pub const IN_ASSET: usize = 18;
    pub const IN_TIME: usize = 19;
    pub const IN_R: usize = 20;       // 8 words
    pub const OUT_PK: usize = 28;     // 8 words
    pub const OUT_TIME: usize = 36;
    pub const OUT_R: usize = 37;      // 8 words
    /// Merkle path of the spent note, leaf level first, 8 words per level.
    pub const PATH: usize = 45;       // DEPTH * 8 words
    pub const INDEX: usize = PATH + DEPTH * 8;   // 301
    pub const COUNT: usize = INDEX + 1;          // 302
}
```

Replace `mod bundle_input` (keep every existing doc comment; only the numbers move):

```rust
pub mod bundle_input {
    use super::DEPTH;
    pub const SK: usize = 0;                                // 8
    pub const IN1_FROM: usize = 8;                          // 8
    pub const IN1_AMOUNT_LO: usize = 16;
    pub const IN1_AMOUNT_HI: usize = 17;
    pub const IN1_ASSET: usize = 18;
    pub const IN1_TIME: usize = 19;
    pub const IN1_R: usize = 20;                            // 8
    pub const IN1_PATH: usize = 28;                         // DEPTH * 8 = 256
    pub const IN1_INDEX: usize = IN1_PATH + DEPTH * 8;      // 284
    pub const IN2_FROM: usize = IN1_INDEX + 1;              // 285
    pub const IN2_AMOUNT_LO: usize = IN2_FROM + 8;          // 293
    pub const IN2_AMOUNT_HI: usize = IN2_AMOUNT_LO + 1;
    pub const IN2_ASSET: usize = IN2_AMOUNT_HI + 1;
    pub const IN2_TIME: usize = IN2_ASSET + 1;
    pub const IN2_R: usize = IN2_TIME + 1;                  // 8
    pub const IN2_PATH: usize = IN2_R + 8;                  // DEPTH * 8
    pub const IN2_INDEX: usize = IN2_PATH + DEPTH * 8;      // 561
    pub const ANCHOR: usize = IN2_INDEX + 1;                // 562, 8 words
    pub const OUT1_PK: usize = ANCHOR + 8;                  // 8
    pub const OUT1_AMOUNT_LO: usize = OUT1_PK + 8;
    pub const OUT1_AMOUNT_HI: usize = OUT1_AMOUNT_LO + 1;
    pub const OUT1_R: usize = OUT1_AMOUNT_HI + 1;           // 8
    pub const OUT2_PK: usize = OUT1_R + 8;                  // 8
    pub const OUT2_AMOUNT_LO: usize = OUT2_PK + 8;
    pub const OUT2_AMOUNT_HI: usize = OUT2_AMOUNT_LO + 1;
    pub const OUT2_R: usize = OUT2_AMOUNT_HI + 1;           // 8
    pub const FEE_LO: usize = OUT2_R + 8;
    pub const FEE_HI: usize = FEE_LO + 1;
    pub const BURN_LO: usize = FEE_HI + 1;
    pub const BURN_HI: usize = BURN_LO + 1;
    pub const ASSET: usize = BURN_HI + 1;
    pub const TIME: usize = ASSET + 1;
    pub const COUNT: usize = TIME + 1;                      // 612
}
```

In `transfer_inputs` replace `v[SK] = sk.0[0]; v[SK + 1] = sk.0[1];` with `v[SK..SK + 8].copy_from_slice(&sk.0);`. Same in `bundle_inputs`. Update the module doc comment sentence that says the spend key "stays two words" to say it is eight words like every other key.

- [ ] **Step 4: Read eight `sk` words in both guests**

In `guests::transfer()`, the `nk = H_NK(sk)` staging currently loads `input::SK` and `input::SK + 1` into two scratch slots after the `NK` domain word and calls `call_poseidon2(BUF, 3)`. Replace it with a loop over eight words and a 9-word hash:

```rust
// nk = H(NK, sk): stage [NK, sk0..sk7] and hash 9 words.
a.extend(li(T0, domain::NK as i32)); a.push(sw(BASE, T0, BUF));
for k in 0..8u32 {
    a.push(lw(T0, BASE, inp(input::SK + k as usize)));
    a.push(sw(BASE, T0, BUF + 4 * (1 + k) as i32));
}
a.extend(call_poseidon2(BUF / 4, 9));
```

Use the exact register/offset helpers the surrounding code already uses (`BASE`, `BUF`, `inp(..)`, `lw`/`sw`, `li`); the shape above is the change, the names are the file's. Do the same in `guests::bundle()` at the `bi::SK` load. The scratch buffer at `BUF` must hold 9 words — check the size the surrounding code reserves (the `NOTE_COMMIT` staging is 29 words, so the existing buffer is large enough).

- [ ] **Step 5: Run the note-layer and bundle suites**

Run: `cargo +1.98.1 test --release --test viewing --test bundle 2>&1 | tail -40`
Expected: every test passes except the measured-number assertions (`transfer_guest_permutation_and_row_counts_are_measured`, the bundle measured test) which now report the new program size / cycle counts. Note the printed numbers.

- [ ] **Step 6: Re-measure and update the docs and the measured tests**

Run: `cargo +1.98.1 test --release --test viewing transfer_guest_permutation_and_row_counts_are_measured -- --nocapture` and `cargo +1.98.1 test --release --test bundle -- --nocapture 2>&1 | grep -iE 'words|cycles|rows|tier|permutation'`.
Update the assertions in both tests to the printed values, then paste the same values into `docs/06-viewing-keys.md` (the M3.3 transfer table, the "Widths" paragraph — replace "`SpendKey` alone stays two words ... no cost or security reason to widen it" with the 256-bit rationale from Step 3 — and the phase Z bundle table: program words, cycles, digest rows, input-digest rows now `1 + ⌈612/4⌉ = 154`, total cycles, tier) and `docs/04-guests.md`'s transfer/bundle rows. The tier must still be 14 for both bundle shapes; if it is not, stop and report.

- [ ] **Step 7: Full suite**

Run: `cargo +1.98.1 test --release 2>&1 | grep -E 'test result|FAILED'`
Expected: every binary `ok`, 0 failed. Test count unchanged plus one (the new test in Step 1); update the count in `README.md`, `AGENTS.md` and `docs/05-roadmap.md` if they state it.

- [ ] **Step 8: Commit**

```bash
git add research/src/notes.rs research/src/guests.rs research/tests/viewing.rs research/tests/bundle.rs research/docs/06-viewing-keys.md research/docs/04-guests.md research/README.md research/AGENTS.md research/docs/05-roadmap.md
git commit -m "research: notes — 256-bit spend keys (SpendKey is Word8; input layouts shift; guests hash nine words for nk)"
```

## Self-review

- Spec coverage: §5 keys — the only requirement touched; every other §5 item unchanged.
- Placeholder scan: the measured numbers are produced by Step 6's commands, not guessed; no TBD.
- Type consistency: `SpendKey(Word8)` is consumed by `viewing_key`, `transfer_inputs`, `bundle_inputs` (all take `&SpendKey`); `input::COUNT`/`bundle_input::COUNT` are read by `machine`-level tests through the constants only.
