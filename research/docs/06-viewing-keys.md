# Viewing keys

This document is the design of the viewing-key layer: the first thing in this
crate that binds a private input to something on a chain, and the first thing
that lets a third party see a shielded transaction without being able to make
one. It sits on top of `R_exec` unchanged — the transfer is a guest program,
the disclosure layer is host-side code — and it exists to make four claims
true and testable (`tests/viewing.rs`):

| Claim | What makes it true |
|---|---|
| **Travel-rule data.** A disclosed row carries an authenticated sender, receiver, amount, asset and time. | All five are fields of the note the proof commits to; the sender is derived in-circuit from the spend key. |
| **View without spend.** The viewing key cannot produce a proof, so disclosure cannot be turned into theft. | The viewing key is a one-way image of the spend key, and the guest takes the spend key as its private input. |
| **Scoped disclosure.** One party's history, or one transaction — never the whole chain. | Two disclosure objects with two scopes; every other envelope on the chain fails authentication under either. |
| **Verifiability.** Every row is checkable against on-chain commitments and nullifiers by anyone holding the same key. | A row carries the note opening; `verify_row` recomputes the commitment (and, for a spend, the nullifier) and compares with the ledger. |

**M3.3** replaces the M1.5 development hash (`Arx8`, 64-bit digests) with the
Poseidon2 chip (`docs/02-tables-and-buses.md`'s `POSEIDON2` bus, the
`POSEIDON2` syscall = 3) and proves membership of the spent note's
commitment in an append-only commitment tree in-circuit
(`MERKLE_VERIFY`), instead of publishing it and letting the ledger check a
`HashSet`. The four claims above, the envelope construction, and the
row-verification checks are unchanged by this — only the hash and the
membership proof are. What did change, and why, is "Public outputs" and
"What this milestone does not do" below.

Code: `src/hash.rs` (the Poseidon2 sponge, host reference for both the
`POSEIDON2` syscall and every note-layer hash), `src/notes.rs` (keys,
notes, commitments, nullifiers, the output-commitment digest), `src/asm.rs`
(the `NOTE_COMMIT`/`NULLIFY`/`MERKLE_VERIFY` guest routines, built on
`asm::ops::call_poseidon2`), `src/guests.rs::transfer` (the guest),
`src/viewing.rs` (envelopes, disclosures, rows), `src/ledger.rs` (the
commitment tree and the simulated chain). Part 9 of the demo narrates it.

## The shape

```
                sender's wallet                          chain                         auditor
   sk ─H_NK→ nk ─H_PK→ pk                    ┌──────────────────────────────┐
   note_in (owned by pk, at tree index i)    │ commitment tree   nullifiers │      Disclosure::Party(nk)
   note_out = (pk_bob, from = pk, amt, …)    │ tx: digest(anchor,nf,cm_out,  │  or  Disclosure::Transaction(K_tx)
                                             │      time) + plaintext + env  │
   R_exec ⟨transfer⟩ ── proof + witness ────▶│ verify; check digest; apply   │
   MERKLE_VERIFY(cm_in, path, index)          │  sets stored, not checked    │──scan──▶ rows ──verify_row──▶ ✓/✗
   Envelope::seal ─────────── envelope ──────▶│                              │
```

A transfer spends one note and creates one of the same amount and asset. The
guest publishes one thing: an 8-word digest of everything the ledger needs
(`anchor`, `nf`, `cm_out`, `time` — see "Public outputs"). Beside the proof
the sender publishes those four plaintext values and an *envelope*: the
created note's plaintext, encrypted so that exactly the right keys can open
it. The ledger checks the digest, checks the anchor against its own recent
tree roots, verifies the proof, and updates the tree and the nullifier set;
it never looks inside the envelope, and — since M3.3 — never sees `cm_in`.

## Keys

```
sk  ──H_NK──▶  nk  (the viewing key)  ──H_PK──▶  pk  (the address)
                │
                ├──H_NF(nk, cm)──▶  nf       nullifier of the party's note with commitment cm
                ├──H_OVK───────▶  ovk       symmetric key over the party's outgoing envelopes
                └──H_KEM_SEED──▶  (dk, ek)  ML-KEM-768 keypair; ek is part of the address
```

Every arrow is `notes::hash` under its own domain tag (the Poseidon2 sponge,
`hash::sponge_hash`, with the tag as the first absorbed word — see
"Notes and what the guest proves" for why that alone isn't a general-purpose
collision guarantee, and why that's fine here), and every arrow points away
from `sk`. That is the whole of "view without spend": `nk` lets its holder
compute the party's address, every nullifier, the outgoing key, and the
decapsulation key — everything needed to *see* — but the `transfer` guest
reads `sk` at `READ_INPUT 0..2` and derives `nk` and `pk` itself, so a
witness built from `nk` alone names a different `pk` and a different
`cm_in`, and the Merkle leaf it derives is not the real note's commitment:
its computed root will not match any anchor the ledger recognizes, a
structural rejection (`LedgerError::BadDigest`/`UnknownAnchor`) that never
reaches the STARK verifier. Overwriting the published digest directly with
a forged value is a constraint failure (`a_viewing_key_cannot_spend`).
Nothing distinguishes a "full" from an "incoming" viewing key here: one key,
one scope — the party.

An **address** is `(pk, ek)`: the `Word8` `pk` a note names its owner by,
and the 1184-byte ML-KEM-768 encapsulation key envelopes are sealed to.

**Widths.** Every key, commitment, nullifier and tree node is `Word8` — four
canonical Goldilocks field elements, each split lo/hi into two 32-bit
machine words (`hash::split_digest`'s layout, `notes::Word8 = [u32; 8]`).
`SpendKey` alone stays two words: nothing hashes it in-circuit except
`H_NK(sk)`, so there is no cost or security reason to widen it.

## Notes and what the guest proves

A note is 28 machine words:

```
pk (8)   from (8)   amount_lo   amount_hi   asset   time   r (8)
```

`amount` is `u64` (SHRUGG units are `1e9` per coin, too wide for `u32`),
carried as two machine words — low then high — in the commitment preimage;
everywhere else in this crate it is a single `u64` value
(`notes::Note::words`/`from_words` do the split/join).

`from` is the address of whoever created the note. It is there so the sender
is *authenticated*, not merely asserted: the guest sets `cm_out`'s `from` to
the `pk` it derived from `sk`, so whoever can open the note knows that the
party who created it held the spend key behind `from`. No extra disclosure
of the sender's input note is needed, which matters — disclosing the input
note's opening to a receiver would hand them the sender's previous
transaction.

`guests::transfer` reads 296 private words (`notes::input`: the spend key,
the spent note's fields, the created note's owner/time/randomness, and a
depth-32 Merkle witness — a sibling path and a leaf index — for the spent
note's commitment) and computes, with the `NOTE_COMMIT`/`NULLIFY`/
`MERKLE_VERIFY` guest routines (`asm.rs`, built on the `POSEIDON2` syscall):

```
nk      = H_NK(sk)
pk      = H_PK(nk)
cm_in   = NOTE_COMMIT(pk,      from_in, amount_lo, amount_hi, asset, time_in,  r_in)
anchor  = MERKLE_VERIFY(cm_in, path, index)        -- the tree root, not cm_in, is published
nf      = NULLIFY(nk, cm_in)                        -- H(NF_DOMAIN, nk, cm_in); no separate nonce
cm_out  = NOTE_COMMIT(pk_out,  pk,      amount_lo, amount_hi, asset, time_out, r_out)
```

Amount and asset conservation is structural — the same input words feed both
commitments — and the sender's ownership of the spent note is structural
too: `cm_in` is computed with the derived `pk` as owner, and `MERKLE_VERIFY`
only accepts `cm_in` if it is genuinely in the tree at the private `index`.
The nullifier is bound to the *commitment*, not to a sender-chosen nonce:
the ledger already rejects duplicate commitments, so two notes minted for
the same owner can never collide to one nullifier, and a sender cannot brick
a receiver's note by reusing a nonce.

Every domain-tagged hash here is `notes::hash(domain, msg) =
sponge_hash([domain, msg...])` — a *padding-free* sponge (exactly what the
`POSEIDON2` chip proves, `hash.rs`), which means it cannot distinguish a
message from itself with extra zero words appended within the same
absorbed rate block (the M1.5 `Arx8` hash avoided this by baking the
message length into its capacity; this sponge does not). That is not a
soundness gap here: every domain's message length is fixed by the call
site (`Note::WORDS`, `nk`/`cm`'s 8 words, a tree node's 16 words, ...),
never attacker-chosen, so no message this crate actually hashes can be
reinterpreted as a shorter or longer one (`tests/viewing.rs::domains_and_lengths_separate`
documents this precisely).

**Measured cost** (`tests/viewing.rs::transfer_guest_permutation_and_row_counts_are_measured`):
1 783 instructions, 3 910 cycles, 38 `POSEIDON2` calls (5 note/key/nullifier
hashes + 32 Merkle levels + 1 output-commitment digest), 192 permutations
from execution itself. M3.4 adds the program's own `hc` digest to every
proof — 446 more digest rows (`⌈1783/4⌉`), counted as cycles too — for a
total of 4 356 cycles and 638 permutations. (Shielded pool phase Z Task 1
replaced `MERKLE_VERIFY`'s 32-times-unrolled body with a counted loop
compiled once and executed 32 times, which is why the instruction count and
digest-row cost dropped sharply from M3.3's unrolled figures — 4 554
instructions / 1 139 digest rows / 4 903 total cycles, superseded here —
while execution-only cycles rose slightly, 3 764 → 3 896, from the loop's
per-iteration branch/counter bookkeeping. Shielded pool phase Z Task 2 then
widened `Note.amount` to `u64` — two words, `amount_lo`/`amount_hi`, in the
commitment preimage (`Note::WORDS` 27 → 28, SHRUGG units being `1e9` per
coin, too wide for `u32`) — which grows each `NOTE_COMMIT` message (`cm_in`
and `cm_out`) from 28 to 29 words, one more permutation apiece, and adds 12
words to the compiled program (one extra `lw`/`sw` pair per note-commit
block): 1 771 → 1 783 instructions, 190 → 192 execution permutations, 443 →
446 digest rows, superseded here.) See "Public outputs" and "Cost" below
for what that meant for the gas tier.

## Public outputs

At `Word2` (64-bit) widths, M1.5 published `cm_in, nf, cm_out, time` as four
separate public outputs. At `Word8` (256-bit) widths those four values are
34 words — `anchor(8) + nf(8) + cm_out(8) + time(1)`, `cm_in` itself having
moved into the Merkle witness (below) — which does not fit the CPU table's
8 output slots (`isa::NUM_OUTPUTS`). Growing `NUM_OUTPUTS` to fit would
widen every `OUT_SEL`/`WRITTEN` column pair in the CPU table (`tables/cpu.rs`)
by `2 * (34 - 8)`, reopening the CPU table's pinned constraint-degree budget
(`cpu` is already at the shared degree cap; see `research/AGENTS.md`'s
hand-off notes) for a change with nothing to do with the note layer itself.

Instead, `guests::transfer` publishes a single 8-word digest,

```
digest = H(OUT_DOMAIN, anchor, nf, cm_out, time)     -- notes::output_digest
```

occupying exactly `NUM_OUTPUTS = 8` (unchanged since M1). `Ledger::apply` is
handed the four plaintext values (`anchor`, `nf`, `cm_out`, `time`) alongside
the proof and the envelope — the same way `cm_out`/`time` were always plain
transaction metadata, never hidden — and recomputes `output_digest` to check
the proof attests to exactly those values before doing anything else
(`LedgerError::BadDigest` on a mismatch). This is a real, deliberate design
choice, not an accident of the widths: it keeps the CPU table's shape and
degree untouched by the note layer, at the cost of one extra Poseidon2 call
(7 permutations) and requiring `apply`'s caller to supply plaintext
alongside the proof rather than reading it back out of the public values.

## Envelopes and the three keys that open them

`Envelope::seal(sender_vk, receiver_address, note, K_tx)` produces four
ciphertexts, all ChaCha20-Poly1305 with the note's commitment in the
associated data:

| field | key | contents |
|---|---|---|
| `kem_ct` | receiver's `ek` | ML-KEM-768 encapsulation → shared secret `ss` |
| `to_receiver` | `ss` | `K_tx` |
| `to_sender` | sender's `ovk` | `K_tx` |
| `body` | `K_tx` | the note plaintext |

`K_tx` is a fresh 32-byte per-transaction key. Three keys open the body, and
they are the three scopes:

| handed over | opens | `Disclosure` |
|---|---|---|
| a party's `nk` | every envelope the party received (through `dk`) or sent (through `ovk`) | `Party(vk)` |
| one transaction's `K_tx` | that envelope's body | `Transaction { tx, key }` |
| nothing | nothing — a stranger's key fails authentication on every envelope | — |

"Never the whole chain" is a property of the construction, not a policy: the
only keys that exist are per-party and per-transaction. Binding the
commitment into the associated data means an envelope cannot be re-attached
to a different transaction and a decrypted note is checked against the
commitment it was published under (`open_with_tx_key` rejects a mismatch).

**One `K_tx` per envelope — a wallet obligation, not an enforced one.** A
`Disclosure::Transaction` carries a bare index `tx`, and since phase Z the
ledger has two independently numbered sequences (`txs` and `bundles`), so
`scan` tries the index in both. That is unambiguous exactly as long as a key
opens one envelope: the commitment in the associated data already stops a key
from opening an envelope it did not seal. But a wallet that reused one
`K_tx` for a transfer and for a bundle output that happened to land at the
same index would have both open under a single `Disclosure::Transaction`, and
both rows would pass `verify_row` — a disclosure wider than the one
transaction this scope promises. Nothing in `viewing.rs` can prevent it (the
key is the caller's to make and to hand out), so it is stated at
`TxKey::random`, which is how the rule is kept.

## The commitment tree

`ledger::CommitmentTree` is an append-only, depth-32, host-side Merkle tree
using the exact hash the guest's `MERKLE_VERIFY` uses,
`notes::hash(domain::NODE, [left(8), right(8)])`. It is the standard
incremental/sparse-Merkle-tree construction: an unfilled subtree at depth
`d` is a fixed "empty" digest, `empty[0]` the all-zero leaf and `empty[d] =
H(NODE, empty[d-1], empty[d-1])`, precomputed once — so a depth-32 tree
never requires materializing `2^32` leaves, and every operation
(`append`/`root`/`path`) costs `O(leaves)`, not `O(2^32)`.

`Ledger` keeps this tree plus a bounded window of its most recent roots
(`recent_roots`, `Ledger::ANCHOR_WINDOW = 64` entries). `Ledger::mint`
appends the minted note's commitment; `Ledger::apply` appends `cm_out` after
a successful transfer; `Ledger::apply_bundle` appends *both* of a bundle's
output commitments. `path_for(cm)` returns the sibling path and index for a
commitment already in the tree — what `notes::transfer_inputs` and
`notes::bundle_inputs` need to spend the note it belongs to.

**Why a window, not just the latest root.** A proof takes real wall-clock
time to build; by the time it is submitted, another transaction may already
have changed the tree. Accepting any of the last `ANCHOR_WINDOW` roots as a
valid `anchor` lets a proof built a little while ago still land, at the cost
of also accepting an `anchor` that is stale enough to be suspicious —
bounded by the window, not unbounded.

The window was 16 through M3.3 and is 64 from shielded pool phase Z Task 4,
the design spec §7's own number: at the 1 s block time the spec assumes, 64
roots is about a minute, which is the order of magnitude a bundle proof
actually takes to build (a `transfer` is cheaper, but both read the same
deque, and there is no reason for the cheaper relation to have the tighter
deadline). `tests/viewing.rs::a_stale_anchor_is_rejected_by_the_ledger` and
`tests/bundle.rs::a_bundles_anchor_expires_after_the_anchor_window` check the
boundary from the transfer and bundle sides respectively: the proof itself is
valid math (Merkle membership against a past root is true forever), but once
that root has scrolled out of the window the ledger rejects it
(`LedgerError::UnknownAnchor`) — a ledger bookkeeping decision, not a
cryptographic one. The bundle-side test pins the exact boundary: `record_root` keeps the
`ANCHOR_WINDOW` most recent roots *including* the one just recorded, so an
anchor that is the newest entry when the window starts scrolling survives
`ANCHOR_WINDOW - 1` = 63 further roots and is evicted by the 64th — the test
admits the bundle with 63 later roots in front of its anchor and refuses it
with `ANCHOR_WINDOW`.

**Testing note.** `MERKLE_VERIFY` compiles down to the same `POSEIDON2`
syscall (and the same `cpu` absorb/write-back hash rows) any other call to
`asm::ops::call_poseidon2` produces — it adds no new AIR surface of its
own — so tamper coverage at the hash-row level (a row forging its absorb
state, claiming to be more than one row kind at once, etc.) is inherited
directly from `tests/cheating.rs`'s M3.2 `POSEIDON2` cheating tests rather
than needing its own copies for the Merkle-verification call site.
Shielded pool phase Z Task 1 changed `MERKLE_VERIFY`'s calling convention
from 32 unrolled copies of its body to a counted loop (`asm::emit_merkle_verify`),
but its AIR-visible behavior — the same `POSEIDON2` absorb/write-back rows,
once per level — did not change, which is why no cheating test needed
updating for the loop.

## Rows and verification

`scan(ledger, disclosure)` walks the chain in order and returns one `Row` per
envelope the disclosure opens:

- `Party(vk)`: a `Received` row for each note whose `to_receiver` decapsulates
  under `vk`'s `dk`, a `Sent` row for each whose `to_sender` opens under
  `vk`'s `ovk`. A `Sent` row also carries `spent`: the party's own earlier
  `Received` note whose *nullifier* (under `vk`) is the transaction's `nf`,
  found from the party's history alone (M3.3: not by commitment — `cm_in`
  is no longer public anywhere, only `nf` is, so the lookup goes through
  `vk.nullifier(note.commitment()) == nf` instead).
- `Transaction { tx, key }`: the single row of `tx`.

Every row carries the travel-rule fields, the transaction's `nf`, `cm_out`,
and the opened note(s). `verify_row(ledger, disclosure, row)` uses nothing
but the same disclosure, so an auditor who was handed the key and a set of
rows confirms each row independently of whoever produced it:

| check | fails with |
|---|---|
| `H_CM(row.note) == ledger.tx.cm_out` | `Commitment` |
| sender/receiver/amount/asset/time equal the note's fields | `Fields` |
| `row.time == ledger.tx.time` | `Time` |
| `row.nf` equals the chain's | `Nullifier` |
| `Received`: `note.pk == vk.pk()`; `Sent`: `note.from == vk.pk()` | `Party` |
| `Sent`: `H_NF(nk, H_CM(spent)) == nf` (a mint has neither, and must carry no `spent`) | `Nullifier` |
| the row's role is one this disclosure can produce | `Scope` |
| the row names a slot the transaction has | `Slot` |

**Rows over a bundle.** A bundle publishes two envelopes, one per output
slot, each sealed against its own slot's commitment by exactly the machinery
above — nothing about an envelope changes. What changes is the indexing: a
`Row` now says which of the ledger's two independently numbered sequences its
`tx` indexes (`source: RowSource::{Transfer, Bundle}`) and which of a
bundle's two slots it is about (`slot: u8`, always 0 for a transfer or mint).
A bundle's slots are paired positionally — slot `s` means
`commitments[s]`, `envelopes[s]` and `nullifiers[s]` — and `scan` and
`verify_row` use the same convention, so a row one produces is checkable by
the other. Everything in the table above is then the identical check, read at
`(tx, slot)` instead of `tx` alone.

`scan` tries each of a bundle's two envelopes both as receiver and as sender,
so up to four rows per bundle per party. The interesting case is the one
2-in-2-out exists for: a wallet consolidating two of its own notes and
keeping the change gets **two `Sent` rows** (one per output slot, each
carrying that slot's nullifier and naming the input note behind it) and
**one `Received` row** (its change output), all three pointing at the same
bundle index with different `slot`s; the party it paid sees exactly one
`Received` row and nothing else.
`tests/bundle.rs::disclosure_scopes_over_a_bundle` is that scenario end to
end, including the per-transaction scope (each of the two `TxKey`s opens
exactly its own slot) and a stranger's key opening nothing.

**A party's history is collected across both sequences before any nullifier
is resolved.** `scan` walks every transfer envelope and every bundle envelope
as receiver first, and only then builds the rows. This is a correctness
condition, not an optimization: either sequence can spend the other's output
— a transfer routinely spends a note a bundle paid out, and a bundle spends
notes transfers paid out — so resolving `spent` while walking, one sequence
to completion and then the other, would leave every such spend unnamed in
whichever sequence came first, and `verify_row` would reject a row `scan`
itself produced. With the two-pass form, walk order cannot affect the result
at all.

One asymmetry with transfers: a bundle `Sent` row may legitimately carry
`spent: None`. A transfer row's `None` means a mint (no nullifier at all),
but a bundle always publishes two nullifiers, and one of them may belong to a
*dummy* input — indistinguishable on chain from a real one by design (§3) —
or to a note outside the history this disclosure covers. Such a row simply
claims less; `verify_row` has already pinned its `nf` to the chain's
`nullifiers[slot]`, so there is nothing it could be lying about.

Who can check what follows from who holds `nk`. The sender's viewing key
verifies the nullifier, because `nf = H_NF(nk_sender, cm_in)`. A receiver, or a
holder of `K_tx`, verifies the commitment and sees `nf` was published in the
same transaction, but cannot recompute it — nor should they be able to,
since that would let them compute the nullifiers of every other note the
sender owns. (M1.5's version of this check also compared against a public
`cm_in`; M3.3 removes that comparison because `cm_in` is no longer public —
the nullifier alone already carries the binding, since it is a hash of the
commitment.)

## What this milestone does not do

- **One in, one out, full value.** No change note, no fee, no multi-asset
  balancing. Adding outputs is more hash calls and a tier step.
- **The envelope is not consensus-checked.** As in every note-encryption
  scheme, a sender who publishes a garbage envelope has paid a receiver who
  cannot find the note; the receiver's refusal to treat it as paid is the
  enforcement. A regulator's travel-rule row exists because the sender's
  wallet sealed it properly, not because the chain verified that it did.
  Making the chain verify it — proving in-circuit that the envelope
  decrypts to the committed note — is a known extension and not attempted
  here.
- **The host-side primitives are real, the in-circuit hash's parameters are
  a development placeholder.** ML-KEM-768 (FIPS 203, the `ml-kem` crate)
  and ChaCha20-Poly1305 are the production choices; the KEM is
  post-quantum, in line with the whitepaper's accounting. Both live
  entirely outside the proof and are swappable under the crypto-agility
  registry. The Poseidon2 permutation itself is the production
  construction (`p3_poseidon2`/`p3_goldilocks`'s own round structure); only
  its round constants (`machine::PERM_SEED`) are a fixed development seed,
  not the published `GOLDILOCKS_POSEIDON2_RC_8_*` constants — swapping them
  is a config change, not a rewrite (`docs/05-roadmap.md`).
- **Closed in M3.4.** `hc` is now an in-circuit public value — the program
  table's digest rows compute it with the Poseidon2 chip, and
  `Machine::verify(hc, proof)` checks it directly, no per-program verifier
  key involved. See `docs/03-privacy.md` for what that does and doesn't
  change about what `hc` leaks.

## Cost

| | |
|---|---|
| `transfer` program | 1 783 instructions (M3.3's unrolled figure, superseded here: 4 554; Task 1's counted-loop figure, superseded here: 1 771) |
| cycles (execution only) | 3 910 (M3.3: 3 764; Task 1: 3 896) |
| digest rows (M3.4, `hc`) | 446 (`⌈1783/4⌉`) — count as cycles too (M3.3's unrolled figure, superseded here: 1 139; Task 1: 443) |
| total cycles | 4 356 → tier 14 (max 16 383; still doesn't fit tier 12's 4 095) (M3.3's unrolled figure, superseded here: 4 903; Task 1: 4 339) |
| `POSEIDON2` calls (execution only) | 38 (5 note/key/nullifier hashes + 32 Merkle levels + 1 output digest) |
| permutations (execution only) | 192 total — 1 (`nk`, 3-word message) + 3 (`pk`, 9 words) + 8 (`cm_in`, 29 words) + 5 (`nf`, 17 words) + 8 (`cm_out`, 29 words) + 32 × 5 (Merkle levels, 17 words each) + 7 (output digest, 26 words) |
| total permutations | 192 + 446 (digest rows) = 638 (M3.3's unrolled figure, superseded here: 1 329; Task 1: 633) |
| gas tier | 14 — still forced by the cycle count alone (4 356 > tier 12's 4 095-cycle budget), unchanged from M3.3's unrolled version despite the much smaller program; the counted-loop routine's 638 total permutations now comfortably fit even the unmodified `poseidon2_height(t) = 2^(t+1)` (1 024 slots at tier 14) that M3.3's 1 329 permutations had forced past — `machine::Tier::poseidon2_height` still ships M3.4's `2^(t+2)` sizing (2 048 slots), a crate-wide constant other guests (e.g. Task 3's two-Merkle-walk bundle) may still need the margin for, not something Task 1 or Task 2 revisits |
| envelope | 1 088 (KEM) + 3 × (12 + 16) + 32 + 32 + 40 bytes ≈ 1.3 KB |
| test-profile proof | tens of seconds in `cargo test` (opt-level 1, debug constraint checking) at tier 14's larger tables; the proof-backed viewing tests are correspondingly slower than the M1.5/M3.2/M3.3 baseline — expected, not a regression |

The M3 design spec's own estimate for the transfer guest was "≈5 + 32·(1+4)
≈ 165 permutations" (treating each of the five non-Merkle hash calls as
roughly one permutation). The measured execution-only count is higher, 192,
because at `Word8` widths the note-commitment calls (29-word messages —
domain tag + `Note::WORDS`, 8 permutations each) and the nullifier call (17
words, 5 permutations) cost more than one permutation apiece, and the
output-commitment digest (`Public outputs`, above) adds 7 more. M3.4 then
adds the program's own digest cost on top. Under M3.3's 32-times-unrolled
`MERKLE_VERIFY`, that digest cost was 1 139 permutations, dwarfing the
execution-only count, because the compiled program was itself large (4 554
words, dominated by the guest-level `NOTE_COMMIT`/`NULLIFY`/`MERKLE_VERIFY`
routines' unrolled Merkle-level loop). Shielded pool phase Z Task 1 replaced
that unrolled loop with a counted loop — the body compiled once, executed 32
times by ordinary branch/jump control flow — which shrank the program to
1 771 words and its digest cost to 443 permutations accordingly, without
changing what `MERKLE_VERIFY` proves or how it compiles at the AIR level
(see "The commitment tree" section's "Testing note" above). Shielded pool
phase Z Task 2 then widened `Note.amount` to `u64` (`Note::WORDS` 27 → 28),
which pushes each `NOTE_COMMIT` call's full absorbed message (domain tag +
`Note::WORDS`) from 28 to 29 words, crossing a rate-4 block boundary
(`⌈28/4⌉ = 7` blocks before, `⌈29/4⌉ = 8` now) — one more permutation
apiece, for `cm_in` and `cm_out` both — and adds 12 words to the compiled
program (one extra `lw`/`sw` pair per note-commit block), growing the
program to 1 783 words and its digest cost to 446 permutations. 192 and 638
are the numbers pinned by
`tests/viewing.rs::transfer_guest_permutation_and_row_counts_are_measured`.

## The `bundle` relation

Shielded pool phase Z Task 3 (`docs/superpowers/specs/2026-09-11-shielded-pool-design.md`
§4) adds a second hand-written note-layer guest, `guests::bundle`: 2-in-2-out, `u64`
fee/burn conservation, dummy notes (`amount == 0`) that skip membership. It shares
`transfer`'s structural idioms (`NOTE_COMMIT`/`NULLIFY`/`MERKLE_VERIFY`, ownership always
forced through the guest's own derived `pk_self`, asset/time never taken from anywhere but
one shared field) but also needs to prove relations that are genuinely arithmetic — no
`assert` primitive exists in this ISA (`BranchCond` only steers control flow, never fails a
proof) — so it introduces a new idiom for those: **taint-and-corrupt**.

**The `bad` flag.** A single register, `BAD`, starts at 0 and is only ever OR'd with a
0/1 "did this check fail" bit (`asm::emit_or_into`) — monotone, so no later passing check
can clear a `bad` an earlier one set. Every genuinely arithmetic relation funnels into it:

- **Anchor agreement.** Each real input's `MERKLE_VERIFY` produces a root; `asm::emit_eq8`
  compares it against the bundle's single claimed `anchor`, and a mismatch ORs into `BAD`
  (`transfer` never needed this — with one input, the derived root simply *is* the
  published anchor; `bundle` has two independent membership checks that must both agree
  with each other and with one published value, so an equality-then-taint gadget replaces
  the direct overwrite).
- **Per-input asset agreement.** A real input's own historical `asset` field free-rides
  into `cm_in`/`nf` unchecked by anything structural (unlike an output, which always reuses
  the bundle's shared `asset` field) — so each real input's `asset` word is separately
  XOR-compared against the bundle's public `asset` and OR'd into `BAD`, gated by that
  input's own `amount != 0` branch exactly like the anchor check (a dummy's asset is
  meaningless).
- **Range checks.** `asm::emit_range_check_u63` flags any of the six amounts (both inputs,
  both outputs, fee, burn) that is `>= 2^63`. (`Ledger::mint` refuses an out-of-range
  amount at deposit time for the same bound, so the pool never holds a leaf no bundle could
  spend.) The *other* half of §4 item 6 — a fee is charged in asset 0, so `asset != 0`
  implies `fee = 0` — is not in the circuit at all: both words are public, so the ledger
  enforces it for free at admission (step 4 of "Ledger admission for bundles" below).
- **64-bit conservation.** `asm::emit_add64_carry` chains `in1 + in2` and
  `out1 + out2 + fee + burn` with carry detection at every step, and a final compare ORs
  `BAD` if the two 65-bit-capable sums disagree. The carry folds are not redundant with
  that final compare: a witness can make the *wrapped* sums compare equal
  (`out1 = out2 = 2^63 − 1`, `fee = 2` wraps `sum_out` to exactly 0, matching two dummy
  inputs' `sum_in = 0`), and only the carry-out catches it — `a_64_bit_wrap_in_the_balance_is_rejected`
  is built on exactly that witness so that deleting the carry folds makes it fail.
- **No duplicate input or output within one bundle** (review round 1). Nothing else in the
  relation compares the two inputs, or the two outputs, against *each other*: the same note
  handed in as both inputs passes membership, anchor agreement and asset agreement twice
  over (it really is the tree's leaf, checked against the same anchor), and the balance sum
  simply sees `amount + amount` — a free doubling. So after both nullifiers and both output
  commitments exist, `asm::emit_eq8` compares `nf1` against `nf2` and `cm_out1` against
  `cm_out2`, and each *equality* (not mismatch — this fold is the inverse polarity of the
  anchor check) ORs into `BAD`. The ledger (Task 4) independently rejects a repeated
  nullifier or a repeated commitment when the bundle is applied, so this is defence in
  depth rather than the only place it is caught. One practical consequence, on **both**
  sides: a dummy *output* still needs a freshly random `r` like any other note, because two
  zero-`r` dummies commit to the identical `cm_out` and would now taint their own bundle
  (and, even one at a time, collide with an earlier bundle's dummy leaf on the ledger); and
  a dummy *input* needs one for the same reason one step removed — two zero-`r` dummy
  inputs share a `cm_in`, hence a nullifier, so `nf1 == nf2` taints the bundle, and one at
  a time it is a nullifier an earlier bundle already spent. Build every dummy with
  `Note::new`, never a hand-written `Note { .., r: [0; 8] }`.

The taint bit is folded into the published digest as **an explicit 47th word**, never
XORed into `time` or any other plaintext field a sender publishes alongside the proof:
`time` is exactly that — plaintext the ledger is handed independently of the proof — so a
cheating sender could otherwise just publish `time XOR 1` and have the ledger's own
recomputation agree. Instead:

```
digest = H(BUNDLE, anchor(8) nf1(8) nf2(8) cm1(8) cm2(8) fee(2) burn(2) asset(1) time(1) bad(1))
```

— 47 words after the domain tag (`notes::domain::BUNDLE = 11`, `notes::bundle_digest`).
The host reference always hashes `bad = 0`; only the guest's own run ever writes a nonzero
`bad` word there. Poseidon2's padding-free sponge means a preimage differing by even one
bit in one word produces, with cryptographic-hash-strength probability, a digest that
matches no real bundle the ledger could reconstruct from plaintext — so
`Ledger::apply_bundle` (Task 4) catches every one of these cheats with a single equality
check against its own independently recomputed digest, never running any of the guest's
arithmetic itself. Every individual check above is a **free, unconstrained** computation —
Plonky3 does not care whether `bad` ends up 0 or 1, both are valid traces — the check only
has teeth because it is funnelled into the one thing an external verifier checks
independently.

**The one relation that is unconstructible, not merely checked.** A dummy input's skip
condition is `amount_lo | amount_hi == 0`, evaluated by `BranchCond::Eq` on exactly the
same two registers that also feed the balance sum's addend for that input. A witness
cannot set `amount != 0` (to claim spending value) and also take the skip branch (whose
condition reads those same words): either the OR is zero — skip runs, the balance sum sees
zero, an honest dummy — or it is nonzero — the membership/anchor/asset checks run,
whatever path was supplied. There is no third case; `a_nonzero_amount_cannot_skip_membership`
(`tests/bundle.rs`) exercises exactly this and shows the corrupted-digest rejection that
results, not a separate "skip was fooled" code path (there is none to fool).

**A memory-layout gotcha worth recording** (found the hard way while implementing this):
`lw`/`sw`/`addi` immediates are genuine 12-bit signed RISC-V I-type fields
(`Instr::encode`'s `i_type` masks to `imm & 0xfff`, `Instr::decode` sign-extends it back
via `sext(.., 12)`) — any compile-time offset outside `[-2048, 2047]` from a base register
silently wraps. `transfer`'s whole RAM layout happens to stay under `0x6a0` (1696), so this
was never visible before. `bundle`'s naive layout is not so lucky: the 606-word private
input vector (`bundle_input::COUNT`) alone reaches byte offset 2420 past its own base, and
the derived-value scratch (`nk`/`pk`/both commitments/both nullifiers/`anchor`/the running
Merkle root/the balance accumulators) sits at `0xb00..0xc50` (2816..3152) — both well past
`0x7ff`. `guests::bundle` fixes this by loading `BASE` with `HEAP + 0x600` instead of
`HEAP` and defining every RAM constant already shifted by `-0x600`, landing every
immediate actually used in `[-1536, 1612]`; `asm::ops::call_poseidon2`'s pointer argument
(built via `li`, which is not immediate-width limited) adds the pivot back to recover the
true absolute address. Any future guest whose RAM footprint is wider than roughly 4 KB
from one base register needs the same trick (or a second base register anchoring a second
window). The same layout table has a second, quieter trap, caught in review round 1: the
hash scratch `BUF` is sized by its *largest* user, and that is the final 48-word digest
absorb (`0x000..0x0c0`), not the 29-word `NOTE_COMMIT` staging — so the note staging area
that is live *simultaneously* with `BUF` must start at `0x0c0`, not at the `0x080` a
`NOTE_COMMIT`-sized reading of `BUF` suggests. Overlapping them was harmless only by
accident (the staging area happens to be dead by the time the digest is absorbed); size
every scratch region by its widest use, and keep the regions disjoint unconditionally.

**Measured** (`tests/bundle.rs`, `-- --nocapture`; re-measured after review round 1's
in-circuit duplicate-input/duplicate-output checks, which added 70 program words and 70
execution cycles to both shapes. `Tier::poseidon2_height(14) / 32 = 2048` permutation
slots; `TIERS` is `[10, 12, 14, 16, 18, 20]` — there is no tier 13 or 15 to fall between
them):

| | 2-in-2-out (`honest_two_in_two_out_proves_and_verifies`) | 1-in-1-out-with-dummies (`honest_one_in_one_out_with_dummies_proves`) |
|---|---|---|
| program | 3 775 words |  (same program, both shapes) |
| cycles (execution only) | 8 018 | 5 779 |
| digest rows (`hc`) | 944 (`⌈3775/4⌉`) | 944 |
| input-digest rows (606 private inputs) | 153 (`1 + ⌈606/4⌉`) | 153 |
| total cycles (what `Tier::for_cycles` sees) | 9 115 | 6 876 |
| `POSEIDON2` calls (execution only) | 73 — 9 non-Merkle hashes (`nk`, `pk`, `cm_in1`, `cm_in2`, `nf1`, `nf2`, `cm_out1`, `cm_out2`, the final digest) + 32 + 32 Merkle levels (both inputs real) | 41 — the same 9 non-Merkle hashes + 32 (only input 1's `MERKLE_VERIFY` runs; input 2's `NOTE_COMMIT`/`NULLIFY` still run, dummy or not — only membership/anchor/asset are skipped) |
| permutations (execution only) | 378 | 218 |
| total permutations (execution + digest rows) | 1 322 | 1 162 |
| gas tier | `Tier(14)`, **forced by the cycle count alone in both shapes**: `Machine::prove` picks the tier from `exec.cycles() + program.digest_rows() + input_digest_row_count(606)` (9 115 / 6 876 above), and the next tier down, `Tier(12)`, has a 4 095-cycle budget (`cpu_height − 1`) that even the execution cycles alone already blow. `Tier(14)`'s own 16 383-cycle budget and 2 048 permutation slots then both hold with room to spare |

Both shapes prove and verify under `FriProfile::Test`. The 1-in-1-out case costs fewer
`POSEIDON2` calls/permutations than 2-in-2-out (skipping one 32-level `MERKLE_VERIFY`
walk, 160 permutations) but the same program (words/digest rows are shape-independent —
`bundle` has no data-dependent control flow that changes the compiled program itself, only
which branches execute) and lands at the same tier either way — on cycles, with the
permutation budget (1 322 / 1 162 against 2 048 slots) never the binding constraint at
this tier.

## Ledger admission for bundles

`Ledger::apply_bundle(machine, proof, bundle)` is the consensus check for a
bundle, the counterpart of `Ledger::apply` for a transfer, and phase Z Task 4
implements the design spec §7 admission order as literally as this crate can.
What it cannot model is named rather than silently dropped: there is no wire
encoding here, so §7's size checks have nothing to measure; no mempool, so no
fee floor; no action types; and no block height, so §7's "`time` within 64 of
the height" is checked against `Ledger::now` instead. Routing the fee to a
proposer and the burn to its destination needs that same missing actions
layer and is phase S2/S3's job, not this crate's.

A `Bundle` is all public chain data — `anchor`, two nullifiers, two
commitments, `fee`, `burn`, `asset`, `time`, two envelopes — submitted
alongside the proof, exactly the way a transfer submits its
`(anchor, nf, cm_out, time)` plaintext today.

Cheap before expensive, so a node never pays for a STARK verification of a
bundle it would reject anyway:

| # | check | fails with |
|---|---|---|
| 1 | the proof carries `pv::NUM` public values, and its eight digest words are canonical `u32`s | `Proof(PublicValues)` / `BadDigest` |
| 2 | `anchor` is one of the last `ANCHOR_WINDOW = 64` recorded roots | `UnknownAnchor` |
| 3 | `now - TIME_WINDOW <= time <= now` (`TIME_WINDOW = 64`) | `Time` |
| 4 | `asset == 0 || fee == 0` — §4 item 6 charges every fee in asset 0 | `FeeInForeignAsset` |
| 5 | `nullifiers[0] != nullifiers[1]`, and neither is already spent | `DuplicateNullifierInBundle` / `Spent` |
| 6 | `commitments[0] != commitments[1]`, and neither is already a leaf | `DuplicateCommitmentInBundle` / `Duplicate` |
| 7 | `notes::bundle_digest(anchor, nf1, nf2, cm1, cm2, fee, burn, asset, time)` equals `pv::OUT0..8` | `BadDigest` |
| 8 | the proof verifies under `bundle_program`'s `hc` — last, and only then | `Proof(..)` |

Then, and only then: both nullifiers inserted, both commitments appended in
slot order, the new root recorded, `fee` and `burn` added to their running
totals (saturating — a `u64` total over unboundedly many bundles can overflow
where no single bundle's `< 2^63` amount can, and a saturated total is
visibly wrong to an auditor where a wrapped one reads as almost nothing), the
bundle pushed. `tests/bundle.rs` has one test per row of that table, plus the
honest path and the replay.

**This is not `Ledger::apply`'s order, deliberately.** `apply` recomputes its
digest *second*, right after the shape check; `apply_bundle` recomputes its
digest *seventh*, after every window/set/tree lookup. A bundle digest is a
Poseidon2 sponge over 47 words, and a `recent_roots` scan plus two `HashSet`
probes plus two `HashMap` probes are nowhere near that cost, so §7's
cheapest-first rule puts them ahead of it. `apply`'s own order is M3.3-era and
was not changed to match: the property the two share, and the one that
matters, is that every free structural check runs before the single expensive
thing — the STARK verification — which is last in both.

Three more things are worth calling out about this order.

**Step 7 is where every in-circuit relation failure lands.** The ledger never
runs any of the guest's arithmetic. `bundle_digest` fixes the preimage's 47th
word, `bad`, at `0`; a bundle whose guest tainted itself — an over-spend, a
wrong Merkle path, an input asset that disagrees with the bundle's, a 64-bit
wrap — published a digest folded from `bad = 1`, which this recomputation can
never match. So over-spending is not a special case in `apply_bundle`; it is
a `BadDigest`, like every other broken relation.

**The within-bundle duplicate checks (5, 6) are not redundant with the
nullifier set and the tree.** Neither slot has been inserted yet when the
bundle is examined, so the set and the tree cannot see a bundle that repeats
itself; only an explicit comparison of the two slots can. `guests::bundle`
also taints such a witness in-circuit, but that is defence in depth in the
other direction — the guest cannot see the cross-bundle cases at all — and
neither check substitutes for the other. The two error variants are kept
distinct from `Spent`/`Duplicate` for exactly that reason.

**Dummies are not detected, deliberately.** A dummy input's nullifier and a
dummy output's commitment are indistinguishable on chain from real ones by
design (§3) — that is the entire point of the fixed 2-in-2-out shape — so
they go through the same `nullifiers.insert` / `tree.append` path as real
ones and `apply_bundle` never tries to tell them apart. This is also why a
wallet must build its dummies with a fresh random `r`: see the duplicate-check
bullet under "The `bundle` relation" above.

**Step 4, the fee-asset rule, is the ledger's job and not the circuit's.**
§4 item 6 charges `fee` in asset 0 (SHRUGG), so a bundle declaring any other
asset must carry `fee = 0`. Both fields are public: the ledger recomputes the
digest over `fee` and `asset` at step 7 and so knows exactly what the proof
is bound to, which leaves an in-circuit comparison of two public words with
nothing to add that two free integer compares here do not already give. Nor
is it a soundness rule — the fee is subtracted from the bundle's own inputs
in whatever asset they are denominated in, so a foreign-asset fee creates no
value. What it protects is `fees_collected`.

`fees_collected` and `burned` are running totals over every admitted bundle,
nothing more — the ledger-level number an auditor would reconcile against,
with no destination attached. They differ in one way worth stating, because
S2/S3 will have to: `fees_collected` is SHRUGG-only, guaranteed by step 4,
while `burned` is a **cross-asset** total, since `burn` is denominated in
whatever the bundle's own `asset` is and no rule confines it to asset 0. Read
it as "units burned, all assets", not as SHRUGG, until the phase that gives
the burn a destination makes it per-asset. `apply`/`mint`, the transfer path,
are unchanged by all of this, including their stricter `time == now` — with
one addition: `mint` now refuses an `amount >= 2^63`
(`LedgerError::AmountOutOfRange`), mirroring the six range checks
`guests::bundle` applies, since a leaf minted above that bound is value no
bundle could ever spend.
