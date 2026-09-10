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

A note is 27 machine words:

```
pk (8)   from (8)   amount   asset   time   r (8)
```

`from` is the address of whoever created the note. It is there so the sender
is *authenticated*, not merely asserted: the guest sets `cm_out`'s `from` to
the `pk` it derived from `sk`, so whoever can open the note knows that the
party who created it held the spend key behind `from`. No extra disclosure
of the sender's input note is needed, which matters — disclosing the input
note's opening to a receiver would hand them the sender's previous
transaction.

`guests::transfer` reads 295 private words (`notes::input`: the spend key,
the spent note's fields, the created note's owner/time/randomness, and a
depth-32 Merkle witness — a sibling path and a leaf index — for the spent
note's commitment) and computes, with the `NOTE_COMMIT`/`NULLIFY`/
`MERKLE_VERIFY` guest routines (`asm.rs`, built on the `POSEIDON2` syscall):

```
nk      = H_NK(sk)
pk      = H_PK(nk)
cm_in   = NOTE_COMMIT(pk,      from_in, amount, asset, time_in,  r_in)
anchor  = MERKLE_VERIFY(cm_in, path, index)        -- the tree root, not cm_in, is published
nf      = NULLIFY(nk, cm_in)                        -- H(NF_DOMAIN, nk, cm_in); no separate nonce
cm_out  = NOTE_COMMIT(pk_out,  pk,      amount, asset, time_out, r_out)
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
4 554 instructions, 3 764 cycles, 38 `POSEIDON2` calls (5 note/key/nullifier
hashes + 32 Merkle levels + 1 output-commitment digest), 190 total
permutations. See "Public outputs" and "Cost" below for what that meant for
the gas tier.

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

## The commitment tree

`ledger::CommitmentTree` is an append-only, depth-32, host-side Merkle tree
using the exact hash the guest's `MERKLE_VERIFY` uses,
`notes::hash(domain::NODE, [left(8), right(8)])`. It is the standard
incremental/sparse-Merkle-tree construction: an unfilled subtree at depth
`d` is a fixed "empty" digest, `empty[0]` the all-zero leaf and `empty[d] =
H(NODE, empty[d-1], empty[d-1])`, precomputed once — so a depth-32 tree
never requires materializing `2^32` leaves, and every operation
(`append`/`root`/`path`) costs `O(leaves)`, not `O(2^32)`.

`Ledger` keeps this tree plus a bounded window of its 16 most recent roots
(`recent_roots`). `Ledger::mint` appends the minted note's commitment;
`Ledger::apply` appends `cm_out` after a successful transfer. `path_for(cm)`
returns the sibling path and index for a commitment already in the tree —
what `notes::transfer_inputs` needs to spend the note it belongs to.

**Why a window, not just the latest root.** A proof takes real wall-clock
time to build; by the time it is submitted, another transaction may already
have changed the tree. Accepting any of the last 16 roots as a valid
`anchor` lets a proof built a little while ago still land, at the cost of
also accepting an `anchor` that is stale enough to be suspicious — bounded
by the window, not unbounded. `tests/viewing.rs::a_stale_anchor_is_rejected_by_the_ledger`
checks the boundary: the proof itself is valid math (Merkle membership
against a past root is true forever), but once that root has scrolled out
of the window `apply` rejects it (`LedgerError::UnknownAnchor`) — a ledger
bookkeeping decision, not a cryptographic one.

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
- **`hc`, the program commitment, is still verifier-side**, not an
  in-circuit public value — unchanged by M3.3; tracked in
  `docs/05-roadmap.md`'s "Known deviations from the whitepaper" list.

## Cost

| | |
|---|---|
| `transfer` program | 4 554 instructions |
| cycles | 3 764 → tier 12 (max 4 095) |
| `POSEIDON2` calls | 38 (5 note/key/nullifier hashes + 32 Merkle levels + 1 output digest) |
| permutations | 190 total — 1 (`nk`, 3-word message) + 3 (`pk`, 9 words) + 7 (`cm_in`, 28 words) + 5 (`nf`, 17 words) + 7 (`cm_out`, 28 words) + 32 × 5 (Merkle levels, 17 words each) + 7 (output digest, 26 words) |
| gas tier | 12 — cycles fit tier 12's 4 095-cycle budget, but 190 permutations exceed the `2^t` = 128 permutation slots tier 12's Poseidon2 table would otherwise have (`machine::Tier::poseidon2_height`, previously `cpu_height()`). **M3.3 decouples it**: `poseidon2_height(t) = 2^(t+1)`, giving tier 12 256 slots — one line in `machine.rs`, per the M3 plan's own contingency. |
| envelope | 1 088 (KEM) + 3 × (12 + 16) + 32 + 32 + 40 bytes ≈ 1.3 KB |
| test-profile proof | tens of seconds in `cargo test` (opt-level 1, debug constraint checking) at the now-larger tier-12 Poseidon2 table; the proof-backed viewing tests are correspondingly slower than the M1.5/M3.2 baseline — expected, not a regression |

The M3 design spec's own estimate for the transfer guest was "≈5 + 32·(1+4)
≈ 165 permutations" (treating each of the five non-Merkle hash calls as
roughly one permutation). The measured count is higher, 190, because at
`Word8` widths the note-commitment calls (28-word messages, 7 permutations
each) and the nullifier call (17 words, 5 permutations) cost more than one
permutation apiece, and the output-commitment digest (`Public outputs`,
above) adds 7 more. Both numbers exceed tier 12's original 128-slot budget,
so the contingency the plan called out (`poseidon2_height = 2^(t+1)`)
applies either way; 190 is the number pinned by
`tests/viewing.rs::transfer_guest_permutation_and_row_counts_are_measured`.
