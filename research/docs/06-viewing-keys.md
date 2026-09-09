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

Code: `src/arx.rs` (the hash), `src/notes.rs` (keys, notes, commitments,
nullifiers), `src/guests.rs::transfer` (the guest), `src/viewing.rs`
(envelopes, disclosures, rows), `src/ledger.rs` (the simulated chain). Part 9
of the demo narrates it.

## The shape

```
                sender's wallet                          chain                         auditor
   sk ─H_NK→ nk ─H_PK→ pk                    ┌──────────────────────────┐
   note_in (owned by pk)                     │ commitments  nullifiers  │      Disclosure::Party(nk)
   note_out = (pk_bob, from = pk, amt, …)    │ tx: cm_in nf cm_out time │  or  Disclosure::Transaction(K_tx)
                                             │     + envelope           │
   R_exec ⟨transfer⟩ ─────── proof ─────────▶│ verify; apply sets       │
   Envelope::seal ────────── envelope ──────▶│ stored, not checked      │──scan──▶ rows ──verify_row──▶ ✓/✗
```

A transfer spends one note and creates one of the same amount and asset. The
guest publishes four things: the spent note's commitment `cm_in`, its
nullifier `nf`, the created note's commitment `cm_out`, and the created note's
`time`. Beside the proof the sender publishes an *envelope*: the created
note's plaintext, encrypted so that exactly the right keys can open it. The
ledger verifies the proof and updates its two sets; it never looks inside the
envelope.

## Keys

```
sk  ──H_NK──▶  nk  (the viewing key)  ──H_PK──▶  pk  (the address)
                │
                ├──H_NF(nk, ρ)──▶  nf        nullifier of the party's note with nonce ρ
                ├──H_OVK───────▶  ovk       symmetric key over the party's outgoing envelopes
                └──H_KEM_SEED──▶  (dk, ek)  ML-KEM-768 keypair; ek is part of the address
```

Every arrow is `arx::hash` under its own domain tag, and every arrow points
away from `sk`. That is the whole of "view without spend": `nk` lets its
holder compute the party's address, every nullifier, the outgoing key, and the
decapsulation key — everything needed to *see* — but the `transfer` guest
reads `sk` at `READ_INPUT 0..2` and derives `nk` and `pk` itself, so a witness
built from `nk` alone names a different `pk`, a different `cm_in`, and is
rejected by the ledger as an unknown commitment. Overwriting the public value
with the real `cm_in` or `nf` is a constraint failure
(`a_viewing_key_cannot_spend`). Nothing distinguishes a "full" from an
"incoming" viewing key here: one key, one scope — the party.

An **address** is `(pk, ek)`: the two-word `pk` a note names its owner by, and
the 1184-byte ML-KEM-768 encapsulation key envelopes are sealed to.

## Notes and what the guest proves

A note is ten machine words:

```
pk (2)   from (2)   amount   asset   time   ρ   r (2)
```

`from` is the address of whoever created the note. It is there so the sender
is *authenticated*, not merely asserted: the guest sets `cm_out`'s `from` to
the `pk` it derived from `sk`, so whoever can open the note knows that the
party who created it held the spend key behind `from`. No extra disclosure of
the sender's input note is needed, which matters — disclosing the input
note's opening to a receiver would hand them the sender's previous
transaction.

`guests::transfer` reads 16 private words (`notes::input`), and computes with
`arx::emit_hash`:

```
nk     = H_NK(sk)
pk     = H_PK(nk)
nf     = H_NF(nk, ρ_in)
cm_in  = H_CM(pk,      from_in, amount, asset, time_in,  ρ_in,  r_in)
cm_out = H_CM(pk_out,  pk,      amount, asset, time_out, ρ_out, r_out)
```

and writes `cm_in, nf, cm_out, time_out` to output slots 0–6
(`notes::output`). Amount and asset conservation is structural — the same
input words feed both commitments — and the sender's ownership of the spent
note is structural too: `cm_in` is computed with the derived `pk` as owner.
543 instructions, 3 276 cycles, gas tier 12.

`time` is both inside `cm_out` and a public output. The ledger pins the public
value to its own clock, so a disclosed row's time is authenticated twice: the
chain recorded it, and the commitment binds it.

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

## Rows and verification

`scan(ledger, disclosure)` walks the chain in order and returns one `Row` per
envelope the disclosure opens:

- `Party(vk)`: a `Received` row for each note whose `to_receiver` decapsulates
  under `vk`'s `dk`, a `Sent` row for each whose `to_sender` opens under
  `vk`'s `ovk`. A `Sent` row also carries `spent`: the party's own earlier
  `Received` note whose commitment is the transaction's `cm_in`, found from
  the party's history alone.
- `Transaction { tx, key }`: the single row of `tx`.

Every row carries the travel-rule fields, the transaction's `cm_in`, `nf`,
`cm_out`, and the opened note(s). `verify_row(ledger, disclosure, row)` uses
nothing but the same disclosure, so an auditor who was handed the key and a
set of rows confirms each row independently of whoever produced it:

| check | fails with |
|---|---|
| `H_CM(row.note) == ledger.tx.cm_out` | `Commitment` |
| sender/receiver/amount/asset/time equal the note's fields | `Fields` |
| `row.time == ledger.tx.time` | `Time` |
| `row.cm_in`, `row.nf` equal the chain's | `Nullifier` |
| `Received`: `note.pk == vk.pk()`; `Sent`: `note.from == vk.pk()` | `Party` |
| `Sent`: `H_CM(spent) == cm_in` and `H_NF(nk, spent.ρ) == nf` (a mint has neither, and must carry no `spent`) | `Nullifier` |
| the row's role is one this disclosure can produce | `Scope` |

Who can check what follows from who holds `nk`. The sender's viewing key
verifies the nullifier, because `nf = H_NF(nk_sender, ρ)`. A receiver, or a
holder of `K_tx`, verifies the commitment and sees that `nf` and `cm_in` were
published in the same transaction, but cannot recompute `nf` — nor should
they be able to, since that would let them compute the nullifiers of every
other note the sender owns.

## What this milestone does not do

- **Membership is not proved in-circuit.** There is no `MERKLE_VERIFY`
  syscall yet (`docs/05-roadmap.md`, M3), so `cm_in` is a *public* output
  and `Ledger::apply` checks it against the commitment set. This is a real
  leak: the chain shows which commitment each transfer spent, so the graph
  from a note's creation to its spend is public. Nothing in the viewing-key
  layer depends on it — the rows, the keys and the checks are the same once
  `cm_in` moves into the witness and a root takes its place — but until then
  the transfer's privacy is that of amounts and parties, not of the
  transaction graph.
- **One in, one out, full value.** No change note, no fee, no multi-asset
  balancing. Adding outputs is more hash calls (each commitment is 3 blocks,
  ≈ 1 040 cycles) and a tier step.
- **`Arx8` is a development hash.** RV32I has no multiplier and M1 has no
  hash syscall, so the only hash a guest can afford is add/xor/rotate. `Arx8`
  is a ChaCha-style 256-bit permutation — the ChaCha quarter-round, four
  rounds of four — as a sponge with a four-word rate. Four rounds is the
  budget that keeps nine permutations inside tier 12; it is the same
  quarter-round density per word as ChaCha8, and it is not a claim of
  cryptographic strength any more than `PERM_SEED` is. Milestone 3's
  Poseidon2 chip replaces it, and `notes.rs`, `viewing.rs` and the guest are
  written so that swap is a change of `arx::hash` and `arx::emit_hash` only.
- **Widths are development widths.** Keys, commitments and nullifiers are
  two 32-bit words. Production is 256-bit values: four times the words, the
  same code.
- **The envelope is not consensus-checked.** As in every note-encryption
  scheme, a sender who publishes a garbage envelope has paid a receiver who
  cannot find the note; the receiver's refusal to treat it as paid is the
  enforcement. A regulator's travel-rule row exists because the sender's
  wallet sealed it properly, not because the chain verified that it did.
  Making the chain verify it — proving in-circuit that the envelope
  decrypts to the committed note — is a known extension and not attempted
  here.
- **The host-side primitives are real, the in-circuit one is not.** ML-KEM-768
  (FIPS 203, the `ml-kem` crate) and ChaCha20-Poly1305 are the production
  choices; the KEM is post-quantum, in line with the whitepaper's accounting.
  Both live entirely outside the proof and are swappable under the
  crypto-agility registry.

## Cost

| | |
|---|---|
| `transfer` program | 543 words (program table 1 024 rows) |
| cycles | 3 276 → tier 12 (max 4 095) |
| `Arx8` permutation | 321 instructions; 2-word hash ≈ 350 cycles, 10-word (a commitment) ≈ 1 040 |
| hashes per transfer | 5 calls, 9 permutations |
| envelope | 1 088 (KEM) + 3 × (12 + 16) + 32 + 32 + 40 bytes ≈ 1.3 KB |
| test-profile proof | ≈ 30 s in `cargo test` (opt-level 1, debug constraint checking); the two proof-backed tests take 70 s together |
