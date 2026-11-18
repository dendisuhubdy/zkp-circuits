//! The EVM interpreter guest under **storage layout 1** (`evm_core::storage::LAYOUT_VERSION = 1`:
//! a depth-32 storage tree, a witness of 272 words). The program is `guests-compiled/evm`'s,
//! source line for source line — this file includes its `guest.rs` — compiled against `evm-core` with
//! its `storage-v1` feature, which is the whole difference (`Cargo.toml`).
//!
//! It exists so that two storage layouts can be admitted side by side (ZKVM-105): a contract
//! whose storage root was built under layout 1 keeps proving against `bin/evm-v1.bin` until it is
//! re-rooted, and a new contract uses `bin/evm.bin` (layout 2, depth 64). Each image binds its
//! layout as the first word of the `EVM_OUT` preimage, so neither's proof passes for the other's
//! roots.
#![no_std]
#![no_main]

include!("../../evm/src/guest.rs");
