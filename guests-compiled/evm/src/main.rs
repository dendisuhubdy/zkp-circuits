//! The EVM interpreter guest (M4.3), storage layout 2 (`evm_core::storage::LAYOUT_VERSION`: a
//! depth-64 storage tree). The program is `guest.rs`, shared with `guests-compiled/evm-v1`, which
//! builds the same source against `evm-core`'s `storage-v1` feature for layout 1.
#![no_std]
#![no_main]

include!("guest.rs");
