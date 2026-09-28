//! Constraint set 8: what a run costs in gas (fullnode spec 2026-09-28 §3.1). One cpu row is one
//! gas; a `POSEIDON2` absorb row pulls one 32-row permutation into the poseidon2 table (+2); a
//! `KECCAK` row pulls 32 rows of 2 612 columns and 100 memory rows (+191); a `SHA256` row 64 rows
//! of 466 columns (+63). The cpu AIR accumulates exactly these weights in its `GAS` column.
use crate::machine::Tier;

pub const KECCAK_GAS: u64 = 192;
pub const SHA256_GAS: u64 = 64;
pub const POSEIDON2_ABSORB_GAS: u64 = 3;

/// The gas no run under this header can exceed: the tier's cycle budget plus the weight of
/// every permutation (`2^klh / 32`) and compression (`2^slh / 64`) the declared tables could
/// hold. `0` = no such table. The verifier refuses a `GAS_LIMIT` above it.
pub fn gas_max(tier: Tier, keccak_log_height: u8, sha256_log_height: u8) -> u64 {
    let cycles = (1u64 << tier.0) - 1;
    let blocks = |h: u8, block: u64| if h == 0 { 0 } else { (1u64 << h.min(40)) / block };
    cycles + blocks(keccak_log_height, 32) * (KECCAK_GAS - 1) + blocks(sha256_log_height, 64) * (SHA256_GAS - 1)
}
