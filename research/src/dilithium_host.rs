//! The host side of `dilithium-core`: its `Keccak` over this crate's own permutation.
pub struct HostKeccak;
impl dilithium_core::Keccak for HostKeccak {
    fn permute(&mut self, s: &mut [u64; 25]) { crate::keccak::keccak_f(s) }
}
