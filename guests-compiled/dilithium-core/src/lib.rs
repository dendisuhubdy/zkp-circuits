//! `dilithium-core`: a no_std Dilithium2 verifier that runs on the host and, compiled to
//! riscv32im, inside the rVM. The Keccak-f[1600] permutation is a trait so the guest can route it
//! to the `KECCAK` syscall while the host uses its own implementation.
#![no_std]

pub mod fips202;

pub use fips202::{shake256, Shake};

/// A Keccak-f[1600] permutation provider.
pub trait Keccak {
    fn permute(&mut self, s: &mut [u64; 25]);
}

impl<K: Keccak + ?Sized> Keccak for &mut K {
    fn permute(&mut self, s: &mut [u64; 25]) {
        (**self).permute(s)
    }
}
