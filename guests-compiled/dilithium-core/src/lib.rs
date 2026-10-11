//! `dilithium-core`: a no_std Dilithium2 verifier that runs on the host and, compiled to
//! riscv32im, inside the rVM. The Keccak-f[1600] permutation is a trait so the guest can route it
//! to the `KECCAK` syscall while the host uses its own implementation.
#![no_std]

pub mod fips202;
pub mod ntt;
pub mod packing;
pub mod params;
pub mod poly;
pub mod reduce;
pub mod ring;
pub mod rounding;
pub mod verify;

pub use fips202::{shake256, Shake};
pub use verify::{verify, verify_reference, verify_with};

/// Round-3 Dilithium2 public-key bytes (`rho` ‖ packed `t1`).
pub const PK_BYTES: usize = 1312;
/// Round-3 Dilithium2 signature bytes (`c` ‖ packed `z` ‖ hint section).
pub const SIG_BYTES: usize = 2420;
const _: () = assert!(PK_BYTES == params::PUBLICKEYBYTES && SIG_BYTES == params::SIGNBYTES);

/// A Keccak-f[1600] permutation provider.
pub trait Keccak {
    fn permute(&mut self, s: &mut [u64; 25]);
}

impl<K: Keccak + ?Sized> Keccak for &mut K {
    fn permute(&mut self, s: &mut [u64; 25]) {
        (**self).permute(s)
    }
}
