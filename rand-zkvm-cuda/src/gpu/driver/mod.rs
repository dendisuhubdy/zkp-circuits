//! The device driver surface used by the GPU orchestration layer (Task 9): a small,
//! synchronous interface implemented either by `real` (actual CUDA, via cuda-core) or
//! by `mock` (the shared kernel bodies run on the host, for testing without a GPU).
#[cfg(all(feature = "cuda", feature = "mock-driver"))]
compile_error!("`cuda` and `mock-driver` are mutually exclusive: enabling both would run the host mock in place of the GPU");

#[cfg(all(feature = "cuda", not(feature = "mock-driver")))]
mod real;
#[cfg(all(feature = "cuda", not(feature = "mock-driver")))]
pub use real::{Buffer, Device, Module};

#[cfg(feature = "mock-driver")]
mod mock;
#[cfg(feature = "mock-driver")]
pub use mock::{Buffer, Device, Module};

pub enum Arg<'a> {
    Buf(&'a Buffer),
    U32(u32),
    U64(u64),
}
