//! GPU (CUDA) orchestration for the NTT and Poseidon2 Merkle backends. This module is
//! compiled when either `cuda` (real hardware, via `cuda-core`) or `mock-driver` (the
//! shared kernel bodies run on the host, for testing without a GPU) is enabled.
pub mod driver;
pub mod hash;
pub mod ntt;

use driver::{Arg, Buffer, Device, Module};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum CudaError {
    #[error("CUDA driver: {0}")]
    Driver(String),
    #[error("CUDA context on device {ordinal}: {msg}")]
    Context { ordinal: usize, msg: String },
    #[error("no PTX for the GPU kernels at {0} (see rand-zkvm-cuda/ptx/PTX_BUILD.md)")]
    MissingPtx(std::path::PathBuf),
    #[error("loading PTX module: {0}")]
    PtxLoad(String),
    #[error("device allocation of {bytes} bytes failed ({free} bytes free); use a lower tier")]
    Alloc { bytes: usize, free: usize },
    #[error("kernel {kernel}: {msg}")]
    Launch { kernel: &'static str, msg: String },
    #[error("host/device copy: {0}")]
    Copy(String),
}

pub struct GpuProver {
    pub dev: Device,
    pub module: Module,
    pub tw_lo: Buffer,
    pub tw_hi: Buffer,
    pub tw_inv_lo: Buffer,
    pub tw_inv_hi: Buffer,
    pub consts: Buffer,
    pub free_bytes: usize,
}

// `Device`/`Module`/`Buffer` (real or mock) don't implement `Debug`, so this is
// written by hand instead of derived; callers (tests included) match on
// `Result<Arc<GpuProver>, CudaError>` and want a `{:?}` on the failure path.
impl std::fmt::Debug for GpuProver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GpuProver")
            .field("free_bytes", &self.free_bytes)
            .finish_non_exhaustive()
    }
}

impl GpuProver {
    /// `$RAND_ZKVM_PTX` if set, else `<crate manifest dir>/ptx/kernels.sm_80.ptx`.
    pub fn ptx_path() -> PathBuf {
        std::env::var_os("RAND_ZKVM_PTX")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ptx/kernels.sm_80.ptx"))
    }

    /// Opens device 0, loads the PTX from `ptx_path()`, and uploads the twiddle tables
    /// and Poseidon2 round constants (derived from `perm_seed`) once.
    pub fn probe(perm_seed: u64) -> Result<Arc<Self>, CudaError> {
        let dev = Device::open(0).map_err(|msg| CudaError::Context { ordinal: 0, msg })?;
        let path = Self::ptx_path();
        let src = std::fs::read_to_string(&path).map_err(|_| CudaError::MissingPtx(path.clone()))?;
        let module = dev.load_ptx(&src).map_err(CudaError::PtxLoad)?;
        let free_bytes = dev.free_bytes().map_err(CudaError::Driver)?;
        let tw = crate::ntt::twiddles();
        let up = |v: &[u64]| dev.upload(v).map_err(CudaError::Copy);
        Ok(Arc::new(Self {
            tw_lo: up(&tw.lo)?,
            tw_hi: up(&tw.hi)?,
            tw_inv_lo: up(&tw.inv_lo)?,
            tw_inv_hi: up(&tw.inv_hi)?,
            consts: up(&crate::constants::poseidon2_constants(perm_seed))?,
            free_bytes,
            dev,
            module,
        }))
    }

    /// Launches kernel `name` over enough blocks of `block` threads to cover
    /// `total_threads`.
    pub fn launch(
        &self,
        name: &'static str,
        total_threads: usize,
        block: u32,
        args: &[Arg<'_>],
    ) -> Result<(), CudaError> {
        if total_threads == 0 {
            return Ok(());
        }
        let grid = (total_threads as u64).div_ceil(block as u64) as u32;
        self.dev
            .launch(&self.module, name, grid, block, args)
            .map_err(|msg| CudaError::Launch { kernel: name, msg })
    }

    pub fn alloc(&self, len: usize) -> Result<Buffer, CudaError> {
        self.dev.alloc(len).map_err(|_| CudaError::Alloc {
            bytes: len * 8,
            free: self.dev.free_bytes().unwrap_or(0),
        })
    }
}
