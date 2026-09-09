//! CUDA driver backed by `cuda-core`. Compiles only with the CUDA toolkit installed
//! (feature `cuda`, and not `mock-driver`); not built or exercised on this machine.
use super::Arg;
use cuda_core::{CudaContext, CudaModule, CudaStream, DeviceBuffer};
use std::ffi::c_void;
use std::sync::Arc;

pub struct Device {
    ctx: Arc<CudaContext>,
    stream: Arc<CudaStream>,
}
pub struct Module(Arc<CudaModule>);
pub struct Buffer(DeviceBuffer<u64>);
impl Buffer {
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl Device {
    pub fn open(ordinal: usize) -> Result<Device, String> {
        let ctx = CudaContext::new(ordinal).map_err(|e| e.to_string())?;
        let stream = ctx.default_stream();
        Ok(Device { ctx, stream })
    }
    pub fn free_bytes(&self) -> Result<usize, String> {
        let (mut free, mut total) = (0usize, 0usize);
        let r = unsafe { cuda_core::sys::cuMemGetInfo_v2(&mut free as *mut _, &mut total as *mut _) };
        if r == cuda_core::sys::cudaError_enum_CUDA_SUCCESS {
            Ok(free)
        } else {
            Err(format!("cuMemGetInfo: {r:?}"))
        }
    }
    pub fn load_ptx(&self, src: &str) -> Result<Module, String> {
        self.ctx
            .load_module_from_ptx_src(src)
            .map(Module)
            .map_err(|e| e.to_string())
    }
    pub fn alloc(&self, len: usize) -> Result<Buffer, String> {
        DeviceBuffer::<u64>::zeroed(&self.stream, len)
            .map(Buffer)
            .map_err(|e| e.to_string())
    }
    pub fn upload(&self, data: &[u64]) -> Result<Buffer, String> {
        DeviceBuffer::from_host(&self.stream, data)
            .map(Buffer)
            .map_err(|e| e.to_string())
    }
    pub fn download(&self, b: &Buffer) -> Result<Vec<u64>, String> {
        b.0.to_host_vec(&self.stream).map_err(|e| e.to_string())
    }
    pub fn launch(
        &self,
        m: &Module,
        name: &str,
        grid: u32,
        block: u32,
        args: &[Arg<'_>],
    ) -> Result<(), String> {
        let f = m.0.load_function(name).map_err(|e| e.to_string())?;
        // Each `&[T]` kernel slice parameter is (ptr, len); scalars are one param each.
        let mut ptrs: Vec<u64> = Vec::new();
        let mut lens: Vec<usize> = Vec::new();
        let mut u32s: Vec<u32> = Vec::new();
        let mut u64s: Vec<u64> = Vec::new();
        for a in args {
            match a {
                Arg::Buf(b) => {
                    ptrs.push(b.0.cu_deviceptr() as u64);
                    lens.push(b.0.len());
                }
                Arg::U32(x) => u32s.push(*x),
                Arg::U64(x) => u64s.push(*x),
            }
        }
        let (mut ip, mut il, mut i32_, mut i64_) = (0, 0, 0, 0);
        let mut params: Vec<*mut c_void> = Vec::new();
        for a in args {
            match a {
                Arg::Buf(_) => {
                    params.push(&mut ptrs[ip] as *mut u64 as *mut c_void);
                    params.push(&mut lens[il] as *mut usize as *mut c_void);
                    ip += 1;
                    il += 1;
                }
                Arg::U32(_) => {
                    params.push(&mut u32s[i32_] as *mut u32 as *mut c_void);
                    i32_ += 1;
                }
                Arg::U64(_) => {
                    params.push(&mut u64s[i64_] as *mut u64 as *mut c_void);
                    i64_ += 1;
                }
            }
        }
        unsafe {
            cuda_core::simt::launch_kernel_on_stream(
                &f,
                (grid, 1, 1),
                (block, 1, 1),
                0,
                &self.stream,
                &mut params,
            )
        }
        .map_err(|e| e.to_string())?;
        self.stream.synchronize().map_err(|e| e.to_string())
    }
}
