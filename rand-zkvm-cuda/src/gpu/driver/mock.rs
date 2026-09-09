//! Runs the shared kernel bodies on the host, sequentially, with the real launch geometry.
//!
//! `Buffer` wraps its data in a `Mutex` (rather than a `RefCell`) so that `Buffer`, and
//! therefore `GpuProver`, is `Send + Sync`: engines that hold a `GpuProver` behind an
//! `Arc` require that bound.
use super::Arg;
use crate::device::kernels as k;
use std::sync::Mutex;

pub struct Device;
pub struct Module;
pub struct Buffer(pub Mutex<Vec<u64>>);
impl Buffer {
    pub fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}

fn buf<'a>(a: &'a Arg<'a>) -> &'a Buffer {
    match a {
        Arg::Buf(b) => b,
        _ => panic!("expected buffer arg"),
    }
}
fn u(a: &Arg<'_>) -> usize {
    match a {
        Arg::U32(x) => *x as usize,
        Arg::U64(x) => *x as usize,
        _ => panic!("expected scalar arg"),
    }
}
fn u64_(a: &Arg<'_>) -> u64 {
    match a {
        Arg::U64(x) => *x,
        Arg::U32(x) => *x as u64,
        _ => panic!("expected scalar arg"),
    }
}

impl Device {
    pub fn open(_ordinal: usize) -> Result<Device, String> {
        Ok(Device)
    }
    pub fn free_bytes(&self) -> Result<usize, String> {
        Ok(1 << 30)
    }
    pub fn load_ptx(&self, _src: &str) -> Result<Module, String> {
        Ok(Module)
    }
    pub fn alloc(&self, len: usize) -> Result<Buffer, String> {
        Ok(Buffer(Mutex::new(vec![0; len])))
    }
    pub fn upload(&self, data: &[u64]) -> Result<Buffer, String> {
        Ok(Buffer(Mutex::new(data.to_vec())))
    }
    pub fn download(&self, b: &Buffer) -> Result<Vec<u64>, String> {
        Ok(b.0.lock().unwrap().clone())
    }
    pub fn launch(
        &self,
        _m: &Module,
        name: &str,
        grid: u32,
        block: u32,
        a: &[Arg<'_>],
    ) -> Result<(), String> {
        let total = grid as usize * block as usize;
        match name {
            "scale_pow" => {
                let mut d = buf(&a[0]).0.lock().unwrap();
                for t in 0..total {
                    k::scale_pow(t, &mut d, u(&a[1]), u64_(&a[2]), u64_(&a[3]));
                }
            }
            "bit_reverse" => {
                let s = buf(&a[0]).0.lock().unwrap();
                let mut d = buf(&a[1]).0.lock().unwrap();
                for t in 0..total {
                    k::bit_reverse(t, &s, &mut d, u(&a[2]), u(&a[3]));
                }
            }
            "zero_extend" => {
                let s = buf(&a[0]).0.lock().unwrap();
                let mut d = buf(&a[1]).0.lock().unwrap();
                for t in 0..total {
                    k::zero_extend(t, &s, &mut d, u(&a[2]), u(&a[3]));
                }
            }
            "to_col_major" => {
                let s = buf(&a[0]).0.lock().unwrap();
                let mut d = buf(&a[1]).0.lock().unwrap();
                for t in 0..total {
                    k::to_col_major(t, &s, &mut d, u(&a[2]), u(&a[3]));
                }
            }
            "to_row_major" => {
                let s = buf(&a[0]).0.lock().unwrap();
                let mut d = buf(&a[1]).0.lock().unwrap();
                for t in 0..total {
                    k::to_row_major(t, &s, &mut d, u(&a[2]), u(&a[3]));
                }
            }
            "dif_stage" => {
                let mut d = buf(&a[0]).0.lock().unwrap();
                let lo = buf(&a[4]).0.lock().unwrap();
                let hi = buf(&a[5]).0.lock().unwrap();
                for t in 0..total {
                    k::dif_stage(t, &mut d, u(&a[1]), u(&a[2]), u(&a[3]), &lo, &hi);
                }
            }
            "dif_tiles" => {
                let mut d = buf(&a[0]).0.lock().unwrap();
                let log_n = u(&a[2]);
                let log_tile = u(&a[3]);
                let lo = buf(&a[4]).0.lock().unwrap();
                let hi = buf(&a[5]).0.lock().unwrap();
                let tile = 1usize << log_tile;
                for b in 0..grid as usize {
                    let chunk = &mut d[b * tile..(b + 1) * tile];
                    for s in (1..=log_tile).rev() {
                        for t in 0..block as usize {
                            k::dif_tile_stage(t, chunk, log_n, s, &lo, &hi);
                        }
                    }
                }
            }
            "copy_columns" => {
                let s = buf(&a[0]).0.lock().unwrap();
                let mut d = buf(&a[2]).0.lock().unwrap();
                for t in 0..total {
                    k::copy_columns(t, &s, u(&a[1]), &mut d, u(&a[3]), u(&a[4]));
                }
            }
            "poseidon2_rows" => {
                let r = buf(&a[0]).0.lock().unwrap();
                let kk = buf(&a[3]).0.lock().unwrap();
                let mut o = buf(&a[4]).0.lock().unwrap();
                for t in 0..total {
                    k::poseidon2_rows(t, &r, u(&a[1]), u(&a[2]), &kk, &mut o);
                }
            }
            "poseidon2_compress" => {
                let p = buf(&a[0]).0.lock().unwrap();
                let kk = buf(&a[2]).0.lock().unwrap();
                let mut o = buf(&a[3]).0.lock().unwrap();
                for t in 0..total {
                    k::poseidon2_compress(t, &p, u(&a[1]), &kk, &mut o);
                }
            }
            "poseidon2_inject" => {
                let p = buf(&a[0]).0.lock().unwrap();
                let r = buf(&a[2]).0.lock().unwrap();
                let kk = buf(&a[5]).0.lock().unwrap();
                let mut o = buf(&a[6]).0.lock().unwrap();
                for t in 0..total {
                    k::poseidon2_inject(t, &p, u(&a[1]), &r, u(&a[3]), u(&a[4]), &kk, &mut o);
                }
            }
            other => return Err(format!("unknown kernel {other}")),
        }
        Ok(())
    }
}
