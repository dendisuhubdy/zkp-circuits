//! A stage-timing harness for the two things this crate puts on a device: the coset LDE and the
//! Poseidon2 Merkle commit (monorepo issue 67, ZKVM-114).
//!
//! It times the same work on every engine the build has — Plonky3's own `Radix2DitParallel`
//! and `MerkleTreeHidingMmcs` (what the CPU prover uses), this crate's CPU twins, and, under
//! `mock-driver` or `cuda-hw`, the device engines — and checks on the way that they agree, so a
//! timing is never the timing of a wrong answer. One line per engine and shape:
//!
//! ```text
//! TIMING engine=<name> log_n=<rows> width=<cols> log_blowup=<b> lde_ms=… commit_ms=… open_ms=… cells=…
//! ```
//!
//! The smoke test runs in every `cargo test` at a toy size. The measurement is `#[ignore]`d:
//!
//! ```sh
//! # the host engines, at a size a laptop holds (2^18 rows × 84 columns, blowup 4)
//! cargo test --release --test timing measure -- --ignored --nocapture
//! # the shapes of a production N=1 aggregate's widest tables, on a GPU host
//! TIMING_SHAPES=18x84,21x11,16x343,18x81 RAND_ZKVM_PTX=/path/kernels.sm_80.ptx \
//!   cargo test --release --features cuda-hw --test timing measure -- --ignored --nocapture
//! ```
//!
//! `TIMING_SHAPES` is a comma-separated list of `<log2 rows>x<columns>`; `TIMING_LOG_BLOWUP`
//! defaults to 2 (the rVM's rate 1/4). The default shapes' columns are the rVM's cpu, RAM,
//! poseidon2 and reduce tables' widths (`recursion/tests/device_model.rs`), at heights small
//! enough for a 16 GB host.
//!
//! What it does not time: trace generation, LogUp, `randomize polys`, the quotient and FRI
//! folding. Those run on the host under every backend, and on the one stage profile there is
//! (`recursion/docs/11-next-levers.md`) they are most of a 16-thread prove. Under `mock-driver`
//! the "device" numbers are host numbers through the driver's copies, not GPU numbers: they
//! show the harness works, nothing about a card.
use p3_commit::Mmcs;
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use rand::{rngs::StdRng, RngExt, SeedableRng};
use rand_zkvm_cuda::dft::Dft;
use rand_zkvm_cuda::merkle::{cpu::CpuHashEngine, mmcs::HidingMmcs};
use rand_zkvm_cuda::ntt::cpu::CpuNttEngine;
use std::sync::Arc;
use std::time::Instant;

const SEED: u64 = 0x5261_6e64_5a4b;
const QUERIES: usize = 92;

fn mat(rng: &mut StdRng, n: usize, w: usize) -> RowMajorMatrix<Goldilocks> {
    RowMajorMatrix::new((0..n * w).map(|_| Goldilocks::from_u64(rng.random::<u64>() % 0xFFFF_FFFF_0000_0001)).collect(), w)
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e3
}

/// One engine's run over one shape: the LDE, the commitment bytes and the opening bytes, with
/// the three times.
struct Run {
    name: &'static str,
    lde: RowMajorMatrix<Goldilocks>,
    commitment: Vec<u8>,
    opening: Vec<u8>,
    lde_ms: f64,
    commit_ms: f64,
    open_ms: f64,
}

fn run<D, M>(name: &'static str, dft: &D, mmcs: &M, input: &RowMajorMatrix<Goldilocks>, log_blowup: usize, idx: &[usize]) -> Run
where
    D: TwoAdicSubgroupDft<Goldilocks>,
    M: Mmcs<Goldilocks>,
    M::Commitment: serde::Serialize,
    M::Proof: serde::Serialize,
{
    let t = Instant::now();
    let lde = dft.coset_lde_batch(input.clone(), log_blowup, Goldilocks::GENERATOR).to_row_major_matrix();
    let lde_ms = ms(t);
    let t = Instant::now();
    let (commitment, data) = mmcs.commit(vec![lde.clone()]);
    let commit_ms = ms(t);
    let t = Instant::now();
    let opening: Vec<u8> = idx.iter().flat_map(|i| postcard::to_allocvec(&mmcs.open_batch(*i, &data).opening_proof).unwrap()).collect();
    let open_ms = ms(t);
    Run { name, lde, commitment: postcard::to_allocvec(&commitment).unwrap(), opening, lde_ms, commit_ms, open_ms }
}

fn p3_mmcs() -> rand_zkvm_cuda::merkle::mmcs::P3Hiding {
    use rand_zkvm_cuda::merkle::mmcs::{Compress, Hash};
    let perm = rand_zkvm_cuda::constants::permutation(SEED);
    rand_zkvm_cuda::merkle::mmcs::P3Hiding::new(Hash::new(perm.clone()), Compress::new(perm), 2, StdRng::seed_from_u64(9))
}

/// Every engine over one shape; returns the runs after checking they agree.
fn shape(log_n: usize, width: usize, log_blowup: usize) -> Vec<Run> {
    let mut rng = StdRng::seed_from_u64(0x7131 + (log_n * 1000 + width) as u64);
    let input = mat(&mut rng, 1 << log_n, width);
    let idx: Vec<usize> = (0..QUERIES).map(|_| rng.random::<u64>() as usize % (1 << (log_n + log_blowup))).collect();
    #[allow(unused_mut)]
    let mut runs = vec![
        run("plonky3", &Radix2DitParallel::<Goldilocks>::default(), &p3_mmcs(), &input, log_blowup, &idx),
        run(
            "cpu-twin",
            &Dft::<CpuNttEngine>::default(),
            &HidingMmcs::new(Arc::new(CpuHashEngine::new(SEED)), SEED, 2, StdRng::seed_from_u64(9)),
            &input,
            log_blowup,
            &idx,
        ),
    ];
    #[cfg(any(feature = "mock-driver", feature = "cuda"))]
    {
        use rand_zkvm_cuda::gpu::{hash::CudaHashEngine, ntt::CudaNttEngine};
        let g = device();
        let name = if cfg!(feature = "mock-driver") { "device(mock-driver)" } else { "device(cuda)" };
        runs.push(run(
            name,
            &Dft(Arc::new(CudaNttEngine { gpu: g.clone() })),
            &HidingMmcs::new(Arc::new(CudaHashEngine { gpu: g }), SEED, 2, StdRng::seed_from_u64(9)),
            &input,
            log_blowup,
            &idx,
        ));
    }
    let cells = (width << (log_n + log_blowup)) as f64;
    for r in &runs {
        eprintln!(
            "TIMING engine={} log_n={log_n} width={width} log_blowup={log_blowup} lde_ms={:.1} commit_ms={:.1} open_ms={:.1} cells={cells:.0} lde_Mcells_per_s={:.1} commit_Mcells_per_s={:.1}",
            r.name,
            r.lde_ms,
            r.commit_ms,
            r.open_ms,
            cells / r.lde_ms / 1e3,
            cells / r.commit_ms / 1e3
        );
    }
    // The same LDE from every engine; the same commitment and openings from every engine that
    // salts from the same generator (all three are seeded alike).
    for r in &runs[1..] {
        assert_eq!(r.lde, runs[0].lde, "{} and {} disagree on the LDE at 2^{log_n} x {width}", r.name, runs[0].name);
        assert_eq!(r.commitment, runs[0].commitment, "{} and {} disagree on the commitment", r.name, runs[0].name);
        assert_eq!(r.opening, runs[0].opening, "{} and {} disagree on the openings", r.name, runs[0].name);
    }
    runs
}

#[cfg(feature = "mock-driver")]
fn device() -> Arc<rand_zkvm_cuda::gpu::GpuProver> {
    let dir = std::env::temp_dir().join("rand-zkvm-cuda-mock-timing");
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("k.ptx");
    std::fs::write(&p, "// mock").unwrap();
    std::env::set_var("RAND_ZKVM_PTX", &p);
    rand_zkvm_cuda::gpu::GpuProver::probe(SEED).unwrap()
}

#[cfg(all(feature = "cuda", not(feature = "mock-driver")))]
fn device() -> Arc<rand_zkvm_cuda::gpu::GpuProver> {
    rand_zkvm_cuda::gpu::GpuProver::probe(SEED).unwrap_or_else(|e| panic!("GpuProver::probe: {e}"))
}

fn shapes_from_env() -> Vec<(usize, usize)> {
    let spec = std::env::var("TIMING_SHAPES").unwrap_or_else(|_| "16x84,18x11,14x343,16x81".into());
    spec.split(',')
        .map(|s| {
            let (a, b) = s.trim().split_once('x').unwrap_or_else(|| panic!("TIMING_SHAPES: `{s}` is not <log2 rows>x<columns>"));
            (a.parse().expect("log2 rows"), b.parse().expect("columns"))
        })
        .collect()
}

/// The harness itself, at a toy size, in every `cargo test`: every engine the build has agrees
/// on the LDE, the commitment and the openings.
#[test]
fn every_engine_agrees_at_a_toy_size() {
    for (log_n, width) in [(6usize, 3usize), (10, 12)] {
        let runs = shape(log_n, width, 2);
        assert!(runs.len() >= 2);
        assert!(runs.iter().all(|r| r.lde.height() == 1 << (log_n + 2) && r.lde.width() == width));
    }
}

/// The measurement. See the module comment for the shapes and the GPU invocation.
#[test]
#[ignore = "measurement: prints TIMING lines; default shapes need about 4 GB"]
fn measure() {
    let log_blowup: usize = std::env::var("TIMING_LOG_BLOWUP").ok().map(|s| s.parse().expect("TIMING_LOG_BLOWUP")).unwrap_or(2);
    let shapes = shapes_from_env();
    let mut totals: std::collections::BTreeMap<&'static str, (f64, f64, f64)> = Default::default();
    for (log_n, width) in shapes {
        for r in shape(log_n, width, log_blowup) {
            let t = totals.entry(r.name).or_default();
            t.0 += r.lde_ms;
            t.1 += r.commit_ms;
            t.2 += r.open_ms;
        }
    }
    for (name, (lde, commit, open)) in totals {
        eprintln!("TIMING-TOTAL engine={name} lde_ms={lde:.1} commit_ms={commit:.1} open_ms={open:.1}");
    }
}
