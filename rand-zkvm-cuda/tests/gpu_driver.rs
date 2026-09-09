#![cfg(feature = "mock-driver")]
use rand_zkvm_cuda::gpu::{
    driver::{Arg, Device},
    CudaError, GpuProver,
};

#[test]
fn mock_launch_runs_kernel_bodies() {
    let d = Device::open(0).unwrap();
    let m = d.load_ptx("// mock").unwrap();
    let src = d.upload(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap(); // row-major 4×2
    let dst = d.alloc(8).unwrap();
    d.launch(
        &m,
        "to_col_major",
        1,
        256,
        &[Arg::Buf(&src), Arg::Buf(&dst), Arg::U32(4), Arg::U32(2)],
    )
    .unwrap();
    assert_eq!(d.download(&dst).unwrap(), vec![1, 3, 5, 7, 2, 4, 6, 8]);
    assert!(d.launch(&m, "no_such_kernel", 1, 1, &[]).is_err());
}

// These two share the RAND_ZKVM_PTX env var, so they run sequentially inside one
// #[test] to avoid a data race between independent test threads.
#[test]
fn probe_env_var_sequenced_cases() {
    // Case 1: missing PTX file.
    std::env::set_var("RAND_ZKVM_PTX", "/nonexistent/kernels.ptx");
    match GpuProver::probe(1) {
        Err(CudaError::MissingPtx(p)) => assert!(p.ends_with("kernels.ptx")),
        other => panic!("{other:?}"),
    }

    // Case 2: mock PTX text succeeds.
    let dir = std::env::temp_dir().join("rand-zkvm-cuda-mock");
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("k.ptx");
    std::fs::write(&p, "// mock ptx").unwrap();
    std::env::set_var("RAND_ZKVM_PTX", &p);
    let g = GpuProver::probe(0x5261_6e64_5a4b).unwrap();
    assert_eq!(g.consts.len(), 86);
    assert_eq!(g.tw_lo.len(), 1 << 13);
}
