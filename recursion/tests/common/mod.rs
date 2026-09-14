//! Real bundle proofs, the only proofs this crate's tests ever verify.
//!
//! Built from `rand_zkvm`'s public API the way `research/tests/bundle.rs::fixture()` does — two
//! minted input notes, an anchor, two outputs, a fee — varying the input amounts so that `n`
//! proofs are `n` genuinely different witnesses. Proofs are cached on disk
//! (`$RECURSION_FIXTURES`, default `target/recursion-fixtures`) because a production-profile one
//! costs ~95 s to prove and even a `FriProfile::Test` one costs tens of seconds.
//!
//! Nothing here builds a *synthetic* proof. A hand-made `Proof` would let the verifier port agree
//! with a second implementation of the same misunderstanding; the whole point of this crate's tests
//! is that the program accepts exactly what `Machine::verify` accepts, so the proofs have to come
//! from `Machine::prove`.
use rand_zkvm::ledger::Ledger;
use rand_zkvm::machine::{FriProfile, Machine, Proof};
use rand_zkvm::notes::{self, Note, SpendKey, ViewingKey, Word8, DEPTH};
use rand_zkvm::viewing::{Envelope, TxKey};

/// `research/tests/bundle.rs`'s own test-local `Party` (it is not public API), reproduced here so
/// the fixtures need no change in `research/`.
pub struct Party {
    pub sk: SpendKey,
    pub vk: ViewingKey,
}
impl Party {
    pub fn new() -> Party {
        let sk = SpendKey::random();
        Party { sk, vk: sk.viewing_key() }
    }
}

/// One proof and the guest digest it was proved against — everything `Machine::verify` needs.
pub struct BundleProof {
    pub proof: Proof,
    pub hc: Word8,
}

/// `$RECURSION_FIXTURES`, or `target/recursion-fixtures` under this crate.
pub fn cache_dir() -> std::path::PathBuf {
    match std::env::var_os("RECURSION_FIXTURES") {
        Some(d) => std::path::PathBuf::from(d),
        None => std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/recursion-fixtures"),
    }
}

fn cache_path(profile: FriProfile, k: usize) -> std::path::PathBuf {
    cache_dir().join(format!("{profile:?}-{k}.proof"))
}

/// The cached `(hc, proof)` pair, or `None` when there is no usable file. A file that fails to
/// decode — *or that no longer verifies* — is treated as absent rather than as an error: the
/// encoding is `postcard` over a type this repository changes, so a stale cache must never be a test
/// failure, it must be a reprove.
///
/// The re-verification is the point of doing it here rather than only on the proving path
/// (`bundle_proofs` already asserts it for a freshly proved one). Every test in this crate is a
/// differential claim against `Machine::verify`, so a cached proof that the *current* machine
/// refuses would make every one of them vacuous — and the cache lives under `target/`, across
/// commits that change the constraint set or the profile. It costs ~0.2 s per proof against the
/// tens of seconds a reprove costs.
fn load_cached(m: &Machine, profile: FriProfile, k: usize) -> Option<BundleProof> {
    let bytes = std::fs::read(cache_path(profile, k)).ok()?;
    if bytes.len() < 32 {
        return None;
    }
    let mut hc = [0u32; 8];
    for (i, w) in hc.iter_mut().enumerate() {
        *w = u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap());
    }
    let proof: Proof = postcard::from_bytes(&bytes[32..]).ok()?;
    m.verify(&hc, &proof).ok()?;
    Some(BundleProof { proof, hc })
}

fn store_cached(profile: FriProfile, k: usize, p: &BundleProof) {
    let dir = cache_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let mut bytes: Vec<u8> = p.hc.iter().flat_map(|w| w.to_le_bytes()).collect();
    bytes.extend(p.proof.to_bytes());
    // A write failure is not a test failure: the cache is an optimisation.
    let _ = std::fs::write(cache_path(profile, k), bytes);
}

/// The pin file the cycle-budget test reads: written on the first run, committed, asserted after.
// `common` is compiled into every test binary; these are used only by `exit.rs` (and Task 7's
// `precompiles.rs`), so the other binaries would report them as dead.
#[allow(dead_code)]
pub struct Pins {
    pub cpu_rows: usize,
    pub permutations: usize,
    pub mem_accesses: usize,
    pub witness_words: usize,
    pub program_instrs: usize,
}

#[allow(dead_code)]
fn pins_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pins.json")
}

/// `recursion/tests/pins.json`, parsed. When the file is absent this *is* the measurement run: it
/// measures, writes the file (which the task then commits) and returns the same values, so the run
/// that produces the pin passes with it and every later run is a diff against it.
#[allow(dead_code)]
pub fn pins() -> Pins {
    if let Ok(s) = std::fs::read_to_string(pins_path()) {
        return parse_pins(&s);
    }
    let r = measure_production_inner_proof();
    let p = Pins {
        cpu_rows: r.cpu_rows,
        permutations: r.permutations,
        mem_accesses: r.mem_accesses,
        witness_words: r.witness_words,
        program_instrs: r.program_instrs,
    };
    let json = format!(
        "{{\n  \"cpu_rows\": {},\n  \"permutations\": {},\n  \"mem_accesses\": {},\n  \
         \"witness_words\": {},\n  \"program_instrs\": {}\n}}\n",
        p.cpu_rows, p.permutations, p.mem_accesses, p.witness_words, p.program_instrs
    );
    std::fs::write(pins_path(), json).expect("the pin file is writable");
    p
}

/// The five numeric fields of the hand-rolled pin JSON, in the order [`pins`] writes them.
#[allow(dead_code)]
fn parse_pins(s: &str) -> Pins {
    let get = |key: &str| -> usize {
        s.split(&format!("\"{key}\": "))
            .nth(1)
            .and_then(|rest| rest.split([',', '\n', ' ', '}']).next())
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("pins.json: no numeric field {key:?}: {s}"))
    };
    Pins {
        cpu_rows: get("cpu_rows"),
        permutations: get("permutations"),
        mem_accesses: get("mem_accesses"),
        witness_words: get("witness_words"),
        program_instrs: get("program_instrs"),
    }
}

/// Task 6's measurement, reused by Task 7's re-measurement: one production-profile inner proof
/// through the shipped (`Checkpoints::Off`) program.
#[allow(dead_code)]
pub fn measure_production_inner_proof() -> recursion::programs::CycleReport {
    use recursion::dsl::Checkpoints;
    use recursion::programs::verify_rv32;
    use recursion::shape::{InnerKey, InnerShape};
    use recursion::witness::WitnessTape;
    let p = bundle_proofs(FriProfile::Production, 1).pop().unwrap();
    let shape = InnerShape::of(
        FriProfile::Production,
        p.proof.tier,
        p.proof.program_log_height,
        p.proof.input_log_height,
        p.proof.keccak_log_height,
        p.proof.sha256_log_height,
        p.proof.public_log_height,
        p.proof.mem_log_height,
    );
    let key = InnerKey::of(FriProfile::Production, &shape);
    let vp = verify_rv32(&shape, &key, Checkpoints::Off);
    let tape = WitnessTape::build(FriProfile::Production, &shape, &key, &p.proof).unwrap();
    let exec = recursion::emulator::execute(&vp.program, &tape.words, 1 << 24).unwrap();
    recursion::programs::cycle_report(&vp, &exec)
}

/// `src/programs/verify_rv32.digest`, trimmed — written on the first measurement run and committed.
#[allow(dead_code)]
pub fn committed_digest() -> String {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/programs/verify_rv32.digest");
    if let Ok(s) = std::fs::read_to_string(&path) {
        return s.trim().to_string();
    }
    use recursion::dsl::Checkpoints;
    use recursion::programs::verify_rv32;
    use recursion::shape::{InnerKey, InnerShape};
    let p = bundle_proofs(FriProfile::Production, 1).pop().unwrap();
    let shape = InnerShape::of(
        FriProfile::Production,
        p.proof.tier,
        p.proof.program_log_height,
        p.proof.input_log_height,
        p.proof.keccak_log_height,
        p.proof.sha256_log_height,
        p.proof.public_log_height,
        p.proof.mem_log_height,
    );
    let key = InnerKey::of(FriProfile::Production, &shape);
    let vp = verify_rv32(&shape, &key, Checkpoints::Off);
    let hex = recursion::programs::digest_hex(&vp.program);
    std::fs::write(&path, format!("{hex}\n")).expect("the digest file is writable");
    hex
}

#[allow(dead_code)]
pub fn random_felt(rng: &mut impl rand::Rng) -> recursion::isa::F {
    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    use rand::RngExt;
    recursion::isa::F::from_u64(rng.random::<u64>() % recursion::isa::F::ORDER_U64)
}

#[allow(dead_code)]
pub fn random_ext(rng: &mut impl rand::Rng) -> recursion::isa::EF {
    use p3_field::BasedVectorSpace;
    let c = [random_felt(rng), random_felt(rng)];
    recursion::isa::EF::from_basis_coefficients_slice(&c).expect("an extension element is two coefficients")
}

/// `n` distinct honest bundle proofs at `profile`, cached on disk by `(profile, k)`.
pub fn bundle_proofs(profile: FriProfile, n: usize) -> Vec<BundleProof> {
    let m = Machine::new(profile);
    (0..n)
        .map(|k| {
            if let Some(p) = load_cached(&m, profile, k) {
                return p;
            }
            let (alice, bob, bridge) = (Party::new(), Party::new(), Party::new());
            let (asset, mint_time) = (0u32, 1_700_000_000u32);
            let mut ledger = Ledger::new(mint_time);
            // A different witness per k, and one that still conserves value below.
            let amounts = [1_000u64 + k as u64, 2_000 + 2 * k as u64];
            let in_notes: [Note; 2] = amounts.map(|amount| {
                let n = Note::new(alice.vk.pk(), bridge.vk.pk(), amount, asset, mint_time);
                let env = Envelope::seal(&bridge.vk, &alice.vk.address(), &n, &TxKey::random());
                ledger.mint(&n, env).unwrap();
                n
            });
            ledger.advance(60);
            let (time, anchor) = (ledger.now, ledger.root());
            let inputs: [(Note, [Word8; DEPTH], u32); 2] = std::array::from_fn(|i| {
                let (path, index) = ledger.path_for(&in_notes[i].commitment()).unwrap();
                (in_notes[i], path, index)
            });
            let total = amounts[0] + amounts[1];
            let (fee, burn) = (100u64, 0u64);
            let outputs = [
                Note::new(bob.vk.pk(), alice.vk.pk(), total - fee - 500, asset, time),
                Note::new(alice.vk.pk(), alice.vk.pk(), 500, asset, time),
            ];
            let inputs_vec =
                notes::bundle_inputs(&alice.sk, &inputs, &outputs, anchor, fee, burn, asset, time);
            // The public segment is empty for bundle proofs: the chain admits only
        // `verify_public(hc, &[], _)`, so the fixtures prove with `&[]` — and `H_PUB` is then
        // the prover-computed digest of the empty segment, carried as ordinary public values.
        let (proof, _) = m.prove(&ledger.bundle_program, &inputs_vec, &[], None).unwrap();
            let hc = ledger.bundle_program.digest();
            m.verify(&hc, &proof).expect("a fixture proof must verify natively");
            let p = BundleProof { proof, hc };
            store_cached(profile, k, &p);
            p
        })
        .collect()
}

// ── `rejects()`, the cheating-test discipline ────────────────────────────────────────────────
// The one definition of what counts as "the constraint system caught this", re-homed from
// `research/tests/common/mod.rs` per the M5.2 plan (its self-test lives in `tests/machine.rs`).
// Every cheating test in this crate counts a rejection through this helper and nothing else.
use std::panic::{catch_unwind, AssertUnwindSafe};

/// The panic `p3-batch-stark`'s debug constraint checker raises when a row violates a
/// constraint (`check_constraints.rs`'s `panic!`); matching the fixed prefix is what separates
/// "the constraint system caught this" from any other unwind. It runs per AIR instance, so it
/// catches violations local to one table's own rows.
#[allow(dead_code)]
pub const CONSTRAINT_PANIC: &str = "constraints not satisfied on row";

/// The panic `p3-lookup`'s debug bus-balance checker (`p3_lookup::debug_util::check_lookups`)
/// raises when a *global* lookup — provider and consumers in different AIR instances — has a
/// nonzero net multiplicity for some tuple. The only mechanism that catches an unpaid table
/// multiplicity on a table with no row-level validity marker of its own.
#[allow(dead_code)]
pub const LOOKUP_BALANCE_PANIC: &str = "Lookup mismatch (";

/// A tamper counts as rejected only if `verify` returned an error, or if the panic came from
/// one of the two constraint-system checks above. Anything else — a trace-builder `assert!`,
/// an index out of bounds — means the test tripped over something other than the constraint it
/// was written for, so it must fail rather than pass for the wrong reason.
#[allow(dead_code)]
pub fn rejects(f: impl FnOnce() -> Result<(), recursion::machine::VerifyError>) -> bool {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => false,
        Ok(Err(_)) => true,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<non-string panic payload>".to_string());
            let is_constraint = msg.contains(CONSTRAINT_PANIC) || msg.contains(LOOKUP_BALANCE_PANIC);
            if !is_constraint { eprintln!("rejects(): panic was not a constraint failure: {msg}"); }
            is_constraint
        }
    }
}
