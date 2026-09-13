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
/// decode is treated as absent rather than as an error: the encoding is `postcard` over a type
/// this repository changes, so a stale cache must never be a test failure.
fn load_cached(profile: FriProfile, k: usize) -> Option<BundleProof> {
    let bytes = std::fs::read(cache_path(profile, k)).ok()?;
    if bytes.len() < 32 {
        return None;
    }
    let mut hc = [0u32; 8];
    for (i, w) in hc.iter_mut().enumerate() {
        *w = u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap());
    }
    let proof: Proof = postcard::from_bytes(&bytes[32..]).ok()?;
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

/// `n` distinct honest bundle proofs at `profile`, cached on disk by `(profile, k)`.
pub fn bundle_proofs(profile: FriProfile, n: usize) -> Vec<BundleProof> {
    let m = Machine::new(profile);
    (0..n)
        .map(|k| {
            if let Some(p) = load_cached(profile, k) {
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
            let (proof, _) = m.prove(&ledger.bundle_program, &inputs_vec, None).unwrap();
            let hc = ledger.bundle_program.digest();
            m.verify(&hc, &proof).expect("a fixture proof must verify natively");
            let p = BundleProof { proof, hc };
            store_cached(profile, k, &p);
            p
        })
        .collect()
}
