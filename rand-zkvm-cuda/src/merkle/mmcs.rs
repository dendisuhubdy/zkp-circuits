//! `HidingMmcs<E>`: a Plonky3 `Mmcs` whose prover side is this crate's own (GPU-capable)
//! Merkle tree and whose verifier side delegates to a `MerkleTreeHidingMmcs` instance.
use std::sync::{Arc, Mutex};
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_matrix::{Dimensions, Matrix};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::{MerkleCap, MerkleTreeError, MerkleTreeHidingMmcs, PrunedMerklePaths};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_util::log2_ceil_usize;
use rand::{SeedableRng, rngs::StdRng};
use super::{build_tree, cap, prune::prune_paths, Digest, HashEngine, Tree};

pub type Val = Goldilocks;
pub type Perm = Poseidon2Goldilocks<8>;
pub type Hash = PaddingFreeSponge<Perm, 8, 4, 4>;
pub type Compress = TruncatedPermutation<Perm, 2, 4, 8>;
pub type Packing = <Val as Field>::Packing;
pub type P3Hiding = MerkleTreeHidingMmcs<Packing, Packing, Hash, Compress, StdRng, 2, 4, 4>;
pub const SALT_ELEMS: usize = 4;

/// Prover data: the unsalted originals (for `get_matrices`), the salted leaves this
/// crate actually hashed, and the digest layers of our own tree.
pub struct ProverData<M> { pub originals: Vec<M>, pub salted: Vec<RowMajorMatrix<Val>>, pub tree: Tree }

pub struct HidingMmcs<E: HashEngine> { engine: Arc<E>, verifier: P3Hiding, cap_height: usize, rng: Arc<Mutex<StdRng>> }

/// Cloning *forks* the salt stream — a fresh seed drawn from the source RNG — exactly as
/// `MerkleTreeHidingMmcs::clone` does. This is not a stylistic choice: `ExtensionMmcs::new(
/// val_mmcs.clone())` is how a FRI config builds its challenge MMCS, so the clone advances the
/// original's stream by one `from_rng` draw. Sharing the `Arc` instead would leave the original
/// un-advanced and every subsequent commit salted differently from Plonky3's, which shows up as
/// a preprocessed commitment the CPU verifier cannot reproduce.
impl<E: HashEngine> Clone for HidingMmcs<E> {
    fn clone(&self) -> Self {
        let forked = StdRng::from_rng(&mut *self.rng.lock().unwrap());
        Self { engine: self.engine.clone(), verifier: self.verifier.clone(), cap_height: self.cap_height, rng: Arc::new(Mutex::new(forked)) }
    }
}

impl<E: HashEngine> HidingMmcs<E> {
    pub fn new(engine: Arc<E>, perm_seed: u64, cap_height: usize, rng: StdRng) -> Self {
        let perm = crate::constants::permutation(perm_seed);
        let verifier = P3Hiding::new(Hash::new(perm.clone()), Compress::new(perm), cap_height, StdRng::seed_from_u64(0));
        Self { engine, verifier, cap_height, rng: Arc::new(Mutex::new(rng)) }
    }

    fn digest(d: &Digest) -> [Val; 4] { d.map(Val::from_u64) }

    /// `num_layers - 1 - min(cap_height, num_layers - 1)`: the levels a proof traverses.
    fn proof_levels(tree: &Tree, cap_height: usize) -> usize {
        let n = tree.digest_layers.len();
        n.saturating_sub(1).saturating_sub(cap_height.min(n.saturating_sub(1)))
    }

    /// Plonky3 `open_batch` over the salted leaves: rows (with salts) and full sibling path.
    fn open_raw<M: Matrix<Val>>(&self, index: usize, pd: &ProverData<M>) -> (Vec<Vec<Val>>, Vec<Digest>) {
        let max_h = pd.salted.iter().map(|m| m.height()).max().unwrap();
        assert!(index < max_h, "index {index} out of bounds for height {max_h}");
        let log_max = log2_ceil_usize(max_h);
        let rows = pd.salted.iter().map(|m| { let r = index >> (log_max - log2_ceil_usize(m.height())); m.row(r).unwrap().into_iter().collect() }).collect();
        let mut sib = Vec::new(); let mut idx = index;
        for l in 0..Self::proof_levels(&pd.tree, self.cap_height) {
            let step = pd.tree.arity_schedule[l];
            let gs = (idx / step) * step; let pos = idx % step;
            for k in 0..step { if k != pos { sib.push(pd.tree.digest_layers[l][gs + k]); } }
            idx /= step;
        }
        (rows, sib)
    }

    fn split_salt(row: Vec<Val>) -> (Vec<Val>, Vec<Val>) { let n = row.len() - SALT_ELEMS; let mut r = row; let s = r.split_off(n); (r, s) }
}

impl<E: HashEngine> Mmcs<Val> for HidingMmcs<E> {
    type ProverData<M> = ProverData<M>;
    type Commitment = MerkleCap<Val, [Val; 4]>;
    type Proof = (Vec<Vec<Val>>, Vec<[Val; 4]>);
    type MultiProof = (Vec<Vec<Vec<Val>>>, PrunedMerklePaths<Val, 4>);
    type Error = MerkleTreeError;

    fn commit<M: Matrix<Val>>(&self, inputs: Vec<M>) -> (Self::Commitment, ProverData<M>) {
        // Salts are drawn one `RowMajorMatrix::rand` call per matrix, in input order,
        // exactly as `MerkleTreeHidingMmcs::commit` does, so the stream matches.
        let mut rng = self.rng.lock().unwrap();
        let salted: Vec<RowMajorMatrix<Val>> = inputs.iter().map(|m| {
            let salts = RowMajorMatrix::<Val>::rand(&mut *rng, m.height(), SALT_ELEMS);
            let w = m.width() + SALT_ELEMS;
            let mut v = Vec::with_capacity(m.height() * w);
            for (r, row) in m.rows().enumerate() { v.extend(row); v.extend_from_slice(&salts.values[r * SALT_ELEMS..(r + 1) * SALT_ELEMS]); }
            RowMajorMatrix::new(v, w)
        }).collect();
        drop(rng);
        let ups: Vec<E::Mat> = salted.iter().map(|m| self.engine.upload(&m.values.iter().map(|x| x.as_canonical_u64()).collect::<Vec<_>>(), m.width())).collect();
        let refs: Vec<(&E::Mat, usize, usize)> = ups.iter().zip(&salted).map(|(u, m)| (u, m.width(), m.height())).collect();
        let tree = build_tree(&*self.engine, &refs);
        let commitment = MerkleCap::new(cap(&tree, self.cap_height).iter().map(Self::digest).collect());
        (commitment, ProverData { originals: inputs, salted, tree })
    }

    fn open_batch<M: Matrix<Val>>(&self, index: usize, pd: &ProverData<M>) -> BatchOpening<Val, Self> {
        let (rows, sib) = self.open_raw(index, pd);
        let (opened, salts): (Vec<_>, Vec<_>) = rows.into_iter().map(Self::split_salt).unzip();
        BatchOpening::new(opened, (salts, sib.iter().map(Self::digest).collect()))
    }

    fn get_matrices<'a, M: Matrix<Val>>(&self, pd: &'a ProverData<M>) -> Vec<&'a M> { pd.originals.iter().collect() }

    fn verify_batch(&self, commit: &Self::Commitment, dims: &[Dimensions], index: usize, opening: BatchOpeningRef<'_, Val, Self>) -> Result<(), MerkleTreeError> {
        let (values, proof) = opening.unpack();
        self.verifier.verify_batch(commit, dims, index, BatchOpeningRef::<Val, P3Hiding>::new(values, proof))
    }

    fn open_multi_batch<M: Matrix<Val>>(&self, indices: &[usize], pd: &ProverData<M>) -> (Vec<Vec<Vec<Val>>>, Self::MultiProof) {
        let levels = Self::proof_levels(&pd.tree, self.cap_height);
        let mut opened = Vec::with_capacity(indices.len()); let mut salts = Vec::with_capacity(indices.len()); let mut paths = Vec::with_capacity(indices.len());
        for &i in indices {
            let (rows, sib) = self.open_raw(i, pd);
            let (o, s): (Vec<_>, Vec<_>) = rows.into_iter().map(Self::split_salt).unzip();
            opened.push(o); salts.push(s); paths.push((i, sib));
        }
        let pruned = prune_paths(&pd.tree.arity_schedule[..levels], &paths);
        (opened, (salts, PrunedMerklePaths { sibling_hashes: pruned.iter().map(Self::digest).collect() }))
    }

    fn verify_multi_batch<R: AsRef<[Val]> + PartialEq>(&self, commit: &Self::Commitment, dims: &[Dimensions], indices: &[usize], opened: &[Vec<R>], proof: &Self::MultiProof) -> Result<(), MerkleTreeError> {
        self.verifier.verify_multi_batch(commit, dims, indices, opened, proof)
    }
}
