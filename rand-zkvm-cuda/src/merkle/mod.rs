pub mod cpu;
pub mod prune;
pub mod mmcs;
pub type Digest = [u64; 4];

pub trait HashEngine: Clone + Send + Sync + 'static {
    type Mat;
    type Dig;
    fn upload(&self, values: &[u64], width: usize) -> Self::Mat;
    fn concat(&self, parts: &[(&Self::Mat, usize)], n: usize) -> (Self::Mat, usize);
    fn hash_rows(&self, rows: &Self::Mat, width: usize, n: usize, out_len: usize) -> Self::Dig;
    fn compress(&self, prev: &Self::Dig, next_len: usize, out_len: usize) -> Self::Dig;
    fn inject(&self, prev: &Self::Dig, raw_next: usize, rows: &Self::Mat, width: usize, n_rows: usize, out_len: usize) -> Self::Dig;
    fn download(&self, dig: &Self::Dig) -> Vec<Digest>;
}

/// Plonky3 `padded_len(raw_len, 2)`.
pub const fn padded_len(raw: usize) -> usize { if raw <= 1 { raw } else { raw.div_ceil(2) * 2 } }

pub struct Plan { pub order: Vec<usize>, pub layers: Vec<Vec<usize>> }

/// Mirror of `MerkleTree::new` scheduling for N = 2 (every step is 2).
pub fn plan(heights: &[usize]) -> Plan {
    let mut order: Vec<usize> = (0..heights.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(heights[i])); // stable
    let max = heights[order[0]];
    let mut pos = order.iter().position(|&i| heights[i] != max).unwrap_or(order.len());
    let mut layers = Vec::new();
    let mut len = padded_len(max);
    while len > 1 {
        let next_len = (len / 2).next_power_of_two();
        let mut inject = Vec::new();
        while pos < order.len() && heights[order[pos]].next_power_of_two() == next_len { inject.push(order[pos]); pos += 1; }
        layers.push(inject);
        let raw_next = len / 2;
        len = padded_len(raw_next);
    }
    Plan { order, layers }
}

pub struct Tree { pub digest_layers: Vec<Vec<Digest>>, pub arity_schedule: Vec<usize> }

/// `mats[i] = (device matrix, width, height)` in commit order.
pub fn build_tree<E: HashEngine>(e: &E, mats: &[(&E::Mat, usize, usize)]) -> Tree {
    let heights: Vec<usize> = mats.iter().map(|m| m.2).collect();
    let p = plan(&heights);
    let max = heights[p.order[0]];
    let tallest: Vec<usize> = p.order.iter().copied().take_while(|&i| heights[i] == max).collect();
    let group = |idx: &[usize]| -> (E::Mat, usize) {
        let parts: Vec<(&E::Mat, usize)> = idx.iter().map(|&i| (mats[i].0, mats[i].1)).collect();
        e.concat(&parts, heights[idx[0]])
    };
    let (leaf_mat, leaf_w) = group(&tallest);
    let mut dig = e.hash_rows(&leaf_mat, leaf_w, max, padded_len(max));
    let mut layers = vec![e.download(&dig)];
    let mut prev_len = padded_len(max);
    for inject in &p.layers {
        let raw_next = prev_len / 2;
        let out_len = padded_len(raw_next);
        dig = if inject.is_empty() {
            e.compress(&dig, raw_next, out_len)
        } else {
            let (m, w) = group(inject);
            e.inject(&dig, raw_next, &m, w, heights[inject[0]], out_len)
        };
        layers.push(e.download(&dig));
        prev_len = out_len;
    }
    let n = layers.len() - 1;
    Tree { digest_layers: layers, arity_schedule: vec![2; n] }
}

/// Plonky3 `MerkleTreeMmcs::commit` cap: effective cap height = min(cap_height, num_layers - 1);
/// cap = digest_layers[num_layers - 1 - h][..min(2^h, layer len)].
pub fn cap(tree: &Tree, cap_height: usize) -> Vec<Digest> {
    let num_layers = tree.digest_layers.len();
    let h = cap_height.min(num_layers.saturating_sub(1));
    let layer = &tree.digest_layers[num_layers - 1 - h];
    let len = (1usize << h).min(layer.len());
    layer[..len].to_vec()
}
