//! The inner proof's *shape* and *key*: everything the verifier program is specialised to at build
//! time, and nothing that comes out of a proof.
//!
//! The plan's ruling: the verifier program is shape-specialised. The transcript needs every
//! instance's degree bits, trace width and quotient-chunk count *before* it reads anything, and
//! recomputing the inner preprocessed commitment in-circuit costs 3.1 M Poseidon2 permutations (the
//! spike's single most important finding), so both are compile-time constants of the program. One
//! program — and one program digest — per shape the chain aggregates.
//!
//! Nothing here is read off a `Proof`. [`InnerShape::of`] takes the declared heights (which the
//! *node* knows, from its own chain config and the bundle it is admitting) and derives the rest from
//! the machine: `chips`, `Machine::log_ext_degrees`, `get_log_num_quotient_chunks` and
//! `Machine::verifier_key` are all pure functions of the tier and those heights.
//! [`InnerShape::matches`] is the other direction — it says whether a given proof is one this
//! program was built for — and the program itself re-checks the same thing word by word off its
//! witness tape (`Segment::Header`), so a proof of the wrong shape is refused rather than
//! misparsed.

use crate::isa::F;
use p3_air::symbolic::AirLayout;
use p3_air::BaseAir;
use p3_commit::Pcs;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::LogUpGadget;
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};
use p3_uni_stark::StarkGenericConfig;
use rand_zkvm::machine::{
    chips, Challenge, Chip, Config, FriProfile, Machine, Perm, Proof, Tier, Val,
};

/// `log_blowup`, from `research`'s `generic_config` (`research/src/machine.rs`). A literal there and
/// a literal here; `InnerShape::of` cannot read it back off a `FriParameters` because the `Config`'s
/// PCS keeps them private.
pub const LOG_BLOWUP: usize = 3;
/// `log_final_poly_len`, same source: the final polynomial is a single coefficient.
pub const LOG_FINAL_POLY_LEN: usize = 0;
/// `max_log_arity`, same source: FRI folds by at most 8 per round.
pub const MAX_LOG_ARITY: usize = 3;
/// `num_random_codewords`, same source: every committed matrix but the preprocessed one carries four
/// extra hiding columns, and every opened point four extra hidden values.
pub const NUM_RANDOM_CODEWORDS: usize = 4;
/// `cap_height`: a commitment is a [`p3_symmetric::MerkleCap`] of `1 << CAP_HEIGHT` digests, and a
/// Merkle walk stops that many levels below the root.
pub const CAP_HEIGHT: usize = 2;
/// The public-values slot: `chips()[1]` is the cpu table and it owns all of them.
pub const PV_INSTANCE: usize = 1;

/// The hash-domain tag of [`inner_vk_digest`]. `rand_zkvm::notes::domain` is occupied through 14 and
/// `crate::isa::RVM_PROGRAM_DOMAIN` is 15, so 16 is the next free tag; all three share one
/// permutation, so a collision would let one construction's digest stand in for another's.
pub const RVM_VK_DOMAIN: u64 = 16;

/// The shape of one inner proof: the declared heights, plus everything the batch transcript and the
/// opening argument need that follows from them.
///
/// `PartialEq` is the load-bearing derive: the exit test asserts every fixture proof shares one
/// shape, which is what makes one program's measurement a statement about all of them.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InnerShape {
    pub tier: usize,
    pub program_log_height: u8,
    pub input_log_height: u8,
    pub keccak_log_height: u8,
    pub sha256_log_height: u8,
    /// Constraint set 6: the mandatory public table's declared height. No `0` "no such table"
    /// value exists — the public instance is in every batch, last in `chips()` order.
    pub public_log_height: u8,
    pub mem_log_height: u8,
    pub num_queries: usize,
    pub query_pow_bits: usize,
    /// Per instance, `log2(|extended trace domain|)` — `Machine::log_ext_degrees`.
    pub degree_bits: Vec<usize>,
    /// Per instance, the main trace width (`BaseAir::width`), *without* the hiding wrapper's four
    /// random codewords.
    pub widths: Vec<usize>,
    /// Per instance, the preprocessed width; `0` when the chip declares none.
    pub preprocessed_widths: Vec<usize>,
    /// Per instance, before ZK doubling: the committed chunk count is `(1 << x) << 1`.
    pub log_num_quotient_chunks: Vec<usize>,
    /// Per instance, `= aux_width - 1`: the permutation trace is one accumulator column plus one
    /// fraction column per lookup, and is `0` wide when the chip declares no lookups.
    pub num_lookups: Vec<usize>,
    pub num_public_values: Vec<usize>,
    /// Per instance, whether the constraints read the next row of the main / preprocessed trace —
    /// which is what decides whether that round opens one point or two.
    pub main_next: Vec<bool>,
    pub pre_next: Vec<bool>,
    /// The global preprocessed commitment's matrix order: `matrix_to_instance[m]` is the instance
    /// whose preprocessed trace is matrix `m`.
    pub preprocessed_matrix_to_instance: Vec<usize>,
    /// The FRI arity schedule this program is built for, one entry per commit-phase round.
    ///
    /// It is **derived, not read off a proof**: `p3_fri::compute_log_arity_for_round` is a pure
    /// function of the current height, the next input height, the final height and
    /// `max_log_arity`, and every matrix in the opening argument has log-height
    /// `degree_bits[i] + LOG_BLOWUP` (the quotient-chunk domains split down to `ext_db - is_zk`
    /// and the ZK doubling puts them back, and the preprocessed matrices carry the instance's own
    /// `degree_bits`). So the schedule is a function of the distinct degree bits alone — which is
    /// what makes it part of the shape rather than of the witness.
    pub log_arities: Vec<usize>,
}

/// The inner preprocessed commitment: a `MerkleCap` of four digests, a constant of the machine at
/// this shape. Sixteen field elements the program carries as immediates.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InnerKey {
    pub cap: [[F; 4]; 4],
}

/// Why a shape could not be built for these heights.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ShapeError {
    /// `check_declared_heights` refused them, so no proof of this shape can exist.
    DeclaredHeights(String),
    /// The machine's preprocessed commitment is not a four-digest cap, so this crate's
    /// `CAP_HEIGHT` no longer matches `research`'s.
    CapShape(usize),
    /// The derived FRI schedule does not roll in every distinct input height, so it is not the
    /// schedule `p3_fri::prover::commit_phase` would build for these degree bits — and a program
    /// built from it would read a commit-phase round the proof does not have. A shape error rather
    /// than an assertion because [`InnerShape::try_of`] is the fallible entry a node calls with
    /// numbers it did not choose.
    FriSchedule { rolled_in: usize, heights: usize },
}

impl InnerShape {
    /// The shape of any proof at `(profile, tier, the six declared heights)`.
    ///
    /// Panics when the heights are ones `Machine::verify` would refuse outright
    /// (`check_declared_heights`), because a verifier program for a shape no proof can have is a
    /// build-time mistake, not a runtime condition. Use [`InnerShape::try_of`] for the fallible
    /// form.
    pub fn of(
        profile: FriProfile,
        tier: Tier,
        program_log_height: u8,
        input_log_height: u8,
        keccak_log_height: u8,
        sha256_log_height: u8,
        public_log_height: u8,
        mem_log_height: u8,
    ) -> Self {
        Self::try_of(
            profile,
            tier,
            program_log_height,
            input_log_height,
            keccak_log_height,
            sha256_log_height,
            public_log_height,
            mem_log_height,
        )
        .expect("a verifier program is built for a shape a proof can actually have")
    }

    /// [`InnerShape::of`], reporting rather than panicking.
    pub fn try_of(
        profile: FriProfile,
        tier: Tier,
        program_log_height: u8,
        input_log_height: u8,
        keccak_log_height: u8,
        sha256_log_height: u8,
        public_log_height: u8,
        mem_log_height: u8,
    ) -> Result<Self, ShapeError> {
        rand_zkvm::machine::check_declared_heights(
            tier,
            program_log_height,
            input_log_height,
            keccak_log_height,
            sha256_log_height,
            public_log_height,
            mem_log_height,
        )
        .map_err(|e| ShapeError::DeclaredHeights(format!("{e:?}")))?;

        let machine = machine(profile);
        let is_zk = machine.config.is_zk();
        let airs = chips(tier, keccak_log_height, sha256_log_height);
        let degree_bits = machine.log_ext_degrees(
            tier,
            program_log_height,
            input_log_height,
            keccak_log_height,
            sha256_log_height,
            public_log_height,
            mem_log_height,
        );
        let common = machine.verifier_key(
            tier,
            program_log_height,
            input_log_height,
            keccak_log_height,
            sha256_log_height,
            public_log_height,
        );

        let widths: Vec<usize> = airs.iter().map(BaseAir::<Val>::width).collect();
        let num_public_values: Vec<usize> =
            airs.iter().map(BaseAir::<Val>::num_public_values).collect();
        let main_next: Vec<bool> = airs
            .iter()
            .map(|a| !BaseAir::<Val>::main_next_row_columns(a).is_empty())
            .collect();
        let pre_next: Vec<bool> = airs
            .iter()
            .map(|a| !BaseAir::<Val>::preprocessed_next_row_columns(a).is_empty())
            .collect();
        let num_lookups: Vec<usize> = common.lookups.iter().map(|l| l.len()).collect();

        // The preprocessed widths and matrix order come from `CommonData`, exactly as
        // `verify_batch`'s own precompute loop takes them (`BaseAir::preprocessed_width` would
        // agree, but the transcript observes *these*, and a disagreement is a proof-shape error
        // rather than something the program should paper over).
        let (preprocessed_widths, preprocessed_matrix_to_instance, cap_roots) =
            match &common.preprocessed {
                Some(global) => (
                    global
                        .instances
                        .iter()
                        .map(|m| m.as_ref().map_or(0, |m| m.width))
                        .collect::<Vec<_>>(),
                    global.matrix_to_instance.clone(),
                    global.commitment.num_roots(),
                ),
                None => (vec![0; airs.len()], Vec::new(), 1 << CAP_HEIGHT),
            };
        if cap_roots != 1 << CAP_HEIGHT {
            return Err(ShapeError::CapShape(cap_roots));
        }

        let lookup_gadget = LogUpGadget::new();
        let log_arities = fri_schedule(&degree_bits)?;

        let mut shape = InnerShape {
            tier: tier.0,
            program_log_height,
            input_log_height,
            keccak_log_height,
            sha256_log_height,
            public_log_height,
            mem_log_height,
            num_queries: profile.num_queries(),
            query_pow_bits: profile.pow_bits(),
            degree_bits,
            widths,
            preprocessed_widths,
            num_lookups,
            num_public_values,
            main_next,
            pre_next,
            preprocessed_matrix_to_instance,
            log_arities,
            // Filled in immediately below. `air_layout` reads three of the fields above, so the
            // shape has to exist before the layouts can be built from it — and building them from
            // the locals instead would be a second copy of `air_layout`'s body, which is exactly
            // what that method exists to prevent.
            log_num_quotient_chunks: Vec::new(),
        };
        shape.log_num_quotient_chunks = airs
            .iter()
            .enumerate()
            .map(|(i, air)| {
                p3_batch_stark::symbolic::get_log_num_quotient_chunks::<Val, Challenge, _, _>(
                    air,
                    shape.air_layout(i, air),
                    1usize << (shape.degree_bits[i] - is_zk),
                    &common.lookups[i],
                    is_zk,
                    &lookup_gadget,
                )
            })
            .collect();
        Ok(shape)
    }

    /// The number of batch instances.
    pub fn instances(&self) -> usize {
        self.degree_bits.len()
    }

    /// The FRI profile this shape was built for.
    ///
    /// Recovered from `(num_queries, query_pow_bits)` rather than stored, because those two numbers
    /// *are* the profile — `FriProfile` has exactly two variants and they agree on neither. The only
    /// constructor is [`InnerShape::try_of`], which sets both from a profile, so the lookup is total
    /// for every shape that exists.
    ///
    /// It is needed because a `Machine` is the only way to reach `CommonData` (below), and the
    /// program builder is handed a shape, not a profile.
    pub fn profile(&self) -> FriProfile {
        [FriProfile::Test, FriProfile::Production]
            .into_iter()
            .find(|p| p.num_queries() == self.num_queries && p.pow_bits() == self.query_pow_bits)
            .expect("a shape's query count and PoW bits come from one of the two profiles")
    }

    /// The `AirLayout` `verify_batch`'s precompute loop builds for instance `i`: the widths the
    /// symbolic builder lays its variables out from.
    ///
    /// The permutation fields are deliberately left at `Default`: `get_symbolic_constraints` and
    /// `get_log_num_quotient_chunks` both overwrite them from the instance's own lookup contexts, so
    /// filling them here would be a second, divergeable source for the same three numbers.
    pub fn air_layout(&self, i: usize, air: &Chip) -> AirLayout {
        AirLayout {
            preprocessed_width: self.preprocessed_widths[i],
            main_width: self.widths[i],
            num_public_values: self.num_public_values[i],
            num_periodic_columns: BaseAir::<Val>::num_periodic_columns(air),
            ..Default::default()
        }
    }

    /// The batch's `CommonData`: the preprocessed commitment and, the reason the constraint emitter
    /// wants it, every instance's lookup contexts.
    ///
    /// A pure function of the tier, the declared heights and the profile — `Machine::verifier_key`
    /// is seeded from a fixed constant precisely so that it is — and cached inside the shared
    /// [`machine`], so calling it per instance costs one hash-map lookup.
    pub(crate) fn common_data(&self) -> std::sync::Arc<p3_batch_stark::CommonData<Config>> {
        machine(self.profile()).verifier_key(
            Tier(self.tier),
            self.program_log_height,
            self.input_log_height,
            self.keccak_log_height,
            self.sha256_log_height,
            self.public_log_height,
        )
    }

    /// `max(degree_bits) + LOG_BLOWUP`, the height every query index is sampled from — and, by the
    /// cross-check `verify_fri` performs, also `Σ log_arities + LOG_BLOWUP + LOG_FINAL_POLY_LEN`.
    pub fn log_global_max_height(&self) -> usize {
        self.degree_bits.iter().copied().max().expect("a batch has instances") + LOG_BLOWUP
    }

    /// The canonical flattening hashed into the vk digest. Every number the program is specialised
    /// to appears here exactly once, so two different shapes cannot share a digest.
    pub fn shape_words(&self) -> Vec<F> {
        let mut w = vec![
            self.tier,
            self.program_log_height as usize,
            self.input_log_height as usize,
            self.keccak_log_height as usize,
            self.sha256_log_height as usize,
            self.public_log_height as usize,
            self.mem_log_height as usize,
            self.num_queries,
            self.query_pow_bits,
            self.instances(),
        ];
        for i in 0..self.instances() {
            w.push(self.degree_bits[i]);
            w.push(self.widths[i]);
            w.push(self.preprocessed_widths[i]);
            w.push(self.log_num_quotient_chunks[i]);
            w.push(self.num_lookups[i]);
            w.push(self.num_public_values[i]);
            w.push(self.main_next[i] as usize);
            w.push(self.pre_next[i] as usize);
        }
        w.extend(self.log_arities.iter().copied());
        w.into_iter().map(F::from_usize).collect()
    }

    /// The `Header` segment's contents, which the program reads and pins word by word:
    /// `[tier, program_log_height, input_log_height, keccak_log_height, sha256_log_height,
    ///   public_log_height, mem_log_height, num_queries, log_arities…]`.
    ///
    /// These are exactly the words a *proof* carries (or, for `num_queries`, that the profile
    /// fixes and the schedule that the proof's `commit_phase_openings` declare), so the program's
    /// first act is to compare the proof's own declared shape against its own — which is why a
    /// proof of another shape is refused at `"header word k"` rather than silently misparsed.
    pub fn header_words(&self) -> Vec<F> {
        let mut w = vec![
            self.tier,
            self.program_log_height as usize,
            self.input_log_height as usize,
            self.keccak_log_height as usize,
            self.sha256_log_height as usize,
            self.public_log_height as usize,
            self.mem_log_height as usize,
            self.num_queries,
        ];
        w.extend(self.log_arities.iter().copied());
        w.into_iter().map(F::from_usize).collect()
    }

    /// Whether `proof` is one a program of this shape verifies: the declared heights, the instance
    /// count, the degree bits and the arity schedule.
    ///
    /// This is the host's pre-flight check. The program does not rely on it — it re-derives the same
    /// comparison from its witness tape — but a node that runs it first can refuse a
    /// wrong-shape proof without building a tape.
    pub fn matches(&self, proof: &Proof) -> bool {
        proof.tier.0 == self.tier
            && proof.program_log_height == self.program_log_height
            && proof.input_log_height == self.input_log_height
            && proof.keccak_log_height == self.keccak_log_height
            && proof.sha256_log_height == self.sha256_log_height
            && proof.public_log_height == self.public_log_height
            && proof.mem_log_height == self.mem_log_height
            && proof.batch.degree_bits == self.degree_bits
            && proof.public_values.len() == self.num_public_values[PV_INSTANCE]
            // `Machine::verify` insists on the canonical representative, so a proof it refuses is
            // one this crate refuses too. The rVM cannot make the check itself — its tape carries
            // field elements, and `x` and `x + p` are the same one — so it belongs here, on the host
            // that deserialised the bytes.
            && proof.public_values.iter().all(|x| *x < <Val as p3_field::PrimeField64>::ORDER_U64)
            && proof_log_arities(proof) == self.log_arities
    }
}

/// The arity schedule of a proof, as `verify_fri` extracts it (bounds unchecked here; the tape
/// builder and the program both compare it against the shape's own).
pub(crate) fn proof_log_arities(proof: &Proof) -> Vec<usize> {
    proof
        .batch
        .opening_proof
        .1
        .commit_phase_openings
        .iter()
        .map(|o| o.log_arity as usize)
        .collect()
}

/// The commit-phase arity schedule implied by a set of extended degree bits.
///
/// `p3_fri::prover::commit_phase`'s loop, with the heights it folds over: the reduced openings live
/// at the distinct input log-heights `degree_bits[i] + LOG_BLOWUP`, descending, and each round folds
/// by `compute_log_arity_for_round(current, next_input, final, max)` — the very function the prover
/// calls, so this is the reference schedule and not a second guess at it.
fn fri_schedule(degree_bits: &[usize]) -> Result<Vec<usize>, ShapeError> {
    let mut heights: Vec<usize> = degree_bits.iter().map(|d| d + LOG_BLOWUP).collect();
    heights.sort_unstable_by(|a, b| b.cmp(a));
    heights.dedup();

    let log_final_height = LOG_BLOWUP + LOG_FINAL_POLY_LEN;
    let mut log_current = heights[0];
    let mut next = 1usize; // the next *unconsumed* input height
    let mut out = Vec::new();
    while log_current > log_final_height {
        let log_arity = p3_fri::compute_log_arity_for_round(
            log_current,
            heights.get(next).copied(),
            log_final_height,
            MAX_LOG_ARITY,
        );
        out.push(log_arity);
        log_current -= log_arity;
        if heights.get(next) == Some(&log_current) {
            next += 1;
        }
    }
    if next != heights.len() {
        return Err(ShapeError::FriSchedule { rolled_in: next, heights: heights.len() });
    }
    Ok(out)
}

impl InnerKey {
    /// The machine's preprocessed `MerkleCap` at this shape: sixteen field elements, recomputable by
    /// anyone who knows the tier and the declared heights and nothing else (`Machine::verifier_key`
    /// is seeded from a fixed constant precisely so that it is).
    pub fn of(profile: FriProfile, shape: &InnerShape) -> Self {
        let machine = machine(profile);
        let common = machine.verifier_key(
            Tier(shape.tier),
            shape.program_log_height,
            shape.input_log_height,
            shape.keccak_log_height,
            shape.sha256_log_height,
            shape.public_log_height,
        );
        let roots = common
            .preprocessed
            .as_ref()
            .expect("this machine's batch always has preprocessed columns")
            .commitment
            .roots();
        assert_eq!(roots.len(), 1 << CAP_HEIGHT, "cap_height is 2");
        InnerKey { cap: std::array::from_fn(|i| roots[i]) }
    }

    /// The cap's sixteen elements in `roots()` order — the order the challenger absorbs them in and
    /// the order [`inner_vk_digest`] hashes them in.
    pub fn flatten(&self) -> Vec<F> {
        self.cap.iter().flatten().copied().collect()
    }
}

/// The published identity of an inner verifier: `PaddingFreeSponge<Perm, 8, 4, 4>` over
/// `[RVM_VK_DOMAIN] ‖ shape_words ‖ cap(16)`, four field elements.
///
/// Spec §4.4 calls this an "inner verifier key digest (8 elements)"; a digest on this machine is
/// four (spec §12 erratum 1), and a verifier key here is a sixteen-element cap plus a shape rather
/// than a digest at all — so both halves are hashed into one value the node and the program compute
/// with the same function. The program recomputes it from its own compile-time constants and
/// `PUBLIC`s it, so the aggregate says which inner verifier it ran.
pub fn inner_vk_digest(shape: &InnerShape, key: &InnerKey) -> [F; 4] {
    let sponge = PaddingFreeSponge::<Perm, 8, 4, 4>::new(rand_zkvm::machine::permutation());
    let mut msg = vec![F::from_u64(RVM_VK_DOMAIN)];
    msg.extend(shape.shape_words());
    msg.extend(key.flatten());
    sponge.hash_iter(msg)
}

/// The one `Machine` this crate verifies against, per profile, built once.
///
/// Amortising it is not a micro-optimisation: `Machine::verifier_key` recomputes the whole
/// preprocessed commitment (the range, nibble and Poseidon2 round-constant tables' Merkle trees) on
/// a cache miss, and its cache lives *in the machine*. A fresh `Machine` per [`InnerShape::of`],
/// [`InnerKey::of`] and [`crate::reference::replay`] call would pay that three times over for every
/// proof, which at Task 6's fifty is the difference between seconds and minutes.
///
/// It is a *verifier's* machine: the only entropy `Machine::new` draws is for the proving side of the
/// config, which nothing here touches. Anything that proves builds its own.
pub(crate) fn machine(profile: FriProfile) -> &'static Machine {
    static TEST: std::sync::OnceLock<Machine> = std::sync::OnceLock::new();
    static PRODUCTION: std::sync::OnceLock<Machine> = std::sync::OnceLock::new();
    let cell = match profile {
        FriProfile::Test => &TEST,
        FriProfile::Production => &PRODUCTION,
    };
    cell.get_or_init(|| Machine::new(profile))
}

/// The value MMCS the input and commit-phase Merkle checks run through, built once.
///
/// `val_mmcs_for_tests` constructs a fresh Poseidon2 permutation (128 rounds of constants drawn from
/// an RNG) on every call, and this crate needs it in the replay and twice more in the tape builder.
pub(crate) fn val_mmcs() -> &'static rand_zkvm::machine::ValMmcs {
    static MMCS: std::sync::OnceLock<rand_zkvm::machine::ValMmcs> = std::sync::OnceLock::new();
    MMCS.get_or_init(rand_zkvm::machine::val_mmcs_for_tests)
}

/// `natural_domain_for_degree`, which is all of the PCS the shape layer needs.
pub(crate) fn natural_domain(
    cfg: &Config,
    size: usize,
) -> p3_field::coset::TwoAdicMultiplicativeCoset<Val> {
    <rand_zkvm::machine::Pcs as Pcs<Challenge, rand_zkvm::machine::Challenger>>::natural_domain_for_degree(
        cfg.pcs(),
        size,
    )
}
