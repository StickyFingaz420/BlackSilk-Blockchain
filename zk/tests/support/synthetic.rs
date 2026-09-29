//! Synthetic proofs for the decoder's bounds (RT-FUZZ-1): every field has an
//! honest proof's structure (counts and lengths as `verify` requires them),
//! with zero values. They decode (and pass the canonical-form rules), but do
//! not verify; no proving is involved.

use blacksilk_zk::config::{Challenge, Val};
use blacksilk_zk::params::{
    EXTENSION_DEGREE, MERKLE_SALT_ELEMS, NUM_QUERIES, NUM_RANDOM_CODEWORDS,
};
use blacksilk_zk::Proof;
use p3_batch_stark::proof::OpenedValuesWithLookups;
use p3_batch_stark::{BatchCommitments, BatchOpenedValues, BatchProof, OpenedValues};
use p3_field::PrimeCharacteristicRing;
use p3_fri::{BatchMultiOpening, CommitPhaseMultiStep, FriProof};
use p3_lookup::LookupTerminal;
use p3_merkle_tree::{MerkleCap, PrunedMerklePaths};

/// The shape of a synthetic proof.
#[derive(Clone, Debug)]
pub struct Spec {
    /// Quotient chunks of each instance (one entry per instance).
    pub chunks: Vec<usize>,
    /// Main trace width of every instance.
    pub width: usize,
    /// Permutation (lookup) width of every instance; 0 for no lookups.
    pub perm_width: usize,
    /// Whether every instance opens preprocessed columns (local and next).
    pub preprocessed: bool,
    /// FRI commit-phase rounds (each of arity 2).
    pub fri_rounds: usize,
    /// Sibling digests of every pruned multiproof.
    pub siblings: usize,
}

impl Spec {
    /// Shaped like the real transfer proof (13 tables).
    pub fn transfer_like() -> Self {
        Spec {
            chunks: vec![4, 4, 4, 4, 16, 4, 4, 8, 8, 8, 4, 8, 4],
            width: 40,
            perm_width: 48,
            preprocessed: false,
            fri_rounds: 7,
            siblings: 64,
        }
    }

    /// A small shape, for many decodes.
    pub fn small() -> Self {
        Spec {
            chunks: vec![2, 4],
            width: 3,
            perm_width: 8,
            preprocessed: true,
            fri_rounds: 2,
            siblings: 3,
        }
    }
}

fn ext(n: usize) -> Vec<Challenge> {
    vec![Challenge::ZERO; n]
}

fn cap() -> MerkleCap<Val, [Val; 8]> {
    MerkleCap::new(vec![[Val::ZERO; 8]])
}

/// One multiproof opening `matrices` matrices at every query.
fn multiproof(matrices: usize, siblings: usize) -> (Vec<Vec<Vec<Val>>>, PrunedMerklePaths<Val, 8>) {
    (
        vec![vec![vec![Val::ZERO; MERKLE_SALT_ELEMS]; matrices]; NUM_QUERIES],
        PrunedMerklePaths {
            sibling_hashes: vec![[Val::ZERO; 8]; siblings],
        },
    )
}

/// The synthetic proof of `s`.
pub fn proof(s: &Spec) -> Proof {
    let n = s.chunks.len();
    let lookups = s.perm_width > 0;
    let instances = s
        .chunks
        .iter()
        .map(|&q| OpenedValuesWithLookups {
            base_opened_values: OpenedValues {
                trace_local: ext(s.width),
                trace_next: Some(ext(s.width)),
                preprocessed_local: s.preprocessed.then(|| ext(2)),
                preprocessed_next: s.preprocessed.then(|| ext(2)),
                quotient_chunks: vec![ext(EXTENSION_DEGREE); q],
                random: Some(ext(EXTENSION_DEGREE)),
            },
            permutation_local: ext(s.perm_width),
            permutation_next: ext(s.perm_width),
        })
        .collect();
    let chunks: usize = s.chunks.iter().sum();
    // Opening rounds: (matrices, points per matrix, hidden values per point,
    // public values per point).
    let mut rounds = vec![
        (n, 1, NUM_RANDOM_CODEWORDS, EXTENSION_DEGREE),
        (n, 2, NUM_RANDOM_CODEWORDS, s.width),
        (chunks, 1, NUM_RANDOM_CODEWORDS, EXTENSION_DEGREE),
    ];
    if s.preprocessed {
        rounds.push((n, 2, 0, 2));
    }
    if lookups {
        rounds.push((n, 2, NUM_RANDOM_CODEWORDS, s.perm_width));
    }
    let hidden = rounds
        .iter()
        .map(|&(m, points, hidden, _)| vec![vec![ext(hidden); points]; m])
        .collect();
    let input_openings = rounds
        .iter()
        .map(|&(m, _, hidden, public)| BatchMultiOpening {
            opened_values: vec![vec![vec![Val::ZERO; public + hidden]; m]; NUM_QUERIES],
            opening_proof: multiproof(m, s.siblings),
        })
        .collect();
    let commit_phase_openings = (0..s.fri_rounds)
        .map(|_| CommitPhaseMultiStep {
            log_arity: 1,
            sibling_values: vec![ext(1); NUM_QUERIES],
            opening_proof: multiproof(1, s.siblings),
        })
        .collect();
    BatchProof {
        commitments: BatchCommitments {
            main: cap(),
            permutation: lookups.then(cap),
            quotient_chunks: cap(),
            random: Some(cap()),
        },
        opened_values: BatchOpenedValues { instances },
        opening_proof: (
            hidden,
            FriProof {
                commit_phase_commits: (0..s.fri_rounds).map(|_| cap()).collect(),
                commit_pow_witnesses: vec![Val::ZERO; s.fri_rounds],
                input_openings,
                commit_phase_openings,
                final_poly: ext(1 << blacksilk_zk::params::LOG_FINAL_POLY_LEN),
                query_pow_witness: Val::ZERO,
            },
        ),
        lookup_terminals: (0..n)
            .map(|_| lookups.then_some(LookupTerminal(Challenge::ZERO)))
            .collect(),
        degree_bits: vec![10; n],
    }
}

/// The most vectors the decoder's caps allow for `n` instances of `q`
/// quotient chunks each, with every vector that may be empty left empty: the
/// most heap per encoded byte a proof can reach the decoder with. It decodes
/// structurally (the canonical-form rules then refuse its empty openings).
pub fn densest(n: usize, q: usize, siblings: usize) -> Proof {
    let mut p = proof(&Spec {
        chunks: vec![q; n],
        width: 0,
        perm_width: 1,
        preprocessed: true,
        fri_rounds: blacksilk_zk::bounds::MAX_FRI_ROUNDS,
        siblings,
    });
    for i in &mut p.opened_values.instances {
        let o = &mut i.base_opened_values;
        o.trace_next = Some(vec![]);
        o.preprocessed_local = Some(vec![]);
        o.preprocessed_next = Some(vec![]);
        o.random = Some(vec![]);
        o.quotient_chunks.iter_mut().for_each(Vec::clear);
        i.permutation_local.clear();
        i.permutation_next.clear();
    }
    p.opening_proof
        .0
        .iter_mut()
        .flatten()
        .flatten()
        .for_each(Vec::clear);
    for b in &mut p.opening_proof.1.input_openings {
        b.opened_values.iter_mut().flatten().for_each(Vec::clear);
    }
    for o in &mut p.opening_proof.1.commit_phase_openings {
        o.sibling_values.iter_mut().for_each(Vec::clear);
    }
    p.opening_proof.1.final_poly.clear();
    p
}
