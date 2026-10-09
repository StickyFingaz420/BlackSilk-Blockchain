//! Offline recompute of a submit log (gate rule H3): every logged submission
//! with a known job is hashed again in a fresh process with
//! `blacksilk_randomx` light mode, whatever its live outcome (stale,
//! duplicate and `Busy` shares included), and compared byte for byte with the
//! result the miner sent. Negative-control shares (jobs labelled `rx/0`) are
//! also hashed with Monero's `rx/0` salt, to identify them positively.
//!
//! The same crate as the node, in a fresh process: not a second
//! implementation.

use crate::stratum::ALGO_RX0;
use crate::submit_log::SubmitRecord;
use blacksilk_consensus::header::POW_BLOB_TAG;
use blacksilk_consensus::{Hash, PowBlob, POW_BLOB_SIZE, POW_NONCE_OFFSET};
use blacksilk_randomx::{Cache, Variant, Vm};
use std::collections::BTreeMap;

/// The hash of one RandomX variant.
pub trait VariantHasher {
    fn hash(&mut self, variant: Variant, seed: &Hash, blob: &PowBlob) -> Hash;
}

/// Light mode with one cache at a time (256 MiB), rebuilt when the key or
/// the variant changes.
#[derive(Default)]
pub struct LightHasher {
    cache: Option<(Variant, Hash, Cache)>,
}

impl VariantHasher for LightHasher {
    fn hash(&mut self, variant: Variant, seed: &Hash, blob: &PowBlob) -> Hash {
        let fresh = !matches!(&self.cache, Some((v, s, _)) if *v == variant && s == seed);
        if fresh {
            self.cache = None; // free the old cache first
            self.cache = Some((variant, *seed, Cache::with_variant(seed, variant)));
        }
        let (_, _, cache) = self.cache.as_ref().expect("built above");
        Vm::light(cache).hash(blob)
    }
}

/// What a recompute found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    /// Records considered (after the agent filter).
    pub records: usize,
    /// Records left out by the agent filter.
    pub skipped_agent: usize,
    /// Live outcomes of the considered records.
    pub by_outcome: BTreeMap<String, usize>,
    /// Records without a job or a decodable nonce or result (nothing to
    /// hash: unknown job, malformed fields, wrong session).
    pub without_inputs: usize,
    /// Records the bridge hashed live.
    pub hashed_live: usize,
    /// Records hashed here.
    pub recomputed: usize,
    /// `rx/blacksilk` records whose result equals the recomputed hash.
    pub matches: usize,
    /// `rx/blacksilk` records whose result differs (one line each).
    pub mismatches: Vec<String>,
    /// Records that contradict themselves: a blob without the submitted
    /// nonce bytes or the tag, or a live hash that differs from the
    /// recomputed one (a bridge fault, never a miner's).
    pub inconsistent: Vec<String>,
    /// Negative-control (`rx/0`) records, and how many of their results are
    /// Monero's `rx/0` hash or BlackSilk's.
    pub nc_records: usize,
    pub nc_rx0_matches: usize,
    pub nc_blacksilk_matches: usize,
}

impl Summary {
    /// No mismatch and no inconsistency among the `rx/blacksilk` records,
    /// and every negative-control record identified as `rx/0`.
    pub fn passed(&self) -> bool {
        self.mismatches.is_empty()
            && self.inconsistent.is_empty()
            && self.nc_rx0_matches == self.nc_records
            && self.nc_blacksilk_matches == 0
    }

    pub fn render(&self) -> String {
        let mut s = format!(
            "records {} (skipped by agent {}), without inputs {}, hashed live {}, recomputed {}, \
             matches {}, mismatches {}, inconsistent {}, negative control {} (rx/0 {}, blacksilk {})\n",
            self.records,
            self.skipped_agent,
            self.without_inputs,
            self.hashed_live,
            self.recomputed,
            self.matches,
            self.mismatches.len(),
            self.inconsistent.len(),
            self.nc_records,
            self.nc_rx0_matches,
            self.nc_blacksilk_matches,
        );
        for (o, n) in &self.by_outcome {
            s.push_str(&format!("outcome {o}: {n}\n"));
        }
        for m in &self.mismatches {
            s.push_str(&format!("MISMATCH {m}\n"));
        }
        for m in &self.inconsistent {
            s.push_str(&format!("INCONSISTENT {m}\n"));
        }
        s.push_str(if self.passed() { "PASS\n" } else { "FAIL\n" });
        s
    }
}

fn inputs(r: &SubmitRecord) -> Option<(Hash, PowBlob, Hash)> {
    let seed: Hash = hex::decode(r.seed.as_deref()?).ok()?.try_into().ok()?;
    let blob: PowBlob = hex::decode(r.blob.as_deref()?).ok()?.try_into().ok()?;
    let result: Hash = hex::decode(&r.result).ok()?.try_into().ok()?;
    Some((seed, blob, result))
}

/// Recomputes `records`; with `only_agent`, only those whose agent starts
/// with it (e.g. `XMRig/`).
pub fn recompute(
    records: &[SubmitRecord],
    only_agent: Option<&str>,
    hasher: &mut dyn VariantHasher,
) -> Summary {
    let mut s = Summary::default();
    let mut todo = Vec::new();
    for (i, r) in records.iter().enumerate() {
        if only_agent.is_some_and(|p| !r.agent.starts_with(p)) {
            s.skipped_agent += 1;
            continue;
        }
        s.records += 1;
        *s.by_outcome.entry(r.outcome.clone()).or_default() += 1;
        if r.hashed {
            s.hashed_live += 1;
        }
        match inputs(r) {
            Some(x) => todo.push((i, x)),
            None => s.without_inputs += 1,
        }
    }
    // One cache per (variant, key): group the work.
    let nc = |i: usize| records[i].job_algo.as_deref() == Some(ALGO_RX0);
    todo.sort_by_key(|(i, (seed, _, _))| (nc(*i), *seed));
    for (i, (seed, blob, result)) in todo {
        let r = &records[i];
        let what = format!(
            "session {} job {} nonce {} height {:?} seed {} result {}",
            r.session,
            r.job_id,
            r.nonce,
            r.height,
            hex::encode(seed),
            r.result
        );
        let nonce_bytes = hex::decode(&r.nonce).ok();
        if blob.len() != POW_BLOB_SIZE
            || &blob[..POW_BLOB_TAG.len()] != POW_BLOB_TAG
            || nonce_bytes.as_deref() != Some(&blob[POW_NONCE_OFFSET..POW_NONCE_OFFSET + 4])
        {
            s.inconsistent
                .push(format!("{what}: the blob does not carry the nonce"));
            continue;
        }
        s.recomputed += 1;
        let bs = hasher.hash(Variant::BlackSilk, &seed, &blob);
        if let Some(live) = &r.bridge_hash {
            if *live != hex::encode(bs) {
                s.inconsistent
                    .push(format!("{what}: live hash {live} differs from recomputed"));
            }
        }
        if nc(i) {
            s.nc_records += 1;
            if result == bs {
                s.nc_blacksilk_matches += 1;
            }
            if result == hasher.hash(Variant::MoneroRx0, &seed, &blob) {
                s.nc_rx0_matches += 1;
            }
        } else if result == bs {
            s.matches += 1;
        } else {
            s.mismatches
                .push(format!("{what}: recomputed {}", hex::encode(bs)));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in for RandomX: the variant, key and blob through Blake2b.
    struct Fake;
    impl VariantHasher for Fake {
        fn hash(&mut self, v: Variant, seed: &Hash, blob: &PowBlob) -> Hash {
            blacksilk_consensus::hash::H::new()
                .chain(&[v as u8])
                .chain(seed)
                .chain(blob)
                .finish()
        }
    }

    fn record(nonce: [u8; 4], algo: &str, result: Option<Hash>) -> SubmitRecord {
        let mut blob = [0u8; POW_BLOB_SIZE];
        blob[..7].copy_from_slice(POW_BLOB_TAG);
        blob[39..43].copy_from_slice(&nonce);
        let variant = if algo == ALGO_RX0 {
            Variant::MoneroRx0
        } else {
            Variant::BlackSilk
        };
        let h = result.unwrap_or_else(|| Fake.hash(variant, &[5; 32], &blob));
        SubmitRecord {
            agent: "XMRig/6.26.0".into(),
            nonce: hex::encode(nonce),
            result: hex::encode(h),
            job_algo: Some(algo.into()),
            seed: Some(hex::encode([5u8; 32])),
            blob: Some(hex::encode(blob)),
            outcome: "stale_job".into(),
            ..Default::default()
        }
    }

    #[test]
    fn matches_mismatches_and_the_negative_control() {
        let good = record([1, 0, 0, 0], "rx/blacksilk", None);
        let bad = record([2, 0, 0, 0], "rx/blacksilk", Some([0; 32]));
        let nc = record([3, 0, 0, 0], ALGO_RX0, None);
        let mut probe = record([4, 0, 0, 0], "rx/blacksilk", Some([1; 32]));
        probe.agent = "blacksilk-stratum-probe/0.1.0".into();
        let mut torn = record([5, 0, 0, 0], "rx/blacksilk", None);
        torn.nonce = "06000000".into();
        let mut no_job = SubmitRecord {
            agent: "XMRig/6.26.0".into(),
            outcome: "stale_job".into(),
            ..Default::default()
        };
        no_job.job_id = "999".into();
        let all = [good, bad, nc, probe, torn, no_job];
        let s = recompute(&all, Some("XMRig/"), &mut Fake);
        assert_eq!(s.records, 5);
        assert_eq!(s.skipped_agent, 1);
        assert_eq!(s.without_inputs, 1);
        assert_eq!(s.recomputed, 3);
        assert_eq!(s.matches, 1);
        assert_eq!(s.mismatches.len(), 1);
        assert_eq!(s.inconsistent.len(), 1);
        assert_eq!((s.nc_records, s.nc_rx0_matches), (1, 1));
        assert!(!s.passed());
        let clean = recompute(&all[..1], None, &mut Fake);
        assert!(clean.passed(), "{}", clean.render());
        assert!(clean.render().ends_with("PASS\n"));
    }
}
