//! Dandelion++ routing state (docs/p2p.md §8).
//!
//! Fanti et al., "Dandelion++: Lightweight Cryptocurrency Networking with Formal
//! Anonymity Guarantees" (SIGMETRICS 2018). Per epoch, a node is a diffuser with
//! probability `q` or a relayer. Relayers forward stem transactions to one of two
//! stem peers. Each source (every inbound peer, and the node itself) keeps a fixed
//! route for the whole epoch. Fixed routes are what defeat the intersection attacks
//! of the original Dandelion.

use rand_core::RngCore;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub type PeerId = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    Local,
    Peer(PeerId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Fluff,
    Stem(PeerId),
}

#[derive(Clone, Debug)]
pub struct DandelionParams {
    pub epoch_min: Duration,
    pub epoch_max: Duration,
    /// Probability of being a diffuser in an epoch.
    pub fluff_probability: f64,
    pub stem_peers: usize,
    /// Embargo = `embargo_base` + Exp(mean `embargo_mean`).
    pub embargo_base: Duration,
    pub embargo_mean: Duration,
}

impl Default for DandelionParams {
    fn default() -> Self {
        Self {
            epoch_min: Duration::from_secs(9 * 60),
            epoch_max: Duration::from_secs(11 * 60),
            fluff_probability: 0.1,
            stem_peers: 2,
            embargo_base: Duration::from_secs(10),
            embargo_mean: Duration::from_secs(39),
        }
    }
}

pub struct Dandelion {
    params: DandelionParams,
    epoch_end: Option<Instant>,
    diffuser: bool,
    stems: Vec<PeerId>,
    routes: HashMap<Source, PeerId>,
}

fn uniform(rng: &mut impl RngCore) -> f64 {
    ((rng.next_u64() >> 11) + 1) as f64 / (1u64 << 53) as f64
}

/// A sample from Exp(mean).
pub fn exponential(mean: Duration, rng: &mut impl RngCore) -> Duration {
    Duration::from_secs_f64(-uniform(rng).ln() * mean.as_secs_f64())
}

impl Dandelion {
    pub fn new(params: DandelionParams) -> Self {
        Self {
            params,
            epoch_end: None,
            diffuser: false,
            stems: Vec::new(),
            routes: HashMap::new(),
        }
    }

    pub fn params(&self) -> &DandelionParams {
        &self.params
    }

    pub fn is_diffuser(&self) -> bool {
        self.diffuser
    }

    pub fn stems(&self) -> &[PeerId] {
        &self.stems
    }

    /// Starts a new epoch if the current one ended (or none started, or a stem
    /// peer disappeared and a replacement is available).
    pub fn maybe_new_epoch(&mut self, now: Instant, outbound: &[PeerId], rng: &mut impl RngCore) {
        let expired = self.epoch_end.is_none_or(|t| now >= t);
        let lost_stem = self.stems.iter().any(|s| !outbound.contains(s));
        let can_fill =
            self.stems.len() < self.params.stem_peers && outbound.len() > self.stems.len();
        if !(expired || lost_stem || can_fill) {
            return;
        }
        if expired {
            let span = self.params.epoch_max.saturating_sub(self.params.epoch_min);
            self.epoch_end = Some(now + self.params.epoch_min + span.mul_f64(uniform(rng)));
            self.diffuser = uniform(rng) < self.params.fluff_probability;
            self.stems.clear();
        }
        self.stems.retain(|s| outbound.contains(s));
        let mut pool: Vec<PeerId> = outbound
            .iter()
            .copied()
            .filter(|p| !self.stems.contains(p))
            .collect();
        while self.stems.len() < self.params.stem_peers && !pool.is_empty() {
            let i = (rng.next_u64() % pool.len() as u64) as usize;
            self.stems.push(pool.swap_remove(i));
        }
        // Routes are per epoch; routes to vanished stems are re-drawn lazily.
        if expired {
            self.routes.clear();
        } else {
            let stems = self.stems.clone();
            self.routes.retain(|_, p| stems.contains(p));
        }
    }

    /// Where a stem transaction from `source` goes.
    pub fn route(&mut self, source: Source, rng: &mut impl RngCore) -> Route {
        if self.diffuser && source != Source::Local {
            return Route::Fluff;
        }
        if self.stems.is_empty() {
            return Route::Fluff;
        }
        if let Some(p) = self.routes.get(&source) {
            return Route::Stem(*p);
        }
        let p = self.stems[(rng.next_u64() % self.stems.len() as u64) as usize];
        self.routes.insert(source, p);
        Route::Stem(p)
    }

    pub fn embargo(&self, rng: &mut impl RngCore) -> Duration {
        self.params.embargo_base + exponential(self.params.embargo_mean, rng)
    }

    pub fn peer_disconnected(&mut self, peer: PeerId) {
        self.stems.retain(|&p| p != peer);
        self.routes
            .retain(|s, p| *p != peer && *s != Source::Peer(peer));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn routes_are_stable_within_an_epoch() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let mut d = Dandelion::new(DandelionParams {
            fluff_probability: 0.0,
            ..Default::default()
        });
        let now = Instant::now();
        d.maybe_new_epoch(now, &[1, 2, 3, 4], &mut rng);
        assert_eq!(d.stems().len(), 2);
        let r = d.route(Source::Peer(9), &mut rng);
        for _ in 0..50 {
            assert_eq!(d.route(Source::Peer(9), &mut rng), r);
        }
        let Route::Stem(p) = r else { panic!() };
        assert!(d.stems().contains(&p));
        // Local transactions are always stemmed, never fluffed directly.
        assert!(matches!(d.route(Source::Local, &mut rng), Route::Stem(_)));
    }

    #[test]
    fn diffuser_fraction_and_epoch_rotation() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let mut d = Dandelion::new(DandelionParams::default());
        let mut t = Instant::now();
        let mut diffuser = 0;
        let n = 2000;
        for _ in 0..n {
            d.maybe_new_epoch(t, &[1, 2, 3], &mut rng);
            diffuser += d.is_diffuser() as u32;
            t += Duration::from_secs(12 * 60);
        }
        let frac = diffuser as f64 / n as f64;
        assert!((0.07..0.13).contains(&frac), "{frac}");
    }

    #[test]
    fn no_outbound_means_fluff_and_lost_stems_are_replaced() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let mut d = Dandelion::new(DandelionParams {
            fluff_probability: 0.0,
            ..Default::default()
        });
        let now = Instant::now();
        d.maybe_new_epoch(now, &[], &mut rng);
        assert_eq!(d.route(Source::Local, &mut rng), Route::Fluff);
        d.maybe_new_epoch(now, &[5, 6], &mut rng);
        assert_eq!(d.stems().len(), 2);
        d.peer_disconnected(5);
        d.maybe_new_epoch(now, &[6, 7], &mut rng);
        assert!(d.stems().contains(&6) && d.stems().contains(&7));
        for _ in 0..20 {
            assert!(matches!(
                d.route(Source::Local, &mut rng),
                Route::Stem(6 | 7)
            ));
        }
    }

    #[test]
    fn embargo_distribution() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let d = Dandelion::new(DandelionParams::default());
        let n = 5000;
        let mean: f64 = (0..n)
            .map(|_| d.embargo(&mut rng).as_secs_f64())
            .sum::<f64>()
            / n as f64;
        assert!((46.0..52.0).contains(&mean), "{mean}");
    }
}
