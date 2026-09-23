//! Address manager (docs/p2p.md §9).
//!
//! Two tables: *new* (heard of) and *tried* (connected to successfully). An
//! address's bucket is `H32("p2p/addrman", secret ‖ table ‖ group(addr) ‖
//! group(source)) mod N`, with a local random `secret`. An attacker controlling
//! few network groups can only fill few buckets, and cannot predict which, which
//! bounds how much of the table it can occupy (eclipse resistance).

use crate::addr::NetAddr;
use blacksilk_crypto::hash::{h32, tags};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

pub const NEW_BUCKETS: usize = 256;
pub const TRIED_BUCKETS: usize = 64;
pub const BUCKET_SIZE: usize = 64;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Entry {
    addr: NetAddr,
    source_group: Vec<u8>,
    /// Unix time of the last successful connection (tried table).
    last_success: u64,
    attempts: u32,
}

#[derive(Serialize, Deserialize)]
pub struct AddrMan {
    secret: [u8; 32],
    new: Vec<Vec<Entry>>,
    tried: Vec<Vec<Entry>>,
}

impl AddrMan {
    pub fn new(rng: &mut impl RngCore) -> Self {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        Self {
            secret,
            new: vec![Vec::new(); NEW_BUCKETS],
            tried: vec![Vec::new(); TRIED_BUCKETS],
        }
    }

    fn bucket(&self, table: u8, addr: &NetAddr, source_group: &[u8], n: usize) -> usize {
        let h = h32(
            tags::P2P_ADDRMAN,
            &[&self.secret, &[table], &addr.group(), source_group],
        );
        (u64::from_le_bytes(h[..8].try_into().expect("8 bytes")) % n as u64) as usize
    }

    fn position(&self, addr: &NetAddr) -> Option<(bool, usize, usize)> {
        for (tried, table) in [(false, &self.new), (true, &self.tried)] {
            for (b, bucket) in table.iter().enumerate() {
                if let Some(i) = bucket.iter().position(|e| &e.addr == addr) {
                    return Some((tried, b, i));
                }
            }
        }
        None
    }

    pub fn contains(&self, addr: &NetAddr) -> bool {
        self.position(addr).is_some()
    }

    pub fn len(&self) -> (usize, usize) {
        (
            self.new.iter().map(Vec::len).sum(),
            self.tried.iter().map(Vec::len).sum(),
        )
    }

    pub fn is_empty(&self) -> bool {
        self.len() == (0, 0)
    }

    /// Records an address heard from `source`. Returns whether it was new.
    pub fn add(&mut self, addr: NetAddr, source: &NetAddr, rng: &mut impl RngCore) -> bool {
        if self.contains(&addr) {
            return false;
        }
        let source_group = source.group();
        let b = self.bucket(0, &addr, &source_group, NEW_BUCKETS);
        let bucket = &mut self.new[b];
        let entry = Entry {
            addr,
            source_group,
            last_success: 0,
            attempts: 0,
        };
        if bucket.len() >= BUCKET_SIZE {
            // Evict a random entry, preferring ones that failed repeatedly.
            let victim = bucket
                .iter()
                .position(|e| e.attempts >= 3)
                .unwrap_or((rng.next_u32() as usize) % bucket.len());
            bucket[victim] = entry;
        } else {
            bucket.push(entry);
        }
        true
    }

    /// Records a successful outbound connection: moves the address to *tried*.
    pub fn mark_good(&mut self, addr: &NetAddr, now: u64) {
        let Some((tried, b, i)) = self.position(addr) else {
            let mut e = Entry {
                addr: addr.clone(),
                source_group: addr.group(),
                last_success: now,
                attempts: 0,
            };
            let tb = self.bucket(1, addr, &e.source_group, TRIED_BUCKETS);
            e.last_success = now;
            self.insert_tried(tb, e);
            return;
        };
        let mut e = if tried {
            self.tried[b].remove(i)
        } else {
            self.new[b].remove(i)
        };
        e.last_success = now;
        e.attempts = 0;
        let tb = self.bucket(1, addr, &addr.group(), TRIED_BUCKETS);
        self.insert_tried(tb, e);
    }

    fn insert_tried(&mut self, tb: usize, e: Entry) {
        let bucket = &mut self.tried[tb];
        if bucket.len() >= BUCKET_SIZE {
            // Keep the more recently successful entries; demote the oldest to *new*.
            let (oldest, _) = bucket
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.last_success)
                .expect("non-empty");
            let demoted = bucket.remove(oldest);
            let nb = self.bucket(0, &demoted.addr, &demoted.source_group, NEW_BUCKETS);
            if self.new[nb].len() < BUCKET_SIZE {
                self.new[nb].push(demoted);
            }
        }
        self.tried[tb].push(e);
    }

    /// Records a failed connection attempt.
    pub fn mark_failed(&mut self, addr: &NetAddr) {
        if let Some((tried, b, i)) = self.position(addr) {
            let e = if tried {
                &mut self.tried[b][i]
            } else {
                &mut self.new[b][i]
            };
            e.attempts = e.attempts.saturating_add(1);
        }
    }

    /// A random candidate for an outbound connection: 50/50 from *tried* and *new*,
    /// skipping addresses for which `skip` is true.
    pub fn select(
        &self,
        rng: &mut impl RngCore,
        skip: impl Fn(&NetAddr) -> bool,
    ) -> Option<NetAddr> {
        let (n_new, n_tried) = self.len();
        for _ in 0..64 {
            let use_tried = n_tried > 0 && (n_new == 0 || rng.next_u32().is_multiple_of(2));
            let table = if use_tried { &self.tried } else { &self.new };
            let total = if use_tried { n_tried } else { n_new };
            if total == 0 {
                return None;
            }
            let mut k = (rng.next_u64() % total as u64) as usize;
            for bucket in table {
                if k < bucket.len() {
                    let e = &bucket[k];
                    if !skip(&e.addr) {
                        return Some(e.addr.clone());
                    }
                    break;
                }
                k -= bucket.len();
            }
        }
        None
    }

    /// Up to `max` random addresses for a `GetAddr` answer.
    pub fn sample(&self, max: usize, rng: &mut impl RngCore) -> Vec<NetAddr> {
        let mut all: Vec<&NetAddr> = self
            .new
            .iter()
            .chain(&self.tried)
            .flatten()
            .map(|e| &e.addr)
            .collect();
        // Fisher–Yates partial shuffle.
        let n = all.len().min(max);
        for i in 0..n {
            let j = i + (rng.next_u64() % (all.len() - i) as u64) as usize;
            all.swap(i, j);
        }
        all.into_iter().take(n).cloned().collect()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(
            &tmp,
            serde_json::to_vec(self).map_err(std::io::Error::other)?,
        )?;
        std::fs::rename(tmp, path)
    }

    /// Loads a saved table; `None` if missing or unreadable (a fresh one is used).
    pub fn load(path: &Path) -> Option<Self> {
        let a: Self = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
        (a.new.len() == NEW_BUCKETS
            && a.tried.len() == TRIED_BUCKETS
            && a.new.iter().chain(&a.tried).all(|b| b.len() <= BUCKET_SIZE))
        .then_some(a)
    }
}

/// Banned IPs with expiry (docs/p2p.md §10).
#[derive(Default, Serialize, Deserialize)]
pub struct BanList {
    until: HashMap<IpAddr, u64>,
}

impl BanList {
    pub fn ban(&mut self, ip: IpAddr, until: u64) {
        self.until.insert(ip, until);
    }

    pub fn is_banned(&self, ip: &IpAddr, now: u64) -> bool {
        self.until.get(ip).is_some_and(|&t| t > now)
    }

    pub fn prune(&mut self, now: u64) {
        self.until.retain(|_, &mut t| t > now);
    }

    pub fn len(&self) -> usize {
        self.until.len()
    }

    pub fn is_empty(&self) -> bool {
        self.until.is_empty()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        std::fs::write(
            path,
            serde_json::to_vec(self).map_err(std::io::Error::other)?,
        )
    }

    pub fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn a(s: &str) -> NetAddr {
        NetAddr::parse(s).unwrap()
    }

    #[test]
    fn add_select_and_promote() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let mut m = AddrMan::new(&mut rng);
        let src = a("9.9.9.9:1");
        assert!(m.add(a("1.2.3.4:5"), &src, &mut rng));
        assert!(!m.add(a("1.2.3.4:5"), &src, &mut rng), "duplicate");
        assert_eq!(m.len(), (1, 0));
        m.mark_good(&a("1.2.3.4:5"), 100);
        assert_eq!(m.len(), (0, 1));
        assert_eq!(m.select(&mut rng, |_| false), Some(a("1.2.3.4:5")));
        assert_eq!(m.select(&mut rng, |_| true), None);
    }

    /// Eclipse resistance: 10 000 addresses from one attacker /16, announced from one
    /// source group, can occupy at most one bucket of *new* (64 slots).
    #[test]
    fn one_group_cannot_flood_the_table() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let mut m = AddrMan::new(&mut rng);
        let src = a("66.66.1.1:1");
        for i in 0..10_000u32 {
            let addr = a(&format!(
                "66.66.{}.{}:{}",
                (i / 256) % 256,
                i % 256,
                1000 + i % 50
            ));
            m.add(addr, &src, &mut rng);
        }
        assert!(m.len().0 <= BUCKET_SIZE, "{:?}", m.len());
        // Honest addresses from many groups still get in.
        for i in 0..200u32 {
            m.add(
                a(&format!("{}.{}.1.1:1", 1 + i % 200, i / 200 + 7)),
                &a(&format!("5.{i}.0.1:1")),
                &mut rng,
            );
        }
        assert!(m.len().0 > BUCKET_SIZE + 150);
    }

    #[test]
    fn different_secrets_give_different_buckets() {
        let mut r1 = ChaCha20Rng::seed_from_u64(3);
        let mut r2 = ChaCha20Rng::seed_from_u64(4);
        let m1 = AddrMan::new(&mut r1);
        let m2 = AddrMan::new(&mut r2);
        let addr = a("7.7.7.7:7");
        let g = addr.group();
        let same = (0..32)
            .filter(|i| {
                let x = a(&format!("7.{i}.7.7:7"));
                m1.bucket(0, &x, &g, NEW_BUCKETS) == m2.bucket(0, &x, &g, NEW_BUCKETS)
            })
            .count();
        assert!(same < 4, "buckets must not be predictable across nodes");
    }

    #[test]
    fn persistence() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let mut m = AddrMan::new(&mut rng);
        m.add(a("1.1.1.1:1"), &a("2.2.2.2:2"), &mut rng);
        m.mark_good(&a("3.3.3.3:3"), 5);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("peers.json");
        m.save(&p).unwrap();
        let l = AddrMan::load(&p).unwrap();
        assert_eq!(l.len(), (1, 1));
        assert!(AddrMan::load(&dir.path().join("missing.json")).is_none());
        std::fs::write(&p, b"{garbage").unwrap();
        assert!(AddrMan::load(&p).is_none());
    }

    #[test]
    fn bans_expire() {
        let mut b = BanList::default();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        b.ban(ip, 100);
        assert!(b.is_banned(&ip, 50));
        assert!(!b.is_banned(&ip, 100));
        b.prune(200);
        assert!(b.is_empty());
    }

    #[test]
    fn sample_is_bounded_and_unique() {
        let mut rng = ChaCha20Rng::seed_from_u64(6);
        let mut m = AddrMan::new(&mut rng);
        for i in 0..300u32 {
            m.add(
                a(&format!("{}.{}.0.1:1", 1 + i % 250, i / 250)),
                &a("9.9.9.9:9"),
                &mut rng,
            );
        }
        let s = m.sample(100, &mut rng);
        assert_eq!(s.len(), 100);
        let set: std::collections::HashSet<_> = s.iter().collect();
        assert_eq!(set.len(), 100);
    }
}
