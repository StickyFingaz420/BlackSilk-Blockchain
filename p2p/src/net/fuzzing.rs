//! Harness hooks for the stateful fuzz targets and their stable twins
//! (fuzz/src/targets/peer_protocol.rs and px_admission.rs). Feature
//! `test-hooks` only: the fuzz workspace and this crate's own tests turn it
//! on; the node never does, so none of this exists in a node build.
//!
//! Nothing here changes how the network behaves. [`Victim`] builds the
//! network's shared state exactly as [`super::Network::start_with`] does
//! (`new_inner`), with a seeded generator and without listeners, and runs the
//! real per-connection code (`conn::run_connection`) on any stream the
//! harness hands it. [`admission`] runs the real admission steps of a relayed
//! transaction (`admission::admit_tx` without the peer's budgets and caches,
//! then the verification) against a chain manager the harness holds.

use super::admission;
use super::blocks::block_worker;
use super::conn::run_connection;
use super::headers::header_worker;
use super::state::Inner;
use super::{new_inner, NetConfig};
use crate::addr::NetAddr;
use crate::addrman::{AddrMan, BanList};
use crate::connman::ConnKind;
use crate::originated::Originated;
use blacksilk_chain::actor::ChainHandle;
use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::mempool::MempoolError;
use blacksilk_consensus::Hash;
use blacksilk_tx::TxError;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;

/// A node's network state with no listener and no maintenance tasks: only
/// the header and block workers run (they serve what a registered peer
/// sends). Build it inside a tokio runtime.
pub struct Victim {
    inner: Arc<Inner>,
    workers: [JoinHandle<()>; 2],
}

impl Victim {
    /// The network state for `cfg` over the chain actor `chain`; its
    /// generator (handshake nonces, address table keys) seeded with `seed`.
    pub fn new(cfg: NetConfig, chain: ChainHandle, seed: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut addrman = AddrMan::new(&mut rng);
        addrman.set_private_groups(cfg.allow_private);
        let (inner, header_rx, block_rx) = new_inner(
            cfg,
            chain,
            rng,
            addrman,
            BanList::default(),
            Originated::default(),
            None,
            None,
        );
        let workers = [
            tokio::spawn(header_worker(inner.clone(), header_rx)),
            tokio::spawn(block_worker(inner.clone(), block_rx)),
        ];
        Self { inner, workers }
    }

    /// One connection of `kind` with the peer at `addr` over `stream`, from
    /// the key exchange to its cleanup: the node's own code
    /// (`conn::run_connection`), without an inbound handshake slot.
    pub async fn run_connection<S>(&self, stream: S, addr: NetAddr, kind: ConnKind, proxied: bool)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        run_connection(self.inner.clone(), stream, addr, kind, proxied, None).await
    }

    /// What the harness checks, read under the state lock.
    pub fn snapshot(&self) -> Snapshot {
        let st = self.inner.state();
        Snapshot {
            registered: self.inner.next_id.load(Ordering::Relaxed) - 1,
            peers: st.peers.len(),
            scores: st.peers.values().map(|p| p.score).collect(),
            banned: st.bans.len(),
            misbehaving_disconnects: st.misbehaving_disconnects,
            known_addresses: st.addrman.len(),
            local_nonces: st.local_nonces.len(),
            transport_failures: st.transport_failures,
            block_requests: st.block_requests.len(),
            tx_requests: st.tx_requests.len(),
            tx_announcers: st.tx_announcers.len(),
            stempool: st.stempool.len(),
            stems: st.dandelion.stems().len(),
            handshakes: st.handshakes.len(),
        }
    }
}

impl Drop for Victim {
    fn drop(&mut self) {
        for w in &self.workers {
            w.abort();
        }
    }
}

/// The network state the harness observes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// Connections registered so far (each completed its handshake).
    pub registered: u64,
    pub peers: usize,
    pub scores: Vec<u32>,
    pub banned: usize,
    pub misbehaving_disconnects: u64,
    /// The address table's (new, tried) counts.
    pub known_addresses: (usize, usize),
    /// Our `Version` nonces of handshakes in progress.
    pub local_nonces: usize,
    pub transport_failures: u64,
    pub block_requests: usize,
    pub tx_requests: usize,
    pub tx_announcers: usize,
    pub stempool: usize,
    /// Dandelion stem peers of the current epoch.
    pub stems: usize,
    /// Inbound handshakes holding a slot.
    pub handshakes: usize,
}

/// What the admission of one relayed transaction did, step by step
/// ([`admission`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admission {
    /// The bytes decode as a relayable (non-coinbase) transaction; if not,
    /// the sender is penalized and nothing else runs.
    pub decoded: bool,
    /// Its id.
    pub id: Option<Hash>,
    /// A PX transaction's stateless checks, run off the chain actor
    /// (`px_pre_checks`): its proof's degree bits, or the rule that failed.
    /// `None` for other transactions, and for a PX transaction that expires
    /// soon (its proof is not decoded).
    pub pre: Option<Result<Vec<usize>, TxError>>,
    /// The cheap checks (`cheap_checks`): `Ok(true)` passed, `Ok(false)`
    /// expires soon (policy, not scored), `Err((e, scored))`.
    pub cheap: Option<Result<bool, (TxError, bool)>>,
    /// The verification on the transaction lane (`check_tx`), if it ran,
    /// and whether a failure proves the relayer broke the rules (scored).
    pub verified: Option<(Result<Hash, MempoolError>, bool)>,
}

/// Runs the admission of `bytes`, relayed by a peer as a `Tx`, against `c`:
/// decoding, the pool and conflict lookups, the stateless PX checks, the
/// cheap checks, and (with `verify`, if they pass) the verification and
/// its scoring, each step as `admit_tx` and `on_tx` run it. The peer's
/// budgets, the reject caches and the node-wide PX token are left out (they
/// read and write the network state, not the chain).
pub fn admission(c: &ChainManager, bytes: &[u8], verify: bool) -> Admission {
    admission::for_tests(c, bytes, verify)
}
