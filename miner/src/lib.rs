//! Miner library: builds a block from a node template and searches nonces with
//! RandomX. The PoW rules are the consensus crate's (`check_hash`, header layout),
//! so a block this miner finds is exactly what the node verifies.

#![forbid(unsafe_code)]

use blacksilk_chain::block::Block;
use blacksilk_chain::emission::format_amount;
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{check_hash, BlockHeader, Hash, NONCE_OFFSET};
use blacksilk_crypto::keys::Address;
use blacksilk_randomx::{Cache, Dataset, Vm};
use blacksilk_rpc as rpc;
use blacksilk_tx::builder::{build_coinbase, Payment};
use blacksilk_tx::types::Transaction;
use rand_core::{CryptoRng, RngCore};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum TemplateError {
    Hex(&'static str),
    Tx(usize),
    Coinbase,
}

/// Builds the block for `template`, paying `reward + fees` to `payout`.
/// The header timestamp is `max(min_timestamp, now)`; the nonce starts at 0.
pub fn build_block<R: RngCore + CryptoRng>(
    template: &rpc::Template,
    payout: &Address,
    hedge_secret: &[u8],
    now: u64,
    rng: &mut R,
) -> Result<Block, TemplateError> {
    let prev_id = rpc::parse_hash(&template.prev_id).ok_or(TemplateError::Hex("prev_id"))?;
    let mut txs = Vec::with_capacity(template.txs.len() + 1);
    let coinbase = build_coinbase(
        template.height,
        &[Payment {
            address: *payout,
            amount: template.reward + template.fees,
        }],
        hedge_secret,
        rng,
    )
    .map_err(|_| TemplateError::Coinbase)?;
    txs.push(Transaction::Coinbase(coinbase));
    for (i, h) in template.txs.iter().enumerate() {
        let bytes = hex::decode(h).map_err(|_| TemplateError::Tx(i))?;
        txs.push(Transaction::decode(&bytes).map_err(|_| TemplateError::Tx(i))?);
    }
    let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
    let header = BlockHeader {
        // The version of the epoch at the template's height (the node's
        // schedule), not a compiled constant.
        version: template.version,
        height: template.height,
        prev_id,
        timestamp: now.max(template.min_timestamp),
        difficulty: template.difficulty,
        tx_root: tx_root(&ids),
        nonce: 0,
    };
    log::debug!(
        "template {}: {} txs, payout {}",
        template.height,
        txs.len() - 1,
        format_amount(template.reward + template.fees)
    );
    Ok(Block { header, txs })
}

/// RandomX state for one seed: light (256 MiB cache, slow) or full (2 GiB
/// dataset, fast).
pub enum PowContext {
    Light { seed: Hash, cache: Cache },
    Full { seed: Hash, dataset: Dataset },
}

impl PowContext {
    pub fn new(seed: Hash, full: bool, threads: usize) -> Self {
        let cache = Cache::new(&seed);
        if full {
            let dataset = Dataset::new(&cache, threads.max(1));
            PowContext::Full { seed, dataset }
        } else {
            PowContext::Light { seed, cache }
        }
    }

    pub fn seed(&self) -> &Hash {
        match self {
            PowContext::Light { seed, .. } | PowContext::Full { seed, .. } => seed,
        }
    }

    /// [`PowContext::new`] with fallible allocation: an allocation failure is
    /// returned instead of aborting the process.
    pub fn try_new(seed: Hash, full: bool, threads: usize) -> Result<Self, BuildError> {
        let cache = Cache::try_new(&seed).map_err(|_| BuildError::OutOfMemory)?;
        if full {
            let dataset =
                Dataset::try_new(&cache, threads.max(1)).map_err(|_| BuildError::OutOfMemory)?;
            Ok(PowContext::Full { seed, dataset })
        } else {
            Ok(PowContext::Light { seed, cache })
        }
    }

    pub fn is_full(&self) -> bool {
        matches!(self, PowContext::Full { .. })
    }

    fn vm(&self) -> Vm<'_> {
        match self {
            PowContext::Light { cache, .. } => Vm::light(cache),
            PowContext::Full { dataset, .. } => Vm::full(dataset),
        }
    }
}

// ------------------------------------------------ RandomX key switches (07 W5)

/// Why a RandomX context could not be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// The cache or dataset allocation failed (`Vec::try_reserve_exact`).
    OutOfMemory,
    /// The background build thread could not start, or panicked.
    Thread,
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::OutOfMemory => f.write_str("out of memory for the RandomX context"),
            BuildError::Thread => f.write_str("the RandomX build thread failed"),
        }
    }
}

/// Builds the contexts a [`SeedPlanner`] mines with. [`RandomXBuilder`] in
/// production; tests use cheap stand-ins.
pub trait ContextBuilder: Send + Sync + 'static {
    type Ctx: Send + 'static;
    fn seed(ctx: &Self::Ctx) -> Hash;
    fn is_full(ctx: &Self::Ctx) -> bool;
    fn build(&self, seed: &Hash, full: bool) -> Result<Self::Ctx, BuildError>;
    /// The first full context, built while the miner has no context at all
    /// (at start): on the calling thread, with every thread the machine
    /// gives the miner, since nothing is mined meanwhile.
    fn build_first(&self, seed: &Hash) -> Result<Self::Ctx, BuildError> {
        self.build(seed, true)
    }
}

/// Real RandomX contexts ([`PowContext::try_new`]): a dataset is expanded on
/// `threads` threads in the background, and on `first_threads` for the
/// first one ([`ContextBuilder::build_first`]).
pub struct RandomXBuilder {
    pub threads: usize,
    pub first_threads: usize,
}

impl ContextBuilder for RandomXBuilder {
    type Ctx = PowContext;
    fn seed(ctx: &PowContext) -> Hash {
        *ctx.seed()
    }
    fn is_full(ctx: &PowContext) -> bool {
        ctx.is_full()
    }
    fn build(&self, seed: &Hash, full: bool) -> Result<PowContext, BuildError> {
        PowContext::try_new(*seed, full, self.threads)
    }
    fn build_first(&self, seed: &Hash) -> Result<PowContext, BuildError> {
        PowContext::try_new(*seed, true, self.first_threads.max(self.threads))
    }
}

/// How the miner handles RandomX key switches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeedPlan {
    /// Mine with the full dataset (2 GiB) instead of the light cache.
    pub full: bool,
    /// Build the next key's context in the background, from the moment the
    /// node announces it (`next_seed_id`, `seed_lag` blocks before the
    /// switch), and keep the previous context for [`KEEP_PREVIOUS_BLOCKS`]
    /// after a switch. With `full` the peak is about 4.4 GiB (two datasets
    /// and a cache).
    pub prebuild: bool,
    /// `--prebuild auto` (the default, decisions "W2-09"): a prebuild whose
    /// full context cannot be allocated turns prebuild off for the rest of
    /// the run, and the miner uses the light-mode bridge at switches (one
    /// dataset at a time). Without it (`--prebuild on`) the key whose
    /// prebuild failed is mined in light mode.
    pub fallback: bool,
}

/// Blocks after a key switch during which a prebuilding miner keeps the
/// previous key's context, for a reorganization back across the switch
/// (the anti-DoS window of the node, `sync_policy::ANTI_DOS_BLOCKS`).
pub const KEEP_PREVIOUS_BLOCKS: u64 = 144;

/// A background build: its key, whether it is a full context, the thread.
type Background<C> = (Hash, bool, JoinHandle<Result<C, BuildError>>);

/// The miner's RandomX contexts across key switches (dossier 07 §3.4, W5):
/// no mining time is lost to a full-mode rebuild at a switch.
///
/// - **First context** (full mode, at start): the dataset is built on the
///   mining thread with every thread ([`ContextBuilder::build_first`]);
///   there is nothing to mine with yet, and light-mode hashing alongside
///   would only slow the build down.
/// - **Light-mode bridge** (full mode without prebuild): at a switch the old
///   dataset is dropped, the new key's light cache is built (about 1 s) and
///   mined with while the dataset is expanded in the background; the next
///   template after it is ready mines in full mode. Before, the miner
///   stopped for the whole dataset build (minutes on a pure-Rust miner).
/// - **Prebuild** ([`SeedPlan::prebuild`]): the next key's context is built
///   in the background before the switch and swapped in at it. If the next
///   key's block is reorganized away first, the stale build is discarded and
///   the new key's started once the old build has ended.
/// - A context that fails to build (allocation failure) is not retried for
///   that key: the miner stays in light mode for it (bridge) or falls back
///   to the bridge at the switch (prebuild). With [`SeedPlan::fallback`] a
///   failed prebuild turns prebuild off instead, so that the bridge builds
///   the dataset once the old one is freed.
pub struct SeedPlanner<B: ContextBuilder> {
    builder: Arc<B>,
    plan: SeedPlan,
    current: Option<B::Ctx>,
    /// The context of the key before the last switch, and the last template
    /// height it is kept for.
    previous: Option<(B::Ctx, u64)>,
    background: Option<Background<B::Ctx>>,
    ready: Option<B::Ctx>,
    /// Keys whose full build failed: not retried.
    failed: Vec<Hash>,
}

impl<B: ContextBuilder> SeedPlanner<B> {
    pub fn new(builder: B, plan: SeedPlan) -> Self {
        Self {
            builder: Arc::new(builder),
            plan,
            current: None,
            previous: None,
            background: None,
            ready: None,
            failed: Vec::new(),
        }
    }

    /// The context to mine a template at `height` under key `seed` with.
    /// `next`: the next key (the template's `next_seed_id`), if announced.
    /// Builds on the calling thread only what mining needs now: nothing if
    /// the key is prepared, else a light cache (or, in light mode without a
    /// prebuilt context, the light context itself).
    pub fn context(
        &mut self,
        height: u64,
        seed: Hash,
        next: Option<Hash>,
    ) -> Result<&B::Ctx, BuildError> {
        self.poll();
        if self
            .previous
            .as_ref()
            .is_some_and(|(_, until)| height > *until)
        {
            self.previous = None;
        }
        let current = self.current.as_ref().map(B::seed);
        if current != Some(seed) {
            self.switch_to(height, seed)?;
        }
        // Discard a prepared context nobody will use (the next key's block
        // was reorganized away).
        if self
            .ready
            .as_ref()
            .is_some_and(|r| B::seed(r) != seed && Some(B::seed(r)) != next)
        {
            self.ready = None;
        }
        // Bridge: a full context of this key is ready.
        let light = self.current.as_ref().is_some_and(|c| !B::is_full(c));
        if self.plan.full && light && self.ready.as_ref().is_some_and(|r| B::seed(r) == seed) {
            self.current = self.ready.take();
        }
        self.start_background(seed, next);
        Ok(self.current.as_ref().expect("set above"))
    }

    /// Whether a background build is running (diagnostics and tests).
    pub fn building(&self) -> Option<Hash> {
        self.background.as_ref().map(|(s, _, _)| *s)
    }

    /// Waits for the background build, if any, and takes its result
    /// (tests; a miner polls with every template instead).
    pub fn finish_background(&mut self) {
        if let Some((seed, full, handle)) = self.background.take() {
            self.take_result(seed, full, handle.join());
        }
    }

    fn poll(&mut self) {
        if self
            .background
            .as_ref()
            .is_some_and(|(_, _, h)| h.is_finished())
        {
            self.finish_background();
        }
    }

    /// Whether prebuild is on now (off after a fallback, [`SeedPlan::fallback`]).
    pub fn prebuilding(&self) -> bool {
        self.plan.prebuild
    }

    fn take_result(
        &mut self,
        seed: Hash,
        full: bool,
        result: std::thread::Result<Result<B::Ctx, BuildError>>,
    ) {
        let e = match result {
            Ok(Ok(ctx)) => {
                self.ready = Some(ctx);
                return;
            }
            Ok(Err(e)) => e,
            Err(_) => BuildError::Thread,
        };
        log::warn!(
            "background RandomX build for key {} failed: {e}",
            hex::encode(&seed[..8])
        );
        if !full {
            return;
        }
        let prebuild = self.current.as_ref().map(B::seed) != Some(seed);
        if prebuild && self.plan.prebuild && self.plan.fallback {
            // Two datasets do not fit: one at a time from now on.
            self.plan.prebuild = false;
            self.previous = None;
            log::warn!(
                "--prebuild auto: prebuild off for this run; at key switches the miner \
                 mines in light mode while the new dataset is built"
            );
        } else {
            self.failed.push(seed);
        }
    }

    /// A template under another key than the current context's.
    fn switch_to(&mut self, height: u64, seed: Hash) -> Result<(), BuildError> {
        let old = self.current.take();
        let keep = |old: Option<B::Ctx>| old.map(|c| (c, height + KEEP_PREVIOUS_BLOCKS));
        if self
            .previous
            .as_ref()
            .is_some_and(|(p, _)| B::seed(p) == seed)
        {
            // A reorganization back across the switch.
            let (prev, _) = self.previous.take().expect("checked");
            self.current = Some(prev);
            self.previous = keep(old);
            return Ok(());
        }
        if self.ready.as_ref().is_some_and(|r| B::seed(r) == seed) {
            self.current = self.ready.take();
            self.previous = if self.plan.prebuild { keep(old) } else { None };
            log::info!(
                "RandomX key {}: prebuilt context in use",
                hex::encode(&seed[..8])
            );
            return Ok(());
        }
        // Not prepared: free the old context first (without prebuild), then
        // build what mining needs now. In full mode that is the light cache;
        // the dataset follows in the background (the bridge).
        let first = old.is_none() && self.previous.is_none();
        if self.plan.prebuild {
            self.previous = keep(old);
        } else {
            drop(old);
        }
        let started = std::time::Instant::now();
        if first && self.plan.full && !self.failed.contains(&seed) {
            match self.builder.build_first(&seed) {
                Ok(ctx) => {
                    self.current = Some(ctx);
                    log::info!(
                        "RandomX key {}: dataset built in {:.1?} on all threads",
                        hex::encode(&seed[..8]),
                        started.elapsed()
                    );
                    return Ok(());
                }
                Err(e) => {
                    log::warn!("RandomX dataset: {e}; mining in light mode");
                    self.failed.push(seed);
                }
            }
        }
        self.current = Some(self.builder.build(&seed, false)?);
        log::info!(
            "RandomX key {}: light context ready in {:.1?}{}",
            hex::encode(&seed[..8]),
            started.elapsed(),
            if self.plan.full {
                "; mining in light mode until the dataset is built"
            } else {
                ""
            }
        );
        Ok(())
    }

    /// Starts the one background build this state calls for, if none runs:
    /// the current key's dataset (bridge), else the next key's context
    /// (prebuild).
    fn start_background(&mut self, seed: Hash, next: Option<Hash>) {
        if self.background.is_some() {
            return;
        }
        let light = self.current.as_ref().is_some_and(|c| !B::is_full(c));
        let ready_for = |s: Hash| self.ready.as_ref().is_some_and(|r| B::seed(r) == s);
        let job = if self.plan.full && light && !ready_for(seed) && !self.failed.contains(&seed) {
            Some((seed, true))
        } else {
            next.filter(|n| {
                self.plan.prebuild
                    && *n != seed
                    && !ready_for(*n)
                    && !(self.plan.full && self.failed.contains(n))
            })
            .map(|n| (n, self.plan.full))
        };
        let Some((key, full)) = job else {
            return;
        };
        let builder = self.builder.clone();
        let spawned = std::thread::Builder::new()
            .name("randomx-build".into())
            .spawn(move || builder.build(&key, full));
        match spawned {
            Ok(handle) => self.background = Some((key, full, handle)),
            Err(_) => {
                self.take_result(key, full, Ok(Err(BuildError::Thread)));
            }
        }
    }
}

// ------------------------------------------------ tip notification (09 I1)

/// The node's latest tip as a [`TipWatcher`] saw it: the mining loop
/// abandons a template whose parent is no longer the tip (stale work).
#[derive(Clone, Default)]
pub struct TipSignal(Arc<Mutex<Option<SeenTip>>>);

#[derive(Clone, Copy, Debug)]
struct SeenTip {
    id: Hash,
    height: u64,
    at: Instant,
}

impl TipSignal {
    /// Records the tip `id` at `height`, seen now, if it is new.
    pub fn observe(&self, id: Hash, height: u64) {
        let mut seen = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if seen.is_none_or(|s| s.id != id) {
            *seen = Some(SeenTip {
                id,
                height,
                at: Instant::now(),
            });
        }
    }

    /// The height of a tip other than `prev_id` first seen after `since`
    /// (the moment the template on `prev_id` was requested), if any. A tip
    /// seen before `since` says nothing about the template: the node
    /// answered the template request after it.
    pub fn moved_since(&self, prev_id: &Hash, since: Instant) -> Option<u64> {
        let seen = *self.0.lock().unwrap_or_else(|e| e.into_inner());
        seen.filter(|s| s.id != *prev_id && s.at >= since)
            .map(|s| s.height)
    }
}

/// One long poll of the node's tip: `GET /tip?after=<id>&wait=<secs>`
/// (`blacksilk_rpc::Client::tip`), with the id the watcher last saw.
pub type TipSource = Box<dyn FnMut(Option<&Hash>, u64) -> Result<rpc::Tip, String> + Send>;

/// A thread that long-polls the node's tip and publishes every change to a
/// [`TipSignal`], so that the miner stops hashing on a parent the node has
/// replaced within a poll interval, instead of at its next template refresh
/// (dossier 09 R9-9 / I1; the stale-work effect measured in
/// docs/evidence/labnet-warmup-2026-09-28). The node holds each poll until
/// its tip changes; a failed poll is retried with a growing pause. Dropping
/// the watcher stops the thread after its current poll.
pub struct TipWatcher {
    signal: TipSignal,
    stop: Arc<AtomicBool>,
}

/// How long each tip poll is held by the node (below
/// `blacksilk_rpc::MAX_TIP_WAIT_SECS` and the client's request timeout).
pub const TIP_WAIT_SECS: u64 = 25;

impl TipWatcher {
    pub fn spawn(mut source: TipSource, wait_secs: u64) -> std::io::Result<Self> {
        let signal = TipSignal::default();
        let stop = Arc::new(AtomicBool::new(false));
        let (sig, halt) = (signal.clone(), stop.clone());
        std::thread::Builder::new()
            .name("tip-watcher".into())
            .spawn(move || {
                let mut after: Option<Hash> = None;
                let mut failures = 0u32;
                while !halt.load(Ordering::Relaxed) {
                    let started = Instant::now();
                    match source(after.as_ref(), wait_secs) {
                        Ok(t) => {
                            failures = 0;
                            match rpc::parse_hash(&t.tip) {
                                Some(id) if Some(id) != after => {
                                    sig.observe(id, t.height);
                                    after = Some(id);
                                }
                                // Unchanged (the wait ended) or malformed: a
                                // node that answers at once is not polled in
                                // a busy loop.
                                _ if started.elapsed() < Duration::from_millis(100) => {
                                    std::thread::sleep(Duration::from_millis(250));
                                }
                                _ => {}
                            }
                        }
                        Err(e) => {
                            failures = failures.saturating_add(1);
                            if failures == 1 {
                                log::debug!("tip poll: {e}");
                            }
                            std::thread::sleep(Duration::from_millis(
                                500 * u64::from(failures.min(10)),
                            ));
                        }
                    }
                }
            })?;
        Ok(Self { signal, stop })
    }

    pub fn signal(&self) -> TipSignal {
        self.signal.clone()
    }
}

impl Drop for TipWatcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Result of a nonce search.
#[derive(Debug, PartialEq, Eq)]
pub struct Found {
    pub nonce: u64,
    pub pow_hash: Hash,
}

/// Searches nonces `start, start+1, …` across `threads` threads until one meets
/// the header's difficulty, `stop` is set, or `max_hashes` hashes were tried.
/// Returns the found nonce and the number of hashes computed.
pub fn search(
    pow: &PowContext,
    header: &BlockHeader,
    start: u64,
    threads: usize,
    max_hashes: u64,
    stop: &AtomicBool,
) -> (Option<Found>, u64) {
    let threads = threads.max(1) as u64;
    let found: Mutex<Option<Found>> = Mutex::new(None);
    let hashes = AtomicU64::new(0);
    let base = header.to_bytes();
    std::thread::scope(|s| {
        for t in 0..threads {
            let (found, hashes, base) = (&found, &hashes, base);
            s.spawn(move || {
                let mut vm = pow.vm();
                let mut bytes = base;
                let mut i = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    let k = i * threads + t;
                    if k >= max_hashes {
                        break;
                    }
                    let nonce = start.wrapping_add(k);
                    bytes[NONCE_OFFSET..NONCE_OFFSET + 8].copy_from_slice(&nonce.to_le_bytes());
                    let h = vm.hash(&bytes);
                    hashes.fetch_add(1, Ordering::Relaxed);
                    if check_hash(&h, header.difficulty) {
                        let mut f = found.lock().unwrap_or_else(|e| e.into_inner());
                        if f.is_none() {
                            *f = Some(Found { nonce, pow_hash: h });
                        }
                        stop.store(true, Ordering::Relaxed);
                        break;
                    }
                    i += 1;
                }
            });
        }
    });
    (
        found.into_inner().unwrap_or_else(|e| e.into_inner()),
        hashes.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use blacksilk_consensus::{ChainParams, HeaderChain, RandomXPow, HEADER_VERSION};
    use std::sync::Arc;

    #[test]
    fn found_nonce_verifies_with_consensus() {
        let params = ChainParams::regtest();
        let chain = HeaderChain::new(params.clone(), Arc::new(RandomXPow::new()));
        let t = chain.template();
        let mut header = BlockHeader {
            version: t.version,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t.min_timestamp.max(params.genesis.timestamp + 120),
            difficulty: 3,
            tx_root: [5; 32],
            nonce: 0,
        };
        let pow = PowContext::new(t.seed_id, false, 2);
        let stop = AtomicBool::new(false);
        let (found, n) = search(&pow, &header, 1000, 2, 200, &stop);
        let found = found.expect("difficulty 3 is found within 200 hashes");
        assert!(n >= 1);
        header.nonce = found.nonce;
        let h = blacksilk_randomx::hash_light(&t.seed_id, &header.to_bytes());
        assert_eq!(h, found.pow_hash);
        assert!(check_hash(&h, 3));
    }

    // -------------------------------------------- SeedPlanner (07 W5 tests)

    use std::sync::mpsc;

    #[derive(Debug)]
    struct FakeCtx {
        seed: Hash,
        full: bool,
    }

    /// Records every build; full builds can be held open on a channel and
    /// made to fail (an allocation failure).
    #[derive(Default)]
    struct FakeBuilder {
        builds: Mutex<Vec<(Hash, bool)>>,
        hold: Mutex<Option<mpsc::Receiver<()>>>,
        fail_full: AtomicBool,
    }

    impl ContextBuilder for Arc<FakeBuilder> {
        type Ctx = FakeCtx;
        fn seed(ctx: &FakeCtx) -> Hash {
            ctx.seed
        }
        fn is_full(ctx: &FakeCtx) -> bool {
            ctx.full
        }
        fn build(&self, seed: &Hash, full: bool) -> Result<FakeCtx, BuildError> {
            if full {
                if let Some(rx) = self.hold.lock().unwrap().as_ref() {
                    let _ = rx.recv();
                }
                if self.fail_full.load(Ordering::SeqCst) {
                    return Err(BuildError::OutOfMemory);
                }
            }
            self.builds.lock().unwrap().push((*seed, full));
            Ok(FakeCtx { seed: *seed, full })
        }
    }

    fn planner(plan: SeedPlan) -> (SeedPlanner<Arc<FakeBuilder>>, Arc<FakeBuilder>) {
        let b = Arc::new(FakeBuilder::default());
        (SeedPlanner::new(b.clone(), plan), b)
    }

    fn state(
        p: &mut SeedPlanner<Arc<FakeBuilder>>,
        h: u64,
        s: Hash,
        n: Option<Hash>,
    ) -> (Hash, bool) {
        let c = p.context(h, s, n).unwrap();
        (c.seed, c.full)
    }

    const A: Hash = [0xA; 32];
    const B: Hash = [0xB; 32];
    const C: Hash = [0xC; 32];
    const FULL_PREBUILD: SeedPlan = SeedPlan {
        full: true,
        prebuild: true,
        fallback: false,
    };
    const AUTO: SeedPlan = SeedPlan {
        full: true,
        prebuild: true,
        fallback: true,
    };

    /// Full mode without prebuild. The first dataset is built at once (no
    /// context exists). At a switch the miner mines in light mode (one
    /// light build on the mining thread) while the dataset is built in the
    /// background, then mines in full mode.
    #[test]
    fn the_light_bridge_keeps_mining_through_a_switch() {
        let (mut p, b) = planner(SeedPlan {
            full: true,
            prebuild: false,
            fallback: false,
        });
        assert_eq!(
            state(&mut p, 1, A, None),
            (A, true),
            "the first dataset, built at once"
        );
        assert_eq!(p.building(), None);
        assert_eq!(state(&mut p, 2, A, Some(B)), (A, true));
        assert_eq!(p.building(), None, "no prebuild");
        assert_eq!(
            state(&mut p, 3, B, None),
            (B, false),
            "bridge at the switch"
        );
        p.finish_background();
        assert_eq!(state(&mut p, 4, B, None), (B, true));
        assert_eq!(
            *b.builds.lock().unwrap(),
            vec![(A, true), (B, false), (B, true)]
        );
    }

    /// The first context uses `build_first` (every thread); a failed first
    /// dataset leaves the miner in light mode for that key.
    #[test]
    fn the_first_dataset_is_built_on_all_threads_once() {
        #[derive(Default)]
        struct Counting {
            first: Mutex<Vec<Hash>>,
            other: Mutex<Vec<(Hash, bool)>>,
            fail: AtomicBool,
        }
        impl ContextBuilder for Arc<Counting> {
            type Ctx = FakeCtx;
            fn seed(ctx: &FakeCtx) -> Hash {
                ctx.seed
            }
            fn is_full(ctx: &FakeCtx) -> bool {
                ctx.full
            }
            fn build(&self, seed: &Hash, full: bool) -> Result<FakeCtx, BuildError> {
                self.other.lock().unwrap().push((*seed, full));
                Ok(FakeCtx { seed: *seed, full })
            }
            fn build_first(&self, seed: &Hash) -> Result<FakeCtx, BuildError> {
                self.first.lock().unwrap().push(*seed);
                if self.fail.load(Ordering::SeqCst) {
                    return Err(BuildError::OutOfMemory);
                }
                Ok(FakeCtx {
                    seed: *seed,
                    full: true,
                })
            }
        }
        let b = Arc::new(Counting::default());
        let mut p = SeedPlanner::new(b.clone(), AUTO);
        let c = p.context(1, A, None).unwrap();
        assert_eq!((c.seed, c.full), (A, true));
        p.context(2, B, None).unwrap();
        p.finish_background();
        assert_eq!(*b.first.lock().unwrap(), vec![A], "only while none exists");
        // Light mode never builds a dataset.
        let b = Arc::new(Counting::default());
        let mut p = SeedPlanner::new(
            b.clone(),
            SeedPlan {
                full: false,
                prebuild: false,
                fallback: false,
            },
        );
        p.context(1, A, None).unwrap();
        assert!(b.first.lock().unwrap().is_empty());
        // An allocation failure: light mode for that key, not retried.
        let b = Arc::new(Counting::default());
        b.fail.store(true, Ordering::SeqCst);
        let mut p = SeedPlanner::new(b.clone(), AUTO);
        let c = p.context(1, A, None).unwrap();
        assert_eq!((c.seed, c.full), (A, false));
        assert_eq!(p.building(), None, "the failed key is not rebuilt");
        assert_eq!(*b.other.lock().unwrap(), vec![(A, false)]);
    }

    /// `--prebuild auto`: a prebuild that cannot be allocated turns prebuild
    /// off, and the switch bridges in light mode while the new dataset is
    /// built with the old one freed; the new key is not marked failed.
    #[test]
    fn auto_falls_back_to_the_bridge_when_the_prebuild_does_not_fit() {
        let (mut p, b) = planner(AUTO);
        assert_eq!(state(&mut p, 1, A, None), (A, true));
        b.fail_full.store(true, Ordering::SeqCst);
        assert_eq!(state(&mut p, 2, A, Some(B)), (A, true));
        assert_eq!(p.building(), Some(B), "the prebuild is tried");
        p.finish_background();
        assert!(!p.prebuilding(), "off after the failed allocation");
        assert_eq!(state(&mut p, 3, A, Some(B)), (A, true));
        assert_eq!(p.building(), None, "not retried");
        // At the switch there is memory for one dataset again.
        b.fail_full.store(false, Ordering::SeqCst);
        assert_eq!(state(&mut p, 4, B, None), (B, false), "bridge");
        assert_eq!(p.building(), Some(B), "the dataset is built after all");
        p.finish_background();
        assert_eq!(state(&mut p, 5, B, None), (B, true));
        // With `--prebuild on` the same failure marks the key: light mode.
        let (mut p, b) = planner(FULL_PREBUILD);
        state(&mut p, 1, A, None);
        b.fail_full.store(true, Ordering::SeqCst);
        state(&mut p, 2, A, Some(B));
        p.finish_background();
        assert!(p.prebuilding());
        b.fail_full.store(false, Ordering::SeqCst);
        assert_eq!(state(&mut p, 3, B, None), (B, false));
        p.finish_background();
        assert_eq!(state(&mut p, 4, B, None), (B, false));
    }

    /// A tip seen after the template request, other than its parent, stops
    /// the work; one seen before it, or the parent itself, does not.
    #[test]
    fn the_tip_signal_reports_only_later_changes() {
        let s = TipSignal::default();
        let before = Instant::now();
        assert_eq!(s.moved_since(&A, before), None, "nothing seen");
        s.observe(B, 7);
        // Apart on a coarse clock (Windows): `moved_since` counts a tip seen
        // at the very instant of the request as later.
        std::thread::sleep(Duration::from_millis(20));
        let fetched = Instant::now();
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(s.moved_since(&A, before), Some(7));
        assert_eq!(s.moved_since(&B, before), None, "the parent is the tip");
        assert_eq!(s.moved_since(&A, fetched), None, "seen before the request");
        s.observe(B, 7);
        assert_eq!(s.moved_since(&A, fetched), None, "the same tip again");
        s.observe(C, 8);
        assert_eq!(s.moved_since(&B, fetched), Some(8));
    }

    /// The watcher long-polls with the last tip it saw and publishes each
    /// change; errors are retried.
    #[test]
    fn the_tip_watcher_publishes_each_new_tip() {
        let calls: Arc<Mutex<Vec<Option<Hash>>>> = Arc::default();
        let (tx, rx) = mpsc::channel::<Result<(Hash, u64), String>>();
        let rx = Mutex::new(rx);
        let log = calls.clone();
        let source: TipSource = Box::new(move |after, wait| {
            assert_eq!(wait, 3);
            log.lock().unwrap().push(after.copied());
            match rx.lock().unwrap().recv() {
                Ok(Ok((id, height))) => Ok(rpc::Tip {
                    height,
                    tip: hex::encode(id),
                    header_height: height,
                    template_ready: true,
                }),
                Ok(Err(e)) => Err(e),
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(50));
                    Err("closed".into())
                }
            }
        });
        let w = TipWatcher::spawn(source, 3).unwrap();
        let sig = w.signal();
        let t0 = Instant::now();
        let wait_for = |prev: Hash, height: u64| {
            let deadline = Instant::now() + Duration::from_secs(10);
            while sig.moved_since(&prev, t0) != Some(height) {
                assert!(Instant::now() < deadline, "no tip {height}");
                std::thread::sleep(Duration::from_millis(5));
            }
        };
        tx.send(Ok((A, 1))).unwrap();
        wait_for(C, 1);
        tx.send(Err("down".into())).unwrap();
        tx.send(Ok((B, 2))).unwrap();
        wait_for(A, 2);
        let seen = calls.lock().unwrap().clone();
        assert_eq!(seen[0], None, "the first poll answers at once");
        assert_eq!(seen[1], Some(A), "then polls after the last tip");
        assert_eq!(seen[2], Some(A), "and again after an error");
        drop(w);
        drop(tx);
    }

    /// Prebuild: the next key's context is built before the switch and used
    /// at it, with no build on the mining thread.
    #[test]
    fn a_ready_prebuild_is_swapped_in_at_the_switch() {
        let (mut p, b) = planner(FULL_PREBUILD);
        state(&mut p, 1, A, None);
        p.finish_background();
        assert_eq!(state(&mut p, 2, A, Some(B)), (A, true));
        assert_eq!(p.building(), Some(B), "prebuild of the next key");
        p.finish_background();
        let before = b.builds.lock().unwrap().len();
        assert_eq!(
            state(&mut p, 3, B, None),
            (B, true),
            "prebuilt, full at once"
        );
        assert_eq!(
            b.builds.lock().unwrap().len(),
            before,
            "nothing built at the switch"
        );
    }

    /// A switch while the prebuild still runs: light bridge, then the
    /// prebuilt full context once it is ready.
    #[test]
    fn a_switch_during_the_prebuild_bridges_in_light_mode() {
        let (mut p, b) = planner(FULL_PREBUILD);
        state(&mut p, 1, A, None);
        p.finish_background();
        state(&mut p, 2, A, None);
        let (release, hold) = mpsc::channel();
        *b.hold.lock().unwrap() = Some(hold);
        assert_eq!(state(&mut p, 3, A, Some(B)), (A, true));
        assert_eq!(p.building(), Some(B));
        assert_eq!(state(&mut p, 4, B, None), (B, false), "light bridge");
        release.send(()).unwrap();
        p.finish_background();
        assert_eq!(state(&mut p, 5, B, None), (B, true));
        let builds = b.builds.lock().unwrap().clone();
        assert_eq!(
            builds.iter().filter(|x| **x == (B, true)).count(),
            1,
            "one dataset"
        );
    }

    /// The next key's block is reorganized away before the switch: the
    /// stale prebuild is discarded and the new next key's is started.
    #[test]
    fn a_reorganized_next_key_restarts_the_prebuild() {
        let (mut p, b) = planner(FULL_PREBUILD);
        state(&mut p, 1, A, None);
        p.finish_background();
        state(&mut p, 2, A, Some(B));
        p.finish_background();
        state(&mut p, 3, A, Some(C));
        assert_eq!(p.building(), Some(C), "B discarded, C started");
        p.finish_background();
        let before = b.builds.lock().unwrap().len();
        assert_eq!(state(&mut p, 4, C, None), (C, true));
        assert_eq!(b.builds.lock().unwrap().len(), before);
    }

    /// A reorganization back across the switch reuses the kept previous
    /// context, until `KEEP_PREVIOUS_BLOCKS` after the switch.
    #[test]
    fn a_reorg_back_after_the_switch_reuses_the_previous_context() {
        let (mut p, b) = planner(FULL_PREBUILD);
        state(&mut p, 1, A, None);
        p.finish_background();
        state(&mut p, 2, A, Some(B));
        p.finish_background();
        state(&mut p, 3, B, None);
        let before = b.builds.lock().unwrap().len();
        assert_eq!(state(&mut p, 3, A, None), (A, true), "back to the old key");
        assert_eq!(state(&mut p, 4, B, None), (B, true), "and forward again");
        assert_eq!(b.builds.lock().unwrap().len(), before, "no rebuilds");
        // Past the window the previous context is dropped.
        state(&mut p, 5 + KEEP_PREVIOUS_BLOCKS, B, None);
        assert_eq!(state(&mut p, 6 + KEEP_PREVIOUS_BLOCKS, A, None), (A, false));
    }

    /// An allocation failure of the dataset (injected) leaves the miner in
    /// light mode for that key, without retrying every template.
    #[test]
    fn a_failed_dataset_build_falls_back_to_light_mode() {
        let (mut p, b) = planner(FULL_PREBUILD);
        b.fail_full.store(true, Ordering::SeqCst);
        assert_eq!(state(&mut p, 1, A, Some(B)), (A, false));
        p.finish_background();
        for h in 2..5 {
            assert_eq!(state(&mut p, h, A, Some(B)), (A, false));
            p.finish_background();
        }
        assert_eq!(
            state(&mut p, 5, B, None),
            (B, false),
            "bridge fallback at the switch"
        );
        p.finish_background();
        assert_eq!(state(&mut p, 6, B, None), (B, false));
        assert_eq!(p.building(), None, "not retried");
        let builds = b.builds.lock().unwrap().clone();
        assert_eq!(builds, vec![(A, false), (B, false)]);
    }

    /// Light mode with prebuild: the next key's cache is built before the
    /// switch; without prebuild the switch builds it (as before).
    #[test]
    fn light_mode_prebuilds_the_next_cache() {
        let (mut p, b) = planner(SeedPlan {
            full: false,
            prebuild: true,
            fallback: false,
        });
        state(&mut p, 1, A, Some(B));
        p.finish_background();
        assert_eq!(state(&mut p, 2, B, None), (B, false));
        assert_eq!(*b.builds.lock().unwrap(), vec![(A, false), (B, false)]);
        let (mut p, b) = planner(SeedPlan {
            full: false,
            prebuild: false,
            fallback: false,
        });
        state(&mut p, 1, A, Some(B));
        assert_eq!(p.building(), None);
        state(&mut p, 2, B, None);
        assert_eq!(*b.builds.lock().unwrap(), vec![(A, false), (B, false)]);
    }

    /// The real builder: a prebuilt light context hashes exactly like a
    /// fresh one (the context is a pure function of the key).
    #[test]
    fn the_randomx_builder_builds_the_same_context() {
        let mut p = SeedPlanner::new(
            RandomXBuilder {
                threads: 1,
                first_threads: 1,
            },
            SeedPlan {
                full: false,
                prebuild: true,
                fallback: false,
            },
        );
        let (a, b) = ([0x21; 32], [0x22; 32]);
        p.context(1, a, Some(b)).unwrap();
        p.finish_background();
        let blob = [9u8; 100];
        let ctx = p.context(2, b, None).unwrap();
        assert_eq!(ctx.seed(), &b);
        assert_eq!(
            ctx.vm().hash(&blob),
            blacksilk_randomx::hash_light(&b, &blob),
            "prebuilt context"
        );
    }

    #[test]
    fn stop_flag_and_limit_end_the_search() {
        let pow = PowContext::new([1; 32], false, 1);
        let header = BlockHeader {
            version: HEADER_VERSION,
            height: 1,
            prev_id: [0; 32],
            timestamp: 0,
            difficulty: u64::MAX,
            tx_root: [0; 32],
            nonce: 0,
        };
        let stop = AtomicBool::new(false);
        let (found, n) = search(&pow, &header, 0, 2, 4, &stop);
        assert_eq!(found, None);
        assert_eq!(n, 4);
        stop.store(true, Ordering::Relaxed);
        let (found, n) = search(&pow, &header, 0, 2, 1000, &stop);
        assert_eq!((found, n), (None, 0));
    }
}
