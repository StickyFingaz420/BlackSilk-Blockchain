//! A scriptable chain and node for the wallet's adversarial sync tests: real
//! headers (validated by `HeaderChain`, with a stand-in proof of work),
//! blocks whose PX transactions carry consensus-valid anchors (checked by the
//! consensus PX state, `blacksilk_px::state::State`), and a node that serves
//! them over [`NodeApi`], honestly or with scripted lies.
//!
//! The PX transactions have no proofs and, for outputs to nobody,
//! undecryptable ciphertexts whose `R` is the base point (a valid ciphertext
//! `R`, as consensus requires: docs/px.md §6): the wallet never verifies
//! proofs, and these tests need only commitments, nullifiers and anchors. Deploys carry real programs (their registrations
//! are what the wallet derives) and placeholder signatures and proofs.

use crate::node::NodeApi;
use crate::px::{anchor_height, digest_hex};
use blacksilk_chain::block::Block;
use blacksilk_consensus::difficulty::next_difficulty;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, HeaderChain, PowFunction};
use blacksilk_crypto::bulletproofs_plus::BppProof;
use blacksilk_crypto::clsag::Clsag;
use blacksilk_crypto::keys::Address;
use blacksilk_crypto::{Point, Scalar};
use blacksilk_px::delivery::{seal, Address as PxAddress, CIPHERTEXT_BYTES};
use blacksilk_px::perm::HostPerm;
use blacksilk_px::state::State;
use blacksilk_px_core::record::{output_rho, Record};
use blacksilk_px_core::{Digest, P};
use blacksilk_rpc as rpc;
use blacksilk_tx::builder::{build_coinbase, Payment};
use blacksilk_tx::params::RING_SIZE;
use blacksilk_tx::px::{PxDeploy, PxTx, Registration, Window};
use blacksilk_tx::types::{Input, Output, Transaction};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::cell::RefCell;
use std::sync::Arc;

/// A ciphertext to nobody: the base point as `R` (canonical, not the
/// identity), then zeros.
fn undelivered() -> Vec<u8> {
    let mut c = vec![0; CIPHERTEXT_BYTES];
    c[..32].copy_from_slice(&blacksilk_crypto::generators::G.compress().to_bytes());
    c
}

/// Every hash meets every difficulty.
pub(crate) struct ZeroPow;

impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        [0; 32]
    }
}

/// A random canonical digest.
pub(crate) fn digest(rng: &mut ChaCha20Rng) -> Digest {
    let mut d = [0u32; 8];
    for x in d.iter_mut() {
        *x = rng.next_u32() % P;
    }
    d
}

/// What the node lies about.
#[derive(Default)]
pub(crate) struct Lies {
    /// `/px/commitments`: the height reported for the commitment at a
    /// position (`None`: the true one).
    pub relabel: Option<Box<dyn Fn(u64, u64) -> u64>>,
    /// `/px/commitments`: the node height reported with every page.
    pub report_height: Option<u64>,
    /// `/px/commitments`: these positions are left out.
    pub omit: Vec<u64>,
    /// `/px/commitments`: the commitment at this position is replaced.
    pub replace: Option<(u64, Digest)>,
    /// A stale tip: `/info`, `/blocks` and `/headers` stop at this height
    /// (the blocks above it are withheld; `/px/commitments` still lists
    /// their commitments, under whatever heights `relabel` gives).
    pub tip: Option<u64>,
    /// `/px/contracts`: the list is changed by this before it is served.
    #[allow(clippy::type_complexity)]
    pub contracts: Option<Box<dyn Fn(&mut Vec<rpc::PxContractEntry>)>>,
    /// `/blocks`: the block at this height is changed by this (and its
    /// `tx_root` recomputed) before it is served; `/headers` serves the
    /// true header.
    #[allow(clippy::type_complexity)]
    pub alter_block: Option<(u64, Box<dyn Fn(&mut Block)>)>,
}

pub(crate) struct MockChain {
    pub params: ChainParams,
    pub headers: HeaderChain,
    /// `blocks[h]`; `blocks[0]` is the genesis (empty body, never served).
    pub blocks: Vec<Block>,
    pub first_output: Vec<u64>,
    outputs: u64,
    /// The consensus PX state after the last block.
    pub px: State,
    /// `roots[h]`: the PX tree root after block `h`.
    pub roots: Vec<Digest>,
    /// Every commitment, with its block height, in tree order.
    pub commitments: Vec<(u64, Digest)>,
    pub rng: ChaCha20Rng,
    /// Seconds between block timestamps.
    pub spacing: u64,
    pub lies: Lies,
    /// Mine PX transactions the consensus PX state would refuse (a forged
    /// chain).
    pub forge: bool,
    /// Every `/px/commitments` request (`from`).
    pub commitment_requests: RefCell<Vec<u64>>,
    /// Every `/headers` request (`from`, `count`).
    pub header_requests: RefCell<Vec<(u64, u64)>>,
    /// Every registration, in chain order, as an honest node lists it.
    pub contracts: Vec<rpc::PxContractEntry>,
    /// The difficulty of the header at a height, instead of the LWMA
    /// rule's over the mock's own headers (`None`: the rule's). Once it
    /// returns `Some`, the headers are no longer checked by `headers`.
    #[allow(clippy::type_complexity)]
    pub difficulty: Option<Box<dyn Fn(u64) -> Option<u64>>>,
    forged_headers: bool,
}

impl MockChain {
    pub fn new(seed: u64) -> Self {
        let params = ChainParams::regtest();
        let genesis = Block {
            header: params.genesis,
            txs: vec![],
        };
        let px = State::new();
        let root = px.root();
        MockChain {
            headers: HeaderChain::new(params.clone(), Arc::new(ZeroPow)),
            spacing: params.target_block_time,
            params,
            blocks: vec![genesis],
            first_output: vec![0],
            outputs: 0,
            px,
            roots: vec![root],
            commitments: Vec::new(),
            rng: ChaCha20Rng::seed_from_u64(seed),
            lies: Lies::default(),
            forge: false,
            commitment_requests: RefCell::new(Vec::new()),
            header_requests: RefCell::new(Vec::new()),
            contracts: Vec::new(),
            difficulty: None,
            forged_headers: false,
        }
    }

    pub fn height(&self) -> u64 {
        self.blocks.len() as u64 - 1
    }

    /// The height the node reports (a stale tip, or the chain's).
    pub fn served_height(&self) -> u64 {
        self.lies.tip.unwrap_or(self.height()).min(self.height())
    }

    /// The LWMA difficulty of the next header over the mock's own headers
    /// (as `HeaderChain` computes it).
    fn next_difficulty(&self) -> u64 {
        let p = &self.params;
        let from = self.blocks.len().saturating_sub(p.difficulty_ancestors());
        let mut cumulative = 0u128;
        let mut ts = Vec::new();
        let mut cd = Vec::new();
        for (i, b) in self.blocks.iter().enumerate() {
            cumulative += b.header.difficulty as u128;
            if i >= from {
                ts.push(b.header.timestamp);
                cd.push(cumulative);
            }
        }
        next_difficulty(
            &ts,
            &cd,
            p.target_block_time,
            p.difficulty_window,
            p.initial_difficulty,
        )
    }

    /// A deploy of `programs` with placeholder inputs, outputs, signatures
    /// and range proof (the wallet reads only its registrations, key image
    /// and salt; it decodes like any deploy).
    pub fn deploy(&mut self, programs: Vec<Registration>) -> PxDeploy {
        let point = |rng: &mut ChaCha20Rng| {
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b);
            Point::from_point(blacksilk_crypto::hash::hash_to_point("mock", &[&b]))
        };
        let mut ring = [0u64; RING_SIZE];
        for (i, r) in ring.iter_mut().enumerate() {
            *r = i as u64;
        }
        let outputs = (0..2)
            .map(|_| Output {
                one_time_key: point(&mut self.rng),
                ephemeral: point(&mut self.rng),
                view_tag: 0,
                commitment: point(&mut self.rng),
                enc_amount: [0; 8],
                enc_anchor: [0; 16],
            })
            .collect();
        let rounds = blacksilk_crypto::bulletproofs_plus::rounds(2).expect("two outputs");
        let p = point(&mut self.rng);
        let mut salt = [0u8; 32];
        self.rng.fill_bytes(&mut salt);
        PxDeploy {
            inputs: vec![Input {
                key_image: point(&mut self.rng),
                ring,
            }],
            outputs,
            fee: 0,
            salt,
            programs,
            pseudo_outs: vec![p],
            range_proof: BppProof {
                a: p,
                a1: p,
                b: p,
                r1: Scalar::ZERO,
                s1: Scalar::ZERO,
                d1: Scalar::ZERO,
                l: vec![p; rounds],
                r: vec![p; rounds],
            },
            signatures: vec![Clsag {
                c0: Scalar::ZERO,
                s: [Scalar::ZERO; RING_SIZE],
                d: p,
            }],
        }
    }

    /// A PX transaction anchored like an honest wallet synced to the tip:
    /// at the canonical anchor height.
    pub fn px_tx(&mut self) -> PxTx {
        let anchor = self.roots[anchor_height(self.height()) as usize];
        self.px_tx_anchored(anchor)
    }

    pub fn px_tx_anchored(&mut self, anchor: Digest) -> PxTx {
        PxTx {
            inputs: vec![],
            outputs: vec![],
            payouts: vec![],
            fee: 0,
            bridge_in: 0,
            bridge_out: 0,
            window: Window::UNBOUNDED,
            anchor,
            nullifiers: [digest(&mut self.rng), digest(&mut self.rng)],
            commitments: [digest(&mut self.rng), digest(&mut self.rng)],
            ciphertexts: [undelivered(), undelivered()],
            functions: vec![],
            pseudo_outs: vec![],
            range_proof: None,
            signatures: vec![],
            proof: vec![],
        }
    }

    /// A PX transaction (honestly anchored) whose outputs pay `outs`: a PX
    /// address, a value and the record's data; `None` for an output to
    /// nobody (a random commitment).
    pub fn px_tx_paying(&mut self, outs: [Option<(PxAddress, u64, Digest)>; 2]) -> PxTx {
        let mut t = self.px_tx();
        let mut perm = HostPerm::new();
        for (j, out) in outs.into_iter().enumerate() {
            let Some((to, value, data)) = out else {
                continue;
            };
            let rho = output_rho(&mut perm, &t.nullifiers[0], j as u32);
            let record = Record::plain(to.owner, value, data, rho, digest(&mut self.rng));
            let cm = record.commit(&mut perm);
            t.commitments[j] = cm;
            t.ciphertexts[j] = seal(&mut self.rng, &[7; 32], &to, &record, &cm).unwrap();
        }
        t
    }

    /// Mines a block with a coinbase to `to` and `px` PX transactions
    /// (honestly anchored); returns its height.
    pub fn mine(&mut self, to: &Address, px: usize) -> u64 {
        let txs: Vec<PxTx> = (0..px).map(|_| self.px_tx()).collect();
        self.mine_with(to, txs)
    }

    /// Mines a block with a coinbase to `to` and the PX transactions `px`,
    /// which must satisfy the consensus PX rules (the anchors).
    pub fn mine_with(&mut self, to: &Address, px: Vec<PxTx>) -> u64 {
        self.mine_deploys(to, px, vec![])
    }

    /// As [`Self::mine_with`], with `deploys` after the PX transactions.
    pub fn mine_deploys(&mut self, to: &Address, px: Vec<PxTx>, deploys: Vec<PxDeploy>) -> u64 {
        let height = self.height() + 1;
        let coinbase = build_coinbase(
            height,
            &[Payment {
                address: *to,
                amount: 1_000,
            }],
            &[9; 32],
            &mut self.rng,
        )
        .unwrap();
        let publics: Vec<_> = px.iter().map(PxTx::public).collect();
        if self.forge {
            // A block no consensus node accepts; the PX state is left as it
            // was (every later root is then the mock's, not the chain's).
            self.roots.push(self.px.root());
        } else {
            self.px
                .apply_block(&publics)
                .expect("the mock's PX transactions follow the consensus rules");
            self.roots.push(self.px.root());
        }
        for t in &px {
            for cm in t.commitments {
                self.commitments.push((height, cm));
            }
        }
        for d in &deploys {
            self.contracts.push(rpc::PxContractEntry {
                height,
                id: digest_hex(&d.contract_id()),
                programs: d
                    .programs
                    .iter()
                    .map(|r| {
                        let b = r.budget;
                        rpc::PxProgramEntry {
                            id: hex::encode(
                                blacksilk_zkvm::Program::from_elf(&r.elf)
                                    .expect("the mock deploys loadable programs")
                                    .id(),
                            ),
                            budget: [
                                b.cycles, b.keys, b.add, b.bit, b.lt, b.shift, b.mul, b.poseidon,
                            ],
                        }
                    })
                    .collect(),
            });
        }
        let mut txs = vec![Transaction::Coinbase(coinbase)];
        txs.extend(px.into_iter().map(|t| Transaction::Px(Box::new(t))));
        txs.extend(
            deploys
                .into_iter()
                .map(|t| Transaction::PxDeploy(Box::new(t))),
        );
        let forged = self.difficulty.as_ref().and_then(|f| f(height));
        self.forged_headers |= forged.is_some();
        let mut block = Block {
            header: BlockHeader {
                version: self.params.epoch_at(height).header_version,
                height,
                prev_id: self.id(height - 1),
                timestamp: self.params.genesis.timestamp + self.spacing * height,
                difficulty: forged.unwrap_or_else(|| self.next_difficulty()),
                tx_root: [0; 32],
                nonce: 0,
            },
            txs,
        };
        block.header.tx_root = block.compute_tx_root();
        if !self.forged_headers {
            let now = block.header.timestamp;
            self.headers
                .accept(block.header, now)
                .expect("valid header");
        }
        self.first_output.push(self.outputs);
        self.outputs += block
            .txs
            .iter()
            .map(|t| t.output_keys().len() as u64)
            .sum::<u64>();
        self.blocks.push(block);
        height
    }

    pub fn id(&self, height: u64) -> Hash {
        self.blocks[height as usize].id(self.params.network_id)
    }

    /// The node's `/px/commitments` list, with the scripted lies.
    fn served_commitments(&self) -> Vec<(u64, String)> {
        self.commitments
            .iter()
            .enumerate()
            .filter(|(p, _)| !self.lies.omit.contains(&(*p as u64)))
            .map(|(p, &(h, cm))| {
                let p = p as u64;
                let h = match &self.lies.relabel {
                    Some(f) => f(p, h),
                    None => h,
                };
                let cm = match self.lies.replace {
                    Some((q, d)) if q == p => d,
                    _ => cm,
                };
                (h, digest_hex(&cm))
            })
            .collect()
    }
}

impl NodeApi for MockChain {
    fn info(&self) -> Result<rpc::Info, String> {
        let height = self.served_height();
        Ok(rpc::Info {
            network: "regtest".into(),
            network_id: self.params.network_id,
            height,
            tip: hex::encode(self.id(height)),
            difficulty: self.blocks[height as usize].header.difficulty,
            generated: 0,
            mempool_txs: 0,
            mempool_bytes: 0,
            outputs: self.outputs,
            peers: 0,
            header_height: height,
            deepest_reorg: 0,
            misbehaving_disconnects: 0,
            template_ready: None,
            genesis_id: Some(hex::encode(self.params.genesis_id())),
            consensus_fingerprint: None,
            rules_fingerprint: None,
            identity_fingerprint: None,
            build_commit: None,
            version: None,
            build_flags: None,
        })
    }

    fn blocks(&self, from: u64, count: u64) -> Result<rpc::Blocks, String> {
        let end = from.saturating_add(count).min(self.served_height() + 1);
        Ok(rpc::Blocks {
            blocks: (from.max(1)..end)
                .map(|h| {
                    let mut b = self.blocks[h as usize].clone();
                    if let Some((at, alter)) = &self.lies.alter_block {
                        if *at == h {
                            alter(&mut b);
                            b.header.tx_root = b.compute_tx_root();
                        }
                    }
                    rpc::BlockEntry {
                        height: h,
                        id: hex::encode(b.id(self.params.network_id)),
                        first_output: self.first_output[h as usize],
                        hex: hex::encode(b.encode()),
                    }
                })
                .collect(),
        })
    }

    fn headers(&self, from: u64, count: u64) -> Result<rpc::Headers, String> {
        self.header_requests.borrow_mut().push((from, count));
        let end = from.saturating_add(count).min(self.served_height() + 1);
        let bytes: Vec<u8> = (from..end)
            .flat_map(|h| self.blocks[h as usize].header.to_bytes())
            .collect();
        Ok(rpc::Headers {
            from,
            headers: hex::encode(bytes),
            height: self.served_height(),
        })
    }

    fn distribution(&self, _: u64) -> Result<rpc::Distribution, String> {
        Err("not used".into())
    }

    fn outputs(&self, _: &[u64]) -> Result<rpc::Outputs, String> {
        Err("not used".into())
    }

    fn submit_tx(&self, _: &[u8]) -> Result<rpc::SubmitResult, String> {
        Err("not used".into())
    }

    fn px_commitments(&self, from: u64) -> Result<rpc::PxCommitments, String> {
        self.commitment_requests.borrow_mut().push(from);
        let all = self.served_commitments();
        let total = all.len() as u64;
        let page: Vec<(u64, String)> = all.into_iter().skip(from as usize).take(1_024).collect();
        let end = from + page.len() as u64;
        Ok(rpc::PxCommitments {
            from,
            commitments: page,
            total,
            root: digest_hex(&self.px.root()),
            height: self.lies.report_height.unwrap_or(self.served_height()),
            next: (end < total).then_some(end),
        })
    }

    fn px_contracts(&self, from: u64) -> Result<rpc::PxContracts, String> {
        let mut all = self.contracts.clone();
        if let Some(f) = &self.lies.contracts {
            f(&mut all);
        }
        let total = all.len() as u64;
        Ok(rpc::PxContracts {
            from,
            contracts: all.into_iter().skip(from as usize).take(1_024).collect(),
            total,
            height: self.served_height(),
        })
    }
}
