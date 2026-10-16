//! The wallet side of the supply audit's PX half (G8 T7; F40-9 without
//! proving).
//!
//! A hand-built chain served by an in-memory node: PX transactions without
//! proofs whose outputs are sealed to the audited wallets
//! (`blacksilk_px::delivery::seal`). Wallets never verify PX proofs, and the
//! scan only decodes, so no proof is needed. The chain follows the consensus
//! PX state (anchors, nullifiers, the pool) as `blacksilk_px::state::State`
//! applies it, and its headers commit to the PX tree and the output range as
//! a block must (B-PXR, B-OMR). The coinbases pay a wallet outside the audited
//! set, so the v1 half shows exactly `generated − px_pool`.
//!
//! Every PX amount below is a constant of this test: 1 050 bridged in, 50
//! bridged out, pool 1 000; W1 holds 300 + 200 + 200 (two records of equal
//! value, distinct commitments) and a 50 that a later block spends; W2 holds
//! 300.

use blacksilk_chain::block::Block;
use blacksilk_chain::emission::block_reward;
use blacksilk_consensus::difficulty::next_difficulty;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, Network};
use blacksilk_px::delivery::{seal, Address as PxAddress, CIPHERTEXT_BYTES};
use blacksilk_px::perm::HostPerm;
use blacksilk_px::state::State;
use blacksilk_px::wallet::{Account, Derivation};
use blacksilk_px_core::record::{nullifier, output_rho, Record};
use blacksilk_px_core::{Digest, P};
use blacksilk_rpc as rpc;
use blacksilk_supply_audit::{audit, Entry, Report};
use blacksilk_tx::builder::{build_coinbase, Payment};
use blacksilk_tx::px::{PxTx, Window};
use blacksilk_tx::types::Transaction;
use blacksilk_wallet::node::NodeApi;
use blacksilk_wallet::px::{anchor_height, digest_hex};
use blacksilk_wallet::seed::Seed;
use blacksilk_wallet::Wallet;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

const POOL: i128 = 1_000;

fn digest(rng: &mut ChaCha20Rng) -> Digest {
    let mut d = [0u32; 8];
    for x in d.iter_mut() {
        *x = rng.next_u32() % P;
    }
    d
}

/// A ciphertext to nobody: the base point as `R`, then zeros.
fn undelivered() -> Vec<u8> {
    let mut c = vec![0; CIPHERTEXT_BYTES];
    c[..32].copy_from_slice(&blacksilk_crypto::generators::G.compress().to_bytes());
    c
}

fn wallet(seed: u8) -> Wallet {
    let mut w = Wallet::from_seed(Network::Regtest, [seed; 32], 1);
    w.set_allow_stale_tip(true);
    w
}

fn px_address(w: &mut Wallet) -> PxAddress {
    blacksilk_chain::address::decode_px_address(Network::Regtest, &w.px_address(0)).unwrap()
}

/// The PX nullifier key of the wallet made by `wallet(seed)`, derived as the
/// wallet derives it from its seed (docs/px.md §3.1).
/// It only shapes the test chain (the spend in block 4) and checks itself: a
/// wrong key leaves the 50 unspent and the exact-zero assertions fail.
fn nk_of(seed: u8) -> Digest {
    let s = Seed::new([seed; 32], Network::Regtest, Seed::birthday_of(1));
    let master = s.master();
    Account::from_seed_with(&master, Derivation::V2)
        .account(blacksilk_wallet::wallet::PX_ACCOUNT)
        .keys()
        .nk
}

/// An output of a PX transaction: to a wallet (its address and a value) or
/// to nobody.
type Out = Option<(PxAddress, u64)>;

/// A record sealed in a mined transaction: what spending it needs.
struct Sealed {
    rho: Digest,
    cm: Digest,
}

struct FakeChain {
    params: ChainParams,
    blocks: Vec<Block>,
    first_output: Vec<u64>,
    outputs: u64,
    output_range: blacksilk_tx::mmr::OutputFrontier,
    px: State,
    roots: Vec<Digest>,
    commitments: Vec<(u64, Digest)>,
    generated: u64,
    rng: ChaCha20Rng,
    payee: blacksilk_crypto::keys::Address,
}

impl FakeChain {
    fn new() -> Self {
        let params = ChainParams::regtest();
        let genesis = Block {
            header: params.genesis,
            txs: vec![],
        };
        let px = State::new();
        let root = px.root();
        Self {
            params,
            blocks: vec![genesis],
            first_output: vec![0],
            outputs: 0,
            output_range: Default::default(),
            px,
            roots: vec![root],
            commitments: Vec::new(),
            generated: 0,
            rng: ChaCha20Rng::seed_from_u64(4_007),
            // Outside the audited set: the coinbases are not audited.
            payee: wallet(99).primary(),
        }
    }

    fn height(&self) -> u64 {
        self.blocks.len() as u64 - 1
    }

    fn id(&self, height: u64) -> Hash {
        self.blocks[height as usize].id(self.params.network_id)
    }

    /// A PX transaction anchored like an honest wallet's, spending
    /// `spends[k]` with nullifier `k` (a random one otherwise), bridging and
    /// paying `outs`. Returns the transaction and the records it seals.
    fn px_tx(
        &mut self,
        spends: Vec<Digest>,
        bridge_in: u64,
        bridge_out: u64,
        outs: [Out; 2],
    ) -> (PxTx, Vec<Option<Sealed>>) {
        let anchor = self.roots[anchor_height(self.height()) as usize];
        let mut nullifiers = [digest(&mut self.rng), digest(&mut self.rng)];
        for (k, nf) in spends.into_iter().enumerate() {
            nullifiers[k] = nf;
        }
        let mut t = PxTx {
            inputs: vec![],
            outputs: vec![],
            payouts: vec![],
            fee: 0,
            bridge_in,
            bridge_out,
            window: Window::UNBOUNDED,
            anchor,
            nullifiers,
            commitments: [digest(&mut self.rng), digest(&mut self.rng)],
            ciphertexts: [undelivered(), undelivered()],
            functions: vec![],
            pseudo_outs: vec![],
            range_proof: None,
            signatures: vec![],
            proof: vec![],
        };
        let mut perm = HostPerm::new();
        let mut sealed = Vec::new();
        for (j, out) in outs.into_iter().enumerate() {
            let Some((to, value)) = out else {
                sealed.push(None);
                continue;
            };
            let rho = output_rho(&mut perm, &t.nullifiers[0], j as u32);
            let record = Record::plain(to.owner, value, [0; 8], rho, digest(&mut self.rng));
            let cm = record.commit(&mut perm);
            t.commitments[j] = cm;
            t.ciphertexts[j] = seal(&mut self.rng, &[7; 32], &to, &record, &cm).unwrap();
            sealed.push(Some(Sealed { rho, cm }));
        }
        (t, sealed)
    }

    /// Mines a block with a coinbase paying the block reward (the PX
    /// transactions here pay no fee) and `px`.
    fn mine(&mut self, px: Vec<PxTx>) {
        let height = self.height() + 1;
        let reward = block_reward(height, self.generated);
        self.generated += reward;
        let coinbase = build_coinbase(
            height,
            &[Payment {
                address: self.payee,
                amount: reward,
            }],
            &[9; 32],
            &mut self.rng,
        )
        .unwrap();
        let publics: Vec<_> = px.iter().map(PxTx::public).collect();
        self.px
            .apply_block(&publics)
            .expect("the PX transactions follow the consensus PX rules");
        self.roots.push(self.px.root());
        for t in &px {
            for cm in t.commitments {
                self.commitments.push((height, cm));
            }
        }
        let mut txs = vec![Transaction::Coinbase(coinbase)];
        txs.extend(px.into_iter().map(|t| Transaction::Px(Box::new(t))));
        self.output_range.append_block(height, &txs);
        let cms: Vec<Digest> = self.commitments.iter().map(|c| c.1).collect();
        let px_root = blacksilk_tx::px::digest_bytes(&State::new().root_after(&cms).unwrap());
        let mut block = Block {
            header: BlockHeader {
                version: self.params.epoch_at(height).header_version,
                height,
                prev_id: self.id(height - 1),
                timestamp: self.params.genesis.timestamp + self.params.target_block_time * height,
                difficulty: self.next_difficulty(),
                tx_root: [0; 32],
                output_count: self.output_range.count(),
                output_root: self.output_range.root(),
                px_root,
                nonce: 0,
            },
            txs,
        };
        block.header.tx_root = block.compute_tx_root();
        self.first_output.push(self.outputs);
        self.outputs += block
            .txs
            .iter()
            .map(|t| t.output_keys().len() as u64)
            .sum::<u64>();
        self.blocks.push(block);
    }

    fn next_difficulty(&self) -> u64 {
        let p = &self.params;
        let from = self.blocks.len().saturating_sub(p.difficulty_ancestors());
        let mut cumulative = 0u128;
        let (mut ts, mut cd) = (Vec::new(), Vec::new());
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
}

impl NodeApi for FakeChain {
    fn info(&self) -> Result<rpc::Info, String> {
        let height = self.height();
        let mut i: rpc::Info = serde_json::from_value(serde_json::json!({
            "network": "regtest",
            "network_id": self.params.network_id,
            "height": height,
            "tip": hex::encode(self.id(height)),
            "difficulty": self.blocks[height as usize].header.difficulty,
            "generated": self.generated,
            "mempool_txs": 0,
            "mempool_bytes": 0,
            "outputs": self.outputs,
            "header_height": height,
        }))
        .unwrap();
        i.genesis_id = Some(hex::encode(self.params.genesis_id()));
        Ok(i)
    }
    fn blocks(&self, from: u64, count: u64) -> Result<rpc::Blocks, String> {
        let end = from.saturating_add(count).min(self.height() + 1);
        Ok(rpc::Blocks {
            blocks: (from.max(1)..end)
                .map(|h| {
                    let b = &self.blocks[h as usize];
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
        let end = from.saturating_add(count).min(self.height() + 1);
        let bytes: Vec<u8> = (from..end)
            .flat_map(|h| self.blocks[h as usize].header.to_bytes())
            .collect();
        Ok(rpc::Headers {
            from,
            headers: hex::encode(bytes),
            height: self.height(),
        })
    }
    fn distribution(&self, _: u64) -> Result<rpc::Distribution, String> {
        Err("not served".into())
    }
    fn outputs(&self, _: &[u64]) -> Result<rpc::Outputs, String> {
        Err("not served".into())
    }
    fn submit_tx(&self, _: &[u8]) -> Result<rpc::SubmitResult, String> {
        Err("not served".into())
    }
    fn px_commitments(&self, from: u64) -> Result<rpc::PxCommitments, String> {
        let all: Vec<(u64, String)> = self
            .commitments
            .iter()
            .map(|&(h, cm)| (h, digest_hex(&cm)))
            .collect();
        let total = all.len() as u64;
        let page: Vec<(u64, String)> = all.into_iter().skip(from as usize).take(1_024).collect();
        let end = from + page.len() as u64;
        Ok(rpc::PxCommitments {
            from,
            commitments: page,
            total,
            root: digest_hex(&self.px.root()),
            height: self.height(),
            next: (end < total).then_some(end),
        })
    }
    fn px_contracts(&self, from: u64) -> Result<rpc::PxContracts, String> {
        Ok(rpc::PxContracts {
            from,
            contracts: vec![],
            total: 0,
            height: self.height(),
        })
    }
}

/// The chain of the scenario: blocks 1-4 as in the module documentation,
/// then `extra` (a PX transaction paying W1 with no bridge-in: value no
/// chain created) if asked.
fn chain(w1: &mut Wallet, w2: &mut Wallet, inflate: bool) -> FakeChain {
    let (a1, a2) = (px_address(w1), px_address(w2));
    let mut c = FakeChain::new();
    let (t, _) = c.px_tx(
        vec![],
        500,
        0,
        [Some((a1.clone(), 300)), Some((a1.clone(), 200))],
    );
    c.mine(vec![t]);
    let (t, _) = c.px_tx(
        vec![],
        500,
        0,
        [Some((a1.clone(), 200)), Some((a2.clone(), 300))],
    );
    c.mine(vec![t]);
    let (t, s) = c.px_tx(vec![], 50, 0, [Some((a1.clone(), 50)), None]);
    c.mine(vec![t]);
    let fifty = s[0].as_ref().unwrap();
    let nf = nullifier(&mut HostPerm::new(), &nk_of(1), &fifty.rho, &fifty.cm);
    let (t, _) = c.px_tx(vec![nf], 0, 50, [None, None]);
    c.mine(vec![t]);
    if inflate {
        let (t, _) = c.px_tx(vec![], 0, 0, [Some((a1.clone(), 40)), None]);
        c.mine(vec![t]);
    }
    c
}

fn entries(ws: Vec<(&str, Wallet)>) -> Vec<Entry> {
    ws.into_iter()
        .map(|(n, w)| Entry {
            name: n.into(),
            wallet: w,
        })
        .collect()
}

fn generated_at(height: u64) -> i128 {
    let mut g = 0;
    for h in 1..=height {
        g += block_reward(h, g);
    }
    g as i128
}

fn check_px_zero(r: &Report) {
    assert!(r.chain_failures.is_empty(), "{:?}", r.chain_failures);
    assert_eq!(r.chain.px_pool as i128, POOL);
    assert_eq!((r.chain.bridge_in, r.chain.bridge_out), (1_050, 50));
    assert_eq!(r.totals.px as i128, POOL, "{}", r.text());
    assert_eq!(r.px_difference, 0);
    // The coinbases are paid outside the set: v1 shows generated − pool.
    assert_eq!(r.totals.v1, 0);
    assert_eq!(r.v1_difference, generated_at(r.height) - POOL);
    assert_eq!(r.total_difference, generated_at(r.height) - POOL);
    assert!(!r.alarm());
}

/// Records spread over two wallets account for the pool exactly; the spent
/// record is not counted; two records of equal value both count.
#[test]
fn px_records_over_two_wallets_account_for_the_pool() {
    let (mut w1, mut w2) = (wallet(1), wallet(2));
    let c = chain(&mut w1, &mut w2, false);
    let mut ws = entries(vec![("w1", w1), ("w2", w2)]);
    let r = audit(&c, &mut ws, None).unwrap();
    assert_eq!(r.height, 4);
    check_px_zero(&r);
    assert_eq!(r.totals.px_duplicates, 0);
    assert_eq!((r.wallets[0].px_unspent, r.wallets[0].px_records), (700, 3));
    assert_eq!((r.wallets[1].px_unspent, r.wallets[1].px_records), (300, 1));

    // W2 left out: exactly its 300 is missing, no alarm.
    let w2 = ws.pop().unwrap();
    let r = audit(&c, &mut ws, None).unwrap();
    assert_eq!(r.px_difference, 300);
    assert_eq!(r.total_difference, generated_at(4) - POOL + 300);
    assert!(!r.alarm() && !r.complete());

    // W1 listed twice: its three records are counted once, and reported.
    ws.push(w2);
    ws.push(Entry {
        name: "w1 (copy)".into(),
        wallet: wallet(1),
    });
    let r = audit(&c, &mut ws, None).unwrap();
    check_px_zero(&r);
    assert_eq!(r.totals.px_duplicates, 3);
}

/// A record the chain never paid for (sealed to W1 with no bridge-in): the
/// wallets hold more PX than the pool, an alarm.
#[test]
fn a_px_record_without_a_bridge_in_raises_the_alarm() {
    let (mut w1, mut w2) = (wallet(1), wallet(2));
    let c = chain(&mut w1, &mut w2, true);
    let mut ws = entries(vec![("w1", w1), ("w2", w2)]);
    let r = audit(&c, &mut ws, None).unwrap();
    assert_eq!(r.height, 5);
    assert_eq!(r.chain.px_pool as i128, POOL);
    assert_eq!(r.totals.px as i128, POOL + 40);
    assert_eq!(r.px_difference, -40);
    assert!(r.alarm());
    assert_eq!(r.exit_code(false), 2);
}
