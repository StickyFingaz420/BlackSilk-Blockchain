//! The two-function PX fixture (`tests/fixtures/px_fixture_2fn.bin` and
//! `.txt`), shared by `tests/px_fixture_2fn.rs` (its generator and its
//! verify-only tests) and `tests/px_tamper.rs` (the tamper sweep): the
//! parsed fixture and the chain view it is valid on.
//!
//! The transaction is a CLAIM and a LOCK of the reference vault (`n_fn = 2`,
//! the B2 base pair): function 0 claims a vault record (kernel input 0) to a
//! user record (output 0), function 1 locks the bridged-in value into a new
//! vault record (output 1). Both functions are the vault program of the
//! golden deploy's contract (`PxFixture::deploy`, its one registration).
//! One v1 input (the fingerprint fixture's first coinbase output, with the
//! fixture transfer's first ring) pays the standard fee and the bridge-in.
//! The validity window is bounded, `[0, height + WINDOW_SPAN]`, so the
//! functions' prefixes bind it into the statement.
//!
//! The chain state ([`Chain2`]) is the fingerprint fixture's outputs plus a
//! synthetic PX state: a tree holding exactly the claimed vault record (the
//! `record` line of the text file), whose root is the transaction's anchor,
//! no spent nullifier, a pool equal to the record's value, and the golden
//! deploy's registration. Test data only, never a consensus or manifest
//! input (decisions, "Two-function PX fixture: test-pinned").

use blacksilk_crypto::Point;
use blacksilk_node::fingerprint::{fixture_rules, Fixture, PxFixture};
use blacksilk_px::core::record::Record;
use blacksilk_px::core::Digest;
use blacksilk_px::perm::HostPerm;
use blacksilk_px::prove::{FunctionCall, VerifyError};
use blacksilk_px::tree::Tree;
use blacksilk_px::vault;
use blacksilk_tx::px::{PxTx, Window};
use blacksilk_tx::validate::{ChainView, OutputRecord, PxProgram, PxProof};
use blacksilk_tx::{Transaction, TxError};
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// The fixture's encoded PX transaction.
pub const FIXTURE_BIN: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/px_fixture_2fn.bin"
));
/// The fixture's chain state (the claimed vault record).
pub const FIXTURE_TEXT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/px_fixture_2fn.txt"
));

/// The window's length past the fingerprint fixture's height:
/// `window = [0, height + WINDOW_SPAN]`.
pub const WINDOW_SPAN: u64 = 100;

/// The parsed two-function fixture.
pub struct Px2Fixture {
    pub px: PxTx,
    /// The vault record the CLAIM spends (the synthetic tree's one leaf).
    pub record: Record,
}

/// A digest as 32 bytes (each word little-endian), in hex.
pub fn digest_hex(d: &Digest) -> String {
    d.iter()
        .flat_map(|w| w.to_le_bytes())
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn parse_digest(s: &str) -> Option<Digest> {
    let b = hex::decode(s).ok()?;
    if b.len() != 32 {
        return None;
    }
    let mut d = [0u32; 8];
    for (i, w) in d.iter_mut().enumerate() {
        *w = u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().ok()?);
    }
    Some(d)
}

/// The `record` line of the text file: `record <value> <owner> <contract>
/// <asset> <data> <rho> <rcm>`.
pub fn record_line(r: &Record) -> String {
    format!(
        "record {} {} {} {} {} {} {}\n",
        r.value,
        digest_hex(&r.owner),
        digest_hex(&r.contract),
        digest_hex(&r.asset),
        digest_hex(&r.data),
        digest_hex(&r.rho),
        digest_hex(&r.rcm)
    )
}

impl Px2Fixture {
    /// Parses the encoded transaction and the text (one `record` line; `#`
    /// starts a comment).
    pub fn parse(bin: &[u8], text: &str) -> Option<Self> {
        let Transaction::Px(px) = Transaction::decode(bin).ok()? else {
            return None;
        };
        let mut record = None;
        for line in text.lines().map(str::trim) {
            let f: Vec<&str> = line.split_whitespace().collect();
            match f.as_slice() {
                [] => {}
                [c, ..] if c.starts_with('#') => {}
                ["record", value, owner, contract, asset, data, rho, rcm] if record.is_none() => {
                    record = Some(Record {
                        owner: parse_digest(owner)?,
                        contract: parse_digest(contract)?,
                        asset: parse_digest(asset)?,
                        value: value.parse().ok()?,
                        data: parse_digest(data)?,
                        rho: parse_digest(rho)?,
                        rcm: parse_digest(rcm)?,
                    })
                }
                _ => return None,
            }
        }
        Some(Px2Fixture {
            px: *px,
            record: record?,
        })
    }

    /// The checked-in fixture.
    pub fn get() -> &'static Px2Fixture {
        static F: OnceLock<Px2Fixture> = OnceLock::new();
        F.get_or_init(|| {
            Px2Fixture::parse(FIXTURE_BIN, FIXTURE_TEXT).expect("the two-function fixture parses")
        })
    }
}

/// The golden deploy's one registration as consensus reads it, and its
/// contract id. The registered binary is the reference vault's.
pub fn registration() -> (Digest, PxProgram) {
    let d = &PxFixture::get().deploy;
    assert_eq!(
        d.programs.len(),
        1,
        "the golden deploy registers one program"
    );
    let r = &d.programs[0];
    assert!(
        r.elf == vault::VAULT_ELF,
        "the golden deploy registers the vault"
    );
    (
        d.contract_id(),
        PxProgram {
            program: vault::program(),
            budget: r.budget,
            abi: r.abi,
            out_words: r.out_words,
        },
    )
}

/// The chain view of the fixture (module docs).
pub struct Chain2 {
    outputs: &'static BTreeMap<u64, OutputRecord>,
    tree: Tree,
    pool: u128,
    contract: Digest,
    program: PxProgram,
}

impl Chain2 {
    /// The fixture's chain: a PX tree holding exactly `record`.
    pub fn new(record: &Record) -> Self {
        let mut perm = HostPerm::new();
        let mut tree = Tree::new(&mut perm);
        let leaf = record.commit(&mut perm);
        let pos = tree.append(&mut perm, leaf).expect("one leaf fits");
        assert_eq!(pos, 0);
        let (contract, program) = registration();
        Chain2 {
            outputs: &Fixture::get().outputs,
            tree,
            pool: record.value as u128,
            contract,
            program,
        }
    }

    /// The PX tree (one leaf, at position 0).
    pub fn tree(&self) -> &Tree {
        &self.tree
    }

    /// `blacksilk_px::prove::verify` of `proof` for `px`'s statement with
    /// `calls`, `window` and `h_tx`, with this chain's registry, as
    /// `check_px_proof_decoded` calls it.
    pub fn verify(
        &self,
        px: &PxTx,
        calls: &[FunctionCall],
        window: &Window,
        h_tx: [u8; 32],
        proof: &PxProof,
    ) -> Result<(), VerifyError> {
        blacksilk_px::prove::verify(&px.public(), calls, window, h_tx, proof, |c, id| {
            self.px_function(c, id).map(|r| r.budget)
        })
    }

    /// The function calls of `px` as the node builds them (`px_calls`): the
    /// registered program and ABI, the transaction's outputs.
    pub fn calls(&self, px: &PxTx) -> Vec<FunctionCall> {
        px.functions
            .iter()
            .map(|f| {
                let r = self
                    .px_function(&f.contract, &f.program_id)
                    .expect("a registered function");
                FunctionCall {
                    program: r.program,
                    abi: r.abi,
                    outputs: f.outputs.clone(),
                }
            })
            .collect()
    }
}

impl ChainView for Chain2 {
    fn output(&self, global_index: u64) -> Option<OutputRecord> {
        self.outputs.get(&global_index).copied()
    }
    fn is_key_image_spent(&self, _: &Point) -> bool {
        false
    }
    fn px_is_recent_root(&self, anchor: &Digest) -> bool {
        *anchor == self.tree.root()
    }
    fn px_nullifier_spent(&self, _: &Digest) -> bool {
        false
    }
    fn px_pool(&self) -> u128 {
        self.pool
    }
    fn px_function(&self, contract: &Digest, program_id: &[u8; 32]) -> Option<PxProgram> {
        (*contract == self.contract && *program_id == self.program.program.id())
            .then(|| self.program.clone())
    }
    fn px_contract_exists(&self, contract: &Digest) -> bool {
        *contract == self.contract
    }
    fn px_tree_size(&self) -> u64 {
        self.tree.size()
    }
    fn px_root_after(&self, leaves: &[Digest]) -> Option<Digest> {
        let mut perm = HostPerm::new();
        let mut t = self.tree.clone();
        for l in leaves {
            t.append(&mut perm, *l).ok()?;
        }
        Some(t.root())
    }
    /// The fixture's outputs are sparse ring members, not a range (as the
    /// fingerprint's `FixtureChain`).
    fn output_frontier(&self) -> blacksilk_tx::mmr::OutputFrontier {
        blacksilk_tx::mmr::OutputFrontier::new()
    }
}

/// Full validation of `px` on the fixture's chain (built from the fixture's
/// record) at `height`, with or without PX5.
pub fn verdict(px: &PxTx, height: u64, with_proof: bool) -> Result<(), TxError> {
    let chain = Chain2::new(&Px2Fixture::get().record);
    let rules = fixture_rules();
    if with_proof {
        blacksilk_tx::validate::validate_px(px, &chain, height, &rules)
    } else {
        blacksilk_tx::validate::validate_px_without_proof(px, &chain, height, &rules)
    }
}
