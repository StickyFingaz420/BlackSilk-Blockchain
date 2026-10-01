//! Writes seed corpora for the fuzz targets: one or more valid encodings per
//! target, so that coverage-guided fuzzing starts from deep inside each
//! format. `cargo run --release --bin seeds` (from `fuzz/`).

use blacksilk_chain::block::Block;
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, HEADER_VERSION};
use blacksilk_crypto::keys::{SubaddressIndex, SubaddressTable, WalletKeys};
use blacksilk_p2p::addr::AddrEntry;
use blacksilk_p2p::message::{Message, Version, PROTOCOL_VERSION};
use blacksilk_p2p::NetAddr;
use blacksilk_px::perm::HostPerm;
use blacksilk_px::prove::{prove_transfer, witness_words};
use blacksilk_px::tree::Tree;
use blacksilk_px::wallet::{self, Account};
use blacksilk_px_core::record::Record;
use blacksilk_tx::builder::{
    build_coinbase, build_transfer, standard_fee, Decoy, InputPlan, Payment, SpendableOutput,
};
use blacksilk_tx::params::TxRules;
use blacksilk_tx::px::Registration;
use blacksilk_tx::px_builder::{build_deploy, build_px, px_standard_fee, PxPlan};
use blacksilk_tx::scan::scan_block;
use blacksilk_tx::types::Transaction;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::path::Path;

// The target bodies shared with the stable drivers in the crates' tests
// (src/targets/driver.rs); here only their seed builders are used.
#[path = "targets/addr_v2.rs"]
#[allow(dead_code)]
mod addr_v2;
#[path = "targets/chain_fixture.rs"]
#[allow(dead_code)]
mod chain_fixture;
#[path = "targets/delivery_plain.rs"]
#[allow(dead_code)]
mod delivery_plain;
#[path = "targets/kernel_shapes.rs"]
mod kernel_shapes;
#[path = "targets/peer_protocol.rs"]
#[allow(dead_code)]
mod peer_protocol;
#[path = "targets/proof_struct.rs"]
#[allow(dead_code)]
mod proof_struct;
#[path = "targets/px_admission.rs"]
#[allow(dead_code)]
mod px_admission;
#[path = "targets/px_tx_struct.rs"]
#[allow(dead_code)]
mod px_tx_struct;
#[path = "targets/scan_outputs.rs"]
#[allow(dead_code)]
mod scan_outputs;
#[path = "../../wallet/src/seed.rs"]
#[allow(dead_code)]
mod seed;
#[path = "targets/seed_words.rs"]
#[allow(dead_code)]
mod seed_words;
#[path = "targets/store_records.rs"]
#[allow(dead_code)]
mod store_records;
#[path = "targets/transport_keyless_peer.rs"]
#[allow(dead_code)]
mod transport_keyless_peer;
#[path = "targets/transport_recv.rs"]
#[allow(dead_code)]
mod transport_recv;

fn put(target: &str, name: &str, bytes: &[u8]) {
    let dir = Path::new("corpus").join(target);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(name), bytes).unwrap();
    println!("corpus/{target}/{name}: {} bytes", bytes.len());
}

fn main() {
    // The targets with their own seed builders (none uses a generator, so
    // the seeds below keep their contents). Naming targets on the command
    // line writes only those and stops: a quick run without the proofs
    // below (`cargo run --release --bin seeds -- store_records addr_v2`).
    let only: Vec<String> = std::env::args().skip(1).collect();
    for (target, seeds) in [
        ("store_records", store_records::seeds()),
        ("seed_words", seed_words::seeds()),
        ("transport_recv", transport_recv::seeds()),
        ("transport_keyless_peer", transport_keyless_peer::seeds()),
        ("addr_v2", addr_v2::seeds()),
        ("delivery_plain", delivery_plain::seeds()),
        ("proof_struct", proof_struct::seeds()),
        ("px_tx_struct", px_tx_struct::seeds()),
        ("peer_protocol", peer_protocol::seeds()),
        ("scan_outputs", scan_outputs::seeds()),
        ("px_admission", px_admission::seeds()),
    ] {
        if only.is_empty() || only.iter().any(|t| t == target) {
            for (name, bytes) in seeds {
                put(target, name, &bytes);
            }
        }
    }
    if !only.is_empty() {
        return;
    }

    let mut rng = ChaCha20Rng::seed_from_u64(1);

    // Transactions and blocks: a coinbase and a block carrying it.
    let (keys, _) = WalletKeys::generate(&mut rng);
    let payouts: Vec<Payment> = (0..4)
        .map(|i| Payment {
            address: keys.address(SubaddressIndex::new(0, i)),
            amount: 1000 + i as u64,
        })
        .collect();
    let cb = build_coinbase(1, &payouts, &[1; 32], &mut rng).unwrap();
    let txs = vec![Transaction::Coinbase(cb)];
    put("tx_decode", "coinbase", &txs[0].encode());
    let ids: Vec<_> = txs.iter().map(Transaction::hash).collect();
    let genesis = ChainParams::regtest().genesis;
    let block = Block {
        header: BlockHeader {
            version: HEADER_VERSION,
            height: 1,
            prev_id: [1; 32],
            timestamp: genesis.timestamp + 120,
            difficulty: 1,
            tx_root: tx_root(&ids),
            nonce: 0,
        },
        txs,
    };
    put("block_decode", "block", &block.encode());

    // Messages of every shape. A Tor v3 host: a real name (version 3 and a
    // valid SHA3 checksum; p2p refuses anything else).
    let onion = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid";
    let messages = [
        Message::Verack,
        Message::Ping(7),
        Message::GetAddr,
        Message::GetHeaders {
            locator: vec![[1; 32], [2; 32]],
            stop: [0; 32],
        },
        Message::Headers(vec![genesis, genesis]),
        Message::GetBlocks(vec![[3; 32]]),
        Message::Block(block.encode()),
        Message::InvTx(vec![[4; 32], [5; 32]]),
        Message::Tx(vec![9; 100]),
        Message::StemTx(vec![8; 50]),
        // Appended after the original ten, so m0..m9 keep their contents.
        Message::Version(Version {
            protocol: PROTOCOL_VERSION,
            network: ChainParams::regtest().network_id,
            nonce: 0x0123_4567_89ab_cdef,
            height: 42,
            tip: [6; 32],
            listen: Some(NetAddr::parse("203.0.113.7:18333").unwrap()),
            relay_txs: true,
        }),
        Message::Version(Version {
            protocol: PROTOCOL_VERSION,
            network: ChainParams::regtest().network_id,
            nonce: 1,
            height: 0,
            tip: [0; 32],
            listen: None,
            relay_txs: false,
        }),
        Message::Pong(7),
        Message::Addr(vec![
            AddrEntry::new(1_700_000_000, NetAddr::parse("198.51.100.1:18333").unwrap()),
            AddrEntry::new(
                1_700_000_300,
                NetAddr::parse("[2001:db9::1]:18333").unwrap(),
            ),
            AddrEntry::new(0, NetAddr::parse(&format!("{onion}.onion:18333")).unwrap()),
        ]),
        Message::NotFound(vec![[10; 32], [11; 32]]),
        Message::GetTx(vec![[12; 32]]),
    ];
    for (i, m) in messages.iter().enumerate() {
        put("p2p_message", &format!("m{i}"), &m.encode());
    }

    // Programs: the committed test guests, the kernel and the vault.
    for (name, elf) in [
        (
            "guest_sum",
            &include_bytes!("../../zkvm/tests/fixtures/guest-sum.elf")[..],
        ),
        (
            "guest_arith",
            &include_bytes!("../../zkvm/tests/fixtures/guest-arith.elf")[..],
        ),
        ("kernel", blacksilk_px::prove::KERNEL_ELF),
        ("vault", blacksilk_px::vault::VAULT_ELF),
    ] {
        put("zkvm_elf", name, elf);
    }

    // A valid kernel witness (spend, dummy, two outputs).
    let mut perm = HostPerm::new();
    let alice = Account::from_seed(&[1; 32]);
    let mut tree = Tree::new(&mut perm);
    let rec = Record::plain(
        alice.owner(0),
        700,
        [0; 8],
        wallet::random_digest(&mut rng),
        wallet::random_digest(&mut rng),
    );
    let cm = rec.commit(&mut perm);
    let pos = tree.append(&mut perm, cm).unwrap();
    let w = wallet::witness(
        tree.root(),
        0,
        0,
        [
            alice.spend(0, &rec, pos, tree.path(pos).unwrap()),
            wallet::dummy_input(&mut rng),
        ],
        [
            wallet::output(&mut rng, alice.owner(1), 300),
            wallet::output(&mut rng, alice.owner(2), 400),
        ],
    );
    let words: Vec<u8> = witness_words(&w)
        .iter()
        .flat_map(|x| x.to_le_bytes())
        .collect();
    put("kernel_diff", "spend", &words);

    // Honest witnesses of the transaction shapes the kernel accepts
    // (W4-FUZZ2; the shapes of px/tests/kernel_budget.rs, which checks every
    // one against its budget): every shape with n_fn = 0 or 1 (4 and 162),
    // and every 8th of the 1,600 with n_fn = 2. With all 1,766, loading the
    // campaign's corpus took 16 minutes (the budget oracle measures each
    // accepted witness), and libFuzzer kept 589 of its 2,957 inputs.
    for (k, shape) in kernel_shapes::valid_shapes().iter().enumerate() {
        if shape.fns.len() == 2 && k % 8 != 0 {
            continue;
        }
        let words: Vec<u8> = witness_words(&shape.witness(k as u64))
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .collect();
        put(
            "kernel_diff",
            &format!("shape{k}_fn{}", shape.fns.len()),
            &words,
        );
    }

    // A ciphertext and a share that decrypt for the target's own keys (the
    // target opens with commitment [1; 8], so they fail only at the final
    // commitment check).
    let target = Account::from_seed(&[42; 32]);
    let to = target.address(0);
    let r = Record::plain(to.owner, 5, [0; 8], [2; 8], [3; 8]);
    let ct = blacksilk_px::delivery::seal(&mut rng, &[0x5e; 32], &to, &r, &[1; 8]).unwrap();
    put("delivery_open", "ciphertext", &ct);
    let sh = blacksilk_px::share::seal_share(&mut rng, &[0x5e; 32], &to, &r, &[1; 8]).unwrap();
    put("delivery_open", "share", &sh);

    // A real transfer proof (about 2 MB; proving takes about a minute).
    let (_, proof) = prove_transfer(&w, [1; 32], &mut rng).unwrap();
    put(
        "proof_decode",
        "transfer",
        &blacksilk_zk::encode_proof(&proof),
    );

    // The other transaction kinds (as in tx/tests/fuzz_decode.rs): a transfer,
    // a PX transaction (one more proof) and a deploy. Their own generator, so
    // the seeds above stay as they were. The spent outputs come from a
    // 16-output coinbase to `keys`; each input's 15 decoys are its siblings.
    // Valid encodings, not chain-valid transactions: nothing here is mined.
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let rules = TxRules::for_chain(&ChainParams::regtest());
    let table = SubaddressTable::new(keys.view_keys(), 1, 16);
    let funds: Vec<Payment> = (0..16)
        .map(|i| Payment {
            address: keys.address(SubaddressIndex::new(0, i)),
            amount: 1_000_000_000 + i as u64,
        })
        .collect();
    let funding = Transaction::Coinbase(build_coinbase(2, &funds, &[2; 32], &mut rng).unwrap());
    let owned = scan_block(
        keys.view_keys(),
        &table,
        std::slice::from_ref(&funding),
        2,
        0,
    )
    .owned;
    assert_eq!(owned.len(), 16, "the wallet owns every funding output");
    let plan = |k: usize| InputPlan {
        real: SpendableOutput::from(&owned[k]),
        decoys: owned
            .iter()
            .enumerate()
            .filter(|&(j, _)| j != k)
            .map(|(_, o)| Decoy {
                global_index: o.global_index,
                key: o.key,
            })
            .collect(),
    };
    let home = keys.address(SubaddressIndex::new(0, 0));

    let transfer = build_transfer(
        &keys,
        vec![plan(0)],
        &[Payment {
            address: keys.address(SubaddressIndex::new(0, 1)),
            amount: 1_000,
        }],
        &home,
        standard_fee(1, 2, &rules),
        &rules,
        &mut rng,
    )
    .unwrap();
    put(
        "tx_decode",
        "transfer",
        &Transaction::from(transfer).encode(),
    );

    let deploy = build_deploy(
        &keys,
        vec![plan(1)],
        &[Payment {
            address: home,
            amount: 1,
        }],
        &home,
        [1; 32],
        vec![Registration {
            elf: blacksilk_px::vault::VAULT_ELF.to_vec(),
            budget: blacksilk_px::vault::BUDGET,
            abi: blacksilk_tx::px::ABI_VERSION,
            out_words: 1,
        }],
        &rules,
        &mut rng,
    )
    .unwrap();
    let deploy_tx = Transaction::PxDeploy(Box::new(deploy));
    put("tx_decode", "deploy", &deploy_tx.encode());

    // A bridge-in of 10_000_000 to a PX record (two dummy inputs).
    let bob = Account::from_seed(&[9; 32]);
    let bridge = wallet::witness(
        Tree::new(&mut perm).root(),
        10_000_000,
        0,
        [wallet::dummy_input(&mut rng), wallet::dummy_input(&mut rng)],
        [
            wallet::output(&mut rng, bob.owner(0), 10_000_000),
            wallet::empty_output(&mut rng),
        ],
    );
    let px = build_px(
        PxPlan {
            keys: Some(&keys),
            inputs: vec![plan(2)],
            change: Some(home),
            payouts: vec![],
            witness: bridge,
            recipients: [Some(bob.address(0)), None],
            functions: vec![],
            fee: px_standard_fee(),
            window: Default::default(),
            hedge_secret: [0x5e; 32],
        },
        &rules,
        &mut rng,
    )
    .unwrap();
    put(
        "tx_decode",
        "px",
        &Transaction::Px(Box::new(px.clone())).encode(),
    );

    // The same PX transaction with a short proof blob (F41-1). The proof is
    // opaque, length-prefixed bytes to the decoder, and the full seed (about
    // 2 MB) is longer than the campaign's -max_len, so libFuzzer truncates it
    // at load and it never decodes: without this seed, the PX decoder and
    // the stateless PX rules are reached only if the fuzzer rebuilds a PX
    // encoding by itself. And a block carrying it, for block_decode.
    let mut short = px;
    short.proof.truncate(64);
    let short = Transaction::Px(Box::new(short));
    put("tx_decode", "px_short_proof", &short.encode());
    let txs = vec![funding, short];
    let ids: Vec<_> = txs.iter().map(Transaction::hash).collect();
    let block = Block {
        header: BlockHeader {
            version: HEADER_VERSION,
            height: 2,
            prev_id: [2; 32],
            timestamp: genesis.timestamp + 240,
            difficulty: 1,
            tx_root: tx_root(&ids),
            nonce: 0,
        },
        txs,
    };
    put("block_decode", "block_px", &block.encode());

    // scan_outputs: the PX transaction (its change pays `keys`, the
    // target's wallet A) and the deploy, as decoded inputs (mode 0).
    for (name, tx) in [("px", &block.txs[1]), ("deploy_tx", &deploy_tx)] {
        put("scan_outputs", name, &[&[0u8][..], &tx.encode()].concat());
    }

    // px_admission's base: a PX deposit with a real proof on the target's
    // fixed chain (deterministic: the target rebuilds the same chain).
    let (chain, mut miner, _) = px_admission::chain();
    let deposit = px_admission::deposit(&chain, &mut miner);
    put(
        "px_admission_base",
        "tx",
        &Transaction::Px(Box::new(deposit)).encode(),
    );
}
