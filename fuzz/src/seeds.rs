//! Writes seed corpora for the fuzz targets: one or more valid encodings per
//! target, so that coverage-guided fuzzing starts from deep inside each
//! format. `cargo run --release --bin seeds` (from `fuzz/`).

use blacksilk_chain::block::Block;
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, HEADER_VERSION};
use blacksilk_crypto::keys::{SubaddressIndex, SubaddressTable, WalletKeys};
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
use blacksilk_zkvm::air::trace::Budget;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::path::Path;

const MODULE: &str = r#"
(module
  (import "bs" "get" (func $get (param i32 i32 i32 i32) (result i32)))
  (import "bs" "set" (func $set (param i32 i32 i32 i32)))
  (memory (export "memory") 1 1)
  (data (i32.const 0) "count")
  (func (export "bs_call")
    (local $i i32)
    (if (i32.eq (call $get (i32.const 0) (i32.const 5) (i32.const 16) (i32.const 8)) (i32.const -1))
      (then (i64.store (i32.const 16) (i64.const 0))))
    (loop $l
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $l (i32.lt_u (local.get $i) (i32.const 50))))
    (i64.store (i32.const 16) (i64.add (i64.load (i32.const 16)) (i64.const 1)))
    (call $set (i32.const 0) (i32.const 5) (i32.const 16) (i32.const 8))))
"#;

fn put(target: &str, name: &str, bytes: &[u8]) {
    let dir = Path::new("corpus").join(target);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(name), bytes).unwrap();
    println!("corpus/{target}/{name}: {} bytes", bytes.len());
}

fn main() {
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

    // Messages of every shape. A Tor v3 host: 56 base32 characters.
    let onion = "abcdefghijklmnopqrstuvwxyz234567".repeat(2);
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
            NetAddr::parse("198.51.100.1:18333").unwrap(),
            NetAddr::parse("[2001:db9::1]:18333").unwrap(),
            NetAddr::parse(&format!("{}.onion:18333", &onion[..56])).unwrap(),
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

    // A contract module.
    put("wasm_module", "counter", &wat::parse_str(MODULE).unwrap());

    // Contract sequences (contract_sequence): call = [op 0, target, len, input.., fuel, storage].
    let key = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let mut set_get = vec![0u8, 0, 12, 0];
    set_get.extend(key);
    set_get.extend([9, 9, 9, 10, 10]); // value, fuel, storage
    set_get.push(2); // end the block
    set_get.extend([0, 0, 9, 2]);
    set_get.extend(key);
    set_get.extend([10, 0]); // read it back
    set_get.extend([0, 1, 0, 10, 10]); // the counter
    set_get.push(3); // undo the block
    put("contract_sequence", "set_get_undo", &set_get);
    put(
        "contract_sequence",
        "burn",
        &[0, 0, 2, 3, 200, 1, 0, 2, 0, 0, 2, 3, 255, 255, 0],
    );

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
    let owned = scan_block(keys.view_keys(), &table, &[funding], 2, 0).owned;
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
            budget: Budget {
                cycles: 6_000,
                keys: 2_200,
                add: 4_300,
                bit: 250,
                lt: 3_500,
                shift: 200,
                mul: 200,
                poseidon: 22,
            },
        }],
        &rules,
        &mut rng,
    )
    .unwrap();
    put(
        "tx_decode",
        "deploy",
        &Transaction::PxDeploy(Box::new(deploy)).encode(),
    );

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
            hedge_secret: [0x5e; 32],
        },
        &rules,
        &mut rng,
    )
    .unwrap();
    put("tx_decode", "px", &Transaction::Px(Box::new(px)).encode());
}
