//! Transactions: decoding never panics; whatever decodes re-encodes to the
//! same bytes; the stateless rules never panic on a decoded transaction.
#![no_main]
use blacksilk_consensus::ChainParams;
use blacksilk_tx::params::TxRules;
use blacksilk_tx::px::{check_deploy_structure, check_px_balance, check_px_structure};
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::check_structure;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(tx) = Transaction::decode(data) else {
        return;
    };
    assert_eq!(tx.encode(), data, "decode then encode is the identity");
    let _ = tx.hash();
    let rules = TxRules::for_chain(&ChainParams::regtest());
    match &tx {
        Transaction::Transfer(t) => {
            let _ = check_structure(t, &rules);
        }
        Transaction::Px(t) => {
            let _ = check_px_structure(t);
            let _ = check_px_balance(t);
            let _ = t.binding(rules.network_id);
        }
        Transaction::PxDeploy(d) => {
            let _ = check_deploy_structure(d, &rules);
            let _ = d.contract_id();
        }
        Transaction::Coinbase(_) => {}
    }
});
