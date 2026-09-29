//! `/info` identifies the node: the full genesis id, the consensus fingerprint
//! of its network, the build commit and the crate version (review R15-8,
//! D-6), over the real router and the RPC client.

use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::{ChainParams, Hash, Network, PowFunction};
use blacksilk_node::fingerprint::{self, consensus_fingerprint, hex, BUILD_COMMIT};
use blacksilk_node::{router, Shared};
use blacksilk_rpc::Client;
use blacksilk_tx::params::TxRules;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

struct ZeroPow;

impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        [0; 32]
    }
}

fn serve(params: ChainParams) -> (tokio::runtime::Runtime, std::net::SocketAddr) {
    let rules = TxRules::for_chain(&params);
    let manager = ChainManager::open(
        params,
        rules,
        Arc::new(ZeroPow),
        Box::<MemoryStore>::default(),
        [3; 32],
    )
    .unwrap();
    let shared: Shared = Arc::new(Mutex::new(manager));
    let rt = tokio::runtime::Runtime::new().unwrap();
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(shared);
    rt.spawn(async move { axum::serve(listener, app).await.unwrap() });
    (rt, addr)
}

fn raw_info(addr: std::net::SocketAddr) -> String {
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    write!(
        s,
        "GET /info HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    resp.split_once("\r\n\r\n")
        .map_or("", |(_, b)| b)
        .to_string()
}

#[test]
fn info_carries_the_node_identity() {
    let params = ChainParams::regtest();
    let genesis = hex(&params.genesis_id());
    let (_rt, addr) = serve(params);
    let info = Client::new(&addr.to_string()).info().unwrap();
    assert_eq!(info.network, "regtest");
    assert_eq!(info.genesis_id.as_deref(), Some(genesis.as_str()));
    let f = hex(&consensus_fingerprint(Network::Regtest));
    assert_eq!(info.consensus_fingerprint.as_deref(), Some(f.as_str()));
    assert_ne!(
        info.consensus_fingerprint.as_deref(),
        Some(hex(&consensus_fingerprint(Network::Testnet)).as_str())
    );
    // Fingerprint v3: the rules and identity fingerprints (decision "Agent 40").
    let r = hex(&fingerprint::rules_fingerprint(Network::Regtest));
    let i = hex(&fingerprint::identity_fingerprint(Network::Regtest));
    assert_eq!(info.rules_fingerprint.as_deref(), Some(r.as_str()));
    assert_eq!(info.identity_fingerprint.as_deref(), Some(i.as_str()));
    assert_eq!(info.build_commit.as_deref(), Some(BUILD_COMMIT));
    assert_eq!(info.version.as_deref(), Some(fingerprint::VERSION));
    assert_eq!(info.genesis_id.as_ref().map(String::len), Some(64));

    // The JSON field names (what check-node.sh and scripts read).
    let body = raw_info(addr);
    for field in [
        format!("\"genesis_id\":\"{genesis}\""),
        format!("\"consensus_fingerprint\":\"{f}\""),
        format!("\"rules_fingerprint\":\"{r}\""),
        format!("\"identity_fingerprint\":\"{i}\""),
        format!("\"build_commit\":\"{BUILD_COMMIT}\""),
    ] {
        assert!(body.contains(&field), "{field} in {body}");
    }
}
