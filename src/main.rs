use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let port = if let Some(i) = args.iter().position(|a| a == "-p" || a == "--port") {
        args.get(i + 1).and_then(|p| p.parse().ok()).unwrap_or(node::config::TESTNET_P2P_PORT)
    } else {
        node::config::TESTNET_P2P_PORT
    };
    let connect_addr = if let Some(i) = args.iter().position(|a| a == "--connect") {
        args.get(i + 1).cloned()
    } else {
        None
    };
    let network = std::env::var("BLACKSILK_NETWORK").unwrap_or_else(|_| "testnet".to_string());
    println!("[BlackSilk] Network: {} | Bootstrap on port {}", network, port);
    // The following CLI commands are not implemented, so print a message and exit if used
    if args.contains(&"send-block".to_string()) {
        println!("[CLI] send-block is not implemented in this build.");
        return;
    }
    if args.contains(&"send-tx".to_string()) {
        println!("[CLI] send-tx is not implemented in this build.");
        return;
    }
    if args.contains(&"save-chain".to_string()) {
        println!("[CLI] save-chain is not implemented in this build.");
        return;
    }
    if args.contains(&"load-chain".to_string()) {
        println!("[CLI] load-chain is not implemented in this build.");
        return;
    }
    // Use the full node startup function that includes HTTP server
    node::start_node_with_args(port, connect_addr, None);
}
