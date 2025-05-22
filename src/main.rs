use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let port = if let Some(i) = args.iter().position(|a| a == "-p" || a == "--port") {
        args.get(i + 1).and_then(|p| p.parse().ok()).unwrap_or(node::config::DEFAULT_P2P_PORT)
    } else {
        node::config::DEFAULT_P2P_PORT
    };
    let connect_addr = if let Some(i) = args.iter().position(|a| a == "--connect") {
        args.get(i + 1).cloned()
    } else {
        None
    };
    println!("[BlackSilk] Testnet bootstrap on port {}", port);
    if args.contains(&"send-block".to_string()) {
        node::cli_send_block();
        return;
    }
    if args.contains(&"send-tx".to_string()) {
        node::cli_send_transaction();
        return;
    }
    if args.contains(&"save-chain".to_string()) {
        node::save_chain();
        println!("[CLI] Chain saved to disk");
        return;
    }
    if args.contains(&"load-chain".to_string()) {
        node::load_chain();
        println!("[CLI] Chain loaded from disk");
        return;
    }
    node::start_node_with_port_and_connect(port, connect_addr);
}
