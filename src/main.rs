use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_help();
        return;
    }
    match args[1].as_str() {
        "status" => {
            node::node_status();
        }
        "info" => {
            node::node_info();
        }
        "peers" => {
            node::node_peers();
        }
        "connect" => {
            if args.len() > 2 {
                node::connect_to_peer(&args[2]);
            } else {
                println!("Usage: connect <ip:port>");
            }
        }
        "disconnect" => {
            if args.len() > 2 {
                node::node_disconnect(&args[2]);
            } else {
                println!("Usage: disconnect <ip:port>");
            }
        }
        "height" => {
            node::node_height();
        }
        "block" => {
            if args.len() > 2 {
                node::node_block(&args[2]);
            } else {
                println!("Usage: block <height|hash>");
            }
        }
        "chain" => {
            node::node_chain();
        }
        "mempool" => {
            node::node_mempool();
        }
        "tx" => {
            if args.len() > 2 {
                node::node_tx(&args[2]);
            } else {
                println!("Usage: tx <hash>");
            }
        }
        "get-block-template" => {
            node::node_get_block_template();
        }
        "save-chain" => {
            node::save_chain();
        }
        "load-chain" => {
            node::load_chain();
        }
        "send-block" => {
            node::cli_send_block();
        }
        "send-tx" => {
            node::cli_send_transaction();
        }
        "exit" => {
            println!("[CLI] Exiting node.");
        }
        "help" => {
            print_help();
        }
        "ban" => {
            if args.len() > 2 {
                node::ban_ip(&args[2]);
            } else {
                println!("Usage: ban <ip>");
            }
        }
        "unban" => {
            if args.len() > 2 {
                node::unban_ip(&args[2]);
            } else {
                println!("Usage: unban <ip>");
            }
        }
        "list-bans" => {
            node::list_bans();
        }
        "sync-status" => {
            node::sync_status();
        }
        "prune-chain" => {
            node::prune_chain();
        }
        "export-chain" => {
            if args.len() > 2 {
                node::export_chain(&args[2]);
            } else {
                println!("Usage: export-chain <file>");
            }
        }
        "import-chain" => {
            if args.len() > 2 {
                node::import_chain(&args[2]);
            } else {
                println!("Usage: import-chain <file>");
            }
        }
        "network-stats" => {
            node::network_stats();
        }
        _ => {
            // Default: start node as before
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
            node::start_node_with_port_and_connect(port, connect_addr);
        }
    }
}

fn print_help() {
    println!("BlackSilk Node CLI - Available commands:");
    println!("  status                Show node status");
    println!("  info                  Show node info");
    println!("  peers                 List connected peers");
    println!("  connect <ip:port>     Connect to a peer");
    println!("  disconnect <ip:port>  Disconnect from a peer");
    println!("  height                Show current chain height");
    println!("  block <height|hash>   Show block details");
    println!("  chain                 Show recent blocks summary");
    println!("  mempool               Show mempool transactions");
    println!("  tx <hash>             Show transaction details");
    println!("  get-block-template    Get block template for mining");
    println!("  save-chain            Save chain to disk");
    println!("  load-chain            Load chain from disk");
    println!("  send-block            Send latest block to a peer");
    println!("  send-tx               Send a transaction to a peer");
    println!("  exit                  Exit node");
    println!("  help                  Show this help message");
    println!("  ban <ip>                Ban a peer IP");
    println!("  unban <ip>              Unban a peer IP");
    println!("  list-bans               List banned IPs");
    println!("  sync-status             Show sync status");
    println!("  prune-chain             Prune old blocks from chain");
    println!("  export-chain <file>     Export chain to file");
    println!("  import-chain <file>     Import chain from file");
    println!("  network-stats           Show network statistics");
    println!("");
    println!("If no command is given, node will start normally.");
}
