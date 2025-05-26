//! BlackSilk Node CLI Entry Point
//! Professional implementation with advanced privacy, network management, and difficulty adjustment

use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "blacksilk-node", version, about = "BlackSilk Privacy Blockchain Node")]
pub struct Cli {
    /// Data directory for blockchain and node state
    #[arg(long, default_value = "./data", value_name = "DIR")]
    pub data_dir: PathBuf,

    /// Network type (mainnet for production, testnet for development)
    #[arg(long, value_enum, default_value = "testnet")]
    pub network: NetworkArg,

    /// Connect to peer addresses (can be specified multiple times)
    #[arg(long, value_name = "ADDR")]
    pub connect: Vec<String>,

    /// Privacy mode for network connections
    #[arg(long, value_enum, default_value = "tor")]
    pub privacy: PrivacyArg,

    /// Enable Tor hidden service
    #[arg(long)]
    pub tor_hidden_service: bool,

    /// Enable I2P support
    #[arg(long)]
    pub i2p_enabled: bool,

    /// Logging verbosity (error, warn, info, debug, trace)
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Genesis timestamp (for chain reset, use October 5, 1986)
    #[arg(long)]
    pub genesis_timestamp: Option<u64>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum NetworkArg {
    Mainnet,
    Testnet,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum PrivacyArg {
    Disabled,
    Tor,
    TorOnly,
    MaxPrivacy,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    // Convert CLI network to internal network type
    let network = match cli.network {
        NetworkArg::Mainnet => node::Network::Mainnet,
        NetworkArg::Testnet => node::Network::Testnet,
    };
    
    // Set global network configuration
    if let Err(_) = node::set_network(network.clone()) {
        eprintln!("[Node] Warning: Network already configured");
    }
    
    // Configure privacy settings
    let privacy_mode = match cli.privacy {
        PrivacyArg::Disabled => node::network::privacy::PrivacyMode::Disabled,
        PrivacyArg::Tor => node::network::privacy::PrivacyMode::Tor,
        PrivacyArg::TorOnly => node::network::privacy::PrivacyMode::TorOnly,
        PrivacyArg::MaxPrivacy => node::network::privacy::PrivacyMode::MaxPrivacy,
    };
    
    let privacy_config = node::network::privacy::PrivacyConfig {
        privacy_mode,
        tor_only: matches!(cli.privacy, PrivacyArg::TorOnly | PrivacyArg::MaxPrivacy),
        i2p_enabled: cli.i2p_enabled || matches!(cli.privacy, PrivacyArg::MaxPrivacy),
        hidden_service_port: network.get_ports().tor,
        ..Default::default()
    };
    
    // Display startup banner
    display_startup_banner(&network, &privacy_config);
    
    // Initialize privacy manager
    let privacy_manager = std::sync::Arc::new(
        node::network::privacy::PrivacyManager::new(privacy_config.clone())
    );
    
    // Setup Tor hidden service if enabled
    if cli.tor_hidden_service || matches!(cli.privacy, PrivacyArg::TorOnly | PrivacyArg::MaxPrivacy) {
        println!("[Privacy] Initializing Tor hidden service...");
        match tokio::runtime::Runtime::new() {
            Ok(rt) => {
                rt.block_on(async {
                    match node::network::privacy::setup_tor_hidden_service(network.get_ports().tor).await {
                        Ok(onion_addr) => println!("[Privacy] ✅ Tor hidden service: {}", onion_addr),
                        Err(e) => eprintln!("[Privacy] ⚠️  Tor setup failed: {}", e),
                    }
                });
            }
            Err(e) => eprintln!("[Privacy] Failed to create async runtime: {}", e),
        }
    }
    
    // Start the enhanced node
    start_enhanced_node(network, privacy_manager, cli.data_dir, cli.connect)?;
    
    Ok(())
}

fn display_startup_banner(network: &node::Network, privacy_config: &node::network::privacy::PrivacyConfig) {
    let ports = network.get_ports();
    
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║                     BlackSilk Blockchain Node                   ║");
    println!("║                Professional Privacy-First Implementation         ║");
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║ Network: {:50} ║", format!("{:?}", network));
    println!("║ Privacy Mode: {:43} ║", format!("{:?}", privacy_config.privacy_mode));
    println!("║                                                                  ║");
    println!("║ Port Configuration:                                              ║");
    println!("║   P2P Network:     {} (All protocols)                        ║", ports.p2p);
    println!("║   HTTP API:        {} (Local only)                           ║", ports.http);
    println!("║   Tor Hidden:      {} (.onion service)                       ║", ports.tor);
    println!("║                                                                  ║");
    println!("║ Features:                                                        ║");
    println!("║   ✓ Real block creation with proper validation                  ║");
    println!("║   ✓ Automatic difficulty adjustment (120s target)               ║");
    println!("║   ✓ Advanced Tor/I2P privacy integration                        ║");
    println!("║   ✓ Professional port management                                ║");
    println!("║   ✓ RandomX proof-of-work mining                                ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();
}

fn start_enhanced_node(
    network: node::Network,
    privacy_manager: std::sync::Arc<node::network::privacy::PrivacyManager>,
    data_dir: PathBuf,
    peers: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ports = network.get_ports();
    
    println!("[Node] Starting enhanced BlackSilk node...");
    println!("[Node] Network: {:?}", network);
    println!("[Node] Data directory: {:?}", data_dir);
    
    // Create data directory if it doesn't exist
    std::fs::create_dir_all(&data_dir)?;
    
    // Display network status with privacy info
    node::network::privacy::display_network_status(&privacy_manager, &ports);
    
    // Start HTTP API server
    let _privacy_manager_clone = privacy_manager.clone();
    let http_handle = std::thread::spawn(move || {
        println!("[HTTP] Starting API server on port {}", ports.http);
        if let Err(e) = node::http_server::start_http_server_sync(ports.http) {
            eprintln!("[HTTP] Server error: {}", e);
        }
    });
    
    // Start P2P network with privacy manager
    let p2p_handle = std::thread::spawn(move || {
        println!("[P2P] Starting network on port {} with privacy controls", ports.p2p);
        // This would integrate with the P2P code using privacy_manager
        if let Err(e) = node::start_p2p_server_with_privacy(ports.p2p, privacy_manager, peers) {
            eprintln!("[P2P] Network error: {}", e);
        }
    });
    
    println!("[Node] ✅ BlackSilk node fully operational!");
    println!("[Node] Press Ctrl+C to stop the node");
    
    // Wait for threads to complete
    let _ = http_handle.join();
    let _ = p2p_handle.join();
    
    Ok(())
}
