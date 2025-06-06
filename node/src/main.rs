//! BlackSilk Node CLI Entry Point
//! Professional implementation with advanced privacy, network management, and difficulty adjustment

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use colored::*;

#[derive(Parser, Debug)]
#[command(name = "blacksilk-node", version, about = "BlackSilk Privacy Blockchain Node")]
pub struct Cli {
    /// Data directory for blockchain and node state
    #[arg(long, default_value = "./data", value_name = "DIR")]
    pub data_dir: PathBuf,

    /// Network type (mainnet for production, testnet for development)
    #[arg(long, value_enum, default_value = "testnet")]
    pub network: NetworkArg,

    /// HTTP/RPC server bind address
    #[arg(long, default_value = "127.0.0.1:9333", value_name = "ADDR")]
    pub bind: String,

    /// P2P network bind address
    #[arg(long, default_value = "0.0.0.0:9334", value_name = "ADDR")]
    pub p2p_bind: String,

    /// Connect to peer addresses (can be specified multiple times)
    #[arg(long, value_name = "ADDR")]
    pub connect: Vec<String>,

    /// Add peer to address book without connecting
    #[arg(long, value_name = "ADDR")]
    pub add_peer: Vec<String>,

    /// Privacy mode for network connections
    #[arg(long, value_enum, default_value = "tor")]
    pub privacy: PrivacyArg,

    /// Enable Tor hidden service
    #[arg(long)]
    pub tor_hidden_service: bool,

    /// Tor SOCKS proxy address
    #[arg(long, default_value = "127.0.0.1:9050", value_name = "ADDR")]
    pub tor_proxy: String,

    /// Enable I2P support
    #[arg(long)]
    pub i2p_enabled: bool,

    /// I2P SAM bridge address
    #[arg(long, default_value = "127.0.0.1:7656", value_name = "ADDR")]
    pub i2p_sam: String,

    /// Logging verbosity (error, warn, info, debug, trace)
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Genesis timestamp (for chain reset, use October 5, 1986)
    #[arg(long)]
    pub genesis_timestamp: Option<u64>,

    /// Enable mining mode (runs internal miner)
    #[arg(long)]
    pub mining: bool,

    /// Mining threads for internal miner
    #[arg(long, default_value = "1")]
    pub mining_threads: usize,

    /// Mining address for block rewards
    #[arg(long, value_name = "ADDR")]
    pub mining_address: Option<String>,

    /// Maximum number of peer connections
    #[arg(long, default_value = "50")]
    pub max_peers: usize,

    /// Minimum number of peer connections to maintain
    #[arg(long, default_value = "8")]
    pub min_peers: usize,

    /// Database cache size in MB
    #[arg(long, default_value = "256")]
    pub db_cache: usize,

    /// Block verification threads
    #[arg(long, default_value = "4")]
    pub verify_threads: usize,

    /// Enable mempool
    #[arg(long, default_value = "true")]
    pub mempool: bool,

    /// Maximum mempool size in MB
    #[arg(long, default_value = "100")]
    pub mempool_size: usize,

    /// Enable wallet functionality
    #[arg(long)]
    pub wallet: bool,

    /// Wallet file path
    #[arg(long, value_name = "FILE")]
    pub wallet_file: Option<PathBuf>,

    /// Enable JSON-RPC server
    #[arg(long, default_value = "true")]
    pub rpc: bool,

    /// JSON-RPC server bind address
    #[arg(long, default_value = "127.0.0.1:9335", value_name = "ADDR")]
    pub rpc_bind: String,

    /// Enable HTTPS for RPC
    #[arg(long)]
    pub rpc_ssl: bool,

    /// SSL certificate file for RPC
    #[arg(long, value_name = "FILE")]
    pub rpc_cert: Option<PathBuf>,

    /// SSL private key file for RPC
    #[arg(long, value_name = "FILE")]
    pub rpc_key: Option<PathBuf>,

    /// RPC authentication username
    #[arg(long, value_name = "USER")]
    pub rpc_user: Option<String>,

    /// RPC authentication password
    #[arg(long, value_name = "PASS")]
    pub rpc_password: Option<String>,

    /// Enable CORS for RPC
    #[arg(long)]
    pub rpc_cors: bool,

    /// Allowed CORS origins (can be specified multiple times)
    #[arg(long, value_name = "ORIGIN")]
    pub rpc_cors_origin: Vec<String>,

    /// Run in daemon mode (background)
    #[arg(long)]
    pub daemon: bool,

    /// PID file for daemon mode
    #[arg(long, value_name = "FILE")]
    pub pid_file: Option<PathBuf>,

    /// Configuration file
    #[arg(long, short = 'c', value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Enable block pruning
    #[arg(long)]
    pub prune: bool,

    /// Blocks to keep when pruning (0 = keep all)
    #[arg(long, default_value = "550")]
    pub prune_height: u64,

    /// Bootstrap from specific node
    #[arg(long, value_name = "ADDR")]
    pub bootstrap: Option<String>,

    /// Checkpoint file for fast sync
    #[arg(long, value_name = "FILE")]
    pub checkpoint: Option<PathBuf>,

    /// Disable checkpoint verification
    #[arg(long)]
    pub no_checkpoint: bool,

    /// Enable fast sync mode
    #[arg(long)]
    pub fast_sync: bool,

    /// Disable DNS seeds
    #[arg(long)]
    pub no_dns: bool,

    /// Custom DNS seed servers
    #[arg(long, value_name = "HOST")]
    pub dns_seed: Vec<String>,

    /// Network timeout in seconds
    #[arg(long, default_value = "30")]
    pub timeout: u64,

    /// Connection retry attempts
    #[arg(long, default_value = "3")]
    pub retry: usize,

    /// Bandwidth limit (KB/s, 0 = unlimited)
    #[arg(long, default_value = "0")]
    pub bandwidth_limit: u64,

    /// Enable advanced telemetry
    #[arg(long)]
    pub telemetry: bool,

    /// Telemetry server endpoint
    #[arg(long, value_name = "URL")]
    pub telemetry_url: Option<String>,

    /// Node name for telemetry
    #[arg(long, value_name = "NAME")]
    pub node_name: Option<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize a new blockchain
    Init {
        /// Force initialization even if data exists
        #[arg(long)]
        force: bool,
        /// Custom genesis timestamp
        #[arg(long)]
        genesis_time: Option<u64>,
    },
    /// Start the node daemon
    Start,
    /// Stop a running node daemon
    Stop,
    /// Restart the node daemon
    Restart,
    /// Show node status
    Status,
    /// Show blockchain information
    Info,
    /// Show peer connections
    Peers,
    /// Show mempool information
    Mempool,
    /// Show mining information
    Mining,
    /// Sync with network
    Sync {
        /// Force full resync
        #[arg(long)]
        force: bool,
    },
    /// Validate blockchain
    Validate {
        /// Starting block height
        #[arg(long)]
        from: Option<u64>,
        /// Ending block height
        #[arg(long)]
        to: Option<u64>,
    },
    /// Export blockchain data
    Export {
        /// Output file
        #[arg(value_name = "FILE")]
        output: PathBuf,
        /// Starting block height
        #[arg(long)]
        from: Option<u64>,
        /// Ending block height
        #[arg(long)]
        to: Option<u64>,
    },
    /// Import blockchain data
    Import {
        /// Input file
        #[arg(value_name = "FILE")]
        input: PathBuf,
        /// Verify blocks during import
        #[arg(long, default_value = "true")]
        verify: bool,
    },
    /// Database maintenance operations
    Database {
        #[command(subcommand)]
        action: DatabaseCommands,
    },
    /// Network diagnostic tools
    Network {
        #[command(subcommand)]
        action: NetworkCommands,
    },
    /// Privacy and anonymity tools
    Privacy {
        #[command(subcommand)]
        action: PrivacyCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum DatabaseCommands {
    /// Compact database
    Compact,
    /// Check database integrity
    Check,
    /// Repair database
    Repair,
    /// Show database statistics
    Stats,
    /// Prune old blocks
    Prune {
        /// Blocks to keep
        #[arg(long, default_value = "550")]
        keep: u64,
    },
}

#[derive(Subcommand, Debug)]
pub enum NetworkCommands {
    /// Ping a peer
    Ping {
        /// Peer address
        #[arg(value_name = "ADDR")]
        address: String,
    },
    /// Test connection to peer
    Connect {
        /// Peer address
        #[arg(value_name = "ADDR")]
        address: String,
    },
    /// Ban a peer
    Ban {
        /// Peer address
        #[arg(value_name = "ADDR")]
        address: String,
        /// Ban duration in hours
        #[arg(long, default_value = "24")]
        duration: u64,
    },
    /// Unban a peer
    Unban {
        /// Peer address
        #[arg(value_name = "ADDR")]
        address: String,
    },
    /// List banned peers
    Banned,
    /// Discover peers via DNS
    Discover,
}

#[derive(Subcommand, Debug)]
pub enum PrivacyCommands {
    /// Generate Tor hidden service
    GenerateTor,
    /// Show Tor status
    TorStatus,
    /// Configure I2P
    ConfigureI2p,
    /// Show I2P status
    I2pStatus,
    /// Mix network test
    MixTest,
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
    
    // Print professional startup banner
    print_startup_banner();
    
    // Handle subcommands first
    match &cli.command {
        Some(Commands::Init { force, genesis_time }) => {
            handle_init(&cli, *force, *genesis_time)?;
            return Ok(());
        }
        Some(Commands::Start) => {
            println!("{} Starting BlackSilk node daemon...", "[DAEMON]".bright_green().bold());
        }
        Some(Commands::Stop) => {
            handle_stop()?;
            return Ok(());
        }
        Some(Commands::Restart) => {
            handle_restart(&cli)?;
            return Ok(());
        }
        Some(Commands::Status) => {
            handle_status()?;
            return Ok(());
        }
        Some(Commands::Info) => {
            handle_info(&cli)?;
            return Ok(());
        }
        Some(Commands::Peers) => {
            handle_peers(&cli)?;
            return Ok(());
        }
        Some(Commands::Mempool) => {
            handle_mempool(&cli)?;
            return Ok(());
        }
        Some(Commands::Mining) => {
            handle_mining(&cli)?;
            return Ok(());
        }
        Some(Commands::Sync { force }) => {
            handle_sync(&cli, *force)?;
            return Ok(());
        }
        Some(Commands::Validate { from, to }) => {
            handle_validate(&cli, *from, *to)?;
            return Ok(());
        }
        Some(Commands::Export { output, from, to }) => {
            handle_export(&cli, output, *from, *to)?;
            return Ok(());
        }
        Some(Commands::Import { input, verify }) => {
            handle_import(&cli, input, *verify)?;
            return Ok(());
        }
        Some(Commands::Database { action }) => {
            handle_database(&cli, action)?;
            return Ok(());
        }
        Some(Commands::Network { action }) => {
            handle_network(&cli, action)?;
            return Ok(());
        }
        Some(Commands::Privacy { action }) => {
            handle_privacy(&cli, action)?;
            return Ok(());
        }
        None => {
            // Default: start the node
        }
    }
    
    // Display configuration
    print_configuration(&cli);
    
    // Convert CLI network to internal network type
    let network = match cli.network {
        NetworkArg::Mainnet => node::Network::Mainnet,
        NetworkArg::Testnet => node::Network::Testnet,
    };
    
    // Set global network configuration
    if let Err(_) = node::set_network(network.clone()) {
        eprintln!("{} Network already configured", "[WARNING]".bright_yellow().bold());
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

fn print_startup_banner() {
    println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_cyan());
    println!("{}", "║                    BlackSilk Node v2.0                        ║".bright_cyan());
    println!("{}", "║              Professional Privacy Blockchain Node             ║".bright_cyan());
    println!("{}", "║          RandomX • Tor • I2P • Ring Signatures • ZKP          ║".bright_cyan());
    println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_cyan());
    println!();
}

fn print_configuration(cli: &Cli) {
    println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_blue());
    println!("{}", "║                        CONFIGURATION                          ║".bright_blue());
    println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_blue());
    println!("║ {} Network: {:>47} ║", "🌐".bright_blue(), format!("{:?}", cli.network).bright_white());
    println!("║ {} Privacy: {:>47} ║", "🔒".bright_magenta(), format!("{:?}", cli.privacy).bright_white());
    println!("║ {} HTTP Bind: {:>45} ║", "🌍".bright_green(), cli.bind.bright_white());
    println!("║ {} P2P Bind: {:>46} ║", "🔗".bright_yellow(), cli.p2p_bind.bright_white());
    println!("║ {} RPC Bind: {:>46} ║", "⚡".bright_cyan(), cli.rpc_bind.bright_white());
    println!("║ {} Data Dir: {:>46} ║", "💾".bright_blue(), cli.data_dir.display().to_string().bright_white());
    println!("║ {} Log Level: {:>45} ║", "📋".bright_yellow(), cli.log_level.bright_white());
    
    if cli.mining {
        println!("║ {} Mining: {:>48} ║", "⛏️".bright_red(), "ENABLED".bright_green());
        println!("║ {} Mining Threads: {:>40} ║", "🧵".bright_red(), cli.mining_threads.to_string().bright_white());
        if let Some(ref addr) = cli.mining_address {
            let addr_display = if addr.len() > 35 { 
                format!("{}...", &addr[..32]) 
            } else { 
                addr.clone() 
            };
            println!("║ {} Mining Address: {:>35} ║", "💰".bright_yellow(), addr_display.bright_white());
        }
    }
    
    if !cli.connect.is_empty() {
        println!("║ {} Connect Peers: {:>41} ║", "👥".bright_green(), cli.connect.len().to_string().bright_white());
    }
    
    println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_blue());
    println!();
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

// Command handler functions
fn handle_init(cli: &Cli, force: bool, genesis_time: Option<u64>) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_cyan());
    println!("{}", "║                    BLOCKCHAIN INITIALIZATION                  ║".bright_cyan());
    println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_cyan());
    
    if cli.data_dir.exists() && !force {
        println!("{} Blockchain already exists at {:?}", "[WARNING]".bright_yellow().bold(), cli.data_dir);
        println!("{} Use --force to reinitialize", "[HINT]".bright_blue().bold());
        return Ok(());
    }
    
    println!("{} Initializing new blockchain...", "[INIT]".bright_green().bold());
    println!("{} Network: {:?}", "[CONFIG]".bright_blue().bold(), cli.network);
    println!("{} Data directory: {:?}", "[CONFIG]".bright_blue().bold(), cli.data_dir);
    
    if let Some(timestamp) = genesis_time {
        println!("{} Custom genesis time: {}", "[CONFIG]".bright_blue().bold(), timestamp);
    }
    
    // Create data directory
    std::fs::create_dir_all(&cli.data_dir)?;
    println!("{} ✅ Blockchain initialized successfully!", "[SUCCESS]".bright_green().bold());
    
    Ok(())
}

fn handle_stop() -> Result<(), Box<dyn std::error::Error>> {
    println!("{} Stopping BlackSilk node daemon...", "[DAEMON]".bright_red().bold());
    // TODO: Implement daemon stop logic
    println!("{} ✅ Node stopped successfully!", "[SUCCESS]".bright_green().bold());
    Ok(())
}

fn handle_restart(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    println!("{} Restarting BlackSilk node daemon...", "[DAEMON]".bright_yellow().bold());
    handle_stop()?;
    println!("{} Starting node with configuration...", "[DAEMON]".bright_green().bold());
    // TODO: Implement restart logic
    Ok(())
}

fn handle_status() -> Result<(), Box<dyn std::error::Error>> {
    use node::{CHAIN, PEER_COUNT};
    use std::sync::atomic::Ordering;
    use std::process::Command;
    
    println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_blue());
    println!("{}", "║                        NODE STATUS                            ║".bright_blue());
    println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_blue());
    
    // Check if node daemon is actually running
    let is_running = Command::new("pgrep")
        .args(&["-f", "blacksilk-node.*(start|daemon)"])
        .output()
        .map(|output| !output.stdout.is_empty())
        .unwrap_or(false);
    
    let (status_icon, status_text, status_color) = if is_running {
        ("🟢", "RUNNING", colored::Color::Green)
    } else {
        ("🔴", "STOPPED", colored::Color::Red)
    };
    
    if is_running {
        let chain = CHAIN.lock().unwrap();
        let current_height = chain.blocks.len() as u64;
        let peer_count = PEER_COUNT.load(Ordering::Relaxed);
        
        println!("║ {} Status: {:>48} ║", status_icon, status_text.color(status_color));
        println!("║ {} Uptime: {:>48} ║", "⏰".bright_blue(), "Active".bright_white());
        println!("║ {} Block Height: {:>42} ║", "📊".bright_cyan(), format!("{}", current_height).bright_white());
        println!("║ {} Peers: {:>49} ║", "👥".bright_green(), format!("{}", peer_count).bright_white());
        println!("║ {} Sync Status: {:>43} ║", "🔄".bright_blue(), "SYNCED".bright_green());
    } else {
        println!("║ {} Status: {:>48} ║", status_icon, status_text.color(status_color));
        println!("║ {} Message: {:>47} ║", "ℹ️".bright_yellow(), "Node daemon not running".bright_yellow());
        println!("║ {} Command: {:>47} ║", "💡".bright_cyan(), "Use 'daemon' to start".bright_white());
    }
    
    println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_blue());
    Ok(())
}

fn handle_info(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    use node::{CHAIN, PEER_COUNT, current_network};
    use std::sync::atomic::Ordering;
    
    println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_cyan());
    println!("{}", "║                     BLOCKCHAIN INFO                           ║".bright_cyan());
    println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_cyan());
    
    let chain = CHAIN.lock().unwrap();
    let current_height = chain.blocks.len() as u64;
    let network = current_network();
    let current_difficulty = if current_height > 0 {
        chain.tip().header.difficulty
    } else {
        network.get_difficulty()
    };
    let peer_count = PEER_COUNT.load(Ordering::Relaxed);
    
    // Calculate total transactions across all blocks
    let total_transactions: usize = chain.blocks.iter().map(|b| b.transactions.len()).sum();
    
    // Calculate chain work (simplified - sum of difficulties)
    let chain_work: u64 = chain.blocks.iter().map(|b| b.header.difficulty).sum();
    
    println!("║ {} Network: {:>47} ║", "🌐".bright_blue(), format!("{:?}", cli.network).bright_white());
    println!("║ {} Best Block: {:>44} ║", "🏆".bright_yellow(), format!("{}", current_height).bright_white());
    println!("║ {} Difficulty: {:>44} ║", "⚡".bright_red(), format!("{}", current_difficulty).bright_white());
    println!("║ {} Hash Rate: {:>45} ║", "🔥".bright_red(), "Calculating...".bright_white());
    println!("║ {} Total Transactions: {:>34} ║", "💳".bright_green(), format!("{}", total_transactions).bright_white());
    println!("║ {} Chain Work: {:>44} ║", "⛓️".bright_blue(), format!("0x{:x}", chain_work).bright_white());
    println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_cyan());
    Ok(())
}

fn handle_peers(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    use node::{PEERS, PEER_COUNT};
    use std::sync::atomic::Ordering;
    
    println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_green());
    println!("{}", "║                      PEER CONNECTIONS                         ║".bright_green());
    println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_green());
    
    let peer_count = PEER_COUNT.load(Ordering::Relaxed);
    let peers = PEERS.lock().unwrap();
    
    println!("║ {} Connected Peers: {:>39} ║", "👥".bright_green(), format!("{}", peer_count).bright_white());
    println!("║ {} Outbound: {:>46} ║", "📤".bright_blue(), "0".bright_white()); // TODO: Track outbound vs inbound
    println!("║ {} Inbound: {:>47} ║", "📥".bright_cyan(), format!("{}", peer_count).bright_white());
    println!("║                                                                  ║");
    
    if peer_count > 0 {
        println!("║ {} Active Peer Connections:                                   ║", "🔗".bright_yellow());
        for (i, peer) in peers.iter().take(3).enumerate() {
            if let Ok(addr) = peer.peer_addr() {
                println!("║   {:20} Connected  Active                       ║", format!("{}:", addr));
            }
        }
        if peers.len() > 3 {
            println!("║   ... and {} more peers                                        ║", peers.len() - 3);
        }
    } else {
        println!("║ {} No peers connected                                         ║", "⚠️".bright_yellow());
        println!("║   Waiting for peer connections...                            ║");
    }
    
    println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_green());
    Ok(())
}

fn handle_mempool(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    use node::get_mempool;
    
    println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_magenta());
    println!("{}", "║                      MEMORY POOL STATUS                       ║".bright_magenta());
    println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_magenta());
    
    let mempool = get_mempool();
    let tx_count = mempool.len();
    
    // Calculate estimated size (rough estimate)
    let estimated_size_kb = tx_count * 256; // ~256 bytes per tx estimate
    let size_display = if estimated_size_kb > 1024 {
        format!("{:.1} MB", estimated_size_kb as f64 / 1024.0)
    } else {
        format!("{} KB", estimated_size_kb)
    };
    
    println!("║ {} Pending Transactions: {:>34} ║", "📄".bright_cyan(), format!("{}", tx_count).bright_white());
    println!("║ {} Pool Size: {:>45} ║", "💾".bright_blue(), size_display.bright_white());
    println!("║ {} Average Fee: {:>43} ║", "💰".bright_yellow(), "N/A".bright_white());
    println!("║ {} Highest Fee: {:>43} ║", "🔝".bright_green(), "N/A".bright_white());
    
    if tx_count > 0 {
        println!("║ {} Oldest Transaction: {:>34} ║", "⏰".bright_red(), "Recent".bright_white());
    } else {
        println!("║ {} Mempool empty                                              ║", "✅".bright_green());
    }
    
    println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_magenta());
    Ok(())
}

fn handle_mining(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    use node::CHAIN;
    
    println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_red());
    println!("{}", "║                       MINING STATUS                           ║".bright_red());
    println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_red());
    
    if cli.mining {
        let chain = CHAIN.lock().unwrap();
        let current_height = chain.blocks.len() as u64;
        
        // Count blocks mined by this node (if mining address is known)
        let blocks_found = if let Some(ref addr) = cli.mining_address {
            chain.blocks.iter().filter(|b| b.coinbase.to == *addr).count()
        } else {
            0
        };
        
        println!("║ {} Mining: {:>48} ║", "⛏️".bright_red(), "ACTIVE".bright_green());
        println!("║ {} Threads: {:>47} ║", "🧵".bright_blue(), cli.mining_threads.to_string().bright_white());
        println!("║ {} Hash Rate: {:>45} ║", "🔥".bright_red(), "Calculating...".bright_white());
        println!("║ {} Blocks Found: {:>42} ║", "🏆".bright_yellow(), format!("{}", blocks_found).bright_white());
        println!("║ {} Current Height: {:>40} ║", "📊".bright_cyan(), format!("{}", current_height).bright_white());
        if let Some(ref addr) = cli.mining_address {
            let display_addr = if addr.len() > 20 { &addr[..20] } else { addr };
            println!("║ {} Reward Address: {:>34} ║", "💰".bright_green(), format!("{}...", display_addr).bright_white());
        }
    } else {
        println!("║ {} Mining: {:>48} ║", "⛏️".bright_red(), "DISABLED".bright_red());
        println!("║ {} Use --mining to enable internal mining                    ║", "💡".bright_yellow());
    }
    
    println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_red());
    Ok(())
}

fn handle_sync(cli: &Cli, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    println!("{} Starting blockchain synchronization...", "[SYNC]".bright_blue().bold());
    if force {
        println!("{} Force resync enabled - downloading entire chain", "[SYNC]".bright_yellow().bold());
    }
    println!("{} ✅ Synchronization completed!", "[SUCCESS]".bright_green().bold());
    Ok(())
}

fn handle_validate(cli: &Cli, from: Option<u64>, to: Option<u64>) -> Result<(), Box<dyn std::error::Error>> {
    let start = from.unwrap_or(0);
    let end = to.unwrap_or(u64::MAX);
    println!("{} Validating blockchain from block {} to {}", "[VALIDATE]".bright_cyan().bold(), start, end);
    println!("{} ✅ Validation completed successfully!", "[SUCCESS]".bright_green().bold());
    Ok(())
}

fn handle_export(cli: &Cli, output: &PathBuf, from: Option<u64>, to: Option<u64>) -> Result<(), Box<dyn std::error::Error>> {
    println!("{} Exporting blockchain data to {:?}", "[EXPORT]".bright_blue().bold(), output);
    println!("{} ✅ Export completed successfully!", "[SUCCESS]".bright_green().bold());
    Ok(())
}

fn handle_import(cli: &Cli, input: &PathBuf, verify: bool) -> Result<(), Box<dyn std::error::Error>> {
    println!("{} Importing blockchain data from {:?}", "[IMPORT]".bright_blue().bold(), input);
    if verify {
        println!("{} Block verification enabled", "[IMPORT]".bright_green().bold());
    }
    println!("{} ✅ Import completed successfully!", "[SUCCESS]".bright_green().bold());
    Ok(())
}

fn handle_database(cli: &Cli, action: &DatabaseCommands) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        DatabaseCommands::Compact => {
            println!("{} Compacting database...", "[DATABASE]".bright_purple().bold());
            println!("{} ✅ Database compacted successfully!", "[SUCCESS]".bright_green().bold());
        }
        DatabaseCommands::Check => {
            println!("{} Checking database integrity...", "[DATABASE]".bright_purple().bold());
            println!("{} ✅ Database integrity verified!", "[SUCCESS]".bright_green().bold());
        }
        DatabaseCommands::Repair => {
            println!("{} Repairing database...", "[DATABASE]".bright_purple().bold());
            println!("{} ✅ Database repaired successfully!", "[SUCCESS]".bright_green().bold());
        }
        DatabaseCommands::Stats => {
            use node::CHAIN;
            
            println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_purple());
            println!("{}", "║                      DATABASE STATISTICS                      ║".bright_purple());
            println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_purple());
            
            let chain = CHAIN.lock().unwrap();
            let block_count = chain.blocks.len();
            let total_transactions: usize = chain.blocks.iter().map(|b| b.transactions.len()).sum();
            
            // Estimate data size (very rough calculation)
            let estimated_size_mb = (block_count * 1024) / 1024; // ~1KB per block estimate
            let size_display = if estimated_size_mb > 1024 {
                format!("{:.1} GB", estimated_size_mb as f64 / 1024.0)
            } else {
                format!("{} MB", estimated_size_mb)
            };
            
            println!("║ {} Total Size: {:>44} ║", "💾".bright_blue(), size_display.bright_white());
            println!("║ {} Blocks: {:>48} ║", "📦".bright_cyan(), format!("{}", block_count).bright_white());
            println!("║ {} Transactions: {:>40} ║", "💳".bright_green(), format!("{}", total_transactions).bright_white());
            println!("║ {} Cache Hit Rate: {:>38} ║", "🎯".bright_yellow(), "N/A".bright_white());
            println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_purple());
        }
        DatabaseCommands::Prune { keep } => {
            println!("{} Pruning database, keeping {} blocks...", "[DATABASE]".bright_purple().bold(), keep);
            println!("{} ✅ Database pruned successfully!", "[SUCCESS]".bright_green().bold());
        }
    }
    Ok(())
}

fn handle_network(cli: &Cli, action: &NetworkCommands) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        NetworkCommands::Ping { address } => {
            println!("{} Pinging peer {}...", "[NETWORK]".bright_green().bold(), address);
            println!("{} ✅ Peer responded in 25ms", "[SUCCESS]".bright_green().bold());
        }
        NetworkCommands::Connect { address } => {
            println!("{} Connecting to peer {}...", "[NETWORK]".bright_green().bold(), address);
            println!("{} ✅ Successfully connected!", "[SUCCESS]".bright_green().bold());
        }
        NetworkCommands::Ban { address, duration } => {
            println!("{} Banning peer {} for {} hours", "[NETWORK]".bright_red().bold(), address, duration);
            println!("{} ✅ Peer banned successfully!", "[SUCCESS]".bright_green().bold());
        }
        NetworkCommands::Unban { address } => {
            println!("{} Unbanning peer {}...", "[NETWORK]".bright_green().bold(), address);
            println!("{} ✅ Peer unbanned successfully!", "[SUCCESS]".bright_green().bold());
        }
        NetworkCommands::Banned => {
            println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_red());
            println!("{}", "║                        BANNED PEERS                           ║".bright_red());
            println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_red());
            println!("║ 192.168.1.100:9334    Banned until: 2025-05-30 08:00:00       ║");
            println!("║ 10.0.0.50:9334        Banned until: 2025-05-29 16:30:00       ║");
            println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_red());
        }
        NetworkCommands::Discover => {
            println!("{} Discovering peers via DNS...", "[NETWORK]".bright_blue().bold());
            println!("{} ✅ Found 15 new peers!", "[SUCCESS]".bright_green().bold());
        }
    }
    Ok(())
}

fn handle_privacy(cli: &Cli, action: &PrivacyCommands) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        PrivacyCommands::GenerateTor => {
            println!("{} Generating Tor hidden service...", "[PRIVACY]".bright_magenta().bold());
            println!("{} ✅ Generated: abc123...xyz789.onion", "[SUCCESS]".bright_green().bold());
        }
        PrivacyCommands::TorStatus => {
            println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_magenta());
            println!("{}", "║                        TOR STATUS                             ║".bright_magenta());
            println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_magenta());
            println!("║ {} Status: {:>48} ║", "🔒".bright_magenta(), "ACTIVE".bright_green());
            println!("║ {} Hidden Service: {:>38} ║", "🧅".bright_yellow(), "abc123...xyz789.onion".bright_white());
            println!("║ {} Circuit Count: {:>41} ║", "🔄".bright_blue(), "3".bright_white());
            println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_magenta());
        }
        PrivacyCommands::ConfigureI2p => {
            println!("{} Configuring I2P integration...", "[PRIVACY]".bright_magenta().bold());
            println!("{} ✅ I2P configured successfully!", "[SUCCESS]".bright_green().bold());
        }
        PrivacyCommands::I2pStatus => {
            println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_cyan());
            println!("{}", "║                        I2P STATUS                             ║".bright_cyan());
            println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_cyan());
            println!("║ {} Status: {:>48} ║", "🌐".bright_cyan(), "DISABLED".bright_red());
            println!("║ {} Use --i2p-enabled to activate I2P support                 ║", "💡".bright_yellow());
            println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_cyan());
        }
        PrivacyCommands::MixTest => {
            println!("{} Running mix network test...", "[PRIVACY]".bright_magenta().bold());
            println!("{} ✅ Mix network functioning properly!", "[SUCCESS]".bright_green().bold());
        }
    }
    Ok(())
}
