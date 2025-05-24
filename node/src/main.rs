//! BlackSilk Node CLI Entry Point
//! This file provides the main entry point for the BlackSilk node binary, including comprehensive CLI argument parsing using `clap`.

use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use node::start_node_with_args;

#[derive(Parser, Debug)]
#[command(name = "blacksilk-node", version, about = "BlackSilk Privacy Node")]
pub struct Cli {
    /// Data directory for blockchain and node state
    #[arg(long, default_value = "./data", value_name = "DIR")]
    pub data_dir: PathBuf,

    /// Network port to listen on
    #[arg(short, long, default_value = "8333")]
    pub port: u16,

    /// Connect to a peer at address (can be specified multiple times)
    #[arg(long, value_name = "ADDR")]
    pub connect: Vec<String>,

    /// Network type (mainnet, testnet, regtest)
    #[arg(long, value_enum, default_value = "testnet")]
    pub network: NetworkArg,

    /// Logging verbosity (error, warn, info, debug, trace)
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Print version info and exit
    #[arg(long)]
    pub version: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum NetworkArg {
    Mainnet,
    Testnet,
    Regtest,
}

fn main() {
    let cli = Cli::parse();
    if cli.version {
        println!("BlackSilk Node version {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    // Set up logging here if needed
    // ...
    // Start node with provided arguments
    start_node_with_args(
        cli.port,
        cli.connect.get(0).cloned(), // Only pass the first connect address, or None
        Some(cli.data_dir),
        // You may need to convert NetworkArg to your internal Network type
    );
}
