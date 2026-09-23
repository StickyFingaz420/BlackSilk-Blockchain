//! `blacksilk-wallet`: command-line wallet.
//!
//! The password is read from the terminal, or from `BLACKSILK_WALLET_PASSWORD`
//! for automation. An environment variable is visible to other processes of the
//! same user, so use it only in controlled environments.

#![forbid(unsafe_code)]

use blacksilk_chain::address::decode_address;
use blacksilk_chain::emission::{format_amount, parse_amount};
use blacksilk_consensus::ChainParams;
use blacksilk_rpc::Client;
use blacksilk_tx::params::TxRules;
use blacksilk_wallet::file::KdfParams;
use blacksilk_wallet::wallet::{network_name, parse_network};
use blacksilk_wallet::{load, save, Wallet};
use clap::{Parser, Subcommand};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::path::PathBuf;
use zeroize::Zeroize;

#[derive(Parser)]
#[command(name = "blacksilk-wallet", version, about = "BlackSilk wallet")]
struct Args {
    /// Wallet file.
    #[arg(long, short)]
    wallet: PathBuf,
    /// Node RPC address.
    #[arg(long, default_value = "127.0.0.1:29333")]
    node: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new wallet (prints the 24-word seed once; write it down).
    Create {
        #[arg(long, default_value = "testnet")]
        network: String,
    },
    /// Restore a wallet from its 24-word seed.
    Restore {
        #[arg(long, default_value = "testnet")]
        network: String,
        /// First block to scan.
        #[arg(long, default_value_t = 1)]
        restore_height: u64,
    },
    /// Show an address (a fresh subaddress per counterparty is recommended).
    Address {
        #[arg(long, default_value_t = 0)]
        account: u32,
        #[arg(long, default_value_t = 0)]
        index: u32,
    },
    /// Scan new blocks.
    Sync,
    /// Sync and show the balance.
    Balance,
    /// Send BLK to an address (amount like 1.5).
    Transfer {
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: String,
    },
    /// Show the 24-word seed.
    Seed,
    /// Forget unconfirmed spends (after a transaction was dropped by the network).
    ClearPending,
}

fn password(confirm: bool) -> Result<Vec<u8>, String> {
    if let Ok(p) = std::env::var("BLACKSILK_WALLET_PASSWORD") {
        return Ok(p.into_bytes());
    }
    let p = rpassword::prompt_password("Wallet password: ").map_err(|e| e.to_string())?;
    if confirm {
        let mut q = rpassword::prompt_password("Repeat password: ").map_err(|e| e.to_string())?;
        let same = p == q;
        q.zeroize();
        if !same {
            return Err("passwords differ".into());
        }
    }
    Ok(p.into_bytes())
}

fn main() {
    if let Err(e) = run(Args::parse()) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn rules_for(w: &Wallet) -> TxRules {
    let params = match w.network() {
        blacksilk_consensus::Network::Mainnet => ChainParams::mainnet(),
        blacksilk_consensus::Network::Testnet => ChainParams::testnet(),
        blacksilk_consensus::Network::Regtest => ChainParams::regtest(),
    };
    TxRules::for_chain(&params)
}

fn run(args: Args) -> Result<(), String> {
    let client = Client::new(&args.node);
    let kdf = KdfParams::default();
    match args.cmd {
        Cmd::Create { network } => {
            let net = parse_network(&network).ok_or("unknown network")?;
            if args.wallet.exists() {
                return Err(format!("{} already exists", args.wallet.display()));
            }
            // Start scanning at the current height when the node is reachable.
            let start = client.info().map(|i| i.height + 1).unwrap_or(1);
            let mut pw = password(true)?;
            let mut w = Wallet::generate(net, start).map_err(|e| e.to_string())?;
            let primary = w.address(0, 0);
            save(&w, &args.wallet, &pw, kdf).map_err(|e| e.to_string())?;
            pw.zeroize();
            println!(
                "Wallet created ({}). Write down these 24 words; they are the only backup:\n",
                network_name(net)
            );
            println!("{}\n", w.mnemonic());
            println!("Primary address: {primary}");
        }
        Cmd::Restore {
            network,
            restore_height,
        } => {
            let net = parse_network(&network).ok_or("unknown network")?;
            if args.wallet.exists() {
                return Err(format!("{} already exists", args.wallet.display()));
            }
            let mut words =
                rpassword::prompt_password("24-word seed: ").map_err(|e| e.to_string())?;
            let w = Wallet::from_mnemonic(net, &words, restore_height).map_err(|e| e.to_string());
            words.zeroize();
            let w = w?;
            let mut pw = password(true)?;
            save(&w, &args.wallet, &pw, kdf).map_err(|e| e.to_string())?;
            pw.zeroize();
            println!("Wallet restored; run `sync` to scan from block {restore_height}.");
        }
        cmd => {
            let mut pw = password(false)?;
            let mut w = load(&args.wallet, &pw)?;
            let result = match cmd {
                Cmd::Address { account, index } => {
                    println!("{}", w.address(account, index));
                    Ok(())
                }
                Cmd::Sync => w
                    .sync(&client)
                    .map(|h| println!("synced to height {h}"))
                    .map_err(|e| e.to_string()),
                Cmd::Balance => w.sync(&client).map_err(|e| e.to_string()).map(|h| {
                    let b = w.balance();
                    println!("height {h}");
                    println!("balance:  {} BLK", format_amount(b.total));
                    println!("unlocked: {} BLK", format_amount(b.unlocked));
                }),
                Cmd::Transfer { to, amount } => (|| {
                    let dest =
                        decode_address(w.network(), &to).map_err(|e| format!("address: {e:?}"))?;
                    let amount = parse_amount(&amount).ok_or("amount: use a number like 1.5")?;
                    let mut seed = [0u8; 32];
                    getrandom::getrandom(&mut seed).map_err(|e| format!("OS RNG: {e}"))?;
                    let mut rng = ChaCha20Rng::from_seed(seed);
                    seed.zeroize();
                    let rules = rules_for(&w);
                    let (id, fee) = w
                        .transfer(&client, &dest, amount, &rules, &mut rng)
                        .map_err(|e| e.to_string())?;
                    println!(
                        "sent {} BLK, fee {} BLK",
                        format_amount(amount),
                        format_amount(fee)
                    );
                    println!("transaction {}", hex::encode(id));
                    Ok(())
                })(),
                Cmd::Seed => {
                    println!("{}", w.mnemonic());
                    Ok(())
                }
                Cmd::ClearPending => {
                    w.clear_pending();
                    Ok(())
                }
                Cmd::Create { .. } | Cmd::Restore { .. } => unreachable!(),
            };
            // Persist whatever was learned (sync progress, pending spends), even on error.
            save(&w, &args.wallet, &pw, kdf).map_err(|e| e.to_string())?;
            pw.zeroize();
            result?;
        }
    }
    Ok(())
}
