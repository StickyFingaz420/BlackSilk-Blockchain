//! `blacksilk-wallet`: command-line wallet.
//!
//! The password is read from the terminal, or from `BLACKSILK_WALLET_PASSWORD`
//! for automation. An environment variable is visible to other processes of the
//! same user, so use it only in controlled environments.

#![forbid(unsafe_code)]

use blacksilk_chain::address::{decode_address, decode_px_address};
use blacksilk_chain::emission::{format_amount, parse_amount};
use blacksilk_px::vault;
use blacksilk_px_core::Digest;
use blacksilk_rpc::Client;
use blacksilk_tx::params::TxRules;
use blacksilk_tx::px::Registration;
use blacksilk_wallet::file::KdfParams;
use blacksilk_wallet::px::{digest_from_hex, digest_hex, RecordSource};
use blacksilk_wallet::wallet::{network_name, parse_network};
use blacksilk_wallet::{load, save, Wallet, WalletError};
use blacksilk_zkvm::air::trace::Budget;
use clap::{Parser, Subcommand};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};

#[derive(Parser)]
#[command(name = "blacksilk-wallet", version, about = "BlackSilk wallet")]
struct Args {
    /// Wallet file.
    #[arg(long, short)]
    wallet: PathBuf,
    /// Node RPC address: host:port or http://host:port. Plain HTTP only
    /// (https:// is refused); use your own node, or reach a remote one over an
    /// SSH tunnel, a VPN or Tor. Proxy environment variables are ignored.
    #[arg(long, default_value = "127.0.0.1:29333")]
    node: String,
    /// The node's RPC cookie: `rpc.cookie` in the node's data directory
    /// (docs/blocks.md §9.1). Default: the file named by
    /// BLACKSILK_RPC_COOKIE, if set.
    #[arg(long)]
    rpc_cookie: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new wallet (prints the 27-word seed once; write it down).
    Create {
        #[arg(long, default_value = "testnet")]
        network: String,
        /// The chain height now, recorded in the seed as its birthday
        /// (restore scans from there). Default: the node's height; without a
        /// reachable node this option is required. A lower value only makes
        /// a restore scan longer; a higher one makes it miss funds.
        #[arg(long)]
        birthday_height: Option<u64>,
    },
    /// Restore a wallet from its 27-word seed (docs/blocks.md §10).
    Restore {
        /// The seed's network, checked against the words. Default: the
        /// network the words name.
        #[arg(long)]
        network: Option<String>,
        /// First block to scan. Default: the start of the seed's birthday
        /// epoch.
        #[arg(long)]
        restore_height: Option<u64>,
    },
    /// Show an address (a fresh subaddress per counterparty is recommended).
    Address {
        #[arg(long, default_value_t = 0)]
        account: u32,
        #[arg(long, default_value_t = 0)]
        index: u32,
        /// Allow an index more than 1,000 beyond the highest one that has
        /// received funds (up to 10,000). Every index up to it is derived at
        /// every load and scanned for.
        #[arg(long)]
        force: bool,
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
    /// Show a private (PX) address.
    PxAddress {
        #[arg(long, default_value_t = 0)]
        index: u32,
        /// Allow an index more than 1,000 beyond the highest PX address that
        /// has received a record (up to 2,000). Every scanned PX address
        /// costs time for every PX output on chain.
        #[arg(long)]
        force: bool,
    },
    /// Sync and show the private (PX) balance.
    PxBalance,
    /// Move BLK from the v1 (ring-signature) wallet into PX. The deposited
    /// amount is public.
    PxDeposit {
        #[arg(long)]
        amount: String,
    },
    /// Pay a PX address privately (proving takes about a minute).
    PxSend {
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: String,
    },
    /// Move BLK out of PX to a v1 address. The withdrawn amount is public.
    PxWithdraw {
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: String,
    },
    /// Register a private contract, paid with v1 funds (the deployer stays
    /// hidden behind ring signatures). Its programs are public.
    PxDeploy {
        /// Register the reference hash-locked vault (px/vault.elf), a
        /// demonstration contract: no timeout, no refund, not trustless. It
        /// is deployed alone: any other program of the same contract could
        /// spend the vault's records without the secret.
        #[arg(long, conflicts_with_all = ["program", "budget"])]
        vault: bool,
        /// A function program (RISC-V ELF); repeat for several.
        #[arg(long)]
        program: Vec<PathBuf>,
        /// Its row budget, one per --program:
        /// cycles,keys,add,bit,lt,shift,mul,poseidon.
        #[arg(long)]
        budget: Vec<String>,
    },
    /// List the private contracts deployed on chain.
    PxContracts,
    /// List the contract records this wallet holds.
    PxRecords,
    /// Lock PX funds in a record of the DEMONSTRATION vault under a secret.
    /// Not a trustless swap: no timeout, no refund, and you (the locker) also
    /// know the secret, so you can claim too (docs/px.md §13.4).
    PxVaultLock {
        /// The vault contract id.
        #[arg(long)]
        contract: String,
        #[arg(long)]
        amount: String,
        /// The secret, 64 hex characters. RISKY: a command-line argument is
        /// kept in shell history and visible to other local users in the
        /// process list; prefer --secret-file or --secret-prompt. Without any
        /// of the three, the wallet derives the secret from its keys and the
        /// vault record (recoverable from the seed; docs/px.md §13.4).
        #[arg(long, conflicts_with_all = ["secret_file", "secret_prompt"])]
        secret: Option<String>,
        /// Read the secret (64 hex characters) from this file.
        #[arg(long, conflicts_with = "secret_prompt")]
        secret_file: Option<PathBuf>,
        /// Ask for the secret on the terminal (not echoed).
        #[arg(long)]
        secret_prompt: bool,
        /// Write a derived secret to this new file (owner-only on Unix)
        /// instead of printing it.
        #[arg(long, conflicts_with_all = ["secret", "secret_file", "secret_prompt"])]
        secret_out: Option<PathBuf>,
        /// PX address of the party that will claim: the record is delivered
        /// to it. Default: this wallet (it keeps a copy either way).
        #[arg(long)]
        deliver_to: Option<String>,
    },
    /// Claim a record of the demonstration vault with its secret, paying its
    /// value privately. The secret is asked for on the terminal unless
    /// --secret-file or --secret is given.
    PxVaultClaim {
        /// The vault record's commitment (from px-records).
        #[arg(long)]
        record: String,
        /// The secret, 64 hex characters. RISKY: kept in shell history and
        /// visible in the process list; prefer --secret-file or the prompt.
        #[arg(long, conflicts_with = "secret_file")]
        secret: Option<String>,
        /// Read the secret (64 hex characters) from this file.
        #[arg(long)]
        secret_file: Option<PathBuf>,
        /// PX address to pay. Default: this wallet.
        #[arg(long)]
        to: Option<String>,
    },
    /// Show the secret of a vault record this wallet locked (stored in the
    /// wallet file before the lock was sent).
    PxVaultSecret {
        /// The vault record's commitment (from px-records).
        #[arg(long)]
        record: String,
        /// Write it to this new file (owner-only on Unix) instead of
        /// printing it.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Share a contract record with a PX address (prints the sealed share).
    PxShare {
        #[arg(long)]
        record: String,
        #[arg(long)]
        to: String,
    },
    /// Import a contract record shared with this wallet.
    PxImport {
        #[arg(long)]
        share: String,
    },
    /// Show the 27-word seed.
    Seed,
    /// Forget unconfirmed spends and stored transactions. Meant for a
    /// transaction that certainly never left this wallet: `sync` rebroadcasts
    /// stored transactions and releases their funds itself when the node
    /// finds them invalid. A new spend of the same funds reuses the old rings,
    /// but it shares their key images, so the two spends are linkable.
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

/// The build commit, from the `BLACKSILK_BUILD_COMMIT` build-time environment
/// variable. Unlike the node (node/build.rs reads `.git`), this crate has no
/// build script, so a build without the variable reports `unknown`; the
/// release procedure sets it (docs/testnet.md, operator checks).
const BUILD_COMMIT: &str = match option_env!("BLACKSILK_BUILD_COMMIT") {
    Some(c) => c,
    None => "unknown",
};

/// Parses the command line with a `--version` that includes the commit.
fn parse_args() -> Args {
    use clap::{CommandFactory, FromArgMatches};
    // clap takes a `'static` string; this runs once per process.
    let version: &'static str = Box::leak(
        format!("{} (commit {BUILD_COMMIT})", env!("CARGO_PKG_VERSION")).into_boxed_str(),
    );
    let matches = Args::command().version(version).get_matches();
    Args::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())
}

fn main() {
    if let Err(e) = run(parse_args()) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// A ChaCha20 RNG seeded from the OS.
fn os_rng() -> Result<ChaCha20Rng, String> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("OS RNG: {e}"))?;
    let rng = ChaCha20Rng::from_seed(seed);
    seed.zeroize();
    Ok(rng)
}

/// Rules of the wallet's network. The wallet builds every transaction with
/// the rules of the block after its synced height (`Wallet::next_block_rules`,
/// after the sync each command starts with), so the epoch of these does not
/// matter.
fn rules_for(w: &Wallet) -> TxRules {
    w.next_block_rules()
}

fn parse_budget(s: &str) -> Result<Budget, String> {
    let v: Vec<usize> = s
        .split(',')
        .map(|x| x.trim().parse::<usize>())
        .collect::<Result<_, _>>()
        .map_err(|_| format!("budget {s:?}: eight comma-separated numbers"))?;
    let [cycles, keys, add, bit, lt, shift, mul, poseidon]: [usize; 8] = v
        .try_into()
        .map_err(|_| format!("budget {s:?}: eight comma-separated numbers"))?;
    Ok(Budget {
        cycles,
        keys,
        add,
        bit,
        lt,
        shift,
        mul,
        poseidon,
    })
}

/// A digest from hex. The error never echoes the input (it may be a secret).
fn digest_arg(what: &str, s: &str) -> Result<Digest, String> {
    digest_from_hex(s.trim()).map_err(|e| format!("{what}: {e}"))
}

/// A vault secret from, in order: the command line (risky: shell history and
/// the process list), a file, or a hidden prompt. `None` if none is asked for.
/// Copies held by this function are wiped; clap's copy of a command-line
/// argument cannot be.
fn read_secret(
    arg: Option<String>,
    file: Option<PathBuf>,
    prompt: bool,
) -> Result<Option<Digest>, String> {
    let text: Zeroizing<String> = if let Some(s) = arg {
        eprintln!("warning: a secret given with --secret stays in shell history and is visible in the process list; prefer --secret-file or the prompt.");
        Zeroizing::new(s)
    } else if let Some(path) = file {
        Zeroizing::new(
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?,
        )
    } else if prompt {
        Zeroizing::new(
            rpassword::prompt_password("Vault secret (64 hex characters): ")
                .map_err(|e| e.to_string())?,
        )
    } else {
        return Ok(None);
    };
    digest_arg("secret", &text).map(Some)
}

/// Writes a vault secret (hex) to `path`, a new file, owner-only on Unix.
fn write_secret_file(path: &std::path::Path, secret: &Digest) -> Result<(), String> {
    use std::io::Write;
    let hex = Zeroizing::new(digest_hex(secret));
    blacksilk_wallet::file::create_private(path)
        .and_then(|mut f| {
            f.write_all(hex.as_bytes())?;
            f.sync_all()
        })
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// An exclusive lock on `<wallet>.lock`, held for the whole command, so two
/// processes never work on one wallet file (review F8). Owner-only on Unix.
fn lock_wallet(path: &std::path::Path) -> Result<std::fs::File, String> {
    let lock_path = path.with_extension("lock");
    let f = blacksilk_wallet::file::open_private(&lock_path, false)
        .map_err(|e| format!("{}: {e}", lock_path.display()))?;
    f.try_lock()
        .map_err(|_| format!("{} is in use by another wallet process", path.display()))?;
    Ok(f)
}

fn run(args: Args) -> Result<(), String> {
    let client = Client::try_new(&args.node)
        .and_then(|c| c.with_cookie_option(args.rpc_cookie.as_deref()))
        .map_err(|e| e.to_string())?;
    let _lock = lock_wallet(&args.wallet)?;
    let kdf = KdfParams::default();
    match args.cmd {
        Cmd::Create {
            network,
            birthday_height,
        } => {
            let net = parse_network(&network).ok_or("unknown network")?;
            if args.wallet.exists() {
                return Err(format!("{} already exists", args.wallet.display()));
            }
            // The chain height now: the seed's birthday, and where scanning
            // starts. Never guessed: a wrong birthday makes a restore miss
            // funds (review W-F15).
            let height = match birthday_height {
                Some(h) => h,
                None => client.info().map(|i| i.height).map_err(|e| {
                    format!(
                        "cannot read the chain height from the node ({e}); it becomes the \
                         seed's birthday. Start the node, or give --birthday-height with the \
                         current height (lower is safe, higher misses funds)"
                    )
                })?,
            };
            let start = height + 1;
            let mut pw = password(true)?;
            let mut w = Wallet::generate(net, start).map_err(|e| e.to_string())?;
            let primary = w.address(0, 0);
            save(&w, &args.wallet, &pw, kdf).map_err(|e| e.to_string())?;
            pw.zeroize();
            println!(
                "Wallet created ({}). Write down these 27 words; they are the only backup of \
                 the keys:\n",
                network_name(net)
            );
            println!("{}\n", w.mnemonic().as_str());
            println!("Primary address: {primary}");
        }
        Cmd::Restore {
            network,
            restore_height,
        } => {
            let net = network
                .map(|n| parse_network(&n).ok_or("unknown network"))
                .transpose()?;
            if args.wallet.exists() {
                return Err(format!("{} already exists", args.wallet.display()));
            }
            let mut words =
                rpassword::prompt_password("27-word seed: ").map_err(|e| e.to_string())?;
            let w = Wallet::restore(&words, net, restore_height).map_err(|e| e.to_string());
            words.zeroize();
            let w = w?;
            let mut pw = password(true)?;
            save(&w, &args.wallet, &pw, kdf).map_err(|e| e.to_string())?;
            pw.zeroize();
            println!(
                "Wallet restored ({}); run `sync` to scan from block {}.",
                network_name(w.network()),
                w.synced_height() + 1
            );
        }
        cmd => {
            let mut pw = password(false)?;
            let mut w = load(&args.wallet, &pw)?;
            for warning in w.take_warnings() {
                eprintln!("warning: {warning}");
            }
            // Save before any transaction leaves the wallet (review F1).
            w.set_autosave(&args.wallet, &pw, kdf);
            let result = match cmd {
                Cmd::Address {
                    account,
                    index,
                    force,
                } => w
                    .try_address(account, index, force)
                    .map_err(|e| e.to_string())
                    .map(|a| {
                        if !w.found_by_restore(account, index) {
                            eprintln!("note: a wallet restored from the seed scans account 0 only, and only {} subaddresses beyond the highest one that has received funds; it will not find payments to this address by itself. Keep the wallet file backed up.", blacksilk_wallet::wallet::LOOKAHEAD);
                        }
                        println!("{a}");
                    }),
                Cmd::Sync => w
                    .sync(&client)
                    .map(|h| {
                        println!("synced to height {h}");
                        // Payments an upgrade invalidated before they were
                        // mined (their funds are released).
                        for t in w.stale_transactions() {
                            println!(
                                "needs rebuilding: transaction {} (built for branch {:#010x}, \
                                 dropped at height {}); send the payment again",
                                t.id, t.built_for, t.height
                            );
                        }
                    })
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
                        "submitted {} BLK, fee {} BLK",
                        format_amount(amount),
                        format_amount(fee)
                    );
                    println!("transaction {}", hex::encode(id));
                    Ok(())
                })(),
                Cmd::PxAddress { index, force } => w
                    .try_px_address(index, force)
                    .map_err(|e| e.to_string())
                    .map(|a| {
                        if !w.px_found_by_restore(index) {
                            eprintln!("note: a wallet restored from the seed scans only {} PX addresses beyond the highest one that has received a record; it will not find records sent to this address by itself. Keep the wallet file backed up.", blacksilk_wallet::px::PX_LOOKAHEAD);
                        }
                        println!("{a}");
                    }),
                Cmd::PxBalance => w.sync(&client).map_err(|e| e.to_string()).map(|h| {
                    let (total, spendable) = w.px_balance();
                    println!("height {h}");
                    println!("private balance:  {} BLK", format_amount(total));
                    println!("spendable:        {} BLK", format_amount(spendable));
                }),
                Cmd::PxDeposit { amount } => (|| {
                    let amount = parse_amount(&amount).ok_or("amount: use a number like 1.5")?;
                    let mut rng = os_rng()?;
                    let rules = rules_for(&w);
                    eprintln!("note: deposit and withdrawal amounts are public; prefer round amounts and do not withdraw the amount you deposited (docs/px.md §12).");
                    println!("proving (about a minute)...");
                    let (id, fee) = w
                        .px_deposit(&client, amount, &rules, &mut rng)
                        .map_err(|e| e.to_string())?;
                    println!(
                        "deposited {} BLK, fee {} BLK",
                        format_amount(amount),
                        format_amount(fee)
                    );
                    println!("transaction {}", hex::encode(id));
                    Ok(())
                })(),
                Cmd::PxSend { to, amount } => (|| {
                    let dest = decode_px_address(w.network(), &to)
                        .map_err(|e| format!("PX address: {e:?}"))?;
                    let amount = parse_amount(&amount).ok_or("amount: use a number like 1.5")?;
                    let mut rng = os_rng()?;
                    let rules = rules_for(&w);
                    println!("proving (about a minute)...");
                    let (id, fee) = w
                        .px_send(&client, &dest, amount, &rules, &mut rng)
                        .map_err(|e| e.to_string())?;
                    println!(
                        "submitted {} BLK privately, fee {} BLK",
                        format_amount(amount),
                        format_amount(fee)
                    );
                    println!("transaction {}", hex::encode(id));
                    Ok(())
                })(),
                Cmd::PxWithdraw { to, amount } => (|| {
                    let dest =
                        decode_address(w.network(), &to).map_err(|e| format!("address: {e:?}"))?;
                    let amount = parse_amount(&amount).ok_or("amount: use a number like 1.5")?;
                    let mut rng = os_rng()?;
                    let rules = rules_for(&w);
                    eprintln!("note: withdrawal amounts are public; prefer round amounts and wait between deposits and withdrawals (docs/px.md §12).");
                    println!("proving (about a minute)...");
                    let (id, fee) = w
                        .px_withdraw(&client, &dest, amount, &rules, &mut rng)
                        .map_err(|e| e.to_string())?;
                    println!(
                        "withdrew {} BLK, fee {} BLK",
                        format_amount(amount),
                        format_amount(fee)
                    );
                    println!("transaction {}", hex::encode(id));
                    Ok(())
                })(),
                Cmd::PxDeploy {
                    vault: with_vault,
                    program,
                    budget,
                } => (|| {
                    if program.len() != budget.len() {
                        return Err("give one --budget per --program".to_string());
                    }
                    let mut programs = Vec::new();
                    if with_vault {
                        programs.push(Registration {
                            elf: vault::VAULT_ELF.to_vec(),
                            budget: vault::BUDGET,
                        });
                    }
                    for (path, b) in program.iter().zip(&budget) {
                        let elf =
                            std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
                        programs.push(Registration {
                            elf,
                            budget: parse_budget(b)?,
                        });
                    }
                    if programs.is_empty() {
                        return Err("nothing to deploy: use --vault or --program".into());
                    }
                    let mut rng = os_rng()?;
                    let rules = rules_for(&w);
                    let (id, contract, fee) = w
                        .px_deploy(&client, programs, &rules, &mut rng)
                        .map_err(|e| e.to_string())?;
                    println!("contract {}", digest_hex(&contract));
                    println!("fee {} BLK", format_amount(fee));
                    println!("transaction {}", hex::encode(id));
                    println!("usable from the block after it confirms");
                    Ok(())
                })(),
                Cmd::PxContracts => w.sync(&client).map_err(|e| e.to_string()).map(|_| {
                    let vault_id = hex::encode(vault::program().id());
                    for c in w.px_contracts() {
                        println!("contract {} (height {})", c.id, c.height);
                        for p in &c.programs {
                            let tag = if p.id == vault_id { " (vault)" } else { "" };
                            println!("  program {}{tag}", p.id);
                        }
                        // A contract's trust boundary is its whole program
                        // set (docs/px.md §13.4).
                        if c.programs.iter().any(|p| p.id == vault_id) {
                            if let Err(e) = blacksilk_wallet::px::vault_check(c) {
                                println!("  WARNING: not usable as a vault: {e}");
                            }
                        }
                    }
                }),
                Cmd::PxRecords => w.sync(&client).map_err(|e| e.to_string()).map(|_| {
                    for r in w.px_contract_records() {
                        let status = match (r.height, r.spent_height, r.pending) {
                            (_, Some(h), _) => format!("spent at {h}"),
                            (_, None, true) => "claim pending".to_string(),
                            (None, None, false) => "unconfirmed".to_string(),
                            (Some(h), None, false) => format!("confirmed at {h}"),
                        };
                        let source = match r.source {
                            RecordSource::Received { index } => {
                                format!("received at PX address {index}")
                            }
                            RecordSource::Created => "created here".to_string(),
                            RecordSource::Imported => "imported".to_string(),
                        };
                        let secret = if r.secret.is_some() {
                            " (secret stored: px-vault-secret)"
                        } else {
                            ""
                        };
                        println!(
                            "record {}\n  contract {}\n  value {} BLK, {status}, {source}{secret}",
                            r.commitment,
                            r.contract,
                            format_amount(r.value)
                        );
                    }
                }),
                Cmd::PxVaultLock {
                    contract,
                    amount,
                    secret,
                    secret_file,
                    secret_prompt,
                    secret_out,
                    deliver_to,
                } => (|| {
                    let contract = digest_arg("contract", &contract)?;
                    let amount = parse_amount(&amount).ok_or("amount: use a number like 1.5")?;
                    let mut rng = os_rng()?;
                    // `None`: the wallet derives the secret; it is stored in
                    // the wallet file before anything is sent and can be
                    // re-derived from the seed (docs/px.md §13.4).
                    let given = read_secret(secret, secret_file, secret_prompt)?.map(Zeroizing::new);
                    let derived = given.is_none();
                    let to = deliver_to
                        .map(|a| {
                            decode_px_address(w.network(), &a)
                                .map_err(|e| format!("PX address: {e:?}"))
                        })
                        .transpose()?;
                    let rules = rules_for(&w);
                    eprintln!("warning: the vault is a DEMONSTRATION contract, not a trustless swap: no timeout, no refund, and you (the locker) also know the secret. Whoever learns the secret and the record can claim it (docs/px.md §13.4).");
                    eprintln!("note: if you deliver the record to someone else, your own copy lives only in this wallet file; restoring from the seed will not recover it.");
                    println!("proving (about a minute)...");
                    let (id, record) = match w.px_vault_lock(
                        &client,
                        &contract,
                        amount,
                        given.as_deref(),
                        to.as_ref(),
                        &rules,
                        &mut rng,
                    ) {
                        Ok(r) => r,
                        Err(e @ WalletError::Uncertain(_)) => {
                            // The lock may still be mined: the secret must not
                            // be lost (review R11-W1). The wallet file holds
                            // it, saved before sending.
                            eprintln!("note: the secret is stored in the wallet file; `px-records` lists the record and `px-vault-secret --record <commitment>` shows its secret.");
                            return Err(e.to_string());
                        }
                        Err(e) => return Err(e.to_string()),
                    };
                    if derived {
                        let secret = w.px_vault_secret(&record).map_err(|e| e.to_string())?;
                        match &secret_out {
                            Some(path) => {
                                write_secret_file(path, &secret)?;
                                println!("secret written to {}", path.display());
                            }
                            None => println!(
                                "secret {}",
                                Zeroizing::new(digest_hex(&secret)).as_str()
                            ),
                        }
                    }
                    println!("record {}", digest_hex(&record));
                    println!("transaction {}", hex::encode(id));
                    Ok(())
                })(),
                Cmd::PxVaultClaim {
                    record,
                    secret,
                    secret_file,
                    to,
                } => (|| {
                    let record = digest_arg("record", &record)?;
                    let secret = Zeroizing::new(
                        read_secret(secret, secret_file, true)?.expect("the prompt is the default"),
                    );
                    let to = to
                        .map(|a| {
                            decode_px_address(w.network(), &a)
                                .map_err(|e| format!("PX address: {e:?}"))
                        })
                        .transpose()?;
                    let mut rng = os_rng()?;
                    let rules = rules_for(&w);
                    println!("proving (about a minute)...");
                    let (id, value) = w
                        .px_vault_claim(&client, &record, &secret, to.as_ref(), &rules, &mut rng)
                        .map_err(|e| e.to_string())?;
                    println!("claimed {} BLK privately", format_amount(value));
                    println!("transaction {}", hex::encode(id));
                    Ok(())
                })(),
                Cmd::PxVaultSecret { record, out } => (|| {
                    let record = digest_arg("record", &record)?;
                    let secret = w.px_vault_secret(&record).map_err(|e| e.to_string())?;
                    match out {
                        Some(path) => {
                            write_secret_file(&path, &secret)?;
                            println!("secret written to {}", path.display());
                        }
                        None => println!("{}", Zeroizing::new(digest_hex(&secret)).as_str()),
                    }
                    Ok(())
                })(),
                Cmd::PxShare { record, to } => (|| {
                    let record = digest_arg("record", &record)?;
                    let to = decode_px_address(w.network(), &to)
                        .map_err(|e| format!("PX address: {e:?}"))?;
                    let mut rng = os_rng()?;
                    let shared = w
                        .px_share(&record, &to, &mut rng)
                        .map_err(|e| e.to_string())?;
                    eprintln!("note: the share reveals the record only to that address; send it over any channel.");
                    println!("{}", hex::encode(shared));
                    Ok(())
                })(),
                Cmd::PxImport { share } => (|| {
                    let bytes = hex::decode(share.trim()).map_err(|_| "share: not hex")?;
                    let cm = w.px_import(&bytes).map_err(|e| e.to_string())?;
                    w.sync(&client).map_err(|e| e.to_string())?;
                    println!("imported record {}", digest_hex(&cm));
                    Ok(())
                })(),
                Cmd::Seed => {
                    println!("{}", w.mnemonic().as_str());
                    Ok(())
                }
                Cmd::ClearPending => {
                    w.clear_pending();
                    Ok(())
                }
                Cmd::Create { .. } | Cmd::Restore { .. } => unreachable!(),
            };
            // Warnings raised by the command (e.g. co-spent outputs, R3-13).
            for warning in w.take_warnings() {
                eprintln!("warning: {warning}");
            }
            // Persist whatever was learned (sync progress, pending spends), even on error.
            save(&w, &args.wallet, &pw, kdf).map_err(|e| e.to_string())?;
            pw.zeroize();
            result?;
        }
    }
    Ok(())
}
