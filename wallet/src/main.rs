//! `blacksilk-wallet`: command-line wallet.
//!
//! The password is read from the terminal, or from `BLACKSILK_WALLET_PASSWORD`
//! for automation. An environment variable is visible to other processes of the
//! same user, so use it only in controlled environments.

#![forbid(unsafe_code)]

use blacksilk_chain::address::{decode_address, decode_px_address};
use blacksilk_chain::emission::{format_amount, parse_amount};
use blacksilk_consensus::ChainParams;
use blacksilk_px::vault;
use blacksilk_px_core::Digest;
use blacksilk_rpc::Client;
use blacksilk_tx::params::TxRules;
use blacksilk_tx::px::Registration;
use blacksilk_wallet::file::KdfParams;
use blacksilk_wallet::px::{digest_from_hex, digest_hex, RecordSource};
use blacksilk_wallet::wallet::{network_name, parse_network};
use blacksilk_wallet::{load, save, Wallet};
use blacksilk_zkvm::air::trace::Budget;
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
    /// Show a private (PX) address.
    PxAddress {
        #[arg(long, default_value_t = 0)]
        index: u32,
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
        /// demonstration contract: no timeout, no refund, not trustless.
        #[arg(long)]
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
        /// The secret, 64 hex characters; generated and printed if omitted.
        #[arg(long)]
        secret: Option<String>,
        /// PX address of the party that will claim: the record is delivered
        /// to it. Default: this wallet (it keeps a copy either way).
        #[arg(long)]
        deliver_to: Option<String>,
    },
    /// Claim a record of the demonstration vault with its secret, paying its
    /// value privately.
    PxVaultClaim {
        /// The vault record's commitment (from px-records).
        #[arg(long)]
        record: String,
        #[arg(long)]
        secret: String,
        /// PX address to pay. Default: this wallet.
        #[arg(long)]
        to: Option<String>,
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
    /// Show the 24-word seed.
    Seed,
    /// Forget unconfirmed spends and stored transactions. Only for a
    /// transaction that certainly never left this wallet: `sync` rebroadcasts
    /// stored transactions and releases their funds itself when the node
    /// finds them invalid. Spending the same funds again after a relayed
    /// transaction links the two by key image and can reveal which ring
    /// member is the real input.
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

/// A ChaCha20 RNG seeded from the OS.
fn os_rng() -> Result<ChaCha20Rng, String> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("OS RNG: {e}"))?;
    let rng = ChaCha20Rng::from_seed(seed);
    seed.zeroize();
    Ok(rng)
}

fn rules_for(w: &Wallet) -> TxRules {
    TxRules::for_chain(&ChainParams::for_network(w.network()))
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

fn digest_arg(what: &str, s: &str) -> Result<Digest, String> {
    digest_from_hex(s.trim()).map_err(|e| format!("{what}: {e}"))
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
                Cmd::PxAddress { index } => {
                    println!("{}", w.px_address(index));
                    Ok(())
                }
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
                        "sent {} BLK privately, fee {} BLK",
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
                        println!(
                            "record {}\n  contract {}\n  value {} BLK, {status}, {source}",
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
                    deliver_to,
                } => (|| {
                    let contract = digest_arg("contract", &contract)?;
                    let amount = parse_amount(&amount).ok_or("amount: use a number like 1.5")?;
                    let mut rng = os_rng()?;
                    let (secret, generated) = match secret {
                        Some(s) => (digest_arg("secret", &s)?, false),
                        None => (blacksilk_px::wallet::random_digest(&mut rng), true),
                    };
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
                    let (id, record) = w
                        .px_vault_lock(
                            &client,
                            &contract,
                            amount,
                            &secret,
                            to.as_ref(),
                            &rules,
                            &mut rng,
                        )
                        .map_err(|e| e.to_string())?;
                    if generated {
                        println!("secret {}", digest_hex(&secret));
                    }
                    println!("record {}", digest_hex(&record));
                    println!("transaction {}", hex::encode(id));
                    Ok(())
                })(),
                Cmd::PxVaultClaim { record, secret, to } => (|| {
                    let record = digest_arg("record", &record)?;
                    let secret = digest_arg("secret", &secret)?;
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
