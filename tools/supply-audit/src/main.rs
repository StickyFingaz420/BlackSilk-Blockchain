//! `blacksilk-supply-audit`: sums every listed wallet's v1 and PX holdings at
//! one block and compares them with the chain's emission and PX pool (see the
//! library documentation and docs/testnet.md, "Supply audit").
//!
//! Read-only by default: wallets are synced in memory and never written back
//! unless `--save` is given, and no transaction is ever (re)broadcast.
//!
//! Exit codes: 0 consistent; 1 the audit could not run; 2 alarm (a chain
//! check failed, or the wallets hold more than the chain created); 3 value
//! outside the set while `--expect-complete` was given.

#![forbid(unsafe_code)]

use blacksilk_chain::build_flags::BuildFlags;
use blacksilk_rpc::Client;
use blacksilk_supply_audit::{audit, Entry};
use blacksilk_wallet::file::KdfParams;
use clap::Parser;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

#[derive(Parser)]
#[command(
    name = "blacksilk-supply-audit",
    about = "Closed-set supply audit: Σ wallets (v1 + PX) against generated and px_pool"
)]
struct Args {
    /// Node RPC address (host:port or http://host:port).
    #[arg(long, default_value = "127.0.0.1:29333")]
    node: String,
    /// The node's RPC cookie: `rpc.cookie` in the node's data directory
    /// (docs/blocks.md §9.1). Default: the file named by
    /// BLACKSILK_RPC_COOKIE, if set.
    #[arg(long)]
    rpc_cookie: Option<PathBuf>,
    /// A wallet file to include (repeat for every wallet of the set).
    #[arg(long = "wallet", required = true)]
    wallets: Vec<PathBuf>,
    /// A file holding the password of the wallet at the same position
    /// (repeat; give one per wallet or none). Without it, each password is
    /// asked for on the terminal. Trailing newlines are ignored.
    #[arg(long = "password-file")]
    password_files: Vec<PathBuf>,
    /// Audit at this height instead of the node's current height.
    #[arg(long)]
    height: Option<u64>,
    /// The listed wallets are the whole set: any difference is a failure
    /// (exit code 3).
    #[arg(long)]
    expect_complete: bool,
    /// Print the report as JSON.
    #[arg(long)]
    json: bool,
    /// Write the synced wallets back to their files (off by default).
    #[arg(long)]
    save: bool,
    /// Refuse to run if this binary has test-only code compiled in, on
    /// regtest too (for audits that are evidence; also the environment
    /// variable BLACKSILK_REQUIRE_CLEAN_BUILD=1).
    #[arg(long)]
    require_clean_build: bool,
}

/// Parses the command line with a `--version` that names the commit (when
/// `BLACKSILK_BUILD_COMMIT` was set at build time) and the build flags
/// (W4-GUARD).
fn parse_args() -> Args {
    use clap::{CommandFactory, FromArgMatches};
    let commit = option_env!("BLACKSILK_BUILD_COMMIT").unwrap_or("unknown");
    let (short, long) =
        BuildFlags::of_chain_layer().version_texts(env!("CARGO_PKG_VERSION"), commit);
    let short: &'static str = Box::leak(short.into_boxed_str());
    let long: &'static str = Box::leak(long.into_boxed_str());
    let matches = Args::command()
        .version(short)
        .long_version(long)
        .get_matches();
    Args::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())
}

fn main() {
    let args = parse_args();
    match run(&args) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

/// Reads a password file, dropping trailing CR/LF.
fn read_password_file(p: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut b = Zeroizing::new(std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?);
    while matches!(b.last(), Some(b'\n' | b'\r')) {
        b.pop();
    }
    Ok(b)
}

/// The KDF parameters in a wallet file header (wallet/src/file.rs format).
fn file_kdf(bytes: &[u8]) -> Option<KdfParams> {
    if bytes.len() < 16 || &bytes[..4] != b"BSW1" {
        return None;
    }
    let u = |i: usize| u32::from_le_bytes(bytes[i..i + 4].try_into().expect("4 bytes"));
    Some(KdfParams {
        m_kib: u(4),
        t: u(8),
        p: u(12),
    })
}

fn run(args: &Args) -> Result<i32, String> {
    // A binary with test-only code (W4-GUARD) audits only regtest wallets, and
    // none with `--require-clean-build`: exit status 1, the audit did not run.
    let flags = BuildFlags::of_chain_layer();
    let require_clean = blacksilk_chain::build_flags::require_clean(args.require_clean_build);
    if require_clean {
        flags.check_clean("blacksilk-supply-audit")?;
    }
    if !args.password_files.is_empty() && args.password_files.len() != args.wallets.len() {
        return Err(format!(
            "{} --password-file for {} --wallet: give one per wallet, in the same order, or none",
            args.password_files.len(),
            args.wallets.len()
        ));
    }
    let mut entries = Vec::new();
    let mut passwords = Vec::new();
    for (i, path) in args.wallets.iter().enumerate() {
        let password = match args.password_files.get(i) {
            Some(f) => read_password_file(f)?,
            None => {
                let mut p =
                    rpassword::prompt_password(format!("Password for {}: ", path.display()))
                        .map_err(|e| e.to_string())?;
                let b = Zeroizing::new(p.as_bytes().to_vec());
                p.zeroize();
                b
            }
        };
        let wallet = blacksilk_wallet::load(path, &password)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        flags.check_network("blacksilk-supply-audit", wallet.network())?;
        entries.push(Entry {
            name: path.display().to_string(),
            wallet,
        });
        passwords.push(password);
    }

    let client = Client::try_new(&args.node)
        .and_then(|c| c.with_cookie_option(args.rpc_cookie.as_deref()))
        .map_err(|e| e.to_string())?;
    let report = audit(&client, &mut entries, args.height)?;

    if args.save {
        for ((e, path), pw) in entries.iter().zip(&args.wallets).zip(&passwords) {
            let kdf = std::fs::read(path)
                .ok()
                .and_then(|b| file_kdf(&b))
                .unwrap_or_default();
            blacksilk_wallet::save(&e.wallet, path, pw, kdf)
                .map_err(|err| format!("saving {}: {err}", path.display()))?;
        }
    }

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        print!("{}", report.text());
    }
    Ok(report.exit_code(args.expect_complete))
}
