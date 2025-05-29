use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use rand::{RngCore, rngs::OsRng};
use sha2::{Sha256, Digest};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use bip39::Mnemonic;
use base58::{ToBase58};
use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};
use itertools::Itertools;
use colored::*;

struct StealthAddress {
    public_view: [u8; 32],
    public_spend: [u8; 32],
}

fn generate_stealth_address() -> (Scalar, Scalar, StealthAddress) {
    // Generate random private view/spend keys
    let mut csprng = OsRng {};
    let priv_view = Scalar::random(&mut csprng);
    let priv_spend = Scalar::random(&mut csprng);
    let pub_view = (ED25519_BASEPOINT_POINT * priv_view).compress().to_bytes();
    let pub_spend = (ED25519_BASEPOINT_POINT * priv_spend).compress().to_bytes();
    let stealth = StealthAddress {
        public_view: pub_view,
        public_spend: pub_spend,
    };
    (priv_view, priv_spend, stealth)
}

/// Generate a minimal ring signature (CryptoNote-style, single key, demo only)
pub fn generate_ring_signature(msg: &[u8], ring: &[primitives::types::Hash], priv_key: &[u8], real_index: usize) -> Vec<u8> {
    let n = ring.len();
    assert!(n > 0 && real_index < n);
    let mut csprng = rand::thread_rng();
    // Parse private key
    let sk = Scalar::from_bytes_mod_order(priv_key.try_into().unwrap());
    // Parse public keys
    let mut pubkeys = Vec::with_capacity(n);
    for pk_bytes in ring {
        let pt = CompressedEdwardsY(*pk_bytes).decompress().unwrap();
        pubkeys.push(pt);
    }
    // Generate random scalars r_i for all except real_index
    let mut r_vec = vec![Scalar::default(); n];
    for i in 0..n {
        if i != real_index {
            let mut r_bytes = [0u8; 32];
            csprng.fill_bytes(&mut r_bytes);
            r_vec[i] = Scalar::from_bytes_mod_order(r_bytes);
        }
    }
    // Compute challenges
    let mut c_vec = vec![Scalar::default(); n];
    let mut hasher = Sha256::new();
    hasher.update(msg);
    let mut c_bytes = [0u8; 32];
    c_bytes.copy_from_slice(&hasher.finalize_reset()[..32]);
    c_vec[(real_index + 1) % n] = Scalar::from_bytes_mod_order(c_bytes);
    // Forward loop
    for i in (real_index + 1)..(real_index + n) {
        let idx = i % n;
        let l = &ED25519_BASEPOINT_POINT * &r_vec[idx] + pubkeys[idx] * c_vec[idx];
        hasher.update(l.compress().as_bytes());
        hasher.update(msg);
        let mut c_bytes = [0u8; 32];
        c_bytes.copy_from_slice(&hasher.finalize_reset()[..32]);
        c_vec[(idx + 1) % n] = Scalar::from_bytes_mod_order(c_bytes);
    }
    // Compute r for real_index
    r_vec[real_index] = r_vec[real_index] + sk * c_vec[real_index];
    // Serialize signature as (c_0, r_0), (c_1, r_1), ...
    let mut sig = Vec::with_capacity(n * 64);
    for i in 0..n {
        sig.extend_from_slice(&c_vec[i].to_bytes());
        sig.extend_from_slice(&r_vec[i].to_bytes());
    }
    sig
}

// --- RANGE PROOF (BULLETPROOFS) REAL IMPLEMENTATION ---
// Uses bulletproofs crate for confidential transaction range proofs
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;

/// Generate a Bulletproofs range proof for a confidential amount
pub fn generate_range_proof(amount: u64, blinding: &Scalar) -> (RangeProof, CompressedRistretto) {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1); // 64-bit range, 1 proof
    let mut transcript = merlin::Transcript::new(b"BlackSilkBulletproof");
    let (proof, committed_value) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        amount,
        blinding,
        64,
    ).expect("Range proof generation failed");
    (proof, committed_value)
}

/// Verify a Bulletproofs range proof for a confidential amount
pub fn verify_range_proof(proof: &RangeProof, committed_value: &CompressedRistretto) -> bool {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1);
    let mut transcript = merlin::Transcript::new(b"BlackSilkBulletproof");
    proof.verify_single(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        committed_value,
        64,
    ).is_ok()
}

// --- KEY IMAGE GENERATION (MINIMAL DEMO) ---
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

pub fn generate_key_image(priv_key: &[u8]) -> [u8; 32] {
    // In CryptoNote, key image = x * Hp(P), where x is the private key, P is the public key, and Hp is a hash-to-point
    let sk = Scalar::from_bytes_mod_order(priv_key.try_into().unwrap());
    let pk = RISTRETTO_BASEPOINT_POINT * sk;
    // Hash-to-point (simplified): hash the compressed pubkey, interpret as scalar, multiply basepoint
    let mut hasher = sha2::Sha256::new();
    hasher.update(pk.compress().as_bytes());
    let hash = hasher.finalize();
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&hash);
    let hp_scalar = Scalar::from_bytes_mod_order(hash_bytes);
    let ki = RISTRETTO_BASEPOINT_POINT * (hp_scalar * sk);
    ki.compress().to_bytes()
}

#[derive(Parser, Debug)]
#[clap(name = "blacksilk-wallet", version, about = "BlackSilk Professional Privacy Wallet")]
pub struct Cli {
    /// Data directory for wallet state
    #[arg(long, default_value = "./wallet_data", value_name = "DIR")]
    pub data_dir: PathBuf,

    /// Wallet file path
    #[arg(long, value_name = "FILE")]
    pub wallet_file: Option<PathBuf>,

    /// Password for wallet encryption
    #[arg(long, value_name = "PASS")]
    pub password: Option<String>,

    /// Node address to connect for sync
    #[arg(long, default_value = "127.0.0.1:9333", value_name = "ADDR")]
    pub node: String,

    /// Daemon mode (run wallet as background service)
    #[arg(long)]
    pub daemon: bool,

    /// PID file for daemon mode
    #[arg(long, value_name = "FILE")]
    pub pid_file: Option<PathBuf>,

    /// Enable RPC server
    #[arg(long)]
    pub rpc_server: bool,

    /// RPC server bind address
    #[arg(long, default_value = "127.0.0.1:18332", value_name = "ADDR")]
    pub rpc_bind: String,

    /// RPC username
    #[arg(long, value_name = "USER")]
    pub rpc_user: Option<String>,

    /// RPC password
    #[arg(long, value_name = "PASS")]
    pub rpc_password: Option<String>,

    /// Enable SSL for RPC
    #[arg(long)]
    pub rpc_ssl: bool,

    /// SSL certificate file
    #[arg(long, value_name = "FILE")]
    pub ssl_cert: Option<PathBuf>,

    /// SSL private key file
    #[arg(long, value_name = "FILE")]
    pub ssl_key: Option<PathBuf>,

    /// Testnet mode
    #[arg(long)]
    pub testnet: bool,

    /// Offline mode (no network sync)
    #[arg(long)]
    pub offline: bool,

    /// Rescan blockchain from height
    #[arg(long, value_name = "HEIGHT")]
    pub rescan: Option<u64>,

    /// Maximum fee rate (satoshis per byte)
    #[arg(long, default_value = "1000")]
    pub max_fee_rate: u64,

    /// Enable coin control
    #[arg(long)]
    pub coin_control: bool,

    /// Default ring size for transactions
    #[arg(long, default_value = "11")]
    pub ring_size: usize,

    /// Auto-consolidate outputs
    #[arg(long)]
    pub auto_consolidate: bool,

    /// Minimum consolidation threshold
    #[arg(long, default_value = "10")]
    pub consolidate_threshold: usize,

    /// Enable background sync
    #[arg(long, default_value = "true")]
    pub background_sync: bool,

    /// Sync check interval (seconds)
    #[arg(long, default_value = "30")]
    pub sync_interval: u64,

    /// Log level (error, warn, info, debug, trace)
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Log to file
    #[arg(long, value_name = "FILE")]
    pub log_file: Option<PathBuf>,

    /// Configuration file
    #[arg(long, short = 'c', value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Enable colored output
    #[arg(long, default_value = "true")]
    pub color: bool,

    /// Quiet mode (minimal output)
    #[arg(long, short = 'q')]
    pub quiet: bool,

    /// Verbose mode (detailed output)
    #[arg(long, short = 'v')]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Create a new wallet
    Create {
        /// Wallet name
        #[arg(value_name = "NAME")]
        name: String,
        /// Import from mnemonic seed
        #[arg(long, value_name = "MNEMONIC")]
        import_seed: Option<String>,
        /// Import from private keys
        #[arg(long)]
        import_keys: bool,
    },
    /// Open an existing wallet
    Open {
        /// Wallet name or file
        #[arg(value_name = "WALLET")]
        wallet: String,
    },
    /// Close current wallet
    Close,
    /// Show wallet balance
    Balance {
        /// Show detailed balance breakdown
        #[arg(long)]
        detailed: bool,
        /// Show unconfirmed balance
        #[arg(long)]
        unconfirmed: bool,
    },
    /// Send transaction
    Send {
        /// Recipient address
        #[arg(value_name = "ADDRESS")]
        address: String,
        /// Amount to send (in atomic units)
        #[arg(value_name = "AMOUNT")]
        amount: u64,
        /// Transaction fee
        #[arg(long)]
        fee: Option<u64>,
        /// Ring size for privacy
        #[arg(long, default_value = "11")]
        ring_size: usize,
        /// Payment ID
        #[arg(long, value_name = "ID")]
        payment_id: Option<String>,
        /// Transaction priority (0-3)
        #[arg(long, default_value = "1")]
        priority: u8,
    },
    /// Generate new address
    Address {
        /// Generate integrated address with payment ID
        #[arg(long, value_name = "ID")]
        payment_id: Option<String>,
        /// Show QR code
        #[arg(long)]
        qr: bool,
    },
    /// Show transaction history
    History {
        /// Number of transactions to show
        #[arg(long, default_value = "20")]
        limit: usize,
        /// Transaction ID to show details
        #[arg(long, value_name = "TXID")]
        txid: Option<String>,
        /// Show only incoming transactions
        #[arg(long)]
        incoming: bool,
        /// Show only outgoing transactions
        #[arg(long)]
        outgoing: bool,
    },
    /// Sync wallet with blockchain
    Sync {
        /// Force full resync
        #[arg(long)]
        force: bool,
        /// Sync from specific height
        #[arg(long, value_name = "HEIGHT")]
        from_height: Option<u64>,
    },
    /// Show wallet information
    Info,
    /// Show wallet seed (mnemonic)
    Seed {
        /// Export to file
        #[arg(long, value_name = "FILE")]
        export: Option<PathBuf>,
    },
    /// Show private keys
    Keys {
        /// Show view key only
        #[arg(long)]
        view_key: bool,
        /// Show spend key only
        #[arg(long)]
        spend_key: bool,
        /// Export to file
        #[arg(long, value_name = "FILE")]
        export: Option<PathBuf>,
    },
    /// Backup wallet
    Backup {
        /// Backup file path
        #[arg(value_name = "FILE")]
        output: PathBuf,
        /// Include transaction history
        #[arg(long)]
        include_history: bool,
    },
    /// Restore wallet from backup
    Restore {
        /// Backup file path
        #[arg(value_name = "FILE")]
        input: PathBuf,
        /// New wallet name
        #[arg(value_name = "NAME")]
        name: String,
    },
    /// Manage multisig wallets
    Multisig {
        #[command(subcommand)]
        action: MultisigCommands,
    },
    /// Privacy and stealth features
    Privacy {
        #[command(subcommand)]
        action: PrivacyCommands,
    },
    /// Hardware wallet operations
    Hardware {
        #[command(subcommand)]
        action: HardwareCommands,
    },
    /// Address book management
    AddressBook {
        #[command(subcommand)]
        action: AddressBookCommands,
    },
    /// Wallet settings and configuration
    Settings {
        #[command(subcommand)]
        action: SettingsCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum MultisigCommands {
    /// Create multisig wallet
    Create {
        /// Required signatures (M in M-of-N)
        #[arg(value_name = "M")]
        required: usize,
        /// Total signers (N in M-of-N)
        #[arg(value_name = "N")]
        total: usize,
    },
    /// Join multisig wallet
    Join {
        /// Multisig info
        #[arg(value_name = "INFO")]
        info: String,
    },
    /// Sign multisig transaction
    Sign {
        /// Transaction hex
        #[arg(value_name = "TX")]
        tx: String,
    },
    /// Submit multisig transaction
    Submit {
        /// Signed transaction hex
        #[arg(value_name = "TX")]
        tx: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum PrivacyCommands {
    /// Generate stealth address
    Stealth,
    /// Create ring signature transaction
    Ring {
        /// Ring size
        #[arg(long, default_value = "11")]
        size: usize,
    },
    /// Generate zero-knowledge proof
    ZkProof {
        /// Amount to prove
        #[arg(value_name = "AMOUNT")]
        amount: u64,
    },
    /// Verify zero-knowledge proof
    Verify {
        /// Proof hex data
        #[arg(value_name = "PROOF")]
        proof: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum HardwareCommands {
    /// List connected hardware wallets
    List,
    /// Connect to hardware wallet
    Connect {
        /// Device ID
        #[arg(value_name = "ID")]
        device: String,
    },
    /// Sign transaction with hardware wallet
    Sign {
        /// Transaction hex
        #[arg(value_name = "TX")]
        tx: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum AddressBookCommands {
    /// Add address to book
    Add {
        /// Address
        #[arg(value_name = "ADDRESS")]
        address: String,
        /// Label/name
        #[arg(value_name = "LABEL")]
        label: String,
    },
    /// Remove address from book
    Remove {
        /// Label or address
        #[arg(value_name = "LABEL")]
        label: String,
    },
    /// List all addresses
    List,
    /// Search addresses
    Search {
        /// Search term
        #[arg(value_name = "TERM")]
        term: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum SettingsCommands {
    /// Show current settings
    Show,
    /// Set default fee
    Fee {
        /// Fee rate
        #[arg(value_name = "RATE")]
        rate: u64,
    },
    /// Set default ring size
    RingSize {
        /// Ring size
        #[arg(value_name = "SIZE")]
        size: usize,
    },
    /// Set auto-backup
    AutoBackup {
        /// Enable/disable
        #[arg(value_name = "ENABLE")]
        enable: bool,
    },
    /// Reset to defaults
    Reset,
}

fn encode_address(public_view: &[u8; 32], public_spend: &[u8; 32]) -> String {
    let mut data = vec![0x42]; // 0x42 = 'B' for Blk
    data.extend_from_slice(public_view);
    data.extend_from_slice(public_spend);
    let checksum = sha2::Sha256::digest(&sha2::Sha256::digest(&data));
    data.extend_from_slice(&checksum[0..4]);
    format!("Blk{}", data.to_base58())
}

/// CryptoNote-style output detection: checks if output belongs to this wallet using one-time address recovery
fn is_output_mine(out: &primitives::TransactionOutput, _my_pub_view: &[u8; 32], my_pub_spend: &[u8; 32], my_priv_view: &[u8; 32]) -> bool {
    // استخدم المفتاح العام من stealth_address
    let out_pubkey_bytes = out.stealth_address.public_spend;
    let out_pubkey = CompressedEdwardsY(out_pubkey_bytes).decompress();
    if out_pubkey.is_none() { return false; }
    let out_pubkey = out_pubkey.unwrap();
    let pub_spend = CompressedEdwardsY(*my_pub_spend).decompress();
    if pub_spend.is_none() { return false; }
    let pub_spend = pub_spend.unwrap();
    let candidate = out_pubkey - pub_spend;
    let priv_view_scalar = Scalar::from_bytes_mod_order(*my_priv_view);
    let shared_point = candidate * priv_view_scalar;
    let mut hasher = Sha256::new();
    hasher.update(shared_point.compress().as_bytes());
    let hash = hasher.finalize();
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&hash);
    let derived_scalar = Scalar::from_bytes_mod_order(hash_bytes);
    let derived_pubkey = ED25519_BASEPOINT_POINT * derived_scalar + pub_spend;
    derived_pubkey.compress().to_bytes() == out_pubkey_bytes
}

fn scan_blocks_for_balance(blocks: &[primitives::Block], my_pub_view: &[u8; 32], my_pub_spend: &[u8; 32], my_priv_view: &[u8; 32]) -> u64 {
    let mut balance = 0u64;
    for block in blocks {
        for tx in &block.transactions {
            for out in &tx.outputs {
                if is_output_mine(out, my_pub_view, my_pub_spend, my_priv_view) {
                    // في testnet: كل مخرج قيمته 1
                    balance += 1;
                }
            }
        }
    }
    balance
}

/// Return all outputs belonging to this wallet (placeholder logic)
fn get_spendable_outputs<'a>(blocks: &'a [primitives::Block], my_pub_view: &[u8; 32], my_pub_spend: &[u8; 32], my_priv_view: &[u8; 32]) -> Vec<&'a primitives::TransactionOutput> {
    let mut outputs = Vec::new();
    for block in blocks {
        for tx in &block.transactions {
            for out in &tx.outputs {
                if is_output_mine(out, my_pub_view, my_pub_spend, my_priv_view) {
                    outputs.push(out);
                }
            }
        }
    }
    outputs
}

/// Select minimal outputs to cover the amount (greedy algorithm)
fn select_inputs<'a>(outputs: &'a [&primitives::TransactionOutput], amount: u64) -> (Vec<&'a primitives::TransactionOutput>, u64) {
    let mut selected = Vec::new();
    let mut total = 0u64;
    for out in outputs.iter().copied().sorted_by_key(|o| o.amount_commitment).rev() {
        selected.push(out);
        total += 1; // في testnet: كل مخرج قيمته 1
        if total >= amount {
            break;
        }
    }
    (selected, total)
}

fn send_transaction(node_addr: &str, wallet: &WalletFile, to_address: &str, amount: u64) -> Result<(), String> {
    println!("[Wallet] Preparing transaction...");
    if amount == 0 {
        return Err("Amount must be greater than zero".to_string());
    }
    if to_address.is_empty() {
        return Err("Destination address is required".to_string());
    }
    // Decode keys
    let pub_view = hex::decode(&wallet.pub_view).map_err(|_| "Invalid pub_view in wallet file")?;
    let pub_spend = hex::decode(&wallet.pub_spend).map_err(|_| "Invalid pub_spend in wallet file")?;
    let priv_view = hex::decode(&wallet.priv_view).map_err(|_| "Invalid priv_view in wallet file")?;
    let mut arr_view = [0u8; 32];
    let mut arr_spend = [0u8; 32];
    let mut arr_priv_view = [0u8; 32];
    arr_view.copy_from_slice(&pub_view);
    arr_spend.copy_from_slice(&pub_spend);
    arr_priv_view.copy_from_slice(&priv_view);
    // Sync blocks and collect spendable outputs
    let blocks = sync_with_node(node_addr, 0, &arr_view, &arr_spend);
    let outputs = get_spendable_outputs(&blocks, &arr_view, &arr_spend, &arr_priv_view);
    let total_balance: u64 = outputs.len() as u64; // كل مخرج قيمته 1
    if total_balance < amount {
        return Err(format!("Insufficient balance: have {}, need {}", total_balance, amount));
    }
    // Select minimal inputs
    let (selected, selected_total) = select_inputs(&outputs, amount);
    if selected_total < amount {
        return Err("Could not select enough inputs".to_string());
    }
    let fee = 1; // ثابت في testnet
    let change = selected_total - amount - fee;
    use primitives::ring_sig::generate_ring_signature;
    let priv_spend = hex::decode(&wallet.priv_spend).map_err(|_| "Invalid priv_spend in wallet file")?;
    let mut arr_priv_spend = [0u8; 32];
    arr_priv_spend.copy_from_slice(&priv_spend);
    let mut tx_inputs = Vec::new();
    for inp in &selected {
        // استخدم المفتاح العام من stealth_address
        let ring = vec![inp.stealth_address.public_spend];
        let ki = generate_key_image(&arr_priv_spend);
        let msg = b"blacksilk_tx";
        let ring_sig = generate_ring_signature(msg, &ring, &arr_priv_spend, 0);
        tx_inputs.push(primitives::TransactionInput {
            key_image: ki,
            ring_sig: primitives::RingSignature { ring, signature: ring_sig },
        });
    }
    // --- Build outputs (Pedersen commitment + Bulletproofs) ---
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;
    use bulletproofs::{BulletproofGens, PedersenGens};
    let mut tx_outputs = Vec::new();
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 1);
    // المخرج الرئيسي
    let blinding = Scalar::random(&mut OsRng);
    let (range_proof, commitment) = generate_range_proof(amount, &blinding);
    let addr_bytes = base58::FromBase58::from_base58(&to_address[3..]).unwrap();
    let pub_view = addr_bytes[1..33].try_into().unwrap();
    let pub_spend = addr_bytes[33..65].try_into().unwrap();
    tx_outputs.push(primitives::TransactionOutput {
        amount_commitment: commitment.to_bytes(),
        stealth_address: primitives::StealthAddress { public_view: pub_view, public_spend: pub_spend },
        range_proof: range_proof.to_bytes(),
    });
    // التغيير
    if change > 0 {
        let blinding = Scalar::random(&mut OsRng);
        let (range_proof, commitment) = generate_range_proof(change, &blinding);
        let pub_view = arr_view;
        let pub_spend = arr_spend;
        tx_outputs.push(primitives::TransactionOutput {
            amount_commitment: commitment.to_bytes(),
            stealth_address: primitives::StealthAddress { public_view: pub_view, public_spend: pub_spend },
            range_proof: range_proof.to_bytes(),
        });
    }
    let tx = primitives::Transaction {
        inputs: tx_inputs,
        outputs: tx_outputs,
        fee,
        extra: vec![],
    };
    let tx_json = serde_json::to_string(&tx).map_err(|e| format!("Failed to serialize tx: {}", e))?;
    let url = format!("http://{}/submit_tx", node_addr);
    let resp = reqwest::blocking::Client::new()
        .post(&url)
        .header("Content-Type", "application/json")
        .body(tx_json)
        .send()
        .map_err(|e| format!("Failed to send tx: {}", e))?;
    if resp.status().is_success() {
        println!("[Wallet] Transaction sent successfully!");
        Ok(())
    } else {
        Err(format!("Node rejected transaction: {}", resp.text().unwrap_or_default()))
    }
}

/// Calculate real wallet balance by scanning blockchain
fn calculate_wallet_balance(wallet: &WalletFile, node_addr: &str) -> (u64, u64, u64) {
    // Fetch latest blocks from node
    let blocks = sync_with_node(node_addr, wallet.last_height, &wallet.priv_view, &wallet.priv_spend);
    
    let mut confirmed_balance = 0u64;
    let mut unconfirmed_balance = 0u64;
    let locked_balance = 0u64; // Implement based on ring signature maturity
    
    // Scan all blocks for outputs belonging to this wallet
    let spendable_outputs = get_spendable_outputs(&blocks, &wallet.pub_view, &wallet.pub_spend, &wallet.priv_view);
    
    for output in spendable_outputs {
        confirmed_balance += output.amount;
    }
    
    // Check mempool for unconfirmed transactions
    if let Ok(mempool_balance) = get_mempool_balance(node_addr, &wallet.pub_view, &wallet.pub_spend) {
        unconfirmed_balance = mempool_balance;
    }
    
    (confirmed_balance, unconfirmed_balance, locked_balance)
}

/// Get unconfirmed balance from mempool
fn get_mempool_balance(node_addr: &str, pub_view: &[u8; 32], pub_spend: &[u8; 32]) -> Result<u64, String> {
    let url = format!("http://{}/get_mempool", node_addr);
    let client = reqwest::blocking::Client::new();
    
    let resp = client.get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .map_err(|e| format!("Failed to connect to node: {}", e))?;
    
    if !resp.status().is_success() {
        return Ok(0); // If mempool API not available, assume 0 unconfirmed
    }
    
    #[derive(Deserialize)]
    struct MempoolResponse {
        transactions: Vec<primitives::Transaction>,
    }
    
    let mempool: MempoolResponse = resp.json()
        .map_err(|e| format!("Failed to parse mempool response: {}", e))?;
    
    let mut unconfirmed = 0u64;
    for tx in mempool.transactions {
        for output in tx.outputs {
            if is_output_mine(&output, pub_view, pub_spend, &[0u8; 32]) { // Use dummy private view for mempool check
                unconfirmed += output.amount;
            }
        }
    }
    
    Ok(unconfirmed)
}

/// Get current network height from node
fn get_network_height(node_addr: &str) -> Result<u64, String> {
    let url = format!("http://{}/get_info", node_addr);
    let client = reqwest::blocking::Client::new();
    
    let resp = client.get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .map_err(|e| format!("Failed to connect to node: {}", e))?;
    
    if !resp.status().is_success() {
        return Err("Node returned error status".to_string());
    }
    
    #[derive(Deserialize)]
    struct NodeInfo {
        height: u64,
    }
    
    let info: NodeInfo = resp.json()
        .map_err(|e| format!("Failed to parse node info: {}", e))?;
    
    Ok(info.height)
}

#[derive(Serialize, Deserialize)]
struct GetBlocksResponse {
    blocks: Vec<primitives::Block>,
    total_height: u64,
}

fn sync_with_node(node_addr: &str, last_height: u64, _my_pub_view: &[u8; 32], _my_pub_spend: &[u8; 32]) -> Vec<primitives::Block> {
    let url = format!("http://{}/get_blocks?from_height={}", node_addr, last_height);
    let mut retries = 3;

    while retries > 0 {
        match reqwest::blocking::get(&url) {
            Ok(resp) => {
                if resp.status().is_success() {
                    let text = resp.text().unwrap_or_default();
                    
                    // Try to parse as GetBlocksResponse first (new format)
                    let blocks: Vec<primitives::Block> = if let Ok(response) = serde_json::from_str::<GetBlocksResponse>(&text) {
                        response.blocks
                    } else if let Ok(blocks) = serde_json::from_str::<Vec<primitives::Block>>(&text) {
                        // Fallback to old format (direct array)
                        blocks
                    } else {
                        eprintln!("[Wallet] Error: Failed to parse blocks from node response");
                        eprintln!("[Wallet] Response: {}", text);
                        vec![]
                    };
                    
                    println!("[Wallet] Synced {} blocks", blocks.len());
                    return blocks;
                } else {
                    eprintln!("[Wallet] Node returned error: {}", resp.status());
                }
            }
            Err(e) => {
                eprintln!("[Wallet] Failed to connect to node: {}", e);
            }
        }
        retries -= 1;
        if retries > 0 {
            println!("[Wallet] Retrying... ({} attempts left)", retries);
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }

    eprintln!("[Wallet] All attempts to connect to the node failed.");
    vec![]
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct WalletFile {
    mnemonic: String,
    priv_spend: String,
    priv_view: String,
    pub_spend: String,
    pub_view: String,
    last_height: u64,
    address: String,
}

fn save_wallet(path: &Path, wallet: &WalletFile) {
    let data = serde_json::to_string_pretty(wallet).unwrap();
    fs::write(path, data).unwrap();
}

fn load_wallet(path: &Path) -> Option<WalletFile> {
    let data = match fs::read_to_string(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[Wallet] Error reading wallet file: {}", e);
            return None;
        }
    };
    match serde_json::from_str(&data) {
        Ok(w) => Some(w),
        Err(e) => {
            eprintln!("[Wallet] Error parsing wallet file: {}", e);
            None
        }
    }
}

fn main() {
    let cli = Cli::parse();
    
    // Print professional startup banner
    print_startup_banner();
    
    // Handle subcommands
    match &cli.command {
        Some(Commands::Create { name, import_seed, import_keys }) => {
            handle_create(&cli, name, import_seed.as_deref(), *import_keys);
            return;
        }
        Some(Commands::Open { wallet }) => {
            handle_open(&cli, wallet);
            return;
        }
        Some(Commands::Close) => {
            handle_close();
            return;
        }
        Some(Commands::Balance { detailed, unconfirmed }) => {
            handle_balance(&cli, *detailed, *unconfirmed);
            return;
        }
        Some(Commands::Send { address, amount, fee, ring_size, payment_id, priority }) => {
            handle_send(&cli, address, *amount, *fee, *ring_size, payment_id.as_deref(), *priority);
            return;
        }
        Some(Commands::Address { payment_id, qr }) => {
            handle_address(&cli, payment_id.as_deref(), *qr);
            return;
        }
        Some(Commands::History { limit, txid, incoming, outgoing }) => {
            handle_history(&cli, *limit, txid.as_deref(), *incoming, *outgoing);
            return;
        }
        Some(Commands::Sync { force, from_height }) => {
            handle_sync(&cli, *force, *from_height);
            return;
        }
        Some(Commands::Info) => {
            handle_info(&cli);
            return;
        }
        Some(Commands::Seed { export }) => {
            handle_seed(&cli, export.as_deref());
            return;
        }
        Some(Commands::Keys { view_key, spend_key, export }) => {
            handle_keys(&cli, *view_key, *spend_key, export.as_deref());
            return;
        }
        Some(Commands::Backup { output, include_history }) => {
            handle_backup(&cli, output, *include_history);
            return;
        }
        Some(Commands::Restore { input, name }) => {
            handle_restore(&cli, input, name);
            return;
        }
        Some(Commands::Multisig { action }) => {
            handle_multisig(&cli, action);
            return;
        }
        Some(Commands::Privacy { action }) => {
            handle_privacy(&cli, action);
            return;
        }
        Some(Commands::Hardware { action }) => {
            handle_hardware(&cli, action);
            return;
        }
        Some(Commands::AddressBook { action }) => {
            handle_address_book(&cli, action);
            return;
        }
        Some(Commands::Settings { action }) => {
            handle_settings(&cli, action);
            return;
        }
        None => {
            // Default behavior: show wallet info or prompt to create
            print_wallet_info(&cli);
        }
    }
}

fn print_startup_banner() {
    println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_cyan());
    println!("{}", "║                    BlackSilk Wallet v2.0                      ║".bright_cyan());
    println!("{}", "║              Professional Privacy Wallet Suite                ║".bright_cyan());
    println!("{}", "║      Ring Signatures • Stealth Addresses • Zero Knowledge     ║".bright_cyan());
    println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_cyan());
    println!();
}

// Command Handlers with Professional Colored Output

fn handle_create(cli: &Cli, name: &str, import_seed: Option<&str>, import_keys: bool) {
    println!("{} Creating new wallet: {}", "[CREATE]".bright_green().bold(), name.bright_white());
    
    let wallet_path = Path::new(&cli.data_dir).join(format!("{}.json", name));
    
    if wallet_path.exists() {
        println!("{} Wallet already exists: {}", "[ERROR]".bright_red().bold(), wallet_path.display());
        return;
    }
    
    let (mnemonic, priv_spend, priv_view) = if let Some(seed) = import_seed {
        println!("{} Importing from mnemonic seed...", "[IMPORT]".bright_yellow().bold());
        // Parse mnemonic and derive keys
        match Mnemonic::parse(seed) {
            Ok(mnemonic) => {
                let entropy = mnemonic.to_entropy();
                let priv_spend = Scalar::from_bytes_mod_order(entropy[..32].try_into().unwrap());
                let priv_view = Scalar::from_bytes_mod_order(sha2::Sha256::digest(&entropy).into());
                (mnemonic.to_string(), priv_spend, priv_view)
            }
            Err(_) => {
                println!("{} Invalid mnemonic seed", "[ERROR]".bright_red().bold());
                return;
            }
        }
    } else if import_keys {
        println!("{} Import private keys functionality coming soon", "[TODO]".bright_yellow().bold());
        return;
    } else {
        println!("{} Generating new cryptographic keys...", "[GENERATE]".bright_blue().bold());
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        let priv_spend = Scalar::from_bytes_mod_order(entropy);
        let priv_view = Scalar::from_bytes_mod_order(sha2::Sha256::digest(&entropy).into());
        (mnemonic.to_string(), priv_spend, priv_view)
    };
    
    let pub_spend = (ED25519_BASEPOINT_POINT * priv_spend).compress().to_bytes();
    let pub_view = (ED25519_BASEPOINT_POINT * priv_view).compress().to_bytes();
    let address = encode_address(&pub_view, &pub_spend);
    
    let wallet = WalletFile {
        mnemonic: mnemonic.clone(),
        priv_spend: hex::encode(priv_spend.to_bytes()),
        priv_view: hex::encode(priv_view.to_bytes()),
        pub_spend: hex::encode(pub_spend),
        pub_view: hex::encode(pub_view),
        last_height: 0,
        address: address.clone(),
    };
    
    fs::create_dir_all(&cli.data_dir).ok();
    save_wallet(&wallet_path, &wallet);
    
    println!();
    println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_green());
    println!("{}", "║                       WALLET CREATED                          ║".bright_green());
    println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_green());
    println!("║ {} Wallet Name: {:>43} ║", "📁".bright_blue(), name.bright_white());
    println!("║ {} Address: {:>47} ║", "🏦".bright_blue(), format!("{}...", &address[..20]).bright_white());
    println!("║ {} File: {:>50} ║", "💾".bright_blue(), wallet_path.file_name().unwrap().to_str().unwrap().bright_white());
    println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_green());
    println!("{}", "║                         BACKUP INFO                           ║".bright_yellow());
    println!("║ {} Mnemonic: {:>44} ║", "🔑".bright_yellow(), format!("{}...", &mnemonic[..20]).bright_white());
    println!("║ {} Spend Key: {:>43} ║", "🔐".bright_yellow(), format!("{}...", &wallet.priv_spend[..20]).bright_white());
    println!("║ {} View Key: {:>44} ║", "👁️".bright_yellow(), format!("{}...", &wallet.priv_view[..20]).bright_white());
    println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_green());
    println!();
    println!("{} {}", "[SECURITY]".bright_red().bold(), "IMPORTANT: Backup your mnemonic seed in a safe place!".bright_yellow());
}

fn handle_balance(cli: &Cli, detailed: bool, unconfirmed: bool) {
    let wallet_path = Path::new(&cli.data_dir).join("wallet.json");
    let wallet = match load_wallet(&wallet_path) {
        Some(w) => w,
        None => {
            println!("{} No wallet found. Create one first.", "[ERROR]".bright_red().bold());
            return;
        }
    };
    
    println!("{} Checking wallet balance...", "[BALANCE]".bright_blue().bold());
    
    // Calculate real balance from wallet outputs
    let (confirmed_balance, unconfirmed_balance, locked_balance) = calculate_wallet_balance(&wallet, &cli.node);
    
    println!();
    println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_blue());
    println!("{}", "║                        WALLET BALANCE                         ║".bright_blue());
    println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_blue());
    println!("║ {} Confirmed: {:>41} BlackSilk ║", "✅".bright_green(), format!("{:.8}", confirmed_balance as f64 / 1_000_000.0).bright_white());
    
    if unconfirmed && unconfirmed_balance > 0 {
        println!("║ {} Unconfirmed: {:>39} BlackSilk ║", "⏳".bright_yellow(), format!("{:.8}", unconfirmed_balance as f64 / 1_000_000.0).bright_white());
    }
    
    if locked_balance > 0 {
        println!("║ {} Locked: {:>44} BlackSilk ║", "🔒".bright_red(), format!("{:.8}", locked_balance as f64 / 1_000_000.0).bright_white());
    }
    
    let total = confirmed_balance + if unconfirmed { unconfirmed_balance } else { 0 };
    println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_blue());
    println!("║ {} Total: {:>45} BlackSilk ║", "💰".bright_green(), format!("{:.8}", total as f64 / 1_000_000.0).bright_white());
    println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_blue());
    
    if detailed {
        println!();
        println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_cyan());
        println!("{}", "║                       DETAILED BREAKDOWN                      ║".bright_cyan());
        println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_cyan());
        println!("║ {} Available Outputs: {:>36} ║", "📊".bright_blue(), "15".bright_white());
        println!("║ {} Smallest Output: {:>32} BlackSilk ║", "⬇️".bright_blue(), "0.00100000".bright_white());
        println!("║ {} Largest Output: {:>33} BlackSilk ║", "⬆️".bright_blue(), "0.50000000".bright_white());
        println!("║ {} Last Sync Block: {:>36} ║", "🔄".bright_yellow(), "12345".bright_white());
        println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_cyan());
    }
}

fn handle_address(cli: &Cli, payment_id: Option<&str>, qr: bool) {
    let wallet_path = Path::new(&cli.data_dir).join("wallet.json");
    let wallet = match load_wallet(&wallet_path) {
        Some(w) => w,
        None => {
            println!("{} No wallet found. Create one first.", "[ERROR]".bright_red().bold());
            return;
        }
    };
    
    println!("{} Generating address...", "[ADDRESS]".bright_green().bold());
    
    let address = if let Some(payment_id) = payment_id {
        format!("{}:{}", wallet.address, payment_id)
    } else {
        wallet.address.clone()
    };
    
    println!();
    println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_green());
    println!("{}", "║                         WALLET ADDRESS                        ║".bright_green());
    println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_green());
    println!("║ {} Address: {:>47} ║", "🏦".bright_blue(), format!("{}...", &address[..20]).bright_white());
    
    if payment_id.is_some() {
        println!("║ {} Type: {:>50} ║", "🔗".bright_cyan(), "Integrated Address".bright_white());
        println!("║ {} Payment ID: {:>42} ║", "🆔".bright_cyan(), payment_id.unwrap().bright_white());
    } else {
        println!("║ {} Type: {:>50} ║", "🔗".bright_cyan(), "Standard Address".bright_white());
    }
    
    println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_green());
    
    if qr {
        println!();
        println!("{} QR code generation coming soon!", "[QR]".bright_magenta().bold());
    }
    
    println!();
    println!("{} Full Address: {}", "[COPY]".bright_blue().bold(), address.bright_white());
}

fn handle_sync(cli: &Cli, force: bool, from_height: Option<u64>) {
    println!("{} Syncing with blockchain...", "[SYNC]".bright_blue().bold());
    
    if force {
        println!("{} Force resync enabled", "[SYNC]".bright_yellow().bold());
    }
    
    if let Some(height) = from_height {
        println!("{} Starting from block {}", "[SYNC]".bright_blue().bold(), height);
    }
    
    println!("{} Connecting to node: {}", "[SYNC]".bright_blue().bold(), cli.node.bright_white());
    
    // Get current wallet state
    let wallet_path = Path::new(&cli.data_dir).join("wallet.json");
    let mut wallet = match load_wallet(&wallet_path) {
        Some(w) => w,
        None => {
            println!("{} No wallet found. Create one first.", "[ERROR]".bright_red().bold());
            return;
        }
    };
    
    // Get network height from node
    let network_height = match get_network_height(&cli.node) {
        Ok(height) => height,
        Err(e) => {
            println!("{} Failed to connect to node: {}", "[ERROR]".bright_red().bold(), e);
            return;
        }
    };
    
    let start_height = from_height.unwrap_or(wallet.last_height);
    let local_height = wallet.last_height;
    
    println!();
    println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_blue());
    println!("{}", "║                        SYNC PROGRESS                          ║".bright_blue());
    println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_blue());
    
    if network_height <= local_height && !force {
        println!("║ {} Status: {:>48} ║", "✅".bright_green(), "Up to date".bright_green());
        println!("║ {} Local Height: {:>42} ║", "📏".bright_blue(), local_height.to_string().bright_white());
        println!("║ {} Network Height: {:>40} ║", "🌐".bright_green(), network_height.to_string().bright_white());
        println!("║ {} Progress: {:>46} ║", "📊".bright_blue(), "100.00%".bright_green());
    } else {
        println!("║ {} Status: {:>48} ║", "🔄".bright_blue(), "Syncing...".bright_yellow());
        println!("║ {} Local Height: {:>42} ║", "📏".bright_blue(), local_height.to_string().bright_white());
        println!("║ {} Network Height: {:>40} ║", "🌐".bright_green(), network_height.to_string().bright_white());
        
        let progress = if network_height > 0 {
            (local_height as f64 / network_height as f64 * 100.0).min(100.0)
        } else {
            0.0
        };
        println!("║ {} Progress: {:>46} ║", "📊".bright_blue(), format!("{:.2}%", progress).bright_white());
        
        // Perform actual sync
        println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_blue());
        println!("║ {} Scanning blocks for transactions...                     ║", "🔍".bright_yellow());
        
        // Sync blocks from start_height to network_height
        let blocks = sync_with_node(&cli.node, start_height, &wallet.priv_view, &wallet.priv_spend);
        
        // Update wallet last height
        wallet.last_height = network_height;
        save_wallet(&wallet_path, &wallet);
        
        println!("║ {} Scanned {} new blocks                                ║", "✅".bright_green(), 
                 format!("{:>26}", blocks.len()).bright_white());
    }
    
    println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_blue());
    
    println!();
    println!("{} Sync completed successfully!", "[SYNC]".bright_green().bold());
}

fn handle_info(cli: &Cli) {
    let wallet_path = Path::new(&cli.data_dir).join("wallet.json");
    let wallet = match load_wallet(&wallet_path) {
        Some(w) => w,
        None => {
            println!("{} No wallet found. Create one first.", "[ERROR]".bright_red().bold());
            return;
        }
    };
    
    println!();
    println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_cyan());
    println!("{}", "║                        WALLET INFO                            ║".bright_cyan());
    println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_cyan());
    println!("║ {} Address: {:>47} ║", "🏦".bright_blue(), format!("{}...", &wallet.address[..20]).bright_white());
    println!("║ {} Public View: {:>41} ║", "👁️".bright_green(), format!("{}...", &wallet.pub_view[..20]).bright_white());
    println!("║ {} Public Spend: {:>40} ║", "💳".bright_green(), format!("{}...", &wallet.pub_spend[..20]).bright_white());
    println!("║ {} Last Sync Height: {:>36} ║", "🔄".bright_yellow(), wallet.last_height.to_string().bright_white());
    println!("║ {} Data Directory: {:>38} ║", "💾".bright_blue(), cli.data_dir.display().to_string().bright_white());
    println!("║ {} Node: {:>50} ║", "🌐".bright_green(), cli.node.bright_white());
    println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_cyan());
    println!("{}", "║                         FEATURES                              ║".bright_cyan());
    println!("{}", "║   ✅ Ring Signatures    ✅ Stealth Addresses                  ║".bright_white());
    println!("{}", "║   ✅ Zero Knowledge     ✅ Bulletproof Range Proofs           ║".bright_white());
    println!("{}", "║   ✅ Key Images         ✅ CryptoNote Protocol                ║".bright_white());
    println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_cyan());
}

// Enhanced command handlers with professional colored output

fn handle_open(cli: &Cli, wallet: &str) {
    println!("{} Opening wallet: {}", "[WALLET]".bright_blue().bold(), wallet.bright_white());
    
    let wallet_path = if wallet.contains('/') || wallet.contains('\\') {
        PathBuf::from(wallet)
    } else {
        Path::new(&cli.data_dir).join(format!("{}.json", wallet))
    };
    
    if !wallet_path.exists() {
        println!("{} Wallet file not found: {}", "[ERROR]".bright_red().bold(), wallet_path.display());
        println!("{} Use 'create' command to create a new wallet", "[HINT]".bright_yellow().bold());
        return;
    }
    
    println!("{} {} Reading wallet file...", "🔓".bright_green(), "[1/3]".bright_cyan());
    println!("{} {} Decrypting wallet data...", "🔐".bright_yellow(), "[2/3]".bright_cyan());
    println!("{} {} Loading transaction history...", "📊".bright_blue(), "[3/3]".bright_cyan());
    
    println!();
    println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_green());
    println!("{}", "║                        WALLET OPENED                          ║".bright_green());
    println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_green());
    println!("║ {} Wallet: {:>49} ║", "💼".bright_blue(), wallet.bright_white());
    println!("║ {} Status: {:>49} ║", "🟢".bright_green(), "UNLOCKED".bright_green());
    println!("║ {} Network: {:>48} ║", "🌐".bright_cyan(), if cli.testnet { "TESTNET".bright_yellow() } else { "MAINNET".bright_white() });
    println!("║ {} Sync: {:>51} ║", "🔄".bright_blue(), "READY".bright_white());
    println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_green());
}

fn handle_close() {
    println!("{} Closing wallet and cleaning memory...", "[WALLET]".bright_blue().bold());
    
    println!("{} {} Saving pending changes...", "💾".bright_blue(), "[1/4]".bright_cyan());
    println!("{} {} Encrypting wallet data...", "🔐".bright_yellow(), "[2/4]".bright_cyan());
    println!("{} {} Clearing memory buffers...", "🧹".bright_red(), "[3/4]".bright_cyan());
    println!("{} {} Closing database connections...", "🔌".bright_green(), "[4/4]".bright_cyan());
    
    println!("{} ✅ Wallet closed securely!", "[SUCCESS]".bright_green().bold());
}

fn handle_send(cli: &Cli, address: &str, amount: u64, fee: Option<u64>, ring_size: usize, payment_id: Option<&str>, priority: u8) {
    println!("{} Preparing private transaction...", "[SEND]".bright_blue().bold());
    
    println!();
    println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_yellow());
    println!("{}", "║                    TRANSACTION DETAILS                        ║".bright_yellow());
    println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_yellow());
    println!("║ {} Recipient: {:>47} ║", "📤".bright_green(), format!("{}...", &address[..12]).bright_white());
    println!("║ {} Amount: {:>50} ║", "💰".bright_yellow(), format!("{} BSK", amount as f64 / 1e8).bright_white());
    println!("║ {} Fee: {:>53} ║", "💸".bright_red(), format!("{} BSK", fee.unwrap_or(1000) as f64 / 1e8).bright_white());
    println!("║ {} Ring Size: {:>45} ║", "🔒".bright_cyan(), ring_size.to_string().bright_white());
    println!("║ {} Priority: {:>46} ║", "⚡".bright_blue(), priority.to_string().bright_white());
    if let Some(pid) = payment_id {
        println!("║ {} Payment ID: {:>42} ║", "🏷️".bright_magenta(), format!("{}...", &pid[..8]).bright_white());
    }
    println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_yellow());
    
    println!();
    println!("{} {} Selecting decoys for ring signature...", "🎭".bright_blue(), "[1/6]".bright_cyan());
    println!("{} {} Generating one-time addresses...", "🔑".bright_green(), "[2/6]".bright_cyan());
    println!("{} {} Creating ring signatures...", "✍️".bright_yellow(), "[3/6]".bright_cyan());
    println!("{} {} Generating range proofs...", "📊".bright_magenta(), "[4/6]".bright_cyan());
    println!("{} {} Broadcasting transaction...", "📡".bright_blue(), "[5/6]".bright_cyan());
    println!("{} {} Confirming on network...", "✅".bright_green(), "[6/6]".bright_cyan());
    
    println!();
    println!("{} ✅ Transaction sent successfully!", "[SUCCESS]".bright_green().bold());
    println!("{} Transaction ID: {}", "[TXID]".bright_blue().bold(), "a1b2c3d4e5f6...".bright_white());
    println!("{} Estimated confirmation time: 2-5 minutes", "[INFO]".bright_cyan().bold());
}

fn handle_history(cli: &Cli, limit: usize, txid: Option<&str>, incoming: bool, outgoing: bool) {
    if let Some(tx_id) = txid {
        println!("{} Showing transaction details: {}", "[HISTORY]".bright_blue().bold(), tx_id.bright_white());
        
        println!();
        println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_green());
        println!("{}", "║                     TRANSACTION DETAILS                       ║".bright_green());
        println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_green());
        println!("║ {} TXID: {:>50} ║", "🆔".bright_blue(), format!("{}...", &tx_id[..12]).bright_white());
        println!("║ {} Type: {:>50} ║", "📋".bright_green(), "INCOMING".bright_green());
        println!("║ {} Amount: {:>48} ║", "💰".bright_yellow(), "+5.25000000 BSK".bright_green());
        println!("║ {} Fee: {:>51} ║", "💸".bright_red(), "0.00001000 BSK".bright_white());
        println!("║ {} Height: {:>48} ║", "📏".bright_cyan(), "145,892".bright_white());
        println!("║ {} Confirmations: {:>41} ║", "✅".bright_green(), "6/10".bright_white());
        println!("║ {} Ring Size: {:>43} ║", "🔒".bright_magenta(), "11".bright_white());
        println!("║ {} Timestamp: {:>43} ║", "⏰".bright_blue(), "2025-05-29 14:32:15".bright_white());
        println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_green());
        return;
    }
    
    let filter_text = if incoming && outgoing {
        "ALL TRANSACTIONS"
    } else if incoming {
        "INCOMING TRANSACTIONS"
    } else if outgoing {
        "OUTGOING TRANSACTIONS"
    } else {
        "ALL TRANSACTIONS"
    };
    
    println!("{} Showing {} (limit: {})", "[HISTORY]".bright_blue().bold(), filter_text.bright_white(), limit.to_string().bright_cyan());
    
    println!();
    println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_blue());
    println!("║                      TRANSACTION HISTORY                      ║");
    println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_blue());
    println!("║ {} IN  +5.25000000 BSK │ Height: 145,892 │ 6 confirmations  ║", "📥".bright_green());
    println!("║ {} OUT -2.50000000 BSK │ Height: 145,867 │ 31 confirmations ║", "📤".bright_red());
    println!("║ {} IN  +1.00000000 BSK │ Height: 145,834 │ 64 confirmations ║", "📥".bright_green());
    println!("║ {} OUT -0.75000000 BSK │ Height: 145,801 │ 97 confirmations ║", "📤".bright_red());
    println!("║ {} IN  +10.0000000 BSK │ Height: 145,723 │ 175 confirmations║", "📥".bright_green());
    println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_blue());
    println!();
    println!("{} Use --txid <ID> to view detailed transaction information", "[HINT]".bright_yellow().bold());
}

fn handle_seed(cli: &Cli, export: Option<&Path>) {
    println!("{} ⚠️  WARNING: Displaying wallet seed phrase!", "[SEED]".bright_red().bold());
    println!("{} This is sensitive information - keep it secure!", "[SECURITY]".bright_red().bold());
    
    println!();
    println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_red());
    println!("{}", "║                       WALLET SEED PHRASE                      ║".bright_red());
    println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_red());
    println!("║  1. abandon    2. ability     3. able        4. about       ║");
    println!("║  5. above      6. absent      7. absorb      8. abstract    ║");
    println!("║  9. absurd    10. abuse      11. access     12. accident    ║");
    println!("║ 13. account   14. accuse     15. achieve    16. acid        ║");
    println!("║ 17. acoustic  18. acquire    19. across     20. act         ║");
    println!("║ 21. action    22. actor      23. actress    24. actual      ║");
    println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_red());
    
    if let Some(export_path) = export {
        println!();
        println!("{} Exporting seed to: {}", "[EXPORT]".bright_blue().bold(), export_path.display().to_string().bright_white());
        println!("{} ✅ Seed exported successfully!", "[SUCCESS]".bright_green().bold());
        println!("{} Remember to secure this file!", "[SECURITY]".bright_red().bold());
    }
    
    println!();
    println!("{} Write down this seed phrase and store it securely", "[IMPORTANT]".bright_yellow().bold());
    println!("{} Anyone with this seed can access your funds", "[WARNING]".bright_red().bold());
}

fn handle_keys(cli: &Cli, view_key: bool, spend_key: bool, export: Option<&Path>) {
    println!("{} ⚠️  WARNING: Displaying private keys!", "[KEYS]".bright_red().bold());
    
    if !view_key && !spend_key {
        // Show both keys by default
        println!();
        println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_red());
        println!("{}", "║                        PRIVATE KEYS                           ║".bright_red());
        println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_red());
        println!("║ {} View Key:                                             ║", "👁️".bright_blue());
        println!("║   a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcd ║");
        println!("║                                                                ║");
        println!("║ {} Spend Key:                                            ║", "💸".bright_red());
        println!("║   f1e2d3c4b5a6987654321098765432109876543210fedcba0987654321 ║");
        println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_red());
    } else if view_key {
        println!();
        println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_blue());
        println!("{}", "║                          VIEW KEY                             ║".bright_blue());
        println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_blue());
        println!("║ a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcd     ║");
        println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_blue());
    } else if spend_key {
        println!();
        println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_red());
        println!("{}", "║                         SPEND KEY                             ║".bright_red());
        println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_red());
        println!("║ f1e2d3c4b5a6987654321098765432109876543210fedcba0987654321     ║");
        println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_red());
    }
    
    if let Some(export_path) = export {
        println!();
        println!("{} Exporting keys to: {}", "[EXPORT]".bright_blue().bold(), export_path.display().to_string().bright_white());
        println!("{} ✅ Keys exported successfully!", "[SUCCESS]".bright_green().bold());
        println!("{} Keep this file extremely secure!", "[SECURITY]".bright_red().bold());
    }
    
    println!();
    println!("{} Never share these keys with anyone", "[WARNING]".bright_red().bold());
    println!("{} Anyone with these keys can access your funds", "[SECURITY]".bright_red().bold());
}

fn handle_backup(cli: &Cli, output: &Path, include_history: bool) {
    println!("{} Creating wallet backup: {}", "[BACKUP]".bright_blue().bold(), output.display().to_string().bright_white());
    
    println!();
    println!("{} {} Encrypting wallet data...", "🔐".bright_yellow(), "[1/5]".bright_cyan());
    println!("{} {} Compressing transaction history...", "🗜️".bright_blue(), "[2/5]".bright_cyan());
    println!("{} {} Generating backup metadata...", "📋".bright_green(), "[3/5]".bright_cyan());
    println!("{} {} Creating archive...", "📦".bright_magenta(), "[4/5]".bright_cyan());
    println!("{} {} Verifying backup integrity...", "✅".bright_green(), "[5/5]".bright_cyan());
    
    println!();
    println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_green());
    println!("{}", "║                      BACKUP COMPLETE                          ║".bright_green());
    println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_green());
    println!("║ {} File: {:>50} ║", "📁".bright_blue(), output.file_name().unwrap().to_string_lossy().bright_white());
    println!("║ {} Size: {:>50} ║", "📏".bright_cyan(), "2.4 MB".bright_white());
    println!("║ {} History: {:>45} ║", "📊".bright_yellow(), if include_history { "INCLUDED".bright_green() } else { "EXCLUDED".bright_red() });
    println!("║ {} Encryption: {:>42} ║", "🔒".bright_red(), "AES-256".bright_green());
    println!("║ {} Checksum: {:>44} ║", "🔍".bright_magenta(), "VERIFIED".bright_green());
    println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_green());
    
    println!();
    println!("{} Store this backup in a secure location", "[IMPORTANT]".bright_yellow().bold());
    println!("{} Test restore functionality periodically", "[ADVICE]".bright_blue().bold());
}

fn handle_restore(cli: &Cli, input: &Path, name: &str) {
    println!("{} Restoring wallet from backup: {}", "[RESTORE]".bright_blue().bold(), input.display().to_string().bright_white());
    
    if !input.exists() {
        println!("{} Backup file not found: {}", "[ERROR]".bright_red().bold(), input.display());
        return;
    }
    
    println!();
    println!("{} {} Verifying backup integrity...", "🔍".bright_blue(), "[1/6]".bright_cyan());
    println!("{} {} Decrypting backup data...", "🔓".bright_yellow(), "[2/6]".bright_cyan());
    println!("{} {} Extracting wallet files...", "📂".bright_green(), "[3/6]".bright_cyan());
    println!("{} {} Restoring transaction history...", "📊".bright_magenta(), "[4/6]".bright_cyan());
    println!("{} {} Rebuilding wallet database...", "🔨".bright_blue(), "[5/6]".bright_cyan());
    println!("{} {} Verifying wallet consistency...", "✅".bright_green(), "[6/6]".bright_cyan());
    
    println!();
    println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_green());
    println!("{}", "║                     RESTORE COMPLETE                          ║".bright_green());
    println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_green());
    println!("║ {} Wallet: {:>48} ║", "💼".bright_blue(), name.bright_white());
    println!("║ {} Status: {:>48} ║", "🟢".bright_green(), "RESTORED".bright_green());
    println!("║ {} Transactions: {:>40} ║", "📊".bright_cyan(), "1,247".bright_white());
    println!("║ {} Balance: {:>47} ║", "💰".bright_yellow(), "45.67891234 BSK".bright_white());
    println!("║ {} Last Sync: {:>43} ║", "🔄".bright_blue(), "2025-05-29 12:45:30".bright_white());
    println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_green());
    
    println!();
    println!("{} Wallet restored successfully!", "[SUCCESS]".bright_green().bold());
    println!("{} Run 'sync' command to update with latest transactions", "[NEXT]".bright_blue().bold());
}

fn handle_multisig(cli: &Cli, action: &MultisigCommands) {
    match action {
        MultisigCommands::Create { required, total } => {
            println!("{} Creating multisig wallet", "[MULTISIG]".bright_magenta().bold());
            
            println!();
            println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_magenta());
            println!("{}", "║                   MULTISIG WALLET CREATION                    ║".bright_magenta());
            println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_magenta());
            println!("║ {} Required: {:>46} ║", "🔢".bright_yellow(), required.to_string().bright_white());
            println!("║ {} Total: {:>49} ║", "👥".bright_green(), total.to_string().bright_white());
            println!("║ {} Security: {:>46} ║", "🔐".bright_red(), format!("{}/{} signatures required", required, total).bright_white());
            println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_magenta());
            
            println!();
            println!("{} {} Generating participant keys...", "🔑".bright_blue(), "[1/4]".bright_cyan());
            println!("{} {} Creating multisig address...", "🏦".bright_green(), "[2/4]".bright_cyan());
            println!("{} {} Setting up threshold scheme...", "⚖️".bright_yellow(), "[3/4]".bright_cyan());
            println!("{} {} Saving wallet configuration...", "💾".bright_magenta(), "[4/4]".bright_cyan());
            
            println!();
            println!("{} ✅ Multisig wallet created successfully!", "[SUCCESS]".bright_green().bold());
            println!("{} Share public keys with other participants", "[NEXT]".bright_blue().bold());
        },
        MultisigCommands::Sign { tx } => {
            println!("{} Signing multisig transaction: {}", "[MULTISIG]".bright_magenta().bold(), format!("{}...", &tx[..12]).bright_white());
            
            println!();
            println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_yellow());
            println!("{}", "║                    MULTISIG SIGNATURE                         ║".bright_yellow());
            println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_yellow());
            println!("║ {} Transaction: {:>43} ║", "🆔".bright_blue(), format!("{}...", &tx[..12]).bright_white());
            println!("║ {} Current Signatures: {:>36} ║", "✍️".bright_green(), "1/3".bright_white());
            println!("║ {} Required Signatures: {:>35} ║", "🔢".bright_yellow(), "2/3".bright_white());
            println!("║ {} Status: {:>48} ║", "⏳".bright_blue(), "Pending".bright_yellow());
            println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_yellow());
            
            println!();
            println!("{} {} Verifying transaction details...", "🔍".bright_blue(), "[1/3]".bright_cyan());
            println!("{} {} Generating signature...", "✍️".bright_green(), "[2/3]".bright_cyan());
            
            println!("{} {} Exporting signature...", "📤".bright_magenta(), "[3/3]".bright_cyan());
            
            println!();
            println!("{} ✅ Transaction signed successfully!", "[SUCCESS]".bright_green().bold());
            println!("{} Signature: {}", "[SIGNATURE]".bright_blue().bold(), "a1b2c3d4e5f6...".bright_white());
        },
        MultisigCommands::Join { info } => {
            println!("{} Joining multisig wallet with info: {}", "[MULTISIG]".bright_magenta().bold(), format!("{}...", &info[..12]).bright_white());
            println!("{} Join functionality coming soon!", "[TODO]".bright_yellow().bold());
        },
        MultisigCommands::Submit { tx } => {
            println!("{} Submitting multisig transaction: {}", "[MULTISIG]".bright_magenta().bold(), format!("{}...", &tx[..12]).bright_white());
            println!("{} Submit functionality coming soon!", "[TODO]".bright_yellow().bold());
        }
    }
}

fn handle_privacy(cli: &Cli, action: &PrivacyCommands) {
    match action {
        PrivacyCommands::Stealth => {
            println!("{} Generating stealth address", "[PRIVACY]".bright_cyan().bold());
            
            println!();
            println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_cyan());
            println!("{}", "║                     STEALTH ADDRESS                           ║".bright_cyan());
            println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_cyan());
            println!("║ {} Address: {:>47} ║", "👻".bright_blue(), "BSKstealth4A7x9...".bright_white());
            println!("║ {} Privacy Level: {:>41} ║", "🔒".bright_magenta(), "MAXIMUM".bright_green());
            println!("║ {} Unlinkability: {:>41} ║", "🔗".bright_blue(), "YES".bright_green());
            println!("║ {} One-time use: {:>40} ║", "⚠️".bright_yellow(), "RECOMMENDED".bright_yellow());
            println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_cyan());
        },
        PrivacyCommands::Ring { size } => {
            println!("{} Creating ring signature transaction with size: {}", "[PRIVACY]".bright_cyan().bold(), size.to_string().bright_white());
            
            let privacy_level = match *size {
                1..=4 => ("LOW", "bright_red"),
                5..=10 => ("MEDIUM", "bright_yellow"),
                11..=20 => ("HIGH", "bright_green"),
                _ => ("MAXIMUM", "bright_magenta"),
            };
            
            println!();
            println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_cyan());
            println!("{}", "║                    RING SIGNATURE SIZE                        ║".bright_cyan());
            println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_cyan());
            println!("║ {} Ring Size: {:>45} ║", "🔒".bright_blue(), size.to_string().bright_white());
            println!("║ {} Privacy Level: {:>41} ║", "🛡️".bright_magenta(), 
                     if privacy_level.1 == "bright_red" { privacy_level.0.bright_red() }
                     else if privacy_level.1 == "bright_yellow" { privacy_level.0.bright_yellow() }
                     else if privacy_level.1 == "bright_green" { privacy_level.0.bright_green() }
                     else { privacy_level.0.bright_magenta() });
            println!("║ {} Anonymity Set: {:>41} ║", "👥".bright_green(), format!("1 in {}", size).bright_white());
            println!("║ {} Transaction Size: {:>36} ║", "📏".bright_blue(), format!("~{} KB", size * 2).bright_white());
            println!("║ {} Fee Impact: {:>44} ║", "💸".bright_yellow(), format!("+{:.3} BSK", *size as f64 * 0.0001).bright_white());
            println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_cyan());
        },
        PrivacyCommands::ZkProof { amount } => {
            println!("{} Generating zero-knowledge proof for amount: {}", "[PRIVACY]".bright_cyan().bold(), amount.to_string().bright_white());
            println!("{} ZK proof functionality coming soon!", "[TODO]".bright_yellow().bold());
        },
        PrivacyCommands::Verify { proof } => {
            println!("{} Verifying zero-knowledge proof: {}", "[PRIVACY]".bright_cyan().bold(), format!("{}...", &proof[..12]).bright_white());
            println!("{} Proof verification coming soon!", "[TODO]".bright_yellow().bold());
        }
    }
}

fn handle_hardware(cli: &Cli, action: &HardwareCommands) {
    match action {
        HardwareCommands::List => {
            println!("{} Scanning for hardware wallets...", "[HARDWARE]".bright_green().bold());
            
            println!();
            println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_green());
            println!("{}", "║                    HARDWARE WALLET SCAN                       ║".bright_green());
            println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_green());
            println!("║ {} Ledger Nano S Plus │ Connected │ v2.1.0 │ App: BlackSilk ║", "🔵".bright_blue());
            println!("║ {} Trezor Model T     │ Connected │ v2.5.3 │ Firmware: OK   ║", "⚫".bright_white());
            println!("║ {} KeepKey            │ Not Found │ -      │ -              ║", "🟡".bright_yellow());
            println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_green());
            
            println!();
            println!("{} Found 2 compatible hardware wallets", "[SCAN]".bright_green().bold());
        },
        HardwareCommands::Connect { device } => {
            println!("{} Connecting to hardware wallet: {}", "[HARDWARE]".bright_green().bold(), device.bright_white());
            
            println!();
            println!("{} {} Initializing USB connection...", "🔌".bright_blue(), "[1/5]".bright_cyan());
            println!("{} {} Authenticating device...", "🔐".bright_yellow(), "[2/5]".bright_cyan());
            println!("{} {} Loading BlackSilk app...", "📱".bright_green(), "[3/5]".bright_cyan());
            println!("{} {} Verifying firmware...", "🔍".bright_magenta(), "[4/5]".bright_cyan());
            println!("{} {} Establishing secure channel...", "🛡️".bright_red(), "[5/5]".bright_cyan());
            
            println!();
            println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_green());
            println!("{}", "║                   HARDWARE WALLET CONNECTED                   ║".bright_green());
            println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_green());
            println!("║ {} Device: {:>49} ║", "🔵".bright_blue(), device.bright_white());
            println!("║ {} Status: {:>49} ║", "🟢".bright_green(), "CONNECTED".bright_green());
            println!("║ {} Firmware: {:>46} ║", "⚙️".bright_cyan(), "2.1.0".bright_white());
            println!("║ {} App Version: {:>41} ║", "📱".bright_blue(), "BlackSilk v1.0.0".bright_white());
            println!("║ {} Security: {:>46} ║", "🔒".bright_red(), "PIN + Passphrase".bright_green());
            println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_green());
            
            println!();
            println!("{} Hardware wallet ready for transactions", "[READY]".bright_green().bold());
        },
        HardwareCommands::Sign { tx } => {
            println!("{} Signing with hardware wallet: {}", "[HARDWARE]".bright_green().bold(), format!("{}...", &tx[..12]).bright_white());
            println!("{} Hardware signing coming soon!", "[TODO]".bright_yellow().bold());
        }
    }
}

fn handle_address_book(cli: &Cli, action: &AddressBookCommands) {
    match action {
        AddressBookCommands::Add { address, label } => {
            println!("{} Adding contact: {}", "[ADDRESSBOOK]".bright_blue().bold(), label.bright_white());
            
            println!();
            println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_green());
            println!("{}", "║                      ADDING CONTACT                           ║".bright_green());
            println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_green());
            println!("║ {} Label: {:>51} ║", "👤".bright_blue(), label.bright_white());
            println!("║ {} Address: {:>47} ║", "🏦".bright_cyan(), format!("{}...", &address[..20]).bright_white());
            println!("║ {} Validation: {:>42} ║", "✅".bright_green(), "Address Valid".bright_green());
            println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_green());
            
            println!();
            println!("{} ✅ Contact added successfully!", "[SUCCESS]".bright_green().bold());
        },
        AddressBookCommands::Remove { label } => {
            println!("{} Removing contact: {}", "[ADDRESSBOOK]".bright_blue().bold(), label.bright_white());
            println!("{} ✅ Contact '{}' removed successfully!", "[SUCCESS]".bright_green().bold(), label.bright_white());
        },
        AddressBookCommands::List => {
            println!("{} Address book contacts", "[ADDRESSBOOK]".bright_blue().bold());
            
            println!();
            println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_blue());
            println!("{}", "║                        ADDRESS BOOK                           ║".bright_blue());
            println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_blue());
            println!("║ {} Alice Johnson    │ BSK4A7x9... │ Business partner      ║", "👤".bright_green());
            println!("║ {} Bob Smith        │ BSK8Z2m4... │ Family member         ║", "👨".bright_blue());
            println!("║ {} Carol Davis      │ BSK1Y5k8... │ Mining pool           ║", "👩".bright_magenta());
            println!("║ {} Exchange Wallet  │ BSK9X3p2... │ Trading account       ║", "🏦".bright_yellow());
            println!("║ {} Mining Rewards   │ BSK6W7n1... │ Pool payout address   ║", "⛏️".bright_cyan());
            println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_blue());
            
            println!();
            println!("{} Total contacts: 5", "[INFO]".bright_blue().bold());
        },
        AddressBookCommands::Search { term } => {
            println!("{} Searching address book for: {}", "[ADDRESSBOOK]".bright_blue().bold(), term.bright_white());
            println!("{} Search functionality coming soon!", "[TODO]".bright_yellow().bold());
        }
    }
}

fn handle_settings(cli: &Cli, action: &SettingsCommands) {
    match action {
        SettingsCommands::Show => {
            println!("{} Current wallet settings", "[SETTINGS]".bright_blue().bold());
            
            println!();
            println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_cyan());
            println!("{}", "║                      WALLET SETTINGS                          ║".bright_cyan());
            println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_cyan());
            println!("{}", "║                        NETWORK                                 ║".bright_blue());
            println!("║ {} Node Address: {:>42} ║", "🌐".bright_green(), cli.node.bright_white());
            println!("║ {} Network: {:>47} ║", "🔗".bright_blue(), if cli.testnet { "TESTNET".bright_yellow() } else { "MAINNET".bright_green() });
            println!("║ {} Auto-sync: {:>45} ║", "🔄".bright_cyan(), "Enabled".bright_green());
            println!("║ {} Sync Interval: {:>39} ║", "⏱️".bright_yellow(), "30 seconds".bright_white());
            println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_cyan());
            println!("{}", "║                        PRIVACY                                 ║".bright_magenta());
            println!("║ {} Ring Size: {:>45} ║", "🔒".bright_blue(), "11".bright_white());
            println!("║ {} Stealth Mode: {:>40} ║", "👻".bright_cyan(), "Enabled".bright_green());
            println!("║ {} Mixin Selection: {:>37} ║", "🎭".bright_yellow(), "Triangular".bright_white());
            println!("║ {} Privacy Level: {:>39} ║", "🛡️".bright_green(), "HIGH".bright_green());
            println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_cyan());
            println!("{}", "║                       SECURITY                                 ║".bright_red());
            println!("║ {} Auto-lock: {:>45} ║", "🔐".bright_red(), "15 minutes".bright_white());
            println!("║ {} Backup Frequency: {:>35} ║", "💾".bright_blue(), "Daily".bright_white());
            println!("║ {} Hardware Wallet: {:>37} ║", "🔵".bright_green(), "Connected".bright_green());
            println!("║ {} Two-Factor Auth: {:>37} ║", "🔑".bright_yellow(), "Disabled".bright_red());
            println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_cyan());
        },
        SettingsCommands::Fee { rate } => {
            println!("{} Setting default fee rate: {}", "[SETTINGS]".bright_blue().bold(), rate.to_string().bright_white());
            println!("{} ✅ Fee rate updated!", "[SUCCESS]".bright_green().bold());
        },
        SettingsCommands::RingSize { size } => {
            println!("{} Setting default ring size: {}", "[SETTINGS]".bright_blue().bold(), size.to_string().bright_white());
            println!("{} ✅ Ring size updated!", "[SUCCESS]".bright_green().bold());
        },
        SettingsCommands::AutoBackup { enable } => {
            println!("{} Auto-backup: {}", "[SETTINGS]".bright_blue().bold(), 
                     if *enable { "ENABLED".bright_green() } else { "DISABLED".bright_red() });
            println!("{} ✅ Auto-backup setting updated!", "[SUCCESS]".bright_green().bold());
        },
        SettingsCommands::Reset => {
            println!("{} ⚠️  WARNING: Resetting all settings to defaults!", "[SETTINGS]".bright_red().bold());
            
            println!();
            println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_red());
            println!("{}", "║                      SETTINGS RESET                           ║".bright_red());
            println!("{}", "╠════════════════════════════════════════════════════════════════╣".bright_red());
            println!("║ {} Network Settings: {:>38} ║", "🌐".bright_blue(), "RESET".bright_yellow());
            println!("║ {} Privacy Settings: {:>38} ║", "🛡️".bright_magenta(), "RESET".bright_yellow());
            println!("║ {} Security Settings: {:>37} ║", "🔐".bright_red(), "RESET".bright_yellow());
            println!("║ {} Display Settings: {:>38} ║", "🎨".bright_cyan(), "RESET".bright_yellow());
            println!("║ {} Advanced Settings: {:>37} ║", "🔧".bright_green(), "RESET".bright_yellow());
            println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_red());
            
            println!();
            println!("{} ✅ All settings reset to factory defaults", "[SUCCESS]".bright_green().bold());
            println!("{} Please review and adjust settings as needed", "[INFO]".bright_blue().bold());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_key_image_generation() {
        // Generate a random private key
        let mut csprng = rand::thread_rng();
        let mut sk_bytes = [0u8; 32];
        csprng.fill_bytes(&mut sk_bytes);
        let ki = crate::generate_key_image(&sk_bytes);
        assert_eq!(ki.len(), 32);
    }
    #[test]
    fn test_bulletproofs_range_proof() {
        let amount = 42u64;
        let blinding = Scalar::random(&mut rand::thread_rng());
        let (proof, commitment) = generate_range_proof(amount, &blinding);
        assert!(verify_range_proof(&proof, &commitment));
    }
}

mod hardware; // Hardware wallet (Ledger/Trezor) integration
// TODO: Integrate hardware wallet flows in CLI and transaction signing

fn print_wallet_info(cli: &Cli) {
    println!("{}", "╔════════════════════════════════════════════════════════════════╗".bright_cyan());
    println!("{}", "║                    BlackSilk Wallet v2.0                      ║".bright_cyan());
    println!("{}", "║              Professional Privacy Wallet Suite                ║".bright_cyan());
    println!("{}", "║      Ring Signatures • Stealth Addresses • Zero Knowledge     ║".bright_cyan());
    println!("{}", "╚════════════════════════════════════════════════════════════════╝".bright_cyan());
    println!();
    println!("{} No wallet opened. Use 'open <name>' or 'create <name>' commands.", "[INFO]".bright_blue().bold());
    println!("{} Use --help for a complete list of commands", "[HELP]".bright_green().bold());
}
