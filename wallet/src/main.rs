mod hardware; // Hardware wallet (Ledger/Trezor) integration

use std::env;
use rand::rngs::OsRng;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use rand::RngCore;
use sha2::{Sha256, Digest};
use clap::{Parser};
use std::path::PathBuf;
use bip39::Mnemonic;
use base58::{ToBase58};
use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};
use primitives::{Transaction, TransactionInput, TransactionOutput, Block};
use itertools::Itertools;

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
#[clap(name = "blacksilk-wallet", version, about = "BlackSilk Privacy Wallet")]
pub struct Cli {
    /// Data directory for wallet state
    #[arg(long, default_value = "./wallet_data", value_name = "DIR")]
    pub data_dir: PathBuf,

    /// Send coins to address (amount: in atomic units)
    #[arg(long, value_name = "ADDR", requires = "amount")]
    pub send: Option<String>,
    #[arg(long, value_name = "AMOUNT", requires = "send")]
    pub amount: Option<u64>,

    /// Show wallet balance
    #[arg(long)]
    pub balance: bool,

    /// Generate and show a new address, private keys, and mnemonic seed
    #[arg(long)]
    pub generate: bool,

    /// Show the mnemonic seed for the current wallet
    #[arg(long)]
    pub show_seed: bool,

    /// Show the private keys for the current wallet
    #[arg(long)]
    pub show_keys: bool,

    /// Node address to connect for sync (default: 127.0.0.1:8333)
    #[arg(long, default_value = "127.0.0.1:8333", value_name = "ADDR")]
    pub node: String,
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
fn is_output_mine(out: &primitives::TransactionOutput, my_pub_view: &[u8; 32], my_pub_spend: &[u8; 32], my_priv_view: &[u8; 32]) -> bool {
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

fn scan_blocks_for_balance(blocks: &[Block], my_pub_view: &[u8; 32], my_pub_spend: &[u8; 32], my_priv_view: &[u8; 32]) -> u64 {
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
fn get_spendable_outputs<'a>(blocks: &'a [Block], my_pub_view: &[u8; 32], my_pub_spend: &[u8; 32], my_priv_view: &[u8; 32]) -> Vec<&'a primitives::TransactionOutput> {
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
    use primitives::types::Hash;
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

fn sync_with_node(node_addr: &str, last_height: u64, my_pub_view: &[u8; 32], my_pub_spend: &[u8; 32]) -> Vec<Block> {
    let url = format!("http://{}/get_blocks?from_height={}", node_addr, last_height);
    let mut retries = 3;

    while retries > 0 {
        match reqwest::blocking::get(&url) {
            Ok(resp) => {
                if resp.status().is_success() {
                    let text = resp.text().unwrap_or_default();
                    let blocks: Vec<Block> = serde_json::from_str(&text).unwrap_or_else(|_| {
                        eprintln!("[Wallet] Error: Failed to parse blocks from node response");
                        vec![]
                    });
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
    let wallet_path = Path::new(&cli.data_dir).join("wallet.json");
    if cli.generate {
        // Generate new wallet and save
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        let phrase = mnemonic.to_string();
        let priv_spend = Scalar::from_bytes_mod_order(entropy);
        let priv_view = Scalar::from_bytes_mod_order(sha2::Sha256::digest(&entropy).into());
        let pub_spend = (ED25519_BASEPOINT_POINT * priv_spend).compress().to_bytes();
        let pub_view = (ED25519_BASEPOINT_POINT * priv_view).compress().to_bytes();
        let address = encode_address(&pub_view, &pub_spend);
        let wallet = WalletFile {
            mnemonic: phrase.clone(),
            priv_spend: hex::encode(priv_spend.to_bytes()),
            priv_view: hex::encode(priv_view.to_bytes()),
            pub_spend: hex::encode(pub_spend),
            pub_view: hex::encode(pub_view),
            last_height: 0,
            address: address.clone(),
        };
        fs::create_dir_all(&cli.data_dir).ok();
        save_wallet(&wallet_path, &wallet);
        println!("[BlackSilk Wallet] Generated new address: {}", address);
        println!("[BlackSilk Wallet] Private spend key: {}", wallet.priv_spend);
        println!("[BlackSilk Wallet] Private view key: {}", wallet.priv_view);
        println!("[BlackSilk Wallet] Mnemonic seed: {}", wallet.mnemonic);
        return;
    }
    let wallet = match load_wallet(&wallet_path) {
        Some(w) => w,
        None => {
            println!("[BlackSilk Wallet] No wallet found. Please run with --generate first.");
            return;
        }
    };
    if cli.show_seed {
        println!("[BlackSilk Wallet] Mnemonic seed: {}", wallet.mnemonic);
        return;
    }
    if cli.show_keys {
        println!("[BlackSilk Wallet] Private spend key: {}", wallet.priv_spend);
        println!("[BlackSilk Wallet] Private view key: {}", wallet.priv_view);
        return;
    }
    if cli.balance {
        let pub_view = hex::decode(&wallet.pub_view).unwrap_or_else(|_| {
            eprintln!("[Wallet] Error: Invalid pub_view in wallet file");
            std::process::exit(1);
        });
        let pub_spend = hex::decode(&wallet.pub_spend).unwrap_or_else(|_| {
            eprintln!("[Wallet] Error: Invalid pub_spend in wallet file");
            std::process::exit(1);
        });
        let priv_view = hex::decode(&wallet.priv_view).unwrap_or_else(|_| {
            eprintln!("[Wallet] Error: Invalid priv_view in wallet file");
            std::process::exit(1);
        });
        let mut arr_view = [0u8; 32];
        let mut arr_spend = [0u8; 32];
        let mut arr_priv_view = [0u8; 32];
        arr_view.copy_from_slice(&pub_view);
        arr_spend.copy_from_slice(&pub_spend);
        arr_priv_view.copy_from_slice(&priv_view);
        let last_height = wallet.last_height;
        let balance = scan_blocks_for_balance(
            &sync_with_node(&cli.node, last_height, &arr_view, &arr_spend),
            &arr_view,
            &arr_spend,
            &arr_priv_view,
        );
        println!("[Wallet] Balance: {}", balance);
        return;
    }
    if let (Some(addr), Some(amount)) = (cli.send, cli.amount) {
        match send_transaction(&cli.node, &wallet, &addr, amount) {
            Ok(_) => println!("[Wallet] Transaction sent (stub)."),
            Err(e) => eprintln!("[Wallet] Error sending transaction: {}", e),
        }
        return;
    }
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("BlackSilk Wallet CLI\nUsage: wallet <command>\nCommands:\n  generate   Generate a new wallet address\n  address    Show wallet address\n  help       Show this help message");
        return;
    }
    match args[1].as_str() {
        "generate" => {
            let (_priv_view, _priv_spend, stealth) = generate_stealth_address();
            let stealth_address = primitives::StealthAddress {
                public_view: stealth.public_view,
                public_spend: stealth.public_spend,
            };
            // TODO: Save keys securely
            println!("[BlackSilk Wallet] Generated new stealth address: view={} spend={}", hex::encode(stealth_address.public_view), hex::encode(stealth_address.public_spend));
        }
        "address" => {
            // TODO: Load and show the wallet address
            println!("[BlackSilk Wallet] Your address: <placeholder>");
        }
        "help" | _ => {
            println!("BlackSilk Wallet CLI\nUsage: wallet <command>\nCommands:\n  generate   Generate a new wallet address\n  address    Show wallet address\n  help       Show this help message");
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

// TODO: Integrate hardware wallet flows in CLI and transaction signing
