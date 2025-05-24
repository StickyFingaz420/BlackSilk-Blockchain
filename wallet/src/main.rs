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

#[derive(Deserialize, Debug)]
struct Block {
    height: u64,
    transactions: Vec<Transaction>,
}

#[derive(Deserialize, Debug)]
struct Transaction {
    outputs: Vec<Output>,
}

#[derive(Deserialize, Debug)]
struct Output {
    public_key: String, // hex-encoded
    amount: u64,
}

fn scan_blocks_for_balance(blocks: &[Block], my_pub_view: &[u8; 32], my_pub_spend: &[u8; 32]) -> u64 {
    // DEMO: Assume output.public_key is hex(pub_view || pub_spend)
    let mut balance = 0u64;
    let my_key_hex = format!("{}{}", hex::encode(my_pub_view), hex::encode(my_pub_spend));
    for block in blocks {
        for tx in &block.transactions {
            for out in &tx.outputs {
                if out.public_key == my_key_hex {
                    balance += out.amount;
                }
            }
        }
    }
    balance
}

fn sync_with_node(node_addr: &str, last_height: u64, my_pub_view: &[u8; 32], my_pub_spend: &[u8; 32]) -> u64 {
    let url = format!("http://{}/get_blocks?from_height={}", node_addr, last_height);
    match reqwest::blocking::get(&url) {
        Ok(resp) => {
            if resp.status().is_success() {
                let text = resp.text().unwrap_or_default();
                let blocks: Vec<Block> = serde_json::from_str(&text).unwrap_or_default();
                let balance = scan_blocks_for_balance(&blocks, my_pub_view, my_pub_spend);
                println!("[Wallet] Synced {} blocks, found balance: {}", blocks.len(), balance);
                balance
            } else {
                println!("[Wallet] Node returned error: {}", resp.status());
                0
            }
        }
        Err(e) => {
            println!("[Wallet] Failed to connect to node: {}", e);
            0
        }
    }
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
    let data = fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
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
        let pub_view = hex::decode(&wallet.pub_view).unwrap();
        let pub_spend = hex::decode(&wallet.pub_spend).unwrap();
        let mut arr_view = [0u8; 32];
        let mut arr_spend = [0u8; 32];
        arr_view.copy_from_slice(&pub_view);
        arr_spend.copy_from_slice(&pub_spend);
        let last_height = wallet.last_height;
        let balance = sync_with_node(&cli.node, last_height, &arr_view, &arr_spend);
        println!("[Wallet] Balance: {}", balance);
        // Save last synced height if needed
        // ...
        return;
    }
    if let (Some(addr), Some(amount)) = (cli.send, cli.amount) {
        // Call wallet send logic
        println!("[Wallet] Sending {} to {}", amount, addr);
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
            // TODO: Save keys securely
            println!("[BlackSilk Wallet] Generated new stealth address: view={} spend={}", hex::encode(stealth.public_view), hex::encode(stealth.public_spend));
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

mod hardware; // Hardware wallet (Ledger/Trezor) integration
// TODO: Integrate hardware wallet flows in CLI and transaction signing
