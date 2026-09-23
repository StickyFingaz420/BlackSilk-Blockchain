//! BlackSilk wallet library: encrypted wallet file, scanning via the node RPC with
//! reorg handling, coin selection, decoy selection and transfers.

#![forbid(unsafe_code)]

pub mod file;
pub mod node;
pub mod wallet;

pub use wallet::{Balance, Wallet, WalletError};

use file::{FileError, KdfParams};
use std::path::Path;

/// Loads and decrypts a wallet file.
pub fn load(path: &Path, password: &[u8]) -> Result<Wallet, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut plain = file::decrypt(&bytes, password).map_err(|e| e.to_string())?;
    let w = Wallet::from_json(&plain).map_err(|e| e.to_string());
    zeroize::Zeroize::zeroize(&mut plain);
    w
}

/// Encrypts and atomically writes a wallet file.
pub fn save(
    wallet: &Wallet,
    path: &Path,
    password: &[u8],
    kdf: KdfParams,
) -> Result<(), FileError> {
    let mut plain = wallet.to_json();
    let enc = file::encrypt(&plain, password, kdf);
    zeroize::Zeroize::zeroize(&mut plain);
    file::write_atomic(path, &enc?)
}
