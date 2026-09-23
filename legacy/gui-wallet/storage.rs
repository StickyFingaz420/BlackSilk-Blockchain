//! Storage: encrypted wallet file, config, transaction history

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use argon2::{self, Config};
use rand::RngCore;
use secrecy::{Secret, ExposeSecret};
use sled::Db;
use std::fs;
use std::path::PathBuf;

pub struct Storage {
    pub db: Db,
    pub wallet_path: PathBuf,
}

impl Storage {
    pub fn new(wallet_path: PathBuf) -> Self {
        let db = sled::open(wallet_path.join("history_db")).unwrap();
        Storage { db, wallet_path }
    }

    /// Encrypt and save wallet seed to disk
    pub fn save_encrypted_seed(&self, seed: &[u8], password: &str) -> Result<(), String> {
        let salt = rand::random::<[u8; 16]>();
        let mut key = [0u8; 32];
        argon2::hash_raw(password.as_bytes(), &salt, &Config::default())
            .map_err(|e| e.to_string())?
            .iter()
            .enumerate()
            .for_each(|(i, b)| if i < 32 { key[i] = *b });
        let cipher = Aes256Gcm::new(Key::from_slice(&key));
        let nonce = rand::random::<[u8; 12]>();
        let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), seed)
            .map_err(|e| e.to_string())?;
        let mut file_data = Vec::new();
        file_data.extend_from_slice(&salt);
        file_data.extend_from_slice(&nonce);
        file_data.extend_from_slice(&ciphertext);
        fs::write(self.wallet_path.join("wallet.dat"), file_data).map_err(|e| e.to_string())
    }

    /// Load and decrypt wallet seed from disk
    pub fn load_encrypted_seed(&self, password: &str) -> Result<Secret<Vec<u8>>, String> {
        let data = fs::read(self.wallet_path.join("wallet.dat")).map_err(|e| e.to_string())?;
        let (salt, rest) = data.split_at(16);
        let (nonce, ciphertext) = rest.split_at(12);
        let mut key = [0u8; 32];
        argon2::hash_raw(password.as_bytes(), salt, &Config::default())
            .map_err(|e| e.to_string())?
            .iter()
            .enumerate()
            .for_each(|(i, b)| if i < 32 { key[i] = *b });
        let cipher = Aes256Gcm::new(Key::from_slice(&key));
        let plaintext = cipher.decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|e| e.to_string())?;
        Ok(Secret::new(plaintext))
    }

    /// Save a transaction to history
    pub fn save_tx_history(&self, entry: &str) -> Result<(), String> {
        self.db.generate_id()
            .map_err(|e| e.to_string())
            .and_then(|id| self.db.insert(id.to_be_bytes(), entry.as_bytes()).map(|_| ()).map_err(|e| e.to_string()))
    }

    /// Load all transaction history entries
    pub fn load_tx_history(&self) -> Result<Vec<String>, String> {
        let mut history = Vec::new();
        for item in self.db.iter() {
            let (_k, v) = item.map_err(|e| e.to_string())?;
            if let Ok(s) = String::from_utf8(v.to_vec()) {
                history.push(s);
            }
        }
        Ok(history)
    }
    // TODO: Add config methods
}
