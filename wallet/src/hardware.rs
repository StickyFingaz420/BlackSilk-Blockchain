//! Hardware wallet (Ledger/Trezor) integration for BlackSilk
//
// This module now includes real support for hardware wallets (Ledger, Trezor, etc.)
// for secure key storage and transaction signing.

use ledger_rs::{LedgerApp, TransportNativeHID};
use trezor_crypto::TrezorApp;
use std::error::Error;

/// Supported hardware wallet types
pub enum HardwareWalletType {
    Ledger,
    Trezor,
}

/// Hardware wallet connection
pub struct HardwareWallet {
    pub device_type: HardwareWalletType,
    pub session: Option<Box<dyn HardwareWalletSession>>,
}

/// Trait for hardware wallet sessions
pub trait HardwareWalletSession {
    fn sign_transaction(&self, tx_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>>;
}

/// Connect to a hardware wallet (Ledger/Trezor)
pub fn connect_hardware_wallet() -> Result<HardwareWallet, Box<dyn Error>> {
    if let Ok(ledger) = TransportNativeHID::new() {
        let app = LedgerApp::new(ledger);
        return Ok(HardwareWallet {
            device_type: HardwareWalletType::Ledger,
            session: Some(Box::new(app)),
        });
    }
    if let Ok(trezor) = TrezorApp::new() {
        return Ok(HardwareWallet {
            device_type: HardwareWalletType::Trezor,
            session: Some(Box::new(trezor)),
        });
    }
    Err("No hardware wallet detected".into())
}

/// Sign a transaction using a hardware wallet
pub fn sign_transaction_with_hardware(wallet: &HardwareWallet, tx_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if let Some(session) = &wallet.session {
        return session.sign_transaction(tx_bytes);
    }
    Err("No active session for hardware wallet".into())
}
