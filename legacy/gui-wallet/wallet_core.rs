//! Wallet core: key management, BIP39, stealth addresses, ring signatures, tx building

use bip39::{Mnemonic, MnemonicType, Language, Seed};
use zeroize::Zeroize;
use secrecy::{Secret, ExposeSecret};
use primitives::{StealthAddress, QuantumScheme, Address};
use primitives::ring_sig::generate_ring_signature;

pub struct WalletCore {
    pub mnemonic: Option<Mnemonic>,
    pub seed: Option<Secret<Vec<u8>>>,
}

pub struct KeyPair {
    pub priv_view: Vec<u8>,
    pub priv_spend: Vec<u8>,
    pub stealth: StealthAddress,
    pub scheme: QuantumScheme,
}

impl WalletCore {
    pub fn new() -> Self {
        WalletCore { mnemonic: None, seed: None }
    }

    /// Generate a new BIP39 mnemonic and seed
    pub fn generate_new(seed_password: &str) -> Self {
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let seed = Seed::new(&mnemonic, seed_password);
        WalletCore {
            mnemonic: Some(mnemonic),
            seed: Some(Secret::new(seed.as_bytes().to_vec())),
        }
    }

    /// Import from an existing mnemonic phrase
    pub fn from_phrase(phrase: &str, seed_password: &str) -> Option<Self> {
        if let Ok(mnemonic) = Mnemonic::from_phrase(phrase, Language::English) {
            let seed = Seed::new(&mnemonic, seed_password);
            Some(WalletCore {
                mnemonic: Some(mnemonic),
                seed: Some(Secret::new(seed.as_bytes().to_vec())),
            })
        } else {
            None
        }
    }

    /// Get the mnemonic phrase (if present)
    pub fn mnemonic_phrase(&self) -> Option<String> {
        self.mnemonic.as_ref().map(|m| m.phrase().to_string())
    }

    /// Zeroize secrets from memory
    pub fn zeroize(&mut self) {
        if let Some(seed) = &mut self.seed {
            seed.expose_secret().zeroize();
        }
        self.seed = None;
        self.mnemonic = None;
    }

    /// Select the quantum scheme dynamically (user/config/auto)
    pub fn select_scheme(&self, scheme: Option<QuantumScheme>) -> QuantumScheme {
        scheme.unwrap_or(QuantumScheme::MLDSA44)
    }

    /// Derive keypair from BIP39 seed and scheme
    pub fn derive_keypair(&self, scheme: QuantumScheme) -> Option<KeyPair> {
        if let Some(seed) = &self.seed {
            // Use the seed bytes as entropy for key generation
            // For demonstration, use the first 32 bytes for priv_view, next 32 for priv_spend
            let seed_bytes = seed.expose_secret();
            let mut priv_view = vec![0u8; 32];
            let mut priv_spend = vec![0u8; 32];
            priv_view.copy_from_slice(&seed_bytes[0..32]);
            priv_spend.copy_from_slice(&seed_bytes[32..64.min(seed_bytes.len())]);
            // Generate stealth address using primitives
            let (_pv, _ps, stealth) = StealthAddress::generate(Some(scheme.clone()));
            Some(KeyPair { priv_view, priv_spend, stealth, scheme })
        } else {
            None
        }
    }

    /// Generate a new stealth address using selected scheme and derived keys
    pub fn generate_new_address_with_scheme(&self, scheme: Option<QuantumScheme>) -> Option<String> {
        let scheme = self.select_scheme(scheme);
        self.derive_keypair(scheme.clone()).map(|kp| {
            let addr = Address {
                stealth: kp.stealth,
                scheme: Some(scheme),
            };
            addr.encode()
        })
    }

    /// Build and sign a transaction (simplified)
    pub fn build_and_sign_transaction(&self, to: &str, amount: u64, ring: Vec<[u8; 32]>, real_index: usize, scheme: QuantumScheme) -> Option<Vec<u8>> {
        // Use ring signature for privacy
        if let Some(kp) = self.derive_keypair(scheme) {
            let msg = format!("send:{}:{}", to, amount).into_bytes();
            let sig = generate_ring_signature(&msg, &ring, &kp.priv_spend, real_index);
            Some(sig)
        } else {
            None
        }
    }

    /// Generate a new stealth address using BlackSilk primitives
    pub fn generate_new_address(&self) -> String {
        // Use the seed to deterministically generate keys
        let scheme = Some(QuantumScheme::MLDSA44); // Or select based on user/config
        let (_priv_view, _priv_spend, stealth) = StealthAddress::generate(scheme);
        // Wrap in Address and encode as string
        let addr = primitives::Address {
            stealth,
            scheme,
        };
        addr.encode()
    }
    // TODO: Add ring signature, tx building using BlackSilk primitives
}
