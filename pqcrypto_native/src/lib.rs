#![no_std]

#[macro_use]
extern crate alloc;

use alloc::vec::Vec;

/// Native Rust PQ Key Generation Library
/// Implements deterministic keypair generation for Dilithium, Falcon, ML-DSA

pub mod algorithms;
pub mod utils;
pub mod wallet;
pub mod traits;

use crate::traits::{Keypair, PublicKey, SecretKey, SignatureScheme, SignatureError};

/// Deterministic keypair generation from a 32-byte seed (BIP39 compatible)
pub fn generate_falcon_keypair_from_seed(seed: &[u8; 32]) -> Result<Keypair<897, 1281>, SignatureError> {
    // Falcon512 secret key is 1281 bytes, public key is 897 bytes
    let (public, secret): (PublicKey<897>, SecretKey<1281>) = crate::algorithms::falcon::Falcon512::keypair_from_seed(seed)?;
    Ok(Keypair { public, secret })
}

pub fn generate_dilithium_keypair_from_seed(seed: &[u8; 32]) -> Result<Keypair<1312, 2560>, SignatureError> {
    // Dilithium2 secret key is 2560 bytes, public key is 1312 bytes
    let (public, secret): (PublicKey<1312>, SecretKey<2560>) = crate::algorithms::dilithium::Dilithium2::keypair_from_seed(seed)?;
    Ok(Keypair { public, secret })
}

/// Derive Falcon public key from secret key
pub fn derive_falcon_public_from_secret(secret: &SecretKey<{pqcrypto_falcon::falcon512::secret_key_bytes()}>) -> PublicKey<{pqcrypto_falcon::falcon512::public_key_bytes()}> {
    // Falcon secret key bytes contain the public key at the end (per NIST spec and pqcrypto)
    let sk_bytes = secret.as_ref();
    let pk_len = pqcrypto_falcon::falcon512::public_key_bytes();
    let pk_offset = sk_bytes.len() - pk_len;
    let mut pk = [0u8; pqcrypto_falcon::falcon512::public_key_bytes()];
    pk.copy_from_slice(&sk_bytes[pk_offset..]);
    PublicKey(pk)
}

/// Derive Dilithium public key from secret key
pub fn derive_dilithium_public_from_secret(secret: &SecretKey<{pqcrypto_dilithium::dilithium2::secret_key_bytes()}>) -> PublicKey<{pqcrypto_dilithium::dilithium2::public_key_bytes()}> {
    // Dilithium secret key bytes contain the public key at the end (per NIST spec and pqcrypto)
    let sk_bytes = secret.as_ref();
    let pk_len = pqcrypto_dilithium::dilithium2::public_key_bytes();
    let pk_offset = sk_bytes.len() - pk_len;
    let mut pk = [0u8; pqcrypto_dilithium::dilithium2::public_key_bytes()];
    pk.copy_from_slice(&sk_bytes[pk_offset..]);
    PublicKey(pk)
}

/// Fixed size for Falcon signatures (in bytes)
pub const FALCON_SIGNATURE_SIZE: usize = 768;

/// Sign a message with Falcon, returning a padded signature
pub fn falcon_sign_padded(message: &[u8], secret: &SecretKey<{pqcrypto_falcon::falcon512::secret_key_bytes()}>) -> Result<[u8; FALCON_SIGNATURE_SIZE], SignatureError> {
    use crate::algorithms::falcon::Falcon512;
    let sig_vec = Falcon512::sign(secret, message)?.0;
    let mut padded = [0u8; FALCON_SIGNATURE_SIZE];
    let sig_len = sig_vec.len().min(FALCON_SIGNATURE_SIZE);
    padded[..sig_len].copy_from_slice(&sig_vec[..sig_len]);
    // Optionally, store sig_len in metadata if needed
    Ok(padded)
}

/// Verify a padded Falcon signature
pub fn falcon_verify_padded(message: &[u8], signature: &[u8; FALCON_SIGNATURE_SIZE], public: &PublicKey<{pqcrypto_falcon::falcon512::public_key_bytes()}>) -> bool {
    use crate::algorithms::falcon::Falcon512;
    // Remove trailing zero padding
    let sig_trimmed = signature.iter().copied().rev().skip_while(|&b| b == 0).collect::<Vec<_>>();
    let sig_trimmed = sig_trimmed.into_iter().rev().collect::<Vec<_>>();
    Falcon512::verify(public, message, &crate::traits::SignatureVec(sig_trimmed)).is_ok()
}

/// Convert a BIP39 mnemonic phrase to a 32-byte seed for PQ key generation
/// Returns None if the mnemonic or passphrase is invalid or not 32 bytes
pub fn bip39_mnemonic_to_seed(mnemonic: &str, passphrase: Option<&str>) -> Option<[u8; 32]> {
    use bip39::{Mnemonic, Language};
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic).ok()?;
    let pass = passphrase.unwrap_or("");
    let seed_bytes = mnemonic.to_seed(pass);
    if seed_bytes.len() < 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&seed_bytes[..32]);
    Some(out)
}
