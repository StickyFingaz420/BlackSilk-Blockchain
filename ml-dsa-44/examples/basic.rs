//! Basic usage example for ML-DSA-44 Rust library
use ml_dsa_44::{Keypair, sign, verify};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate keypair
    let keypair = Keypair::generate()?;
    println!("Public key: {} bytes", keypair.public_key.0.len());
    println!("Secret key: {} bytes", keypair.secret_key.0.len());

    // Sign a message
    let message = b"Hello, post-quantum world!";
    let signature = sign(message, &keypair.secret_key)?;
    println!("Signature: {} bytes", signature.data.len());

    // Verify the signature
    let is_valid = verify(&signature, message, &keypair.public_key)?;
    assert!(is_valid);
    println!("Signature verified successfully!");
    Ok(())
}
