use ml_dsa_44::{Keypair, sign, verify};
use std::io::{self, Write};

fn main() {
    let mut input = String::new();
    println!("Enter message to sign:");
    io::stdin().read_line(&mut input).unwrap();
    let message = input.trim().as_bytes();
    let keypair = Keypair::generate().expect("Keygen failed");
    let signature = sign(message, &keypair.secret_key).expect("Sign failed");
    println!("Signature (hex): {}", hex::encode(&signature.data));
    let is_valid = verify(&signature, message, &keypair.public_key).expect("Verify failed");
    println!("Signature valid: {}", is_valid);
}
