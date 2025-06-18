//! CLI for pqcrypto_native: Generate PQ keypairs (randomized only)
use pqcrypto_native::algorithms::dilithium::Dilithium2;
use pqcrypto_native::algorithms::falcon::Falcon512;
use pqcrypto_native::traits::SignatureScheme;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: pqgen --algo <dilithium2|falcon512>");
        std::process::exit(1);
    }
    let algo = args[2].to_lowercase();
    match algo.as_str() {
        "dilithium2" => {
            let (pk, sk) = Dilithium2::keypair_from_seed(&[0u8; 32]).unwrap();
            println!("Dilithium2 public key: {}", base64::encode(pk.as_ref()));
            println!("Dilithium2 secret key: {}", base64::encode(sk.as_ref()));
        },
        "falcon512" => {
            let (pk, sk) = Falcon512::keypair_from_seed(&[0u8; 32]).unwrap();
            println!("Falcon512 public key: {}", base64::encode(pk.as_ref()));
            println!("Falcon512 secret key: {}", base64::encode(sk.as_ref()));
        },
        _ => {
            eprintln!("Unknown algorithm");
            std::process::exit(1);
        }
    }
}
