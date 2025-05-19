use std::env;
use rand::rngs::OsRng;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer};

fn generate_wallet() -> (PublicKey, SecretKey) {
    let mut csprng = OsRng {};
    let keypair = Keypair::generate(&mut csprng);
    (keypair.public, keypair.secret)
}

fn public_key_to_address(pk: &PublicKey) -> String {
    // Placeholder: encode as hex
    hex::encode(pk.as_bytes())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("BlackSilk Wallet CLI\nUsage: wallet <command>\nCommands:\n  generate   Generate a new wallet address\n  address    Show wallet address\n  help       Show this help message");
        return;
    }
    match args[1].as_str() {
        "generate" => {
            let (pk, sk) = generate_wallet();
            let address = public_key_to_address(&pk);
            // TODO: Save keys securely
            println!("[BlackSilk Wallet] Generated new address: {}", address);
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
