#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Commands, PrivacyCommands};
    use clap::Parser;
    use primitives::zkp::{generate_zk_proof, verify_zk_proof};
    use primitives::zkp::ark_groth16::data_structures::{ProvingKey, VerifyingKey}; // Import ProvingKey and VerifyingKey directly
    use std::fs;
    use std::path::Path;

    #[test]
    fn test_generate_zk_proof() {
        let args = Cli::parse_from(["wallet", "privacy", "zkproof", "--amount", "100"]);
        if let Some(Commands::Privacy { action }) = args.command {
            if let PrivacyCommands::ZkProof { amount } = action {
                assert_eq!(amount, 100);

                // Fetch the proving key from a file or node
                let proving_key_path = Path::new("config/proving_key.bin");
                let proving_key_data = fs::read(proving_key_path).expect("Failed to read proving key");
                let proving_key: ProvingKey = bincode::deserialize(&proving_key_data).expect("Failed to deserialize proving key");

                // Generate the proof
                let result = generate_zk_proof(amount, &proving_key);
                assert!(result.proof.is_some()); // Check if proof is generated
            }
        }
    }

    #[test]
    fn test_verify_zk_proof() {
        let args = Cli::parse_from(["wallet", "privacy", "verify", "--proof", "dummy_proof"]);
        if let Some(Commands::Privacy { action }) = args.command {
            if let PrivacyCommands::Verify { proof } = action {
                assert_eq!(proof, "dummy_proof");
                // Simulate proof verification
                let verifying_key_path = Path::new("config/verifying_key.bin");
                let verifying_key_data = fs::read(verifying_key_path).expect("Failed to read verifying key");
                let verifying_key: VerifyingKey = bincode::deserialize(&verifying_key_data).expect("Failed to deserialize verifying key");
                let result = verify_zk_proof(&proof, &verifying_key); // Provide required arguments
                assert!(result.is_ok());
                assert!(result.unwrap());
            }
        }
    }
}
