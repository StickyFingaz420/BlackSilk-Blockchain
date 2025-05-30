#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cli;
    use clap::Parser;

    #[test]
    fn test_generate_zk_proof() {
        let args = Cli::parse_from(["wallet", "privacy", "zkproof", "--amount", "100"]);
        if let Some(Commands::Privacy { action }) = args.command {
            if let PrivacyCommands::ZkProof { amount } = action {
                assert_eq!(amount, 100);
                // Simulate proof generation
                let result = primitives::zkp::generate_proof(amount);
                assert!(result.is_ok());
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
                let result = primitives::zkp::verify_proof(&proof);
                assert!(result.is_ok());
                assert!(result.unwrap());
            }
        }
    }
}
