pub mod cli;

mod pqsignatures_integration;
pub mod pqkey;

#[cfg(test)]
mod tests {
    use super::pqsignatures_integration;
    use crate::pqkey::PQKeypair;
    use crate::pqsignatures_integration::{sign_tx_dilithium2, verify_tx_dilithium2, sign_tx_falcon512, verify_tx_falcon512};

    #[test]
    fn test_dilithium2_integration() {
        pqsignatures_integration::dilithium2_demo();
    }
    #[test]
    fn test_falcon512_integration() {
        pqsignatures_integration::falcon512_demo();
    }

    #[test]
    fn test_pq_sign_and_verify_dilithium2() {
        let pqkey = PQKeypair::generate();
        let tx = b"real transaction bytes";
        let sig = sign_tx_dilithium2(tx, &pqkey);
        assert!(verify_tx_dilithium2(tx, &sig, &pqkey));
    }

    #[test]
    fn test_pq_sign_and_verify_falcon512() {
        let pqkey = PQKeypair::generate();
        let tx = b"real transaction bytes";
        let sig = sign_tx_falcon512(tx, &pqkey);
        assert!(verify_tx_falcon512(tx, &sig, &pqkey));
    }
}