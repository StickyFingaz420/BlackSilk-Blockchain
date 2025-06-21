//! PQ key management for wallet: Dilithium2 and Falcon512
use pqsignatures::{Dilithium2, Falcon512, PQSignatureScheme};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct PQKeypair {
    pub dilithium2_pk: Vec<u8>,
    pub dilithium2_sk: Vec<u8>,
    pub falcon512_pk: Vec<u8>,
    pub falcon512_sk: Vec<u8>,
}

impl PQKeypair {
    pub fn generate() -> Self {
        let (dpk, dsk) = Dilithium2::keypair();
        let (fpk, fsk) = Falcon512::keypair();
        Self {
            dilithium2_pk: dpk.to_bytes().to_vec(),
            dilithium2_sk: dsk.to_bytes().to_vec(),
            falcon512_pk: fpk.to_bytes().to_vec(),
            falcon512_sk: fsk.to_bytes().to_vec(),
        }
    }
    pub fn save_to_file(&self, path: &str) -> std::io::Result<()> {
        let data = serde_json::to_vec(self).unwrap();
        std::fs::write(path, data)
    }
    pub fn load_from_file(path: &str) -> std::io::Result<Self> {
        let data = std::fs::read(path)?;
        Ok(serde_json::from_slice(&data).unwrap())
    }
}
