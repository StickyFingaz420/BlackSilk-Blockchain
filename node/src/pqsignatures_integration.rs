//! Example: PQ signature integration in node
use pqsignatures::{Dilithium2, Falcon512, PQSignatureScheme};

/// Generate, sign, and verify a message using Dilithium2
pub fn dilithium2_demo() {
    let (pk, sk) = Dilithium2::keypair();
    let msg = b"node transaction";
    let sig = Dilithium2::sign(&sk, msg);
    assert!(Dilithium2::verify(&pk, msg, &sig));
    println!("Dilithium2 signature verified in node!");
}

/// Generate, sign, and verify a message using Falcon512
pub fn falcon512_demo() {
    let (pk, sk) = Falcon512::keypair();
    let msg = b"node transaction";
    let sig = Falcon512::sign(&sk, msg);
    assert!(Falcon512::verify(&pk, msg, &sig));
    println!("Falcon512 signature verified in node!");
}
