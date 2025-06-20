// Debug test for ML-DSA-44: Dump packed PK/SK bytes for all-zero seed
// Allows manual comparison with NIST KATs or C reference

use BlackSilk::mldsa44::{keygen, pack_pk, pack_sk};
use hex;

#[test]
fn debug_dump_packed_keys_zero_seed() {
    // All-zero seed (32 bytes)
    let seed = [0u8; 32];
    let (pk, sk) = keygen(&seed);
    let pk_bytes = pack_pk(&pk);
    let sk_bytes = pack_sk(&sk);

    println!("PK: {}", hex::encode(&pk_bytes));
    println!("SK: {}", hex::encode(&sk_bytes));
}
