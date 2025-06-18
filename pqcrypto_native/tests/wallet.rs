//! Tests for PQ wallet/address module
use pqcrypto_native::wallet::{derive_child_seed, encode_address};

#[test]
fn test_derive_child_seed() {
    let master = b"master-seed";
    let child0 = derive_child_seed(master, 0);
    let child1 = derive_child_seed(master, 1);
    assert_ne!(child0, child1);
    assert_eq!(child0, derive_child_seed(master, 0));
}

#[test]
fn test_encode_address() {
    let pubkey = [1u8; 32];
    let addr = encode_address(&pubkey);
    assert!(!addr.is_empty());
}
