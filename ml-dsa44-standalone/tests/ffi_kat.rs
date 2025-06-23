#[test]
fn test_ffi_keypair_from_seed() {
    use crate::ffi_keypair_from_seed;
    let seed = [42u8; 32];
    let (pk, sk) = ffi_keypair_from_seed(&seed);
    // For the stub, pk/sk are all zeros. In real use, compare to known KAT vectors.
    assert_eq!(pk, [0u8; 1184]);
    assert_eq!(sk, [0u8; 2400]);
}
