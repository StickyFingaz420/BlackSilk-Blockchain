use super::falcon_prng::FalconPrng;

#[test]
fn test_prng_determinism() {
    let seed = [42u8; 48];
    let mut prng1 = FalconPrng::from_seed(&seed);
    let mut prng2 = FalconPrng::from_seed(&seed);
    let mut buf1 = [0u8; 64];
    let mut buf2 = [0u8; 64];
    prng1.fill_bytes(&mut buf1);
    prng2.fill_bytes(&mut buf2);
    assert_eq!(buf1, buf2);
    assert_eq!(prng1.next_u64(), prng2.next_u64());
}
