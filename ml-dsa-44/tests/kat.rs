use ml_dsa_44::Keypair;

// Example NIST KAT vector (replace with real values for your algorithm)
const KAT_SEED: [u8; 32] = [0x00; 32];
const KAT_PUBLIC_KEY: [u8; 1312] = [0xAA; 1312]; // Replace with real KAT value
const KAT_SECRET_KEY: [u8; 2560] = [0xBB; 2560]; // Replace with real KAT value

#[test]
fn test_kat_keypair() {
    let keypair = Keypair::from_seed(&KAT_SEED).expect("KAT keygen failed");
    // Compare to known answer test vectors
    assert_eq!(&keypair.public_key.0[..], &KAT_PUBLIC_KEY[..], "KAT public key mismatch");
    assert_eq!(&keypair.secret_key.0[..], &KAT_SECRET_KEY[..], "KAT secret key mismatch");
}
