//! Proofs: the strict decoder never panics (outside its own catch), and a
//! decoded proof has exactly one encoding.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(proof) = blacksilk_zk::decode_proof(data) {
        assert_eq!(blacksilk_zk::encode_proof(&proof), data);
    }
});
