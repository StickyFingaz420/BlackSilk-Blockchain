//! R4-11: the circuit tag opens the statement digest, which the transcript
//! absorbs right after `PARAMS_ID` (docs/zk.md §9.3). Native, no proving.

use blacksilk_crypto::hash::{tags, Hasher64};
use blacksilk_zkvm::air::Table;
use blacksilk_zkvm::prove::{statement_digest, CIRCUIT_ID};

/// The digest of a statement without tables is exactly
/// `H64(ZKVM_STATEMENT, LE64(len) ‖ CIRCUIT_ID ‖ LE64(0))[..32]`: the tag is
/// the first thing hashed.
#[test]
fn the_circuit_tag_is_the_first_input_of_the_statement_digest() {
    assert_eq!(CIRCUIT_ID, b"BlackSilk/zkvm/BVM-1/circuit/v1");
    let mut h = Hasher64::new(tags::ZKVM_STATEMENT);
    h.update(&(CIRCUIT_ID.len() as u64).to_le_bytes());
    h.update(CIRCUIT_ID);
    h.update(&0u64.to_le_bytes());
    let wide = h.finalize();
    assert_eq!(statement_digest(&[]), wide[..32]);

    // Without the tag (the construction before R4-11) the digest differs.
    let mut old = Hasher64::new(tags::ZKVM_STATEMENT);
    old.update(&0u64.to_le_bytes());
    assert_ne!(statement_digest(&[]), old.finalize()[..32]);

    // Tables still count: the byte table changes the digest.
    assert_ne!(statement_digest(&[Table::Byte]), statement_digest(&[]));
}
