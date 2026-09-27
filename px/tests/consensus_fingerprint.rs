//! A fingerprint of the consensus-critical constants reachable from this crate:
//! the BS-ZK-2 proof parameters (zk), the BVM-1 machine limits (zkvm), the PX
//! kernel and its pinned program id (px-core, px), the PX state and delivery
//! formats (px), and the v1 ring size (crypto).
//!
//! **Changing any of these is a consensus change and requires a new network
//! id** (and, for the kernel or the proof parameters, a new testnet identity;
//! docs/testnet-reset-plan.md). When this test fails, the change must be
//! deliberate: update the pinned digest in the same commit as the new network
//! id, never on its own.
//!
//! The chain-level constants (network ids, genesis, difficulty and time rules,
//! RandomX key schedule, transaction and PX fee/size rules, emission) are not
//! reachable from `blacksilk-px` (it does not depend on consensus, tx or
//! chain); `node/tests/deploy_configs.rs` pins them the same way.
//!
//! Constants only: no proof is built, the test is instant.

use blacksilk_crypto::hash::Hasher64;
use std::fmt::Write;

/// `name = value` lines, in a fixed order.
struct Fingerprint(String);

impl Fingerprint {
    fn add(&mut self, name: &str, value: impl std::fmt::Debug) -> &mut Self {
        writeln!(self.0, "{name} = {value:?}").unwrap();
        self
    }

    fn digest(&self) -> String {
        let mut h = Hasher64::new("test/consensus-fingerprint");
        h.update(self.0.as_bytes());
        h.finalize()[..32]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

fn px_side() -> Fingerprint {
    use blacksilk_px_core::hash::domain;
    use blacksilk_zk::params as zk;
    let mut f = Fingerprint(String::new());
    // BS-ZK-2 (zk/src/params.rs).
    f.add("zk.PARAMS_ID", std::str::from_utf8(zk::PARAMS_ID).unwrap())
        .add("zk.LOG_BLOWUP", zk::LOG_BLOWUP)
        .add("zk.NUM_QUERIES", zk::NUM_QUERIES)
        .add("zk.MAX_LOG_ARITY", zk::MAX_LOG_ARITY)
        .add("zk.LOG_FINAL_POLY_LEN", zk::LOG_FINAL_POLY_LEN)
        .add("zk.QUERY_POW_BITS", zk::QUERY_POW_BITS)
        .add("zk.COMMIT_POW_BITS", zk::COMMIT_POW_BITS)
        .add("zk.NUM_RANDOM_CODEWORDS", zk::NUM_RANDOM_CODEWORDS)
        .add("zk.MERKLE_SALT_ELEMS", zk::MERKLE_SALT_ELEMS)
        .add("zk.EXTENSION_DEGREE", zk::EXTENSION_DEGREE)
        .add("zk.CHALLENGE_FIELD_BITS", zk::CHALLENGE_FIELD_BITS)
        .add("zk.MIN_PROVEN_BITS", zk::MIN_PROVEN_BITS)
        .add("zk.TARGET_JOHNSON_BITS", zk::TARGET_JOHNSON_BITS)
        .add("zk.MIN_LOG_HEIGHT", zk::MIN_LOG_HEIGHT)
        .add("zk.MAX_LOG_HEIGHT", zk::MAX_LOG_HEIGHT)
        .add("zk.MAX_COMMITTED_COLUMNS", zk::MAX_COMMITTED_COLUMNS)
        .add("zk.MAX_PROOF_BYTES", zk::MAX_PROOF_BYTES)
        .add("zk.MAX_ADVERSARIAL_COLUMNS", zk::MAX_ADVERSARIAL_COLUMNS);
    // BVM-1 (zkvm/src/lib.rs, program.rs).
    f.add("zkvm.MEM_SIZE", blacksilk_zkvm::MEM_SIZE)
        .add("zkvm.NULL_GUARD", blacksilk_zkvm::NULL_GUARD)
        .add("zkvm.STACK_TOP", blacksilk_zkvm::STACK_TOP)
        .add("zkvm.STACK_SIZE", blacksilk_zkvm::STACK_SIZE)
        .add("zkvm.CODE_LIMIT_WORDS", blacksilk_zkvm::CODE_LIMIT_WORDS)
        .add("zkvm.DATA_LIMIT_BYTES", blacksilk_zkvm::DATA_LIMIT_BYTES)
        .add("zkvm.MAX_CYCLES", blacksilk_zkvm::MAX_CYCLES)
        .add("zkvm.MAX_INPUT_WORDS", blacksilk_zkvm::MAX_INPUT_WORDS)
        .add("zkvm.MAX_OUTPUT_WORDS", blacksilk_zkvm::MAX_OUTPUT_WORDS)
        .add(
            "zkvm.MAX_DATA_SEGMENTS",
            blacksilk_zkvm::program::MAX_DATA_SEGMENTS,
        );
    // The PX kernel (px-core) and its pinned program id (px/kernel.id).
    f.add("px_core.P", blacksilk_px_core::P)
        .add("px_core.kernel.VERSION", blacksilk_px_core::kernel::VERSION)
        .add(
            "px_core.kernel.TREE_DEPTH",
            blacksilk_px_core::kernel::TREE_DEPTH,
        )
        .add("px_core.kernel.N_IN", blacksilk_px_core::kernel::N_IN)
        .add("px_core.kernel.N_OUT", blacksilk_px_core::kernel::N_OUT)
        .add(
            "px_core.kernel.MAX_PUBLIC_WORDS",
            blacksilk_px_core::kernel::MAX_PUBLIC_WORDS,
        )
        .add("px_core.call.MAX_FN", blacksilk_px_core::call::MAX_FN)
        .add(
            "px_core.hash.domain",
            [
                domain::SK,
                domain::NK,
                domain::AK,
                domain::OWNER,
                domain::DIVERSIFIER,
                domain::RECORD,
                domain::NULLIFIER,
                domain::RHO,
                domain::IO,
                domain::NULLIFIER_CONTRACT,
            ],
        )
        .add(
            "px.KERNEL_PROGRAM_ID",
            blacksilk_px::prove::KERNEL_PROGRAM_ID.trim(),
        );
    // PX state and record delivery (px).
    f.add("px.state.ROOT_WINDOW", blacksilk_px::state::ROOT_WINDOW)
        .add("px.tree.CAPACITY", blacksilk_px::tree::CAPACITY)
        .add(
            "px.delivery.CIPHERTEXT_BYTES",
            blacksilk_px::delivery::CIPHERTEXT_BYTES,
        );
    // v1 (crypto).
    f.add("crypto.RING_SIZE", blacksilk_crypto::clsag::RING_SIZE)
        .add(
            "crypto.DOMAIN_PREFIX",
            blacksilk_crypto::hash::DOMAIN_PREFIX,
        );
    f
}

/// Changing any of these is a consensus change and requires a new network id.
const PX_SIDE_DIGEST: &str = "52d7e4114c983f31b9bed4fa7cbcf5f684b239922532d6eae06a01df53fd2971";

#[test]
fn px_side_consensus_constants_are_pinned() {
    let f = px_side();
    let digest = f.digest();
    assert_eq!(
        digest, PX_SIDE_DIGEST,
        "a consensus constant changed (this is a consensus change and requires a new network id); \
         current values:\n{}",
        f.0
    );
}
