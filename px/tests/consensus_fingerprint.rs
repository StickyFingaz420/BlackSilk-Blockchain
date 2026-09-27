//! Pins the PX-side consensus entries ([`blacksilk_px::fingerprint::px_entries`]):
//! the BS-ZK-2 proof parameters and `PROOF_VERSION` (zk), the BVM-1 machine
//! limits (zkvm), the PX kernel and its hash domains (px-core), the pinned
//! kernel and vault program ids, the PX state and delivery formats (px), and
//! the v1 ring size (crypto).
//!
//! These entries are part of the node's `consensus_fingerprint(network)`
//! (node/src/fingerprint.rs), which operators compare before a trial and
//! which `node/tests/deploy_configs.rs` pins per network. This test pins the
//! PX part on its own so that a change here fails in the crate that made it.
//!
//! **Changing any of these is a consensus change and requires a new network
//! id** (and, for the kernel or the proof parameters, a new testnet identity;
//! docs/testnet-reset-plan.md). When this test fails, the change must be
//! deliberate: update the pinned digest in the same commit as the new network
//! id, never on its own.
//!
//! Constants only: no proof is built, the test is instant.

use blacksilk_px::fingerprint::px_entries;

/// Changing this is a consensus change and requires a new network id.
const PX_SIDE_DIGEST: &str = "1673ae51a5323ee983af7d76e560d104be7989830102b27ddb9e1db3d4031b0a";

#[test]
fn px_side_consensus_constants_are_pinned() {
    let m = px_entries();
    let digest: String = m
        .digest("test/consensus-fingerprint/px")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        digest,
        PX_SIDE_DIGEST,
        "a consensus constant changed (this is a consensus change and requires a new network id); \
         current values:\n{}",
        m.render()
    );
}
