//! Pins the PX-side consensus entries ([`blacksilk_px::fingerprint::px_entries`]):
//! the proof parameter set and `PROOF_VERSION` (zk), the BVM-1 machine limits
//! and circuit digest (zkvm), the PX kernel, its hash domains and call ABI
//! (px-core), the pinned kernel and vault program ids, budgets and entry
//! points, the PX state and delivery formats (px), the v1 ring size
//! (crypto), and the PX rule samples (Poseidon2, `Hk`, node, commitment,
//! nullifier, exit codes, function prefix, PX6 window).
//!
//! These entries are part of the node's rules fingerprint and so of its
//! `consensus_fingerprint(network)` (node/src/fingerprint.rs), which
//! operators compare before a trial and which `node/tests/deploy_configs.rs`
//! pins per network. This test pins the PX part on its own so that a change
//! here fails in the crate that made it.
//!
//! **Changing any of these is a consensus change.** When this test fails, the
//! change must be deliberate: re-pin in the same commit as the change, with a
//! `Consensus-Change:` trailer naming its record in
//! docs/reviews/v3-consensus-changes.md (the re-pin procedure is in its
//! `fingerprint-v3` section).
//!
//! No proof is built, the test is instant.

use blacksilk_px::fingerprint::px_entries;

/// Changing this is a consensus change (fingerprint v3: see the module text).
const PX_SIDE_DIGEST: &str = "ee47cdc27639acee5d4317df1945f3ccabd37fdb6da4bb96efb757e57633585a";

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
        "a PX consensus constant or rule sample changed (a consensus change: re-pin with its \
         record); current values:\n{}",
        m.render()
    );
}
