//! Blocks: decoding never panics; whatever decodes re-encodes identically.
#![no_main]
use blacksilk_chain::block::Block;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(block) = Block::decode(data) {
        assert_eq!(block.encode(), data, "decode then encode is the identity");
        let _ = block.compute_tx_root();
    }
});
