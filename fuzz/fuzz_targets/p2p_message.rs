//! Peer-to-peer messages: decoding never panics; whatever decodes re-encodes
//! identically.
#![no_main]
use blacksilk_p2p::message::Message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = Message::decode(data) {
        assert_eq!(msg.encode(), data, "decode then encode is the identity");
    }
});
