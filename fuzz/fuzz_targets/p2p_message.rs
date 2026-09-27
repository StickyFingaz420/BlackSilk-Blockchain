//! Peer-to-peer messages: decoding never panics; whatever decodes re-encodes
//! identically, except `Version`, whose extension area (bytes after its last
//! known field) is ignored: it re-encodes to a prefix of the input that decodes
//! to the same message (docs/p2p.md §4.1).
#![no_main]
use blacksilk_p2p::message::Message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = Message::decode(data) {
        let enc = msg.encode();
        if matches!(msg, Message::Version(_)) {
            assert!(data.starts_with(&enc), "version re-encodes to a prefix");
            assert_eq!(Message::decode(&enc).as_ref(), Ok(&msg));
        } else {
            assert_eq!(enc, data, "decode then encode is the identity");
        }
    }
});
