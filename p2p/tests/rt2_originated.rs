//! RT2-TM2P2P: `originated.json` salvage of a torn file.

use blacksilk_p2p::originated::{Originated, Verdict, NETWORK_EXPIRY_BLOCKS};

/// A file torn inside the last entry's height (`["<id>",81234` cut to
/// `["<id>",81`) is salvaged with the truncated height: the entry's window
/// then ends about 81,000 blocks early and the transaction is `Fresh`
/// (originated again) at once. Failing closed keeps the id with a
/// conservative height (the height at load), never a truncated one.
/// Expected to FAIL while the gap exists.
#[test]
fn rt2_a_torn_height_is_not_salvaged_short() {
    let id = [7u8; 32];
    let full = format!(
        r#"{{"version":1,"entries":[["{}",81234]]}}"#,
        hex::encode(id)
    );
    let cut = &full[..full.find("81234").unwrap() + 2]; // `...",81`
    let (o, problems) = Originated::decode(cut.as_bytes());
    eprintln!(
        "RT2 salvage: relayed {:?}, problems {problems:?}",
        o.relayed(&id)
    );
    let next = 81_234 + 10;
    assert!(next < 81_234 + NETWORK_EXPIRY_BLOCKS);
    assert_ne!(
        o.verdict(&id, next),
        Verdict::Fresh,
        "a torn height must not reopen origination"
    );
}
