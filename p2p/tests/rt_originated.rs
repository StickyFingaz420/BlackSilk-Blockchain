//! RT-TM2P2P: format 1/2 reading of `originated.json` under corrupt,
//! truncated and mixed inputs, and the held-mark lifecycle edges.

use blacksilk_p2p::originated::{Originated, NETWORK_EXPIRY_BLOCKS};

fn id(n: u8) -> [u8; 32] {
    [n; 32]
}

fn h(n: u8) -> String {
    hex::encode(id(n))
}

#[test]
fn rt_format_reading_edges() {
    let cases: Vec<(&str, String)> = vec![
        (
            "v1 ok",
            format!(r#"{{"version":1,"entries":[["{}",5]]}}"#, h(1)),
        ),
        (
            "v2 ok",
            format!(r#"{{"version":2,"entries":[["{}",5,7]]}}"#, h(1)),
        ),
        (
            "v2 with one 2-tuple entry (mixed)",
            format!(
                r#"{{"version":2,"entries":[["{}",5,7],["{}",6]]}}"#,
                h(1),
                h(2)
            ),
        ),
        (
            "v1 with one 3-tuple entry (mixed)",
            format!(
                r#"{{"version":1,"entries":[["{}",5],["{}",6,9]]}}"#,
                h(1),
                h(2)
            ),
        ),
        (
            "v1, one bad height",
            format!(
                r#"{{"version":1,"entries":[["{}",5],["{}",-1]]}}"#,
                h(1),
                h(2)
            ),
        ),
        (
            "v1, one bad id (kept: dropped alone)",
            format!(r#"{{"version":1,"entries":[["{}",5],["zz",6]]}}"#, h(1)),
        ),
        (
            "v1, duplicate id",
            format!(
                r#"{{"version":1,"entries":[["{}",5],["{}",900]]}}"#,
                h(1),
                h(1)
            ),
        ),
        (
            "v2 then truncated",
            format!(r#"{{"version":2,"entries":[["{}",5,7]"#, h(1)),
        ),
        (
            "version after entries",
            format!(r#"{{"entries":[["{}",5]],"version":1}}"#, h(1)),
        ),
        (
            "version missing",
            format!(r#"{{"entries":[["{}",5]]}}"#, h(1)),
        ),
        (
            "v2 entries as v1 shape, extra field",
            format!(r#"{{"version":1,"entries":[["{}",5]],"x":1}}"#, h(1)),
        ),
    ];
    for (what, json) in cases {
        match Originated::decode(json.as_bytes()) {
            Ok(o) => eprintln!(
                "RT decode {what}: Ok len {} relayed(1) {:?}",
                o.len(),
                o.relayed(&id(1))
            ),
            Err(e) => eprintln!("RT decode {what}: Err {e}"),
        }
    }
}

/// The held mark across a mined-then-returned cycle at the same height, as
/// `refresh_held` sees it only at a height tick.
#[test]
fn rt_held_mark_survives_a_same_height_return() {
    let mut o = Originated::new();
    o.record(id(1), 81);
    o.note_held(id(1), 90);
    // Mined at 90 and returned by a reorganization readmitting it for 90
    // before any tick saw it gone.
    o.refresh_held(&[(id(1), Some(90))]);
    eprintln!(
        "RT held after same-height return: {:?}",
        o.anchor(&id(1), 90)
    );
    // Prune boundary: the mark goes with the entry exactly at the window.
    o.note_held(id(1), 90);
    assert_eq!(o.prune(81 + NETWORK_EXPIRY_BLOCKS - 1), 0);
    assert!(o.is_held(&id(1)));
    assert_eq!(o.prune(81 + NETWORK_EXPIRY_BLOCKS), 1);
    assert!(!o.is_held(&id(1)));
}
