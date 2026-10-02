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
    // Fails closed (RT-TM2P2P item 5): id 1, at height 5, survives every
    // damage below, and a duplicate keeps the highest height.
    for (what, json) in cases {
        let (o, problems) = Originated::decode(json.as_bytes());
        eprintln!(
            "RT decode {what}: len {} relayed(1) {:?} problems {problems:?}",
            o.len(),
            o.relayed(&id(1))
        );
        let want = if what == "v1, duplicate id" { 900 } else { 5 };
        assert_eq!(o.relayed(&id(1)), Some(want), "{what}");
    }
}

/// The prune boundary of an entry (the held marks of the earlier design are
/// gone: a held copy is not pooled at all).
#[test]
fn rt_prune_boundary_is_exact() {
    let mut o = Originated::new();
    o.record(id(1), 81);
    assert_eq!(o.prune(81 + NETWORK_EXPIRY_BLOCKS - 1), 0);
    assert_eq!(o.relayed(&id(1)), Some(81));
    assert_eq!(o.prune(81 + NETWORK_EXPIRY_BLOCKS), 1);
    assert!(o.is_empty());
}
