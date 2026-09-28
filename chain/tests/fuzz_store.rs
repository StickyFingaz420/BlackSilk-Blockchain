//! The `blocks.dat` v2 record decoder under the stable fuzz driver: the body
//! of the `store_records` fuzz target (fuzz/src/targets/store_records.rs:
//! bind, load and repair through the public `FileStore` API, with a spec
//! oracle for the canonical round trip) on seeded mutations of its seed
//! corpus. `BLACKSILK_FUZZ_ITERS` scales it (fuzz/src/targets/driver.rs).

#[path = "../../fuzz/src/targets/driver.rs"]
mod driver;
#[path = "../../fuzz/src/targets/store_records.rs"]
mod target;

use blacksilk_chain::store::{BlockStore, FileStore, StoreIdentity};
use blacksilk_consensus::Network;

#[test]
fn store_records_survive_mutation() {
    let seeds: Vec<Vec<u8>> = target::seeds().into_iter().map(|(_, s)| s).collect();
    driver::drive("store_records", &seeds, 64 * 1024, target::run);
}

/// The target's independent CRC-32 and header encoder agree with the store:
/// fixing the checksums of a file the store wrote changes nothing, and the
/// header is the one `bind` writes. Every seed passes on its own.
#[test]
fn the_oracle_agrees_with_the_store() {
    assert_eq!(
        target::crc32(&[b"123456789"]),
        0xCBF4_3926,
        "the CRC-32 check value"
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocks.dat");
    let mut s = FileStore::open(&path).unwrap();
    s.bind(&StoreIdentity {
        network: Network::Regtest,
        network_id: 0x0001_D672,
        genesis_id: [0x42; 32],
    })
    .unwrap();
    s.append(&[1; 32], b"block").unwrap();
    s.append(&[2; 32], &[7; 1000]).unwrap();
    drop(s);
    let file = std::fs::read(&path).unwrap();
    assert_eq!(file[..48], target::file_header()[..]);
    let mut fixed = file.clone();
    target::fix_checksums(&mut fixed);
    assert_eq!(fixed, file);
    for (name, s) in target::seeds() {
        println!("seed {name}: {} bytes", s.len());
        target::run(&s);
    }
}
