//! `CachedPow::compute_parallel` logs no error when nothing went wrong: the
//! pool's "PoW helper thread(s) ended unexpectedly" report is for helpers
//! that really ended, not for every start (a miscounted check logged it on
//! the first start and on every later one). Its own test binary, so the
//! global logger installed here sees only this test.

use blacksilk_chain::manager::{CachedPow, PowJob};
use blacksilk_consensus::hash::H;
use blacksilk_consensus::{Hash, PowFunction, POW_BLOB_SIZE};
use std::sync::{Arc, Mutex};

/// Records the message of every error-level record.
struct Capture {
    errors: Mutex<Vec<String>>,
}

impl log::Log for Capture {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Error
    }
    fn log(&self, record: &log::Record) {
        if record.level() <= log::Level::Error {
            self.errors
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(record.args().to_string());
        }
    }
    fn flush(&self) {}
}

static CAPTURE: Capture = Capture {
    errors: Mutex::new(Vec::new()),
};

fn take_errors() -> Vec<String> {
    std::mem::take(&mut *CAPTURE.errors.lock().unwrap_or_else(|e| e.into_inner()))
}

/// A cheap deterministic proof of work (no RandomX).
struct Cheap;

impl PowFunction for Cheap {
    fn pow_hash(&self, seed: &Hash, blob: &blacksilk_consensus::PowBlob) -> Hash {
        H::new()
            .chain(b"pow-pool-log-test")
            .chain(seed)
            .chain(blob)
            .finish()
    }
}

fn jobs(n: u64, salt: u8) -> Vec<PowJob> {
    (0..n)
        .map(|i| {
            let mut b = [salt; POW_BLOB_SIZE];
            b[..8].copy_from_slice(&i.to_le_bytes());
            ([(i % 3) as u8 + 1; 32], b)
        })
        .collect()
}

#[test]
fn starting_the_pool_logs_no_error_when_no_helper_ended() {
    log::set_logger(&CAPTURE).expect("the only logger of this test binary");
    log::set_max_level(log::LevelFilter::Error);

    // The capture works: a marker error is recorded.
    log::error!("pow-pool-log-test marker");
    assert_eq!(take_errors(), vec!["pow-pool-log-test marker".to_string()]);

    let pow = CachedPow::new(Arc::new(Cheap));
    // The first call starts the helpers; the later ones reuse them (nothing
    // ended, so each start's check finds every helper still running).
    for (round, salt) in [0x11u8, 0x22, 0x33].into_iter().enumerate() {
        let batch = jobs(40, salt);
        pow.compute_parallel(&batch, 4);
        assert!(
            batch.iter().all(|(s, b)| pow.lookup(s, b).is_some()),
            "round {round}: every job hashed"
        );
        assert_eq!(pow.pool_threads(), 3, "round {round}: three helpers run");
        assert_eq!(take_errors(), Vec::<String>::new(), "round {round}");
    }
}
