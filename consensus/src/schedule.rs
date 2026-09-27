//! Height-scheduled rule sets (docs/consensus.md §11; design and alternatives in
//! docs/reviews/v3-upgrade-mechanism.md).
//!
//! A [`Schedule`] is a table of [`Epoch`]s, each active from its activation
//! height until the next one. An epoch names what a block at that height must
//! use:
//! - the header version (checked by [`crate::HeaderChain`]);
//! - the branch id, hashed into every transaction signature message and the PX
//!   proof binding, so a transaction is valid in one epoch only;
//! - the PX verifier id.
//!
//! Every built-in network uses [`V3`], a single epoch from height 0, so the
//! rules are the same at every height.

use crate::header::HEADER_VERSION;

/// One rule set and the height from which it applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Epoch {
    /// A label for logs and errors; not consensus data.
    pub name: &'static str,
    pub activation_height: u64,
    /// The version every header of this epoch carries.
    pub header_version: u32,
    /// Committed to by every signature message and the PX binding `h_tx`.
    pub branch_id: u32,
    /// The PX verifier (kernel, parameter set and kernel budgets) of this epoch.
    pub verifier_id: u32,
}

/// The PX verifier of testnet v3: the kernel pinned in `px/kernel.id`, the
/// parameter set of `blacksilk_zk::params` and `px::prove::kernel_budget`.
pub const VERIFIER_PX_1: u32 = 1;

/// Branch id of the v3 rule set: the ASCII bytes `BSv3`, big-endian.
pub const BRANCH_ID_V3: u32 = u32::from_be_bytes(*b"BSv3");

/// An activation table, validated when it is built ([`Schedule::new`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Schedule {
    epochs: &'static [Epoch],
}

/// The schedule of every built-in network: one epoch from genesis.
pub const V3: Schedule = Schedule::new(&[Epoch {
    name: "v3",
    activation_height: 0,
    header_version: HEADER_VERSION,
    branch_id: BRANCH_ID_V3,
    verifier_id: VERIFIER_PX_1,
}]);

impl Schedule {
    /// Builds a schedule.
    ///
    /// # Panics
    /// Unless the table is non-empty, starts at height 0, has strictly
    /// increasing activation heights and non-decreasing header versions, and
    /// has nonzero, pairwise distinct branch ids. In a `const` or `static`
    /// this is a compile error.
    pub const fn new(epochs: &'static [Epoch]) -> Self {
        assert!(!epochs.is_empty(), "a schedule needs an epoch");
        assert!(
            epochs[0].activation_height == 0,
            "the first epoch starts at genesis"
        );
        let mut i = 0;
        while i < epochs.len() {
            assert!(epochs[i].branch_id != 0, "branch id 0 is reserved");
            if i > 0 {
                assert!(
                    epochs[i].activation_height > epochs[i - 1].activation_height,
                    "activation heights must increase"
                );
                assert!(
                    epochs[i].header_version >= epochs[i - 1].header_version,
                    "header versions must not decrease"
                );
            }
            let mut j = 0;
            while j < i {
                assert!(
                    epochs[j].branch_id != epochs[i].branch_id,
                    "branch ids must be distinct"
                );
                j += 1;
            }
            i += 1;
        }
        Self { epochs }
    }

    pub fn epochs(&self) -> &'static [Epoch] {
        self.epochs
    }

    /// The number of epochs (at least 1).
    pub fn len(&self) -> usize {
        self.epochs.len()
    }

    /// Always false: a schedule has at least one epoch.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The epoch active at `height`: the last one whose activation height is
    /// at most `height`.
    pub fn epoch_at(&self, height: u64) -> &'static Epoch {
        let i = self
            .epochs
            .partition_point(|e| e.activation_height <= height);
        // The first epoch starts at 0, so `i >= 1`.
        &self.epochs[i - 1]
    }

    /// The highest header version any epoch uses. A header with a higher
    /// version belongs to an upgrade this node does not know.
    pub fn max_header_version(&self) -> u32 {
        self.epochs
            .iter()
            .map(|e| e.header_version)
            .max()
            .unwrap_or(HEADER_VERSION)
    }

    /// The first epoch activated at a height in `(from, to]`, if any. A pool
    /// of transactions checked for inclusion at `from` must be flushed (or
    /// fully revalidated) when the next block height becomes `to`.
    pub fn activation_in(&self, from: u64, to: u64) -> Option<&'static Epoch> {
        self.epochs
            .iter()
            .find(|e| e.activation_height > from && e.activation_height <= to)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn epoch(activation_height: u64, header_version: u32, branch_id: u32) -> Epoch {
        Epoch {
            name: "t",
            activation_height,
            header_version,
            branch_id,
            verifier_id: VERIFIER_PX_1,
        }
    }

    static THREE: [Epoch; 3] = [epoch(0, 1, 10), epoch(100, 1, 11), epoch(250, 2, 12)];

    #[test]
    fn v3_is_one_epoch_from_genesis_with_header_version_1() {
        assert_eq!(V3.len(), 1);
        let e = V3.epoch_at(0);
        assert_eq!(e.header_version, HEADER_VERSION);
        assert_eq!(e.header_version, 1);
        assert_eq!(e.branch_id, 0x4253_7633);
        assert_eq!(e.verifier_id, VERIFIER_PX_1);
        assert_eq!(V3.epoch_at(u64::MAX), e);
        assert_eq!(V3.max_header_version(), 1);
        assert_eq!(V3.activation_in(0, u64::MAX), None);
    }

    #[test]
    fn epoch_lookup_at_boundaries() {
        let s = Schedule::new(&THREE);
        let branch = |h| s.epoch_at(h).branch_id;
        assert_eq!(branch(0), 10);
        assert_eq!(branch(99), 10);
        assert_eq!(branch(100), 11);
        assert_eq!(branch(101), 11);
        assert_eq!(branch(249), 11);
        assert_eq!(branch(250), 12);
        assert_eq!(branch(u64::MAX), 12);
        assert_eq!(s.max_header_version(), 2);
    }

    #[test]
    fn activation_in_is_half_open() {
        let s = Schedule::new(&THREE);
        assert_eq!(s.activation_in(0, 99), None);
        assert_eq!(s.activation_in(99, 100).map(|e| e.branch_id), Some(11));
        assert_eq!(s.activation_in(100, 101), None);
        assert_eq!(s.activation_in(50, 300).map(|e| e.branch_id), Some(11));
        assert_eq!(s.activation_in(249, 250).map(|e| e.branch_id), Some(12));
        assert_eq!(s.activation_in(250, u64::MAX), None);
    }

    fn rejects(epochs: &'static [Epoch]) -> bool {
        std::panic::catch_unwind(|| Schedule::new(epochs)).is_err()
    }

    #[test]
    fn malformed_tables_are_rejected() {
        static EMPTY: [Epoch; 0] = [];
        static LATE_START: [Epoch; 1] = [epoch(1, 1, 10)];
        static SAME_HEIGHT: [Epoch; 2] = [epoch(0, 1, 10), epoch(0, 1, 11)];
        static TWO: [Epoch; 2] = [epoch(0, 1, 10), epoch(5, 1, 11)];
        static DECREASING: [Epoch; 3] = [epoch(0, 1, 10), epoch(5, 1, 11), epoch(3, 1, 12)];
        static OLDER_VERSION: [Epoch; 2] = [epoch(0, 2, 10), epoch(5, 1, 11)];
        static REUSED_BRANCH: [Epoch; 3] = [epoch(0, 1, 10), epoch(5, 1, 11), epoch(9, 1, 10)];
        static ZERO_BRANCH: [Epoch; 1] = [epoch(0, 1, 0)];
        assert!(rejects(&EMPTY));
        assert!(rejects(&LATE_START));
        assert!(rejects(&SAME_HEIGHT));
        assert!(!rejects(&TWO), "same header version, new branch id");
        assert!(rejects(&DECREASING));
        assert!(rejects(&OLDER_VERSION));
        assert!(rejects(&REUSED_BRANCH));
        assert!(rejects(&ZERO_BRANCH));
        assert!(!rejects(&THREE));
    }
}
