//! BlackSilk peer-to-peer network (`docs/p2p.md`).
//!
//! | Module | Spec | Content |
//! |---|---|---|
//! | [`transport`] | §3 | Ristretto255 key exchange, AES-256-GCM framed encryption, optional network pre-shared key |
//! | [`message`] | §4–§5 | protocol messages, strict bounded codec |
//! | [`addr`] | §5, §9 | IPv4/IPv6/Tor v3 addresses, network groups, routability |
//! | [`addrman`] | §9 | keyed new/tried address tables with test-before-evict, ban list |
//! | [`addrman_gate`] | §9 | per-peer admission and freshness of received addresses |
//! | [`clock`] | §6.1 | warn-only estimate of the local clock's offset against recent blocks |
//! | [`connman`] | §9 | inbound eviction, anchors, feelers, stale-tip rotation |
//! | [`dandelion`] | §8 | Dandelion++ epochs, routes, embargo |
//! | [`limits`] | §10 | token buckets, misbehavior scores |
//! | [`socks5`] | §11 | SOCKS5 client for Tor |
//! | [`net`] | §4–§11 | the network manager |
//! | [`originated`] | §8.1 | transactions this node originated, persisted (no re-origination) |

#![forbid(unsafe_code)]

pub mod addr;
pub mod addrman;
pub mod addrman_gate;
pub mod clock;
pub mod connman;
pub mod dandelion;
pub mod limits;
pub mod message;
pub mod net;
pub mod originated;
pub mod private_file;
pub mod socks5;
pub mod transport;

pub use addr::NetAddr;
pub use net::{
    chain_access, lock_or_exit, NetConfig, NetStats, Network, PeerInfo, SharedChain,
    POISONED_EXIT_CODE,
};

/// The build marker of this crate's test-only code (the stateful fuzz targets'
/// network hooks, `net::fuzzing` and `admission::for_tests`):
/// `Some("+test-hooks:p2p")` when the `test-hooks` feature is compiled
/// in, `None` otherwise. A dev-dependency of a `cargo test` build turns the
/// feature on, and cargo unifies it into every binary that invocation builds;
/// the string is in a binary only when the hooks are. Binaries print it in
/// `--version` and refuse every network but regtest while it is set
/// (`blacksilk_chain::build_flags`, W4-GUARD).
#[cfg(feature = "test-hooks")]
pub const TEST_HOOKS_MARKER: Option<&str> = Some("+test-hooks:p2p");
/// See the `test-hooks` variant: `None`, no test-only code compiled in.
#[cfg(not(feature = "test-hooks"))]
pub const TEST_HOOKS_MARKER: Option<&str> = None;
/// Whether this crate's `test-hooks` feature is compiled in.
pub const TEST_HOOKS: bool = TEST_HOOKS_MARKER.is_some();

/// The build marker of this crate's `cfg(fuzzing)` code (the transport's
/// fixed ephemeral secrets on request, `transport.rs`): `Some("+fuzzing:p2p")`
/// only in a cargo-fuzz build. The node prints it with the test-hooks markers
/// and refuses every network but regtest while it is set; its build script
/// refuses `cfg(fuzzing)` outright (W4-GUARD).
#[cfg(fuzzing)]
pub const FUZZING_MARKER: Option<&str> = Some("+fuzzing:p2p");
/// See the `cfg(fuzzing)` variant: `None` outside a fuzz build.
#[cfg(not(fuzzing))]
pub const FUZZING_MARKER: Option<&str> = None;
