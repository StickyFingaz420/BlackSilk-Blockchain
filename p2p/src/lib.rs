//! BlackSilk peer-to-peer network (`docs/p2p.md`).
//!
//! | Module | Spec | Content |
//! |---|---|---|
//! | [`transport`] | §3 | Ristretto255 key exchange, AES-256-GCM framed encryption, optional network pre-shared key |
//! | [`message`] | §4–§5 | protocol messages, strict bounded codec |
//! | [`addr`] | §5, §9 | IPv4/IPv6/Tor v3 addresses, network groups, routability |
//! | [`addrman`] | §9 | bucketed address manager, ban list |
//! | [`addrman_gate`] | §9 | per-peer admission and freshness of received addresses |
//! | [`dandelion`] | §8 | Dandelion++ epochs, routes, embargo |
//! | [`limits`] | §10 | token buckets, misbehavior scores |
//! | [`socks5`] | §11 | SOCKS5 client for Tor |
//! | [`net`] | §4–§11 | the network manager |
//! | [`originated`] | §8.1 | transactions this node originated, persisted (no re-origination) |

#![forbid(unsafe_code)]

pub mod addr;
pub mod addrman;
pub mod addrman_gate;
pub mod dandelion;
pub mod limits;
pub mod message;
pub mod net;
pub mod originated;
pub mod socks5;
pub mod transport;

pub use addr::NetAddr;
pub use net::{
    chain_access, lock_or_exit, NetConfig, NetStats, Network, PeerInfo, SharedChain,
    POISONED_EXIT_CODE,
};
