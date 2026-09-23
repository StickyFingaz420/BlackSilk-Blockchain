//! BlackSilk transaction cryptography.
//!
//! Implements the cryptographic parts of `docs/transactions.md` and
//! `docs/contracts.md`:
//!
//! | Module | Spec | Content |
//! |---|---|---|
//! | [`hash`] | §1.2 | domain-separated Blake2b, hash-to-scalar, hash-to-group |
//! | [`point`] | §1.1 | canonical Ristretto255 point and scalar decoding |
//! | [`generators`] | §1.3 | `G`, `H` and the Bulletproofs+ vector generators |
//! | [`commitment`] | §1.4 | Pedersen commitments |
//! | [`keys`] | §2 | wallet keys, view keys, subaddresses |
//! | [`stealth`] | §3 | one-time outputs, view tags, scanning |
//! | [`janus`] | §12 | the Janus anchor |
//! | [`clsag`] | §6.1 | CLSAG ring signatures and key images |
//! | [`bulletproofs_plus`] | §7 | aggregated Bulletproofs+ range proofs |
//! | [`nonce`] | §10 | hedged randomness for all secret values |
//! | [`schnorr`] | contracts §6.2, §7.1 | tagged Schnorr: balance kernel, auth keys |
//! | [`membership`] | contracts §7.2 | scoped linkable ring signatures (anonymous membership) |
//! | [`claims`] | contracts §8 | range, equality and reveal claims on commitments |
//!
//! All secret-dependent arithmetic uses dalek's constant-time operations.
//! Variable-time multi-scalar multiplication is used only on public data
//! (verification). Secret values are zeroized on drop. The caller supplies the
//! CSPRNG; nothing in this crate creates its own randomness source.

#![forbid(unsafe_code)]

pub mod bulletproofs_plus;
pub mod claims;
pub mod clsag;
pub mod commitment;
pub mod generators;
pub mod hash;
pub mod janus;
pub mod keys;
pub mod membership;
pub mod nonce;
pub mod point;
pub mod schnorr;
pub mod stealth;

pub use curve25519_dalek::ristretto::RistrettoPoint;
pub use curve25519_dalek::scalar::Scalar;
pub use point::Point;
