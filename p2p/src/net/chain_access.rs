//! Async access to the chain actor (`blacksilk_chain::actor`, docs/p2p.md
//! §10): every chain operation of the P2P layer (and of the node's RPC)
//! goes through these functions, so later changes to how the chain is
//! reached stay here.
//!
//! - A command's result comes back through a `tokio::sync::oneshot`: no
//!   async worker and no blocking thread ever waits for chain work.
//! - A full lane is back-pressure, not a failure: [`call`] and
//!   [`submit_block`] offer the command again after [`FULL_RETRY`] (the
//!   caller's task sleeps; nothing blocks). Only relayed transactions use
//!   [`try_call`], which gives up at once (relay is best effort, never
//!   penalized).
//! - The actor never takes the network-state lock or awaits P2P, and these
//!   functions are never called with the state lock held (the lock-ordering
//!   rule: `State` is behind a `std::sync::Mutex`, whose guard is not held
//!   across these `.await`s).

use blacksilk_chain::actor::{BlockReply, ChainHandle, Lane, SendError};
use blacksilk_chain::block::Block;
use blacksilk_chain::manager::ChainManager;
use std::time::Duration;

/// How long a caller waits before it offers a command to a full lane again.
pub const FULL_RETRY: Duration = Duration::from_millis(2);

/// Runs `f` on `lane` and returns its result. Waits (asynchronously) while
/// the lane is full. `None` if the actor stopped: the node is shutting
/// down.
pub async fn call<T, F>(chain: &ChainHandle, lane: Lane, f: F) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce(&mut ChainManager) -> T + Send + 'static,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut offer = (f, move |r| {
        let _ = tx.send(r);
    });
    loop {
        match chain.call(lane, offer.0, offer.1) {
            Ok(()) => return rx.await.ok(),
            Err(r) if matches!(r.error, SendError::Full(_)) => {
                offer = *r.returned;
                tokio::time::sleep(FULL_RETRY).await;
            }
            Err(_) => return None,
        }
    }
}

/// Runs `f` on `lane` if the lane has room now: `Err(Full)` drops the
/// command (relayed transactions, best effort).
pub async fn try_call<T, F>(chain: &ChainHandle, lane: Lane, f: F) -> Result<T, SendError>
where
    T: Send + 'static,
    F: FnOnce(&mut ChainManager) -> T + Send + 'static,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    chain
        .call(lane, f, move |r| {
            let _ = tx.send(r);
        })
        .map_err(|r| r.error)?;
    rx.await.map_err(|_| SendError::Stopped)
}

/// Submits `block` on the Blocks lane and returns the final verdict (the
/// actor answers once the drain it started has finished), waiting while the
/// lane is full. `None` if the actor stopped; `Some(None)` if
/// `only_if_header_known` and the header is unknown.
pub async fn submit_block(
    chain: &ChainHandle,
    block: Block,
    now: u64,
    only_if_header_known: bool,
) -> Option<BlockReply> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut offer = (block, move |r| {
        let _ = tx.send(r);
    });
    loop {
        match chain.submit_block(offer.0, now, only_if_header_known, offer.1) {
            Ok(()) => return rx.await.ok(),
            Err(r) if matches!(r.error, SendError::Full(_)) => {
                offer = *r.returned;
                tokio::time::sleep(FULL_RETRY).await;
            }
            Err(_) => return None,
        }
    }
}
