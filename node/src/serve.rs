//! The RPC server loop (docs/blocks.md §9.1): connection limits around the
//! router, and the node's authenticated RPC ([`run`]).
//!
//! `axum::serve` (axum 0.7) gives hyper no timer, so hyper's header-read
//! timeout never fires, and it accepts connections without bound (F36-4).
//! This loop drives hyper's HTTP/1 connections itself, with:
//! - a cap on open connections: a connection beyond it is closed at once;
//! - a header-read timeout, which also ends idle keep-alive connections
//!   (hyper starts it whenever it waits for a request head);
//! - a bound on the request head (`max_buf_size`, then `431`);
//! - graceful shutdown: in-flight requests finish, within a grace period.

use crate::cookie::CookieFile;
use crate::guard::Policy;
use crate::{router_secured, App};
use axum::Router;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use std::future::Future;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};

/// Connection-level limits.
#[derive(Clone, Debug)]
pub struct ConnLimits {
    /// Open connections at once.
    pub max_connections: usize,
    /// Time to receive a request head, and the longest idle time between
    /// requests on a kept-alive connection.
    pub header_read_timeout: Duration,
    /// Largest request head (request line and headers), in bytes. hyper's
    /// minimum is 8 KiB.
    pub max_head_bytes: usize,
    /// How long shutdown waits for in-flight requests.
    pub shutdown_grace: Duration,
}

impl Default for ConnLimits {
    fn default() -> Self {
        Self {
            // The admission classes (guard::Limits) bound the chain work;
            // this bounds sockets and tasks, with room for the long polls.
            max_connections: 64,
            header_read_timeout: Duration::from_secs(10),
            max_head_bytes: 16 * 1024,
            shutdown_grace: Duration::from_secs(10),
        }
    }
}

/// Serves `router` on `listener` until `shutdown` resolves, then lets
/// in-flight requests finish (at most [`ConnLimits::shutdown_grace`]).
pub async fn serve(
    listener: TcpListener,
    router: Router,
    limits: ConnLimits,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    let slots = Arc::new(Semaphore::new(limits.max_connections));
    let (stop_tx, stop_rx) = watch::channel(false);
    let service = TowerToHyperService::new(router);
    tokio::pin!(shutdown);
    loop {
        let (stream, peer) = tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok(a) => a,
                Err(e) => {
                    // Out of file descriptors and similar: back off, as
                    // axum::serve does, instead of spinning.
                    log::warn!("RPC accept: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            log::debug!(
                "RPC: connection from {peer} refused: {} open",
                limits.max_connections
            );
            drop(stream);
            continue;
        };
        let _ = stream.set_nodelay(true);
        let service = service.clone();
        let mut stop = stop_rx.clone();
        let (timeout, head) = (limits.header_read_timeout, limits.max_head_bytes);
        tokio::spawn(async move {
            let _slot = slot;
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(timeout)
                .max_buf_size(head.max(8 * 1024))
                .keep_alive(true);
            let conn = builder.serve_connection(TokioIo::new(stream), service);
            tokio::pin!(conn);
            let stopping = async move {
                let _ = stop.wait_for(|s| *s).await;
            };
            tokio::select! {
                r = conn.as_mut() => {
                    if let Err(e) = r {
                        log::debug!("RPC connection {peer}: {e}");
                    }
                }
                () = stopping => {
                    conn.as_mut().graceful_shutdown();
                    let _ = conn.await;
                }
            }
        });
    }
    drop(listener);
    let _ = stop_tx.send(true);
    // Every connection task holds a slot until it ends.
    let all = limits.max_connections as u32;
    if tokio::time::timeout(limits.shutdown_grace, slots.acquire_many(all))
        .await
        .is_err()
    {
        log::warn!("RPC: requests still running after the shutdown grace period");
    }
    Ok(())
}

/// Everything the node's RPC needs besides the chain.
#[derive(Clone, Debug, Default)]
pub struct RpcSettings {
    /// Host names accepted besides loopback and the bound address
    /// (`rpc_allow_hosts`).
    pub allow_hosts: Vec<String>,
    pub limits: crate::guard::Limits,
    pub conn: ConnLimits,
}

/// The node's RPC: writes a fresh credential to `<data_dir>/rpc.cookie`,
/// serves the guarded, authenticated router on `listener` until `shutdown`,
/// then removes the cookie. There is no way to run it without
/// authentication.
pub async fn run(
    listener: TcpListener,
    app: App,
    data_dir: &Path,
    settings: RpcSettings,
    shutdown: impl Future<Output = ()>,
) -> Result<(), String> {
    let bound: IpAddr = listener.local_addr().map_err(|e| e.to_string())?.ip();
    let cookie = CookieFile::create(data_dir)
        .map_err(|e| format!("RPC cookie in {}: {e}", data_dir.display()))?;
    log::info!(
        "RPC credential written to {} (clients read it: --rpc-cookie)",
        cookie.path().display()
    );
    let policy = Policy {
        token: Some(cookie.token().clone()),
        allow_hosts: settings.allow_hosts,
        bound_ip: Some(bound),
        limits: settings.limits,
    };
    let served = serve(
        listener,
        router_secured(app, policy),
        settings.conn,
        shutdown,
    )
    .await
    .map_err(|e| e.to_string());
    drop(cookie);
    served
}
