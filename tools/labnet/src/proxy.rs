//! A TCP link emulator: forwards connections to a target, delays every chunk by
//! `latency + U(0, jitter)` (order preserved), and can be cut (all connections
//! dropped, new ones refused) to model partitions.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

#[derive(Clone)]
pub struct LinkHandle {
    up: watch::Sender<bool>,
    pub bytes: Arc<AtomicU64>,
}

impl LinkHandle {
    pub fn set_up(&self, up: bool) {
        let _ = self.up.send(up);
    }
}

struct Jitter(u64);

impl Jitter {
    fn next(&mut self, max_ms: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        if max_ms == 0 {
            0
        } else {
            self.0 % (max_ms + 1)
        }
    }
}

pub async fn start(
    listen: SocketAddr,
    target: SocketAddr,
    latency: Duration,
    jitter_ms: u64,
) -> std::io::Result<LinkHandle> {
    let listener = TcpListener::bind(listen).await?;
    let (tx, rx) = watch::channel(true);
    let bytes = Arc::new(AtomicU64::new(0));
    let handle = LinkHandle {
        up: tx,
        bytes: bytes.clone(),
    };
    let seed = (listen.port() as u64 * 0x9E37_79B9_7F4A_7C15) | 1;
    tokio::spawn(async move {
        let mut n = 0u64;
        loop {
            let Ok((inbound, _)) = listener.accept().await else {
                continue;
            };
            if !*rx.borrow() {
                drop(inbound);
                continue;
            }
            n += 1;
            let rx = rx.clone();
            let bytes = bytes.clone();
            tokio::spawn(async move {
                let Ok(outbound) = TcpStream::connect(target).await else {
                    return;
                };
                let _ = inbound.set_nodelay(true);
                let _ = outbound.set_nodelay(true);
                let (ir, iw) = inbound.into_split();
                let (or, ow) = outbound.into_split();
                let a = tokio::spawn(pump(ir, ow, latency, jitter_ms, seed ^ n, bytes.clone()));
                let b = tokio::spawn(pump(or, iw, latency, jitter_ms, seed ^ (n << 1), bytes));
                let mut rx = rx;
                // Cut the connection when the link goes down.
                loop {
                    tokio::select! {
                        _ = rx.changed() => {
                            if !*rx.borrow() { break; }
                        }
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {
                            if a.is_finished() || b.is_finished() { break; }
                        }
                    }
                }
                a.abort();
                b.abort();
            });
        }
    });
    Ok(handle)
}

async fn pump<R, W>(
    mut r: R,
    mut w: W,
    latency: Duration,
    jitter_ms: u64,
    seed: u64,
    bytes: Arc<AtomicU64>,
) where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
    let writer = tokio::spawn(async move {
        while let Some((at, chunk)) = rx.recv().await {
            tokio::time::sleep_until(at).await;
            if w.write_all(&chunk).await.is_err() {
                break;
            }
        }
    });
    let mut jitter = Jitter(seed | 1);
    let mut last = Instant::now();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        bytes.fetch_add(n as u64, Ordering::Relaxed);
        let at =
            (Instant::now() + latency + Duration::from_millis(jitter.next(jitter_ms))).max(last);
        last = at;
        if tx.send((at, buf[..n].to_vec())).is_err() {
            break;
        }
    }
    drop(tx);
    let _ = writer.await;
}
