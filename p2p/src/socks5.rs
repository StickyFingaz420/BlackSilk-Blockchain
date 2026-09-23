//! Minimal SOCKS5 client (RFC 1928, no authentication) for Tor (docs/p2p.md §11).
//! Onion addresses are passed to the proxy as domain names; no local DNS lookup
//! ever happens.

use crate::addr::NetAddr;
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn connect(proxy: SocketAddr, target: &NetAddr) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(proxy).await?;
    // Greeting: version 5, one method, "no authentication".
    s.write_all(&[5, 1, 0]).await?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await?;
    if reply != [5, 0] {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "SOCKS5 proxy refused no-auth",
        ));
    }
    let mut req = vec![5, 1, 0]; // CONNECT
    match target {
        NetAddr::Ip(a) => {
            match a.ip() {
                IpAddr::V4(v4) => {
                    req.push(1);
                    req.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    req.push(4);
                    req.extend_from_slice(&v6.octets());
                }
            }
            req.extend_from_slice(&a.port().to_be_bytes());
        }
        NetAddr::Onion { host, port } => {
            let name = format!("{host}.onion");
            req.push(3);
            req.push(name.len() as u8);
            req.extend_from_slice(name.as_bytes());
            req.extend_from_slice(&port.to_be_bytes());
        }
    }
    s.write_all(&req).await?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[0] != 5 || head[1] != 0 {
        return Err(Error::new(
            ErrorKind::ConnectionRefused,
            format!("SOCKS5 connect failed (code {})", head[1]),
        ));
    }
    // Skip the bound address.
    let skip = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize + 2
        }
        _ => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "SOCKS5 bad address type",
            ))
        }
    };
    let mut buf = vec![0u8; skip];
    s.read_exact(&mut buf).await?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// A mock SOCKS5 proxy that records the requested target and then echoes.
    async fn mock_proxy(accept: bool) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let h = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut g = [0u8; 3];
            s.read_exact(&mut g).await.unwrap();
            assert_eq!(g, [5, 1, 0]);
            s.write_all(&[5, 0]).await.unwrap();
            let mut head = [0u8; 5];
            s.read_exact(&mut head).await.unwrap();
            let mut rest = vec![0u8; head[4] as usize + 2];
            s.read_exact(&mut rest).await.unwrap();
            let mut req = head.to_vec();
            req.extend_from_slice(&rest);
            let code = if accept { 0 } else { 5 };
            s.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            if accept {
                let mut b = [0u8; 4];
                s.read_exact(&mut b).await.unwrap();
                s.write_all(&b).await.unwrap();
            }
            req
        });
        (addr, h)
    }

    #[tokio::test]
    async fn onion_names_go_to_the_proxy() {
        let onion = NetAddr::parse(&format!("{}.onion:29334", "a".repeat(56))).unwrap();
        let (proxy, h) = mock_proxy(true).await;
        let mut s = connect(proxy, &onion).await.unwrap();
        s.write_all(b"ping").await.unwrap();
        let mut b = [0u8; 4];
        s.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"ping");
        let req = h.await.unwrap();
        assert_eq!(req[3], 3, "domain-name address type (no local DNS)");
        assert_eq!(
            &req[5..5 + 62],
            format!("{}.onion", "a".repeat(56)).as_bytes()
        );
        assert_eq!(&req[req.len() - 2..], &29334u16.to_be_bytes());
    }

    #[tokio::test]
    async fn refusal_is_an_error() {
        let (proxy, h) = mock_proxy(false).await;
        let r = connect(
            proxy,
            &NetAddr::parse(&format!("{}.onion:1", "b".repeat(56))).unwrap(),
        )
        .await;
        assert!(r.is_err());
        h.await.unwrap();
    }
}
