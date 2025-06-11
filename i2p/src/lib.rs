//! I2P SAM client for BlackSilk node (production-ready scaffold)
//! Provides session management, destination/key generation, and streaming/datagram support

use std::io::{BufRead, BufReader, Write, Read};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use rand::Rng;

/// Default SAM bridge address (localhost)
pub const DEFAULT_SAM_ADDR: &str = "127.0.0.1:7656";

#[derive(Debug, Clone)]
pub struct I2pDestination {
    pub public: String,
    pub private: String,
}

#[derive(Debug)]
pub struct SamSession {
    pub nickname: String,
    pub dest: I2pDestination,
    pub sam_addr: String,
    stream: TcpStream,
}

impl SamSession {
    /// Connect to SAM bridge and create a session (STREAM or DATAGRAM)
    pub fn connect<A: ToSocketAddrs>(sam_addr: A, session_nick: &str, style: &str) -> std::io::Result<Self> {
        let mut stream = TcpStream::connect(sam_addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        let mut reader = BufReader::new(stream.try_clone()?);

        // Generate a random nickname if not provided
        let nickname = if session_nick.is_empty() {
            let mut rng = rand::thread_rng();
            format!("bsilk-{}", rng.gen::<u32>())
        } else {
            session_nick.to_string()
        };

        // Create session
        let cmd = format!("SESSION CREATE STYLE={} ID={} DESTINATION=TRANSIENT\n", style, nickname);
        stream.write_all(cmd.as_bytes())?;
        stream.flush()?;
        let mut response = String::new();
        reader.read_line(&mut response)?;
        if !response.contains("RESULT=OK") {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("SAM session failed: {}", response)));
        }

        // Extract destination keys
        let mut pubkey = String::new();
        let mut privkey = String::new();
        for part in response.split_whitespace() {
            if part.starts_with("DESTINATION=") {
                let dest = part.trim_start_matches("DESTINATION=");
                pubkey = dest.to_string();
                privkey = dest.to_string(); // For TRANSIENT, both are the same; for PERSISTENT, parse keys
            }
        }
        let dest = I2pDestination { public: pubkey, private: privkey };
        Ok(Self { nickname: nickname.clone(), dest, sam_addr: nickname.clone(), stream })
    }

    /// Send a datagram to a destination
    pub fn send_datagram(&mut self, dest: &str, data: &[u8]) -> std::io::Result<()> {
        let cmd = format!("DATAGRAM SEND DESTINATION={} SIZE={}\n", dest, data.len());
        self.stream.write_all(cmd.as_bytes())?;
        self.stream.write_all(data)?;
        self.stream.flush()
    }

    /// Receive a datagram (blocking)
    pub fn recv_datagram(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }

    /// Send a streaming message (I2P streaming)
    pub fn send_stream(&mut self, dest: &str, data: &[u8]) -> std::io::Result<()> {
        // For streaming, open a new connection to SAM STREAM FORWARD
        let mut stream = TcpStream::connect(&self.sam_addr)?;
        let cmd = format!("STREAM CONNECT ID={} DESTINATION={} SILENT=false\n", self.nickname, dest);
        stream.write_all(cmd.as_bytes())?;
        stream.write_all(data)?;
        stream.flush()
    }

    /// Receive from stream (blocking)
    pub fn recv_stream(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }
}

/// High-level API for node integration
pub struct I2pClient {
    pub session: SamSession,
}

impl I2pClient {
    pub fn new(sam_addr: &str, session_nick: &str, style: &str) -> std::io::Result<Self> {
        let session = SamSession::connect(sam_addr, session_nick, style)?;
        Ok(Self { session })
    }

    pub fn get_destination(&self) -> &I2pDestination {
        &self.session.dest
    }

    pub fn send_to(&mut self, dest: &str, data: &[u8]) -> std::io::Result<()> {
        self.session.send_datagram(dest, data)
    }

    pub fn receive(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.session.recv_datagram(buf)
    }
}
