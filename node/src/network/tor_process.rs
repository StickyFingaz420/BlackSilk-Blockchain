//! Tor process management for BlackSilk node (Windows-compatible)
//! Handles auto-start, health check, and shutdown of Tor for privacy networking.

use std::process::{Child, Command, Stdio};
use std::io::{self, Write};
use std::net::TcpStream;
use std::time::Duration;
use std::thread;

pub struct TorProcess {
    child: Option<Child>,
    pub running: bool,
}

impl TorProcess {
    /// Attempt to connect to the Tor SOCKS5 proxy to check if Tor is running
    pub fn is_tor_running(socks_port: u16) -> bool {
        TcpStream::connect(("127.0.0.1", socks_port)).is_ok()
    }

    /// Start the Tor process if not already running
    pub fn start(socks_port: u16, control_port: u16) -> io::Result<Self> {
        if Self::is_tor_running(socks_port) {
            println!("[Privacy] Tor is already running on port {}", socks_port);
            return Ok(TorProcess { child: None, running: true });
        }
        println!("[Privacy] Attempting to start Tor process...");
        // Windows: use tor.exe if available in PATH or local dir
        let tor_cmd = if cfg!(windows) { "tor.exe" } else { "tor" };
        let child = Command::new(tor_cmd)
            .arg(format!("--SocksPort {}", socks_port))
            .arg(format!("--ControlPort {}", control_port))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        // Wait for Tor to become available
        for _ in 0..10 {
            if Self::is_tor_running(socks_port) {
                println!("[Privacy] Tor started successfully on port {}", socks_port);
                return Ok(TorProcess { child: Some(child), running: true });
            }
            thread::sleep(Duration::from_secs(1));
        }
        println!("[Privacy] Failed to start Tor within timeout");
        Ok(TorProcess { child: Some(child), running: false })
    }

    /// Cleanly shut down the Tor process if we started it
    pub fn shutdown(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
            println!("[Privacy] Tor process shut down");
        }
        self.running = false;
    }
}

impl Drop for TorProcess {
    fn drop(&mut self) {
        self.shutdown();
    }
}
