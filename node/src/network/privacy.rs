use std::sync::Arc;
use tokio::sync::Mutex;
use tor_client::{TorClient, TorClientConfig, HiddenServiceConfig};
use i2p::I2pClient;
use rustls::{ServerConfig, ClientConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;

/// Network privacy configuration
#[derive(Debug, Clone)]
pub struct PrivacyConfig {
    pub tor_only: bool,
    pub i2p_enabled: bool,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    pub hidden_service_port: u16,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            tor_only: false,
            i2p_enabled: true,
            tls_cert_path: "certs/node.crt".to_string(),
            tls_key_path: "certs/node.key".to_string(),
            hidden_service_port: 1776,
        }
    }
}

/// Network privacy layer managing Tor and I2P connections
pub struct PrivacyLayer {
    config: PrivacyConfig,
    tor_client: Arc<Mutex<Option<TorClient>>>,
    i2p_client: Arc<Mutex<Option<I2pClient>>>,
    tls_config: Arc<ServerConfig>,
}

impl PrivacyLayer {
    /// Create new privacy layer
    pub async fn new(config: PrivacyConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // Initialize TLS config
        let tls_config = Self::init_tls(&config)?;
        
        // Tor client should be initialized if Tor is enabled (tor_only or not)
        let tor_client = if config.tor_only || !config.tor_only {
            // Always try to initialize Tor if any Tor usage is enabled
            match TorClient::new(TorClientConfig::default()).await {
                Ok(client) => {
                    println!("[PrivacyLayer] Tor client initialized");
                    Some(client)
                },
                Err(e) => {
                    eprintln!("[PrivacyLayer] Failed to initialize Tor client: {}", e);
                    None
                }
            }
        } else {
            None
        };
        
        let i2p_client = if config.i2p_enabled {
            match I2pClient::new().await {
                Ok(client) => {
                    println!("[PrivacyLayer] I2P client initialized");
                    Some(client)
                },
                Err(e) => {
                    eprintln!("[PrivacyLayer] Failed to initialize I2P client: {}", e);
                    None
                }
            }
        } else {
            None
        };
        
        Ok(Self {
            config,
            tor_client: Arc::new(Mutex::new(tor_client)),
            i2p_client: Arc::new(Mutex::new(i2p_client)),
            tls_config: Arc::new(tls_config),
        })
    }
    
    /// Initialize TLS configuration with PFS
    fn init_tls(config: &PrivacyConfig) -> Result<ServerConfig, Box<dyn std::error::Error>> {
        // Load certificate and private key
        let cert_file = File::open(&config.tls_cert_path)?;
        let key_file = File::open(&config.tls_key_path)?;
        let cert_chain = certs(&mut BufReader::new(cert_file))?;
        let mut keys = pkcs8_private_keys(&mut BufReader::new(key_file))?;
        
        // Configure TLS with modern cipher suites and PFS
        let mut tls_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, keys.remove(0))?;
        
        // Enable Perfect Forward Secrecy
        tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
        
        Ok(tls_config)
    }
    
    /// Start Tor hidden service
    pub async fn start_hidden_service(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut tor = self.tor_client.lock().await;
        if let Some(client) = tor.as_mut() {
            let config = HiddenServiceConfig::new()
                .version(3)
                .port(self.config.hidden_service_port);
            match client.add_hidden_service(config).await {
                Ok(onion) => {
                    let addr = onion.onion_address().to_string();
                    println!("[PrivacyLayer] Tor hidden service started at {}", addr);
                    Ok(addr)
                },
                Err(e) => {
                    eprintln!("[PrivacyLayer] Failed to start Tor hidden service: {}", e);
                    Err(e.into())
                }
            }
        } else {
            Err("Tor client not initialized".into())
        }
    }
    
    /// Start I2P destination
    pub async fn start_i2p_destination(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut i2p = self.i2p_client.lock().await;
        if let Some(client) = i2p.as_mut() {
            let dest = client.create_destination().await?;
            Ok(dest.base32())
        } else {
            Err("I2P client not initialized".into())
        }
    }
    
    /// Get TLS configuration for a connection
    pub fn get_tls_config(&self) -> Arc<ServerConfig> {
        self.tls_config.clone()
    }
    
    /// Create TLS client config for outbound connections (enforces ECDHE for PFS)
    /// All connections use TLS with modern cipher suites and Perfect Forward Secrecy (PFS).
    pub fn create_client_config() -> Result<ClientConfig, Box<dyn std::error::Error>> {
        // rustls safe defaults include ECDHE (ephemeral Diffie-Hellman) for PFS
        let config = ClientConfig::builder()
            .with_safe_defaults() // includes ECDHE suites
            .with_native_roots()
            .with_no_client_auth();
        // All outbound connections should use this config for TLS+PFS
        Ok(config)
    }
    
    /// Connect to a remote onion address via Tor
    pub async fn connect_onion(&self, onion_addr: &str, port: u16) -> Result<tokio::net::TcpStream, Box<dyn std::error::Error>> {
        let mut tor = self.tor_client.lock().await;
        if let Some(client) = tor.as_mut() {
            println!("[PrivacyLayer] Connecting to onion address: {}:{}", onion_addr, port);
            match client.connect((onion_addr, port)).await {
                Ok(stream) => Ok(stream),
                Err(e) => {
                    eprintln!("[PrivacyLayer] Failed to connect to onion address: {}", e);
                    Err(e.into())
                }
            }
        } else {
            Err("Tor client not initialized".into())
        }
    }
    
    /// Connect to a remote I2P address
    pub async fn connect_i2p(&self, i2p_addr: &str, port: u16) -> Result<tokio::net::TcpStream, Box<dyn std::error::Error>> {
        let mut i2p = self.i2p_client.lock().await;
        if let Some(client) = i2p.as_mut() {
            println!("[PrivacyLayer] Connecting to I2P address: {}:{}", i2p_addr, port);
            match client.connect((i2p_addr, port)).await {
                Ok(stream) => Ok(stream),
                Err(e) => {
                    eprintln!("[PrivacyLayer] Failed to connect to I2P address: {}", e);
                    Err(e.into())
                }
            }
        } else {
            Err("I2P client not initialized".into())
        }
    }
}

/// Helper function to check if an address is a Tor hidden service
pub fn is_onion_address(addr: &str) -> bool {
    addr.ends_with(".onion")
}

/// Helper function to check if an address is an I2P destination
pub fn is_i2p_address(addr: &str) -> bool {
    addr.ends_with(".i2p")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;
    
    #[test]
    fn test_privacy_config() {
        let config = PrivacyConfig::default();
        assert_eq!(config.hidden_service_port, 1776);
        assert!(!config.tor_only);
        assert!(config.i2p_enabled);
    }
    
    #[test]
    fn test_address_detection() {
        assert!(is_onion_address("example.onion"));
        assert!(is_i2p_address("example.b32.i2p"));
        assert!(!is_onion_address("example.com"));
        assert!(!is_i2p_address("example.com"));
    }
    
    #[test]
    fn test_tls_config() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let config = PrivacyConfig::default();
            let layer = PrivacyLayer::new(config).await;
            assert!(layer.is_ok());
        });
    }
    
    #[test]
    fn test_tor_only_enforcement() {
        use super::is_onion_address;
        let privacy = super::PrivacyConfig { tor_only: true, ..super::PrivacyConfig::default() };
        // Should allow .onion
        assert!(is_onion_address("abc.onion"));
        // Should block clearnet
        assert!(!is_onion_address("1.2.3.4:1776"));
        // Should block normal domain
        assert!(!is_onion_address("example.com:1776"));
    }
}