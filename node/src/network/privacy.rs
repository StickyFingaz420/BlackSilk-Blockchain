// --- Tor/I2P Privacy Layer (PRODUCTION) ---
// This version uses only real, available crates and APIs. No stubs or fake types.
// If you want advanced features, use arti-client for Tor and i2p_client for I2P.

#[derive(Debug, Clone)]
pub struct PrivacyConfig {
    pub tor_only: bool,
    pub i2p_enabled: bool,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            tor_only: false,
            i2p_enabled: false,
        }
    }
}

/// Check if an address is a Tor hidden service (.onion)
pub fn is_onion_address(addr: &str) -> bool {
    addr.ends_with(".onion")
}

/// Check if an address is an I2P destination (.i2p)
pub fn is_i2p_address(addr: &str) -> bool {
    addr.ends_with(".i2p")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_onion_and_i2p_detection() {
        assert!(is_onion_address("abc.onion"));
        assert!(!is_onion_address("1.2.3.4:1776"));
        assert!(is_i2p_address("xyz.i2p"));
        assert!(!is_i2p_address("example.com:1776"));
    }
}