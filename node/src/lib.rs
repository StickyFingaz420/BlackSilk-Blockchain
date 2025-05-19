//! BlackSilk Node - Testnet Bootstrap

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

pub mod config {
    pub const TESTNET_MAGIC: u32 = 0x1D670; // July 26, 1953
    pub const DEFAULT_P2P_PORT: u16 = 1776;
    pub const BLOCK_TIME_SEC: u64 = 120; // 2 minutes
    pub const GENESIS_REWARD: u64 = 86; // BLK
    pub const HALVING_INTERVAL: u64 = 125_000;
    pub const TAIL_EMISSION: u64 = 50_000_000; // 0.5 BLK in atomic units
    pub const SUPPLY_CAP: u64 = 21_000_000 * 1_000_000; // 21M BLK, atomic units
}

/// Placeholder for node startup
pub fn start_node() {
    println!("[BlackSilk Node] Starting Testnet node on port {} (magic: 0x{:X})", config::DEFAULT_P2P_PORT, config::TESTNET_MAGIC);
    // TODO: Networking, consensus, mining, etc.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
