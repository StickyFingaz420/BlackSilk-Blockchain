// Quick test to verify Genesis Block generation
use std::collections::VecDeque;

mod config {
    pub const GENESIS_REWARD: u64 = 5_000_000;
    pub const HALVING_INTERVAL: u64 = 1_051_200;
    pub const TAIL_EMISSION: u64 = 0;
    pub const SUPPLY_CAP: u64 = 21_000_000 * 1_000_000;
    pub const TESTNET_GENESIS_TIMESTAMP: u64 = 1_716_150_000;
}

#[derive(Debug)]
struct EmissionSchedule {
    pub genesis_reward: u64,
    pub halving_interval: u64,
    pub tail_emission: u64,
    pub supply_cap: u64,
}

impl EmissionSchedule {
    pub fn block_reward(&self, height: u64) -> u64 {
        let mut reward = self.genesis_reward;
        let mut halvings = height / self.halving_interval;
        while halvings > 0 && reward > self.tail_emission {
            reward /= 2;
            halvings -= 1;
        }
        if reward < self.tail_emission {
            self.tail_emission
        } else {
            reward
        }
    }
}

fn main() {
    let emission = EmissionSchedule {
        genesis_reward: config::GENESIS_REWARD,
        halving_interval: config::HALVING_INTERVAL,
        tail_emission: config::TAIL_EMISSION,
        supply_cap: config::SUPPLY_CAP,
    };
    
    println!("Genesis Reward Config: {}", config::GENESIS_REWARD);
    println!("Emission Genesis Reward: {}", emission.genesis_reward);
    println!("Block Reward for Height 0: {}", emission.block_reward(0));
    println!("Block Reward for Height 1: {}", emission.block_reward(1));
    
    // Test Genesis Block creation
    println!("\nGenesis Block would have reward: {}", emission.genesis_reward);
    println!("This equals {} BLK", emission.genesis_reward as f64 / 1_000_000.0);
}
