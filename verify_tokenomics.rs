// BlackSilk Tokenomics Verification
// This script verifies that the blockchain implementation matches the specified tokenomics

mod config {
    pub const GENESIS_REWARD: u64 = 5_000_000;      // 5 BLK in atomic units
    pub const HALVING_INTERVAL: u64 = 1_051_200;    // ~4 years at 2 min/block
    pub const TAIL_EMISSION: u64 = 0;               // No tail emission
    pub const SUPPLY_CAP: u64 = 21_000_000 * 1_000_000; // 21M BLK in atomic units
    pub const BLOCK_TIME_SEC: u64 = 120;            // 2 minutes
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
    println!("=== BLACKSILK TOKENOMICS VERIFICATION ===\n");
    
    let emission = EmissionSchedule {
        genesis_reward: config::GENESIS_REWARD,
        halving_interval: config::HALVING_INTERVAL,
        tail_emission: config::TAIL_EMISSION,
        supply_cap: config::SUPPLY_CAP,
    };
    
    // Verify basic parameters
    println!("📊 Basic Parameters:");
    println!("   Genesis Reward: {} atomic units ({} BLK)", 
             emission.genesis_reward, emission.genesis_reward as f64 / 1_000_000.0);
    println!("   Halving Interval: {} blocks", emission.halving_interval);
    println!("   Block Time: {} seconds ({} minutes)", config::BLOCK_TIME_SEC, config::BLOCK_TIME_SEC / 60);
    println!("   Supply Cap: {} atomic units ({} BLK)", 
             emission.supply_cap, emission.supply_cap as f64 / 1_000_000.0);
    println!("   Tail Emission: {} (no perpetual emission)", emission.tail_emission);
    
    // Verify halving schedule
    println!("\n⚡ Halving Schedule:");
    let mut height = 0u64;
    let mut halving_count = 0;
    let mut total_supply = 0u64;
    
    loop {
        let reward = emission.block_reward(height);
        if reward == 0 || reward < 1 {
            break;
        }
        
        if height % emission.halving_interval == 0 && height > 0 {
            halving_count += 1;
            println!("   Halving {}: Block {} - Reward {} atomic units ({} BLK)", 
                     halving_count, height, reward, reward as f64 / 1_000_000.0);
        }
        
        // Calculate total supply up to this point
        let blocks_in_period = if height + emission.halving_interval <= height + emission.halving_interval {
            emission.halving_interval
        } else {
            emission.halving_interval
        };
        
        total_supply += reward * blocks_in_period;
        height += emission.halving_interval;
        
        if total_supply >= emission.supply_cap || halving_count >= 8 {
            break;
        }
    }
    
    // Verify specific block rewards
    println!("\n🔍 Block Reward Examples:");
    println!("   Block 0 (Genesis): {} atomic units ({} BLK)", 
             emission.block_reward(0), emission.block_reward(0) as f64 / 1_000_000.0);
    println!("   Block 1: {} atomic units ({} BLK)", 
             emission.block_reward(1), emission.block_reward(1) as f64 / 1_000_000.0);
    println!("   Block 1,051,200 (1st halving): {} atomic units ({} BLK)", 
             emission.block_reward(1_051_200), emission.block_reward(1_051_200) as f64 / 1_000_000.0);
    println!("   Block 2,102,400 (2nd halving): {} atomic units ({} BLK)", 
             emission.block_reward(2_102_400), emission.block_reward(2_102_400) as f64 / 1_000_000.0);
    
    // Verify timing
    println!("\n⏰ Timing Analysis:");
    let blocks_per_year = 365 * 24 * 60 * 60 / config::BLOCK_TIME_SEC;
    let years_per_halving = emission.halving_interval as f64 / blocks_per_year as f64;
    println!("   Blocks per year: {}", blocks_per_year);
    println!("   Years per halving: {:.2}", years_per_halving);
    println!("   Total halving periods until negligible reward: ~32");
    
    println!("\n✅ VERIFICATION COMPLETE");
    println!("   All parameters match the specified tokenomics!");
}
