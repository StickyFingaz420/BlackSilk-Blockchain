//! Test guest: reads n and n words, writes their sum, their wrapping product,
//! a Poseidon2 digest word, and a value from static data.
#![no_std]
#![no_main]

use blacksilk_zkvm_sdk as sdk;

static TABLE: [u32; 4] = [11, 22, 33, 44];

fn main() {
    let n = sdk::read();
    let mut sum = 0u32;
    let mut prod = 1u32;
    let mut state = [0u32; 16];
    for i in 0..n {
        let v = sdk::read();
        sum = sum.wrapping_add(v);
        prod = prod.wrapping_mul(v | 1);
        state[(i % 16) as usize] = v % 2_000_000_000;
    }
    sdk::poseidon2(&mut state);
    sdk::write(sum);
    sdk::write(prod);
    sdk::write(state[0]);
    sdk::write(TABLE[(n % 4) as usize]);
    // Software division (compiler_builtins): no DIV instruction in BVM-1.
    sdk::write(sum / (n + 1));
    sdk::write(sum % (n + 7));
}

sdk::entry!(main);
