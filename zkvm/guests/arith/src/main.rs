//! Test guest without Poseidon2: a private-input computation over an array.
//! Reads n ≤ 64 and n words; sorts them (insertion sort), and writes the
//! median, the sum, a checksum mixing multiplication and software division,
//! and the maximum.
#![no_std]
#![no_main]

use blacksilk_zkvm_sdk as sdk;

fn main() {
    let n = (sdk::read() as usize).min(64);
    let mut v = [0u32; 64];
    for x in v.iter_mut().take(n) {
        *x = sdk::read();
    }
    let a = &mut v[..n];
    for i in 1..a.len() {
        let mut j = i;
        while j > 0 && a[j - 1] > a[j] {
            a.swap(j - 1, j);
            j -= 1;
        }
    }
    let sum = a.iter().fold(0u32, |s, x| s.wrapping_add(*x));
    let mut check = 0x9e37_79b9u32;
    for x in a.iter() {
        check = check.wrapping_mul(31).wrapping_add(*x / 7 + *x % 13);
    }
    sdk::write(if n > 0 { a[n / 2] } else { 0 });
    sdk::write(sum);
    sdk::write(check);
    sdk::write(a.last().copied().unwrap_or(0));
}

sdk::entry!(main);
