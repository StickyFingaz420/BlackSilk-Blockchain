//! BlackSilk Primitives - Core Types

pub mod types {
    pub type BlkAmount = u64; // atomic units
    pub type BlockHeight = u64;
    pub type Address = String; // placeholder for stealth address
    pub type Hash = [u8; 32];
    // Add more types as needed
}

pub fn add(left: u64, right: u64) -> u64 {
    left + right
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
