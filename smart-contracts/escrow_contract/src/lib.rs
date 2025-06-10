//! Escrow Contract
//! This contract facilitates secure transactions between a buyer and a seller.

#[derive(Debug, PartialEq)]
pub enum EscrowState {
    Pending,
    Completed,
    Refunded,
}

#[derive(Debug)]
pub struct Escrow {
    pub buyer: String,
    pub seller: String,
    pub amount: u128,
    pub state: EscrowState,
}

impl Escrow {
    pub fn new(buyer: String, seller: String, amount: u128) -> Self {
        Self {
            buyer,
            seller,
            amount,
            state: EscrowState::Pending,
        }
    }

    pub fn confirm_delivery(&mut self) -> Result<(), &'static str> {
        if self.state == EscrowState::Pending {
            self.state = EscrowState::Completed;
            Ok(())
        } else {
            Err("Invalid state for confirming delivery")
        }
    }

    pub fn refund(&mut self) -> Result<(), &'static str> {
        if self.state == EscrowState::Pending {
            self.state = EscrowState::Refunded;
            Ok(())
        } else {
            Err("Invalid state for refund")
        }
    }
}

fn main() {
    let mut escrow = Escrow::new("buyer1".to_string(), "seller1".to_string(), 1000);
    println!("Escrow created: {:?}", escrow);

    match escrow.confirm_delivery() {
        Ok(_) => println!("Delivery confirmed: {:?}", escrow),
        Err(e) => println!("Error: {}", e),
    }
}
