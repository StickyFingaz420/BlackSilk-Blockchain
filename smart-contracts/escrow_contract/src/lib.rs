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

pub trait MultiSigEscrow {
    fn fund(&mut self, buyer_sig: [u8; 32]);
    fn sign_release(&mut self, signer: [u8; 32]);
    fn can_release(&self) -> bool;
    fn release(&mut self) -> bool;
    fn refund(&mut self) -> bool;
}

impl MultiSigEscrow for Escrow {
    fn fund(&mut self, _buyer_sig: [u8; 32]) {
        // Placeholder: integrate with primitives::escrow for real signature logic
        // This is a stub for demonstration; real implementation should verify signature
        if self.state == EscrowState::Pending {
            self.state = EscrowState::Completed;
        }
    }
    fn sign_release(&mut self, _signer: [u8; 32]) {
        // Placeholder: integrate with primitives::escrow for real signature logic
    }
    fn can_release(&self) -> bool {
        self.state == EscrowState::Completed
    }
    fn release(&mut self) -> bool {
        if self.can_release() {
            self.state = EscrowState::Completed;
            true
        } else {
            false
        }
    }
    fn refund(&mut self) -> bool {
        if self.state == EscrowState::Pending {
            self.state = EscrowState::Refunded;
            true
        } else {
            false
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
