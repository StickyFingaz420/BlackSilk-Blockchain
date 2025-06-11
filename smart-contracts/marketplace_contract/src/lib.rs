//! Marketplace Contract
//! This contract facilitates listing and purchasing items in a decentralized marketplace.

use std::collections::HashMap;

#[derive(Debug)]
pub struct Item {
    pub id: u64,
    pub seller: String,
    pub price: u128,
    pub is_sold: bool,
}

#[derive(Debug)]
pub struct Review {
    pub reviewer: String,
    pub item_id: u64,
    pub rating: u8, // 1-5
    pub comment: String,
}

#[derive(Debug)]
pub struct Auction {
    pub item_id: u64,
    pub seller: String,
    pub start_time: u64,
    pub end_time: u64,
    pub min_bid: u128,
    pub highest_bid: u128,
    pub highest_bidder: Option<String>,
    pub finalized: bool,
}

pub struct Marketplace {
    pub items: HashMap<u64, Item>,
    pub next_item_id: u64,
    pub reviews: Vec<Review>,
    pub auctions: HashMap<u64, Auction>,
}

impl Marketplace {
    pub fn new() -> Self {
        Self {
            items: HashMap::new(),
            next_item_id: 1,
            reviews: Vec::new(),
            auctions: HashMap::new(),
        }
    }

    pub fn list_item(&mut self, seller: String, price: u128) -> u64 {
        let item_id = self.next_item_id;
        self.items.insert(
            item_id,
            Item {
                id: item_id,
                seller,
                price,
                is_sold: false,
            },
        );
        self.next_item_id += 1;
        item_id
    }

    pub fn purchase_item(&mut self, item_id: u64) -> Result<(), &'static str> {
        if let Some(item) = self.items.get_mut(&item_id) {
            if item.is_sold {
                return Err("Item already sold");
            }
            item.is_sold = true;
            Ok(())
        } else {
            Err("Item not found")
        }
    }

    pub fn submit_review(&mut self, reviewer: String, item_id: u64, rating: u8, comment: String) {
        self.reviews.push(Review { reviewer, item_id, rating, comment });
    }

    pub fn start_auction(&mut self, seller: String, price: u128, min_bid: u128, start_time: u64, end_time: u64) -> u64 {
        let item_id = self.list_item(seller.clone(), price);
        self.auctions.insert(item_id, Auction {
            item_id,
            seller,
            start_time,
            end_time,
            min_bid,
            highest_bid: 0,
            highest_bidder: None,
            finalized: false,
        });
        item_id
    }

    pub fn place_bid(&mut self, item_id: u64, bidder: String, bid: u128, now: u64) -> Result<(), &'static str> {
        if let Some(auction) = self.auctions.get_mut(&item_id) {
            if now < auction.start_time || now > auction.end_time {
                return Err("Auction not active");
            }
            if bid < auction.min_bid || bid <= auction.highest_bid {
                return Err("Bid too low");
            }
            auction.highest_bid = bid;
            auction.highest_bidder = Some(bidder);
            Ok(())
        } else {
            Err("Auction not found")
        }
    }

    pub fn finalize_auction(&mut self, item_id: u64, now: u64) -> Result<(), &'static str> {
        if let Some(auction) = self.auctions.get_mut(&item_id) {
            if now < auction.end_time {
                return Err("Auction not ended");
            }
            if auction.finalized {
                return Err("Auction already finalized");
            }
            auction.finalized = true;
            if let Some(winner) = &auction.highest_bidder {
                if let Some(item) = self.items.get_mut(&item_id) {
                    item.seller = winner.clone();
                    item.is_sold = true;
                }
            }
            Ok(())
        } else {
            Err("Auction not found")
        }
    }
}

pub trait Reviewable {
    fn submit_review(&mut self, reviewer: String, item_id: u64, rating: u8, comment: String);
    fn get_reviews(&self, item_id: u64) -> Vec<&Review>;
}

impl Reviewable for Marketplace {
    fn submit_review(&mut self, reviewer: String, item_id: u64, rating: u8, comment: String) {
        self.submit_review(reviewer, item_id, rating, comment);
    }
    fn get_reviews(&self, item_id: u64) -> Vec<&Review> {
        self.reviews.iter().filter(|r| r.item_id == item_id).collect()
    }
}

pub trait Auctionable {
    fn start_auction(&mut self, seller: String, price: u128, min_bid: u128, start_time: u64, end_time: u64) -> u64;
    fn place_bid(&mut self, item_id: u64, bidder: String, bid: u128, now: u64) -> Result<(), &'static str>;
    fn finalize_auction(&mut self, item_id: u64, now: u64) -> Result<(), &'static str>;
}

impl Auctionable for Marketplace {
    fn start_auction(&mut self, seller: String, price: u128, min_bid: u128, start_time: u64, end_time: u64) -> u64 {
        self.start_auction(seller, price, min_bid, start_time, end_time)
    }
    fn place_bid(&mut self, item_id: u64, bidder: String, bid: u128, now: u64) -> Result<(), &'static str> {
        self.place_bid(item_id, bidder, bid, now)
    }
    fn finalize_auction(&mut self, item_id: u64, now: u64) -> Result<(), &'static str> {
        self.finalize_auction(item_id, now)
    }
}

fn main() {
    let mut marketplace = Marketplace::new();
    let item_id = marketplace.list_item("seller1".to_string(), 500);
    println!("Item listed: {:?}", marketplace.items.get(&item_id));

    match marketplace.purchase_item(item_id) {
        Ok(_) => println!("Item purchased: {:?}", marketplace.items.get(&item_id)),
        Err(e) => println!("Error: {}", e),
    }
}
