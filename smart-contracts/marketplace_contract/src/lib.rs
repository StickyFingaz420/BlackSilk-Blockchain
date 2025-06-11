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

pub struct Marketplace {
    pub items: HashMap<u64, Item>,
    pub next_item_id: u64,
}

impl Marketplace {
    pub fn new() -> Self {
        Self {
            items: HashMap::new(),
            next_item_id: 1,
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
