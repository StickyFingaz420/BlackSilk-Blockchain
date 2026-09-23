//! Integration Tests for Smart Contracts

#[cfg(test)]
mod tests {
    use escrow_contract::Escrow;
    use marketplace_contract::Marketplace;

    #[test]
    fn test_escrow_contract() {
        let mut escrow = Escrow::new("buyer1".to_string(), "seller1".to_string(), 1000);
        assert_eq!(escrow.state, EscrowState::Pending);

        escrow.confirm_delivery().unwrap();
        assert_eq!(escrow.state, EscrowState::Completed);
    }

    #[test]
    fn test_marketplace_contract() {
        let mut marketplace = Marketplace::new();
        let item_id = marketplace.list_item("seller1".to_string(), 500);
        assert!(marketplace.items.contains_key(&item_id));

        marketplace.purchase_item(item_id).unwrap();
        assert!(marketplace.items.get(&item_id).unwrap().is_sold);
    }
}
