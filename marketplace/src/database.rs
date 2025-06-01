use sqlx::{SqlitePool, migrate::MigrateDatabase};
use anyhow::Result;
use uuid::Uuid;
use chrono::Utc;
use crate::models::*;

pub struct Database {
    pool: SqlitePool,
}

impl Database {
    pub async fn new(database_url: &str) -> Result<Self> {
        // Create database if it doesn't exist
        if !sqlx::Sqlite::database_exists(database_url).await? {
            sqlx::Sqlite::create_database(database_url).await?;
        }

        let pool = SqlitePool::connect(database_url).await?;
        
        // Run migrations
        sqlx::migrate!("./migrations").run(&pool).await?;
        
        Ok(Database { pool })
    }

    // User operations
    pub async fn create_user(&self, username: &str, public_key: &[u8]) -> Result<User> {
        let user = User {
            id: Uuid::new_v4(),
            username: username.to_string(),
            public_key: public_key.to_vec(),
            reputation_score: 0.0,
            total_sales: 0,
            total_purchases: 0,
            join_date: Utc::now(),
            last_seen: Utc::now(),
            is_vendor: false,
            vendor_bond: None,
            pgp_key: None,
        };

        sqlx::query!(
            "INSERT INTO users (id, username, public_key, reputation_score, total_sales, total_purchases, join_date, last_seen, is_vendor, vendor_bond, pgp_key) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            user.id,
            user.username,
            user.public_key,
            user.reputation_score,
            user.total_sales,
            user.total_purchases,
            user.join_date,
            user.last_seen,
            user.is_vendor,
            user.vendor_bond,
            user.pgp_key
        ).execute(&self.pool).await?;

        Ok(user)
    }

    pub async fn get_user_by_id(&self, user_id: &Uuid) -> Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            "SELECT * FROM users WHERE id = ?",
            user_id
        ).fetch_optional(&self.pool).await?;

        Ok(user)
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            "SELECT * FROM users WHERE username = ?",
            username
        ).fetch_optional(&self.pool).await?;

        Ok(user)
    }

    pub async fn upgrade_to_vendor(&self, user_id: &Uuid, bond_amount: u64) -> Result<()> {
        sqlx::query!(
            "UPDATE users SET is_vendor = true, vendor_bond = ? WHERE id = ?",
            bond_amount,
            user_id
        ).execute(&self.pool).await?;

        Ok(())
    }

    // Product operations
    pub async fn create_product(&self, product: &Product) -> Result<()> {
        let ships_to_json = serde_json::to_string(&product.ships_to)?;
        let image_hashes_json = serde_json::to_string(&product.image_hashes)?;

        sqlx::query!(
            "INSERT INTO products (id, vendor_id, title, description, category, subcategory, price, currency, quantity_available, ships_from, ships_to, shipping_price, processing_time, created_at, updated_at, is_active, image_hashes, stealth_required, escrow_required)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            product.id,
            product.vendor_id,
            product.title,
            product.description,
            product.category,
            product.subcategory,
            product.price,
            product.currency,
            product.quantity_available,
            product.ships_from,
            ships_to_json,
            product.shipping_price,
            product.processing_time,
            product.created_at,
            product.updated_at,
            product.is_active,
            image_hashes_json,
            product.stealth_required,
            product.escrow_required
        ).execute(&self.pool).await?;

        Ok(())
    }

    pub async fn get_products_by_category(&self, category: &str, limit: u32, offset: u32) -> Result<Vec<Product>> {
        let products = sqlx::query_as!(
            Product,
            "SELECT * FROM products WHERE category = ? AND is_active = true ORDER BY created_at DESC LIMIT ? OFFSET ?",
            category,
            limit,
            offset
        ).fetch_all(&self.pool).await?;

        Ok(products)
    }

    pub async fn search_products(&self, query: &str, limit: u32, offset: u32) -> Result<Vec<Product>> {
        let search_term = format!("%{}%", query);
        let products = sqlx::query_as!(
            Product,
            "SELECT * FROM products WHERE (title LIKE ? OR description LIKE ?) AND is_active = true ORDER BY created_at DESC LIMIT ? OFFSET ?",
            search_term,
            search_term,
            limit,
            offset
        ).fetch_all(&self.pool).await?;

        Ok(products)
    }

    pub async fn get_vendor_products(&self, vendor_id: &Uuid) -> Result<Vec<Product>> {
        let products = sqlx::query_as!(
            Product,
            "SELECT * FROM products WHERE vendor_id = ? ORDER BY created_at DESC",
            vendor_id
        ).fetch_all(&self.pool).await?;

        Ok(products)
    }

    // Order operations
    pub async fn create_order(&self, order: &Order) -> Result<()> {
        sqlx::query!(
            "INSERT INTO orders (id, buyer_id, vendor_id, product_id, quantity, total_price, shipping_address_encrypted, status, escrow_contract_id, created_at, shipped_at, delivered_at, dispute_reason, tracking_number)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            order.id,
            order.buyer_id,
            order.vendor_id,
            order.product_id,
            order.quantity,
            order.total_price,
            order.shipping_address_encrypted,
            order.status,
            order.escrow_contract_id,
            order.created_at,
            order.shipped_at,
            order.delivered_at,
            order.dispute_reason,
            order.tracking_number
        ).execute(&self.pool).await?;

        Ok(())
    }

    pub async fn update_order_status(&self, order_id: &Uuid, status: OrderStatus) -> Result<()> {
        sqlx::query!(
            "UPDATE orders SET status = ?, updated_at = ? WHERE id = ?",
            status,
            Utc::now(),
            order_id
        ).execute(&self.pool).await?;

        Ok(())
    }

    pub async fn get_user_orders(&self, user_id: &Uuid, as_buyer: bool) -> Result<Vec<Order>> {
        let orders = if as_buyer {
            sqlx::query_as!(
                Order,
                "SELECT * FROM orders WHERE buyer_id = ? ORDER BY created_at DESC",
                user_id
            ).fetch_all(&self.pool).await?
        } else {
            sqlx::query_as!(
                Order,
                "SELECT * FROM orders WHERE vendor_id = ? ORDER BY created_at DESC",
                user_id
            ).fetch_all(&self.pool).await?
        };

        Ok(orders)
    }

    // Review operations
    pub async fn create_review(&self, review: &Review) -> Result<()> {
        sqlx::query!(
            "INSERT INTO reviews (id, order_id, reviewer_id, reviewed_id, rating, review_text, product_quality, shipping_speed, communication, created_at, is_anonymous)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            review.id,
            review.order_id,
            review.reviewer_id,
            review.reviewed_id,
            review.rating,
            review.review_text,
            review.product_quality,
            review.shipping_speed,
            review.communication,
            review.created_at,
            review.is_anonymous
        ).execute(&self.pool).await?;

        Ok(())
    }

    pub async fn get_vendor_reviews(&self, vendor_id: &Uuid) -> Result<Vec<Review>> {
        let reviews = sqlx::query_as!(
            Review,
            "SELECT * FROM reviews WHERE reviewed_id = ? ORDER BY created_at DESC",
            vendor_id
        ).fetch_all(&self.pool).await?;

        Ok(reviews)
    }

    // Message operations
    pub async fn create_message(&self, message: &Message) -> Result<()> {
        sqlx::query!(
            "INSERT INTO messages (id, from_user_id, to_user_id, order_id, subject, content_encrypted, created_at, read_at, message_type)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            message.id,
            message.from_user_id,
            message.to_user_id,
            message.order_id,
            message.subject,
            message.content_encrypted,
            message.created_at,
            message.read_at,
            message.message_type
        ).execute(&self.pool).await?;

        Ok(())
    }

    pub async fn get_user_messages(&self, user_id: &Uuid) -> Result<Vec<Message>> {
        let messages = sqlx::query_as!(
            Message,
            "SELECT * FROM messages WHERE to_user_id = ? OR from_user_id = ? ORDER BY created_at DESC",
            user_id,
            user_id
        ).fetch_all(&self.pool).await?;

        Ok(messages)
    }

    // Market statistics
    pub async fn get_market_stats(&self) -> Result<MarketStats> {
        let user_count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool).await?.unwrap_or(0);

        let vendor_count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM users WHERE is_vendor = true")
            .fetch_one(&self.pool).await?.unwrap_or(0);

        let product_count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM products")
            .fetch_one(&self.pool).await?.unwrap_or(0);

        let order_count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM orders")
            .fetch_one(&self.pool).await?.unwrap_or(0);

        let active_listings: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM products WHERE is_active = true")
            .fetch_one(&self.pool).await?.unwrap_or(0);

        let successful_orders: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM orders WHERE status = 'delivered'")
            .fetch_one(&self.pool).await?.unwrap_or(0);

        let avg_rating: f64 = sqlx::query_scalar!("SELECT AVG(rating) FROM reviews")
            .fetch_one(&self.pool).await?.unwrap_or(0.0);

        Ok(MarketStats {
            total_users: user_count as u64,
            total_vendors: vendor_count as u64,
            total_products: product_count as u64,
            total_orders: order_count as u64,
            total_volume_blk: 0, // TODO: Calculate from orders
            active_listings: active_listings as u64,
            successful_transactions: successful_orders as u64,
            average_rating: avg_rating,
        })
    }
}
