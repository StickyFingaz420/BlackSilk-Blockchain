-- Create reviews table for on-chain reputation
CREATE TABLE IF NOT EXISTS reviews (
    id SERIAL PRIMARY KEY,
    order_id VARCHAR(64) NOT NULL,
    reviewer VARCHAR(128) NOT NULL,
    reviewed VARCHAR(128) NOT NULL,
    rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
    comment TEXT,
    created_at BIGINT NOT NULL
);

-- Index for fast lookup
CREATE INDEX IF NOT EXISTS idx_reviews_reviewed ON reviews (reviewed);
