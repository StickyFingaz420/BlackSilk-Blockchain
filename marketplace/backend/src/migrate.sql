-- Migration: Create users table for wallet-based authentication
CREATE TABLE IF NOT EXISTS users (
    wallet_address VARCHAR PRIMARY KEY,
    encrypted_metadata JSONB
);

-- Migration: Create listings table
CREATE TABLE IF NOT EXISTS listings (
    id VARCHAR PRIMARY KEY,
    title VARCHAR NOT NULL,
    description TEXT NOT NULL,
    price BIGINT NOT NULL,
    seller VARCHAR NOT NULL,
    images TEXT[] NOT NULL,
    category VARCHAR NOT NULL,
    created_at BIGINT NOT NULL,
    status VARCHAR NOT NULL
);

-- Migration: Create orders table
CREATE TABLE IF NOT EXISTS orders (
    id VARCHAR PRIMARY KEY,
    listing_id VARCHAR NOT NULL REFERENCES listings(id),
    buyer VARCHAR NOT NULL,
    seller VARCHAR NOT NULL,
    amount BIGINT NOT NULL,
    escrow_address VARCHAR NOT NULL,
    status VARCHAR NOT NULL,
    created_at BIGINT NOT NULL
);

-- Migration: Create escrows table
CREATE TABLE IF NOT EXISTS escrows (
    contract_id VARCHAR PRIMARY KEY,
    buyer VARCHAR NOT NULL,
    seller VARCHAR NOT NULL,
    arbiter VARCHAR NOT NULL,
    amount BIGINT NOT NULL,
    status VARCHAR NOT NULL
); 