export interface Listing {
    id: string;
    title: string;
    description: string;
    price: number;
    seller: string;
    images: string[]; // IPFS hashes
    category: string;
    created_at: number;
    status: ListingStatus;
}

export enum ListingStatus {
    Active = 'Active',
    Sold = 'Sold',
    Suspended = 'Suspended'
}

export interface Order {
    id: string;
    listing_id: string;
    buyer: string;
    seller: string;
    amount: number;
    escrow_address: string;
    status: OrderStatus;
    created_at: number;
}

export enum OrderStatus {
    Created = 'Created',
    PaidToEscrow = 'PaidToEscrow',
    Shipped = 'Shipped',
    Completed = 'Completed',
    Disputed = 'Disputed',
    Refunded = 'Refunded'
}

export interface User {
    address: string;
    reputation: number;
    listings: string[]; // listing IDs
    orders: string[]; // order IDs
    created_at: number;
}

export interface Review {
    id: string;
    order_id: string;
    reviewer: string;
    reviewed: string;
    rating: number;
    comment: string;
    created_at: number;
}

export interface EscrowContract {
    address: string;
    buyer: string;
    seller: string;
    arbiter: string;
    amount: number;
    status: EscrowStatus;
    created_at: number;
}

export enum EscrowStatus {
    Created = 'Created',
    Funded = 'Funded',
    Released = 'Released',
    Refunded = 'Refunded',
    Disputed = 'Disputed'
} 