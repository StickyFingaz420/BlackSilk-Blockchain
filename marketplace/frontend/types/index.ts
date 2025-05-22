export interface Listing {
    id: string;
    title: string;
    description: string;
    price: number;
    seller: string;
    images: string[]; // IPFS hashes
    category: Category;
    subcategory: string;
    tags: string[];
    condition: ItemCondition;
    shipping: ShippingOption[];
    location: string;
    quantity: number;
    created_at: number;
    updated_at: number;
    status: ListingStatus;
    views: number;
    rating: number;
    ratings_count: number;
}

export enum Category {
    Electronics = 'Electronics',
    Fashion = 'Fashion',
    Home = 'Home',
    Art = 'Art',
    Collectibles = 'Collectibles',
    Books = 'Books',
    Sports = 'Sports',
    Health = 'Health',
    Beauty = 'Beauty',
    Automotive = 'Automotive',
    Other = 'Other'
}

export enum ItemCondition {
    New = 'New',
    LikeNew = 'Like New',
    VeryGood = 'Very Good',
    Good = 'Good',
    Acceptable = 'Acceptable'
}

export interface ShippingOption {
    method: string;
    price: number;
    estimated_days: number;
    regions: string[];
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
    reputation: number; // Average rating (computed from reviews)
    ratings_count: number; // Number of reviews
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

export interface SearchFilters {
    query: string;
    category?: Category;
    subcategory?: string;
    minPrice?: number;
    maxPrice?: number;
    condition?: ItemCondition;
    location?: string;
    sortBy: SortOption;
    page: number;
    limit: number;
}

export enum SortOption {
    RecentlyListed = 'recently_listed',
    PriceLowToHigh = 'price_low_to_high',
    PriceHighToLow = 'price_high_to_low',
    MostViewed = 'most_viewed',
    TopRated = 'top_rated'
}

export interface CategoryMetadata {
    category: Category;
    subcategories: string[];
    icon: string;
    count: number;
}

export interface DisputeVote {
    voter: string; // address
    vote: boolean; // true = favor buyer, false = favor seller
}

export interface EscrowDispute {
    contractId: string;
    status: string;
    votes: DisputeVote[];
}