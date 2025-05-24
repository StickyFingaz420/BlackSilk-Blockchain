# BlackSilk Architecture Overview

## System Components

```mermaid
graph TB
    subgraph Core Node
        BC[Blockchain Core]
        POW[RandomX PoW]
        P2P[P2P Network]
        PRIV[Privacy Layer]
        MEM[Mempool]
    end
    
    subgraph Privacy Features
        RING[Ring Signatures]
        STEALTH[Stealth Addresses]
        CT[Confidential Transactions]
        BP[Bulletproofs]
    end
    
    subgraph Network Layer
        TOR[Tor Network]
        I2P[I2P Network]
        TLS[TLS + PFS]
    end
    
    subgraph Marketplace
        API[Backend API]
        UI[Frontend UI]
        IPFS[IPFS Storage]
        ESCROW[Smart Escrow]
    end
    
    BC --> POW
    BC --> P2P
    BC --> PRIV
    BC --> MEM
    
    PRIV --> RING
    PRIV --> STEALTH
    PRIV --> CT
    CT --> BP
    
    P2P --> TOR
    P2P --> I2P
    P2P --> TLS
    
    API --> BC
    UI --> API
    API --> IPFS
    API --> ESCROW
```

## Component Details

### 1. Core Node (`node/src/`)
- Blockchain state management
- Block validation and consensus
- RandomX proof-of-work mining
- P2P networking and synchronization
- Transaction pool management
- Privacy protocol implementation

### 2. Wallet (`wallet/src/`)
- Key generation and management
- Transaction creation and signing
- Ring signature generation
- Stealth address handling
- Hardware wallet integration
- CLI and RPC interfaces

### 3. Primitives (`primitives/src/`)
- Core cryptographic types
- Transaction structures
- Block structures
- Ring signature types
- Stealth address types
- Bulletproof range proof types

### 4. Network Privacy (`node/src/network/`)
- Tor hidden service integration
- I2P destination management
- TLS with Perfect Forward Secrecy
- P2P protocol encryption
- Network address privacy

### 5. Marketplace Backend (`marketplace/backend/`)
- RESTful API (FastAPI/Rocket)
- Listing management
- Order processing
- Smart escrow contracts
- User reputation system
- IPFS integration
- Authentication & authorization

### 6. Marketplace Frontend (`marketplace/frontend/`)
- Static site generation (Next.js)
- User interface components
- Wallet integration
- Search and filtering
- Order management
- Responsive design
- Privacy-preserving analytics

## Data Flow

### Transaction Flow
1. Wallet creates transaction with:
   - Ring signature (input privacy)
   - Stealth address (output privacy)
   - Confidential amount (Bulletproofs)
2. Transaction submitted to node
3. Node validates and broadcasts
4. Miners include in blocks
5. Network reaches consensus

### Marketplace Flow
1. Seller creates listing (stored in IPFS)
2. Buyer initiates purchase
3. Funds locked in smart escrow
4. Seller confirms shipping
5. Buyer confirms receipt
6. Escrow releases funds

## Security Considerations

### Node Security
- No clearnet leaks in Tor/I2P mode
- All P2P communications encrypted
- No logging of sensitive data
- Secure memory handling
- DoS protection

### Wallet Security
- Encrypted key storage
- Hardware wallet support
- Secure RPC
- Memory wiping
- Backup functionality

### Marketplace Security
- End-to-end encryption
- No third-party trackers
- Secure headers
- Input validation
- Rate limiting
- IPFS content verification

## Development Guidelines

### Code Organization
- Modular architecture
- Clear separation of concerns
- Comprehensive test coverage
- Consistent error handling
- Documentation requirements

### Contribution Process
1. Issue discussion
2. Design review
3. Implementation
4. Testing
5. Security review
6. Code review
7. Merge

## Future Considerations

### Scalability
- Layer 2 solutions
- Optimized block propagation
- IPFS clustering
- API load balancing

### Privacy Enhancements
- zk-SNARKs integration
- Improved stealth addresses
- Enhanced network privacy
- Marketplace anonymity

### Marketplace Features
- Decentralized arbitration
- Enhanced reputation system
- Automated escrow
- Mobile applications

### Emission Schedule & Tokenomics
BlackSilk’s emission model is designed for fairness and long-term sustainability:
- **Block Reward:** Starts at 5 BLK per block.
- **Halving:** Every 1,051,200 blocks (~4 years), the block reward halves.
- **Supply Cap:** Hard cap of 21,000,000 BLK. No new coins are created after this cap is reached.
- **No Tail Emission:** After the cap, miners are paid only transaction fees. There is no perpetual emission.
- **No Premine/ICO:** All coins are distributed via mining.
- **Dynamic Fees:** After the cap, network security is maintained by transaction fees, which are dynamically adjusted based on network demand and block space.

#### Emission Logic (Code Reference)
- See `node/src/lib.rs` for the `EmissionSchedule` struct and `block_reward` logic.
- The emission schedule is enforced at the consensus layer; any block with an invalid reward is rejected.
- The fee model is designed to be flexible for future upgrades (e.g., EIP-1559-style dynamic fees).