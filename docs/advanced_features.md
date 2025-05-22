# BlackSilk Blockchain - Advanced Features & Privacy Documentation

## Advanced Features Implemented

### 1. Advanced IPFS Support
- All file/image uploads are proxied through the backend and stored on IPFS using a production-grade client.
- Listings and orders reference only the IPFS CID; images/files are retrieved via any public or private gateway.
- Frontend and backend are fully integrated for auto-distribution and retrieval of IPFS content.

### 2. Zero-Trace Operation
- No persistent logs or sensitive data are written to disk by the node, wallet, or backend (except encrypted wallet files).
- All debug output and logging is disabled or routed to memory only in privacy mode.
- Runtime config disables all analytics and tracking by default.

### 3. Full Security Headers
- All backend (Axum) responses include strict security headers:
  - Content-Security-Policy (CSP)
  - Strict-Transport-Security (HSTS)
  - X-Content-Type-Options
  - X-Frame-Options
  - Referrer-Policy
  - Permissions-Policy
- Frontend (Next.js) uses middleware to enforce the same headers on all responses.

### 4. On-chain Reputation & Decentralized Arbitration
- Reputation system and DAO voting are implemented in both backend and frontend.
- All flows are tested and documented in the API and UI.

### 5. Privacy & Network Enforcement
- All P2P and API connections are Tor/I2P-only by default.
- No clearnet leaks; all privacy checks are enforced at runtime.

---

## Usage Guide

### IPFS Upload & Retrieval
- Upload files/images via the marketplace UI or backend API (`/ipfs/upload`).
- Retrieve content using any IPFS gateway: `https://ipfs.io/ipfs/{cid}` or your own node.

### Zero-Trace Mode
- Enabled by default. No logs are written to disk.
- For compliance, set the `PRIVACY_MODE=1` environment variable to enforce zero-trace at runtime.

### Security Headers
- All HTTP(S) responses include strict security headers for maximum protection.
- CSP allows images from IPFS and disables all inline scripts except styles.

---

## Developer Notes
- See `docs/architecture.md` for system diagrams and component details.
- See `docs/api/openapi.yaml` for full API documentation.
- All advanced features are covered by integration and unit tests.

---

_Last updated: 2025-05-22_
