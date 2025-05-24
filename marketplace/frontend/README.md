# BlackSilk Marketplace Frontend

## Overview
- **Automatic HTML Page Generation:** Uses Next.js SSG/ISR to generate all marketplace pages (home, categories, products, sell, account, orders) as static HTML/JS during build (`npm run build`). No manual HTML setup required.
- **Silk Road-inspired UI:** Modern, professional, and privacy-focused design with clear categories, product cards, and simple navigation—just like the original Silk Road, but easier and safer.
- **Automatic Node Connection:** All pages connect automatically to the BlackSilk node (REST/WebSocket) as configured in `.env.local`. Supports clearnet, Tor, and I2P endpoints out of the box.
- **No User Complexity:** Users only need to open the site, log in with their private key/phrase, and can buy/sell instantly. No browser plugins, no manual config, no technical steps.
- **Privacy & Security:** All sensitive operations (signing, wallet) are done locally in the browser. No private keys or secrets ever leave the device. All communication is via HTTPS/WSS or onion/I2P.
- **IPFS Integration:** Product images are uploaded to IPFS and displayed via their CID, ensuring censorship resistance and decentralization.
- **OpenAPI Spec:** Node API is fully documented in `../../docs/api/openapi.yaml` for easy backend/frontend integration.

## Pages & Structure
| Page      | Path              | Description                                 |
|-----------|-------------------|---------------------------------------------|
| Home      | `/`               | Categories and featured products            |
| Category  | `/category/[id]`  | Products in a category                      |
| Product   | `/product/[id]`   | Product details and buy button              |
| Sell      | `/sell`           | Add product form (with IPFS upload)         |
| Account   | `/account`        | Login with private key/phrase (wallet)      |
| Orders    | `/orders`         | View all purchases and sales                |

## How it Works
- **Build:**
  ```powershell
  npm install
  npm run build
  npm start
  ```
- **Automatic HTML:** All main pages are generated as static HTML/JS for speed and security.
- **Node Connection:** Set your node endpoint in `.env.local` (clearnet, Tor, or I2P). The frontend connects automatically—no user config needed.
- **Wallet:** Login is non-custodial (private key/phrase only, never sent to server).
- **Buy/Sell:** All transactions are signed locally and sent to the node. Status updates are real-time via WebSocket.
- **IPFS:** Images are uploaded to IPFS and displayed from the network.

## Security & Privacy
- All transactions signed locally (never send private key to server)
- Images/files uploaded to IPFS
- **Enforces HTTPS/WSS, .onion, or .i2p endpoints for all API calls**
- No sensitive data ever leaves the browser
- Supports Tor/I2P endpoints for anonymous access

## OpenAPI
- Node REST API is documented in `../../docs/api/openapi.yaml`
- Use this spec for backend/frontend integration and client code generation

## Latest Updates
- Full automatic static HTML generation for all marketplace pages
- Seamless, Silk Road-inspired UI/UX
- One-click node connection (clearnet, Tor, I2P)
- Real-time order status via WebSocket
- All sensitive operations are browser-only
- Developer and user experience is as simple and private as possible

---
