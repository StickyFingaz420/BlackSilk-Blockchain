# BlackSilk GUI Wallet

A native, cross-platform Rust GUI wallet for the BlackSilk blockchain.

## Features
- BIP39 mnemonic/seed management
- Stealth addresses, ring signatures, quantum-safe signatures
- Secure, encrypted wallet storage
- Send/receive BSX, view balance and transaction history
- Connects to local/remote BlackSilk node via JSON-RPC (port 9333)
- Pure Rust, no Electron or C/C++ dependencies

## Build

```
cargo build --release
```

## Run

```
cargo run --release
```

## Dependencies
- iced (GUI)
- reqwest, tokio, serde, serde_json (RPC/HTTP)
- bip39, aes-gcm, argon2, zeroize, secrecy (crypto)
- sled (storage)
- dirs, rpassword (UX/security)

## Security
- Wallet file is encrypted with a password (Argon2 + AES-GCM)
- Seed/keys are never stored in plaintext
- All sensitive data is zeroized in memory

## License
MIT
