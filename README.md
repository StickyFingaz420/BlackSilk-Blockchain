# BlackSilk Blockchain Node

## Professional Privacy Networking

BlackSilk provides automatic, production-ready privacy networking. You can select your preferred privacy mode at startup:

- `--net-privacy clearnet` — Use direct clearnet connections only.
- `--net-privacy tor` — Require Tor for all connections. Node will exit if Tor is unavailable.
- `--net-privacy i2p` — Require I2P for all connections (via I2P SAM bridge).
- `--net-privacy auto` (default) — Try Tor first, then I2P, then clearnet. Fallbacks are automatic and clearly logged.

### Example Usage

```powershell
# Start node in auto privacy mode (default)
cargo run --bin blacksilk-node -- --net-privacy auto

# Start node in Tor-only mode (Tor must be running)
cargo run --bin blacksilk-node -- --net-privacy tor

# Start node in I2P-only mode (I2P SAM must be running)
cargo run --bin blacksilk-node -- --net-privacy i2p

# Start node in clearnet mode
cargo run --bin blacksilk-node -- --net-privacy clearnet
```

### Fallback Behavior
- In `auto` mode, the node will attempt to use Tor. If Tor is unavailable, it will fallback to I2P, and finally to clearnet if neither privacy network is available. Each fallback is logged to the console.
- In `tor` or `i2p` mode, the node will exit if the required privacy network is unavailable.

### CLI Help
Run `cargo run --bin blacksilk-node -- --help` to see all available options, including privacy settings.

---

For more, see the `node/` source code and integration tests in `tests/integration/e2e/`.
