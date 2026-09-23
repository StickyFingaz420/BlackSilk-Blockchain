FROM rust:1.80 as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    build-essential \
    cmake \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source code
COPY . .

# Initialize and update submodules
RUN git submodule update --init --recursive

# Build the node
RUN cargo build --release --bin blacksilk-node

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create blacksilk user
RUN useradd -r -s /bin/bash -m blacksilk

# Copy binary
COPY --from=builder /app/target/release/blacksilk-node /usr/local/bin/blacksilk-node

# Copy configuration files
COPY --from=builder /app/config /etc/blacksilk/config

# Create data and log directories
RUN mkdir -p /data/blacksilk /logs/blacksilk && \
    chown -R blacksilk:blacksilk /data/blacksilk /logs/blacksilk

# Switch to blacksilk user
USER blacksilk
WORKDIR /data/blacksilk

# Expose ports
EXPOSE 19333 19334 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:19333/health || exit 1

# Default command
CMD ["blacksilk-node", "--network", "testnet", "--data-dir", "/data/blacksilk", "--config", "/etc/blacksilk/config/testnet/node_config.toml"]
