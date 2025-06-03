FROM rust:1.75 as builder

WORKDIR /app
COPY . .

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    build-essential \
    cmake \
    git \
    && rm -rf /var/lib/apt/lists/*

# Initialize submodules
RUN git submodule update --init --recursive

# Build the wallet
RUN cargo build --release --bin blacksilk-wallet

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create blacksilk user
RUN useradd -r -s /bin/bash -m blacksilk

# Copy binary and config
COPY --from=builder /app/target/release/blacksilk-wallet /usr/local/bin/blacksilk-wallet
COPY --from=builder /app/config /etc/blacksilk/config

# Create wallet data directory
RUN mkdir -p /data/wallet && chown blacksilk:blacksilk /data/wallet

USER blacksilk
WORKDIR /data/wallet

ENTRYPOINT ["blacksilk-wallet"]
