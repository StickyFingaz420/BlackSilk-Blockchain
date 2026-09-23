FROM rust:1.80 as builder

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

# Build the marketplace
RUN cargo build --release --bin blacksilk-marketplace

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create blacksilk user
RUN useradd -r -s /bin/bash -m blacksilk

# Copy binary and config
COPY --from=builder /app/target/release/blacksilk-marketplace /usr/local/bin/blacksilk-marketplace
COPY --from=builder /app/config /etc/blacksilk/config
COPY --from=builder /app/marketplace/templates /usr/share/blacksilk/templates

# Create data directory
RUN mkdir -p /data/marketplace && chown blacksilk:blacksilk /data/marketplace

USER blacksilk
WORKDIR /data/marketplace

# Expose marketplace port
EXPOSE 3000

CMD ["blacksilk-marketplace", "--config", "/etc/blacksilk/config/marketplace_config.toml"]
