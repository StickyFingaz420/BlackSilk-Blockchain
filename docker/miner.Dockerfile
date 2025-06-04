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

# Build the miner
RUN cargo build --release --bin blacksilk-miner

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create blacksilk user
RUN useradd -r -s /bin/bash -m blacksilk

# Copy binary and config
COPY --from=builder /app/target/release/blacksilk-miner /usr/local/bin/blacksilk-miner
COPY --from=builder /app/config /etc/blacksilk/config

USER blacksilk
WORKDIR /home/blacksilk

CMD ["blacksilk-miner", "--config", "/etc/blacksilk/config/miner_config.toml"]
