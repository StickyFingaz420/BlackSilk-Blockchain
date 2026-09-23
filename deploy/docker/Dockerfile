# BlackSilk node / miner / wallet image.
#   docker build -f deploy/docker/Dockerfile -t blacksilk .
#   docker run -d --name bs-node -p 29334:29334 -v bs-data:/data blacksilk \
#       blacksilk-node --config /etc/blacksilk/node.toml
#
# Pure Rust build: no C toolchain is needed beyond the Rust image's defaults.

FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked \
        -p blacksilk-node -p blacksilk-miner -p blacksilk-wallet \
 && strip target/release/blacksilk-node target/release/blacksilk-miner target/release/blacksilk-wallet

FROM debian:bookworm-slim
RUN useradd --system --home /data --shell /usr/sbin/nologin blacksilk \
 && mkdir -p /data /etc/blacksilk && chown blacksilk:blacksilk /data
COPY --from=build /src/target/release/blacksilk-node /src/target/release/blacksilk-miner \
     /src/target/release/blacksilk-wallet /usr/local/bin/
COPY deploy/docker/node.toml /etc/blacksilk/node.toml
USER blacksilk
VOLUME ["/data"]
EXPOSE 29334
# RPC (29333) is intentionally not exposed; reach it with `docker exec`.
CMD ["blacksilk-node", "--config", "/etc/blacksilk/node.toml"]
