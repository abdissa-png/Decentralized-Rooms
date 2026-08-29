# rooms-relay — TCP DRRL splice helper (not HTTP, not STUN/TURN).
#
# Bind 0.0.0.0:44099. Generic ngrok/bore/libp2p circuit v2 endpoints are not
# drop-in compatible unless they speak this protocol.
#
# Build:  docker build -t rooms-relay .
# Run:    docker run --rm -p 44099:44099 rooms-relay
#
# Fly.io (TCP service): see fly.toml and docs/relay-nat.md.
# There is no public DeRooms relay fleet; this image is for self-host / $0-tier.

FROM rust:1.83-bookworm AS build
WORKDIR /src
COPY core /src/core
WORKDIR /src/core
RUN cargo build --release -p rooms-transport --bin rooms-relay

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/core/target/release/rooms-relay /usr/local/bin/rooms-relay
EXPOSE 44099
USER nobody
ENTRYPOINT ["rooms-relay"]
CMD ["0.0.0.0:44099"]
