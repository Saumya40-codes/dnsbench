# syntax=docker/dockerfile:1
FROM rust:1.95-bookworm AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgcc-s1 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /state
COPY --from=build /app/target/release/dns-bench /usr/local/bin/dns-bench
ENV XDG_STATE_HOME=/state
ENTRYPOINT ["dns-bench"]
CMD ["--help"]
