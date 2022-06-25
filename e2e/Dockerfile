#------------------------------------------------------------------------------#

FROM rust:1-alpine3.16 as BUILDER

RUN apk add --no-cache musl-dev protoc

WORKDIR /usr/src/p2p-tun
COPY ./src ./src
COPY ./Cargo.toml ./Cargo.toml
RUN cargo build

WORKDIR /usr/src/p2p-tun/e2e
COPY ./e2e/src ./src
COPY ./e2e/Cargo.toml ./Cargo.toml
RUN cargo build

#------------------------------------------------------------------------------#

FROM alpine:3.16

WORKDIR /usr/bin
COPY --from=BUILDER /usr/src/p2p-tun/target/debug/p2p-tun ./p2p-tun
COPY --from=BUILDER /usr/src/p2p-tun/e2e/target/debug/p2p-tun-e2e ./p2p-tun-e2e

CMD [ "sleep", "3600" ]
