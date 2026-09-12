# LeGion

Beacon Privacy Network is a monorepo scaffold for a decentralized relay-driven
privacy system that exchanges signed Wi-Fi beacon profiles without introducing a
central authority.

## Current scope

This repository currently includes:

- a Rust `privacy-relay` service implementing the temporary bootstrap/relay API;
- bundle and peer validation with explicit size and schema limits;
- content-addressed storage backed by SQLite with bundle and peer expiration;
- protocol documentation and JSON schemas for the relay-facing objects.

## Relay API

The relay exposes:

- `POST /v1/bundles`
- `GET /v1/bundles/random?count=N`
- `GET /v1/objects/{hash}`
- `POST /v1/announce`
- `GET /v1/peers`

## Development

```bash
cargo test
```

The relay listens on `127.0.0.1:8080` and stores its database at
`relay/data/relay.sqlite3`.
