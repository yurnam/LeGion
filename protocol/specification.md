# Beacon Privacy Network Protocol v0.1

This repository currently implements the relay/bootstrap slice of the broader
Beacon Privacy Network specification.

## Implemented objects

### BeaconBundle

- signed by the publisher's P-256 key;
- publisher identity is `SHA256(public_key_bytes)`;
- object identity is `SHA256(canonical_json_bundle)`;
- maximum serialized size: 32 KiB;
- maximum profiles per bundle: 32;
- unknown fields are rejected.

### PeerAnnouncement

- peer identity is `SHA256(public_key_bytes)`;
- addresses are bounded and scheme-checked;
- optional signatures are verified using the announced public key;
- unknown fields are rejected.

## Validation order

1. request body size limit;
2. schema and version checks;
3. field bounds;
4. canonical serialization;
5. publisher/peer identity derivation;
6. signature verification;
7. expiry checks;
8. storage deduplication by object hash.

## Relay retention behavior

- expired bundles are deleted before read/write operations;
- peer announcements are removed once their explicit expiry passes;
- peers without an explicit expiry are treated as stale after 7 days without a refresh;
- `GET /v1/peers` only returns non-expired, non-stale peer announcements.
