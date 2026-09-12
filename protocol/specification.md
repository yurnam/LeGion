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
