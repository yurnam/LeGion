use std::{
    fmt::{Display, Formatter},
    net::SocketAddr,
    path::Path,
    str::FromStr,
    sync::{Arc, Mutex},
};

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    EncodedPoint,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tower_http::limit::RequestBodyLimitLayer;

pub const CURRENT_PROTOCOL_VERSION: u8 = 1;
pub const CURRENT_BUNDLE_VERSION: u8 = 1;
pub const MAX_PROFILES_PER_BUNDLE: usize = 32;
pub const MAX_SERIALIZED_BUNDLE_BYTES: usize = 32 * 1024;
pub const MAX_BUNDLE_LIFETIME_SECS: u64 = 60 * 60 * 24 * 30;
pub const MAX_RANDOM_BUNDLE_COUNT: usize = 32;
pub const MAX_PEER_COUNT: usize = 128;
pub const MAX_PEER_ADDRESSES: usize = 16;
pub const MAX_ADDRESS_LENGTH: usize = 256;
pub const MAX_NONCE_HEX_LENGTH: usize = 64;
pub const MAX_SIGNATURE_HEX_LENGTH: usize = 160;
pub const MAX_VENDOR_IE_DIGEST_BYTES: usize = 64;
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
pub const MAX_PEER_STALENESS_SECS: u64 = 60 * 60 * 24 * 7;

#[derive(Clone)]
pub struct AppState {
    db: Arc<Mutex<Connection>>,
}

impl AppState {
    pub fn new_in_memory() -> Result<Self, AppError> {
        let conn = Connection::open_in_memory().map_err(AppError::internal)?;
        init_db(&conn).map_err(AppError::internal)?;
        Ok(Self {
            db: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn new_at_path(path: &str) -> Result<Self, AppError> {
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent).map_err(AppError::internal)?;
        }
        let conn = Connection::open(path).map_err(AppError::internal)?;
        init_db(&conn).map_err(AppError::internal)?;
        Ok(Self {
            db: Arc::new(Mutex::new(conn)),
        })
    }
}

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/v1/bundles", post(post_bundle))
        .route("/v1/bundles/random", get(get_random_bundles))
        .route("/v1/objects/{hash}", get(get_object))
        .route("/v1/announce", post(post_announce))
        .route("/v1/peers", get(get_peers))
        .with_state(state)
        .layer(RequestBodyLimitLayer::new(MAX_MESSAGE_BYTES))
}

pub async fn serve(addr: SocketAddr, state: AppState) -> Result<(), AppError> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(AppError::internal)?;
    axum::serve(listener, app(state))
        .await
        .map_err(AppError::internal)
}

fn init_db(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        CREATE TABLE IF NOT EXISTS bundles (
            object_id TEXT PRIMARY KEY,
            payload TEXT NOT NULL,
            publisher_node_id TEXT NOT NULL,
            created_epoch INTEGER NOT NULL,
            expires_epoch INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS peers (
            node_id TEXT PRIMARY KEY,
            payload TEXT NOT NULL,
            last_seen_epoch INTEGER NOT NULL
        );
        ",
    )?;
    ensure_peer_expiry_column(conn)
}

fn ensure_peer_expiry_column(conn: &Connection) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(peers)")?;
    let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let mut has_expires_epoch = false;
    for column in columns {
        if column? == "expires_epoch" {
            has_expires_epoch = true;
            break;
        }
    }
    if !has_expires_epoch {
        conn.execute("ALTER TABLE peers ADD COLUMN expires_epoch INTEGER", [])?;
    }
    Ok(())
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct BeaconProfile {
    pub version: u8,
    pub bssid: String,
    pub ssid: Vec<u8>,
    pub beacon_interval_tu: u16,
    pub capability_flags: u16,
    pub security_type: SecurityType,
    pub band: Band,
    pub phy_flags: u32,
    pub channel_class: ChannelClass,
    pub vendor_ie_digest: Option<String>,
    pub feature_flags: u32,
    pub source_class: SourceClass,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum SecurityType {
    Open,
    Wep,
    Wpa2Personal,
    Wpa3Personal,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Band {
    Ghz2_4,
    Ghz5,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum ChannelClass {
    NonDfs24,
    NonDfs5,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum SourceClass {
    Synthetic,
    Consented,
    ObservedResearch,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct BundleMetadata {}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct BeaconBundle {
    pub protocol_version: u8,
    pub bundle_version: u8,
    pub publisher_node_id: String,
    pub publisher_public_key: String,
    pub created_epoch: u64,
    pub expires_epoch: u64,
    pub nonce: String,
    pub profiles: Vec<BeaconProfile>,
    #[serde(default)]
    pub metadata: BundleMetadata,
    pub signature: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct UnsignedBeaconBundle<'a> {
    protocol_version: u8,
    bundle_version: u8,
    publisher_node_id: &'a str,
    publisher_public_key: &'a str,
    created_epoch: u64,
    expires_epoch: u64,
    nonce: &'a str,
    profiles: &'a [BeaconProfile],
    metadata: &'a BundleMetadata,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct PeerAnnouncement {
    pub protocol_version: u8,
    pub node_id: String,
    pub public_key: String,
    pub addresses: Vec<String>,
    pub expires_epoch: Option<u64>,
    pub signature: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct UnsignedPeerAnnouncement<'a> {
    protocol_version: u8,
    node_id: &'a str,
    public_key: &'a str,
    addresses: &'a [String],
    expires_epoch: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AcceptedObject {
    pub object_id: String,
    pub stored: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PeerList {
    pub peers: Vec<PeerAnnouncement>,
}

#[derive(Debug, Deserialize)]
pub struct RandomBundlesQuery {
    count: Option<usize>,
}

async fn post_bundle(
    State(state): State<AppState>,
    Json(bundle): Json<BeaconBundle>,
) -> Result<Json<AcceptedObject>, AppError> {
    let validated = ValidatedBundle::from_bundle(bundle)?;
    let conn = state.db.lock().map_err(|_| AppError::internal("db lock"))?;
    expire_storage(&conn).map_err(AppError::internal)?;
    let inserted = conn
        .execute(
            "INSERT OR IGNORE INTO bundles (object_id, payload, publisher_node_id, created_epoch, expires_epoch)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                validated.object_id,
                validated.payload,
                validated.publisher_node_id,
                validated.created_epoch as i64,
                validated.expires_epoch as i64
            ],
        )
        .map_err(AppError::internal)?;
    Ok(Json(AcceptedObject {
        object_id: validated.object_id,
        stored: inserted > 0,
    }))
}

async fn get_random_bundles(
    State(state): State<AppState>,
    Query(query): Query<RandomBundlesQuery>,
) -> Result<Json<Vec<BeaconBundle>>, AppError> {
    let count = query.count.unwrap_or(1).clamp(1, MAX_RANDOM_BUNDLE_COUNT);
    let now = now_epoch();
    let conn = state.db.lock().map_err(|_| AppError::internal("db lock"))?;
    expire_storage(&conn).map_err(AppError::internal)?;
    let mut stmt = conn
        .prepare(
            "SELECT payload FROM bundles
             WHERE expires_epoch > ?1
             ORDER BY RANDOM()
             LIMIT ?2",
        )
        .map_err(AppError::internal)?;
    let rows = stmt
        .query_map(params![now as i64, count as i64], |row| row.get::<_, String>(0))
        .map_err(AppError::internal)?;

    let bundles = rows
        .map(|row| {
            row.map_err(AppError::internal)
                .and_then(|payload| serde_json::from_str(&payload).map_err(AppError::internal))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(bundles))
}

async fn get_object(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> Result<Json<BeaconBundle>, AppError> {
    validate_hash_string(&hash)?;
    let conn = state.db.lock().map_err(|_| AppError::internal("db lock"))?;
    expire_storage(&conn).map_err(AppError::internal)?;
    let payload = conn
        .query_row(
            "SELECT payload FROM bundles WHERE object_id = ?1 AND expires_epoch > ?2",
            params![hash, now_epoch() as i64],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(AppError::internal)?
        .ok_or_else(|| AppError::not_found("object not found"))?;
    let bundle = serde_json::from_str(&payload).map_err(AppError::internal)?;
    Ok(Json(bundle))
}

async fn post_announce(
    State(state): State<AppState>,
    Json(peer): Json<PeerAnnouncement>,
) -> Result<Json<PeerAnnouncement>, AppError> {
    let validated = ValidatedPeerAnnouncement::from_peer(peer)?;
    let conn = state.db.lock().map_err(|_| AppError::internal("db lock"))?;
    expire_storage(&conn).map_err(AppError::internal)?;
    conn.execute(
        "INSERT INTO peers (node_id, payload, last_seen_epoch, expires_epoch)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(node_id) DO UPDATE SET payload = excluded.payload, last_seen_epoch = excluded.last_seen_epoch, expires_epoch = excluded.expires_epoch",
        params![
            validated.node_id,
            validated.payload,
            validated.last_seen_epoch as i64,
            validated.expires_epoch.map(|epoch| epoch as i64)
        ],
    )
    .map_err(AppError::internal)?;
    Ok(Json(validated.peer))
}

async fn get_peers(State(state): State<AppState>) -> Result<Json<PeerList>, AppError> {
    let now = now_epoch();
    let stale_cutoff = now.saturating_sub(MAX_PEER_STALENESS_SECS);
    let conn = state.db.lock().map_err(|_| AppError::internal("db lock"))?;
    expire_storage(&conn).map_err(AppError::internal)?;
    let mut stmt = conn
        .prepare(
            "SELECT payload FROM peers
             WHERE (expires_epoch IS NULL OR expires_epoch > ?1)
               AND last_seen_epoch > ?2
             ORDER BY last_seen_epoch DESC
             LIMIT ?3",
        )
        .map_err(AppError::internal)?;
    let rows = stmt
        .query_map(
            params![now as i64, stale_cutoff as i64, MAX_PEER_COUNT as i64],
            |row| row.get::<_, String>(0),
        )
        .map_err(AppError::internal)?;
    let peers = rows
        .map(|row| {
            row.map_err(AppError::internal)
                .and_then(|payload| serde_json::from_str(&payload).map_err(AppError::internal))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(PeerList { peers }))
}

struct ValidatedBundle {
    object_id: String,
    payload: String,
    publisher_node_id: String,
    created_epoch: u64,
    expires_epoch: u64,
}

impl ValidatedBundle {
    fn from_bundle(bundle: BeaconBundle) -> Result<Self, AppError> {
        if bundle.protocol_version != CURRENT_PROTOCOL_VERSION {
            return Err(AppError::bad_request("unsupported protocol version"));
        }
        if bundle.bundle_version != CURRENT_BUNDLE_VERSION {
            return Err(AppError::bad_request("unsupported bundle version"));
        }
        if bundle.profiles.is_empty() || bundle.profiles.len() > MAX_PROFILES_PER_BUNDLE {
            return Err(AppError::bad_request("invalid profile count"));
        }
        if bundle.nonce.is_empty() || bundle.nonce.len() > MAX_NONCE_HEX_LENGTH {
            return Err(AppError::bad_request("invalid nonce length"));
        }
        if bundle.signature.is_empty() || bundle.signature.len() > MAX_SIGNATURE_HEX_LENGTH {
            return Err(AppError::bad_request("invalid signature length"));
        }
        validate_time_window(bundle.created_epoch, bundle.expires_epoch)?;
        for profile in &bundle.profiles {
            validate_profile(profile)?;
        }
        validate_hash_string(&bundle.publisher_node_id)?;

        let public_key_bytes = decode_hex_exact(&bundle.publisher_public_key, None, "public key")?;
        let node_id = sha256_hex(&public_key_bytes);
        if node_id != bundle.publisher_node_id {
            return Err(AppError::bad_request("publisher node id mismatch"));
        }

        let unsigned = UnsignedBeaconBundle {
            protocol_version: bundle.protocol_version,
            bundle_version: bundle.bundle_version,
            publisher_node_id: &bundle.publisher_node_id,
            publisher_public_key: &bundle.publisher_public_key,
            created_epoch: bundle.created_epoch,
            expires_epoch: bundle.expires_epoch,
            nonce: &bundle.nonce,
            profiles: &bundle.profiles,
            metadata: &bundle.metadata,
        };
        let unsigned_bytes = serde_json::to_vec(&unsigned).map_err(AppError::internal)?;
        let signature_bytes = decode_hex_exact(&bundle.signature, None, "signature")?;
        verify_signature(&public_key_bytes, &unsigned_bytes, &signature_bytes)?;

        let payload = serde_json::to_string(&bundle).map_err(AppError::internal)?;
        if payload.len() > MAX_SERIALIZED_BUNDLE_BYTES {
            return Err(AppError::bad_request("bundle exceeds size limit"));
        }
        let object_id = sha256_hex(payload.as_bytes());

        Ok(Self {
            object_id,
            payload,
            publisher_node_id: bundle.publisher_node_id,
            created_epoch: bundle.created_epoch,
            expires_epoch: bundle.expires_epoch,
        })
    }
}

struct ValidatedPeerAnnouncement {
    peer: PeerAnnouncement,
    payload: String,
    node_id: String,
    last_seen_epoch: u64,
    expires_epoch: Option<u64>,
}

impl ValidatedPeerAnnouncement {
    fn from_peer(peer: PeerAnnouncement) -> Result<Self, AppError> {
        if peer.protocol_version != CURRENT_PROTOCOL_VERSION {
            return Err(AppError::bad_request("unsupported protocol version"));
        }
        if peer.addresses.is_empty() || peer.addresses.len() > MAX_PEER_ADDRESSES {
            return Err(AppError::bad_request("invalid peer address count"));
        }
        validate_hash_string(&peer.node_id)?;
        let public_key_bytes = decode_hex_exact(&peer.public_key, None, "public key")?;
        let node_id = sha256_hex(&public_key_bytes);
        if node_id != peer.node_id {
            return Err(AppError::bad_request("peer node id mismatch"));
        }
        for address in &peer.addresses {
            if address.is_empty() || address.len() > MAX_ADDRESS_LENGTH {
                return Err(AppError::bad_request("invalid peer address"));
            }
            if !address.starts_with("https://")
                && !address.contains(".onion")
                && !address.starts_with("tcp://")
            {
                return Err(AppError::bad_request("unsupported peer address scheme"));
            }
        }
        if let Some(expires_epoch) = peer.expires_epoch {
            if expires_epoch <= now_epoch() {
                return Err(AppError::bad_request("peer announcement expired"));
            }
        }
        if let Some(signature_hex) = &peer.signature {
            let unsigned = UnsignedPeerAnnouncement {
                protocol_version: peer.protocol_version,
                node_id: &peer.node_id,
                public_key: &peer.public_key,
                addresses: &peer.addresses,
                expires_epoch: peer.expires_epoch,
            };
            let bytes = serde_json::to_vec(&unsigned).map_err(AppError::internal)?;
            let signature_bytes = decode_hex_exact(signature_hex, None, "signature")?;
            verify_signature(&public_key_bytes, &bytes, &signature_bytes)?;
        }
        let payload = serde_json::to_string(&peer).map_err(AppError::internal)?;
        Ok(Self {
            peer,
            payload,
            node_id,
            last_seen_epoch: now_epoch(),
            expires_epoch: peer.expires_epoch,
        })
    }
}

fn expire_storage(conn: &Connection) -> rusqlite::Result<()> {
    let now = now_epoch();
    let stale_cutoff = now.saturating_sub(MAX_PEER_STALENESS_SECS);
    conn.execute(
        "DELETE FROM bundles WHERE expires_epoch <= ?1",
        params![now as i64],
    )?;
    conn.execute(
        "DELETE FROM peers
         WHERE (expires_epoch IS NOT NULL AND expires_epoch <= ?1)
            OR last_seen_epoch <= ?2",
        params![now as i64, stale_cutoff as i64],
    )?;
    Ok(())
}

fn validate_profile(profile: &BeaconProfile) -> Result<(), AppError> {
    if profile.version != 1 {
        return Err(AppError::bad_request("unsupported profile version"));
    }
    let bssid = decode_hex_exact(&profile.bssid, Some(6), "bssid")?;
    if bssid[0] & 0x01 != 0 {
        return Err(AppError::bad_request("bssid must be unicast"));
    }
    if profile.ssid.len() > 32 {
        return Err(AppError::bad_request("ssid exceeds 32 bytes"));
    }
    if let Some(digest) = &profile.vendor_ie_digest {
        let bytes = decode_hex_exact(digest, None, "vendor_ie_digest")?;
        if bytes.len() > MAX_VENDOR_IE_DIGEST_BYTES {
            return Err(AppError::bad_request("vendor_ie_digest too large"));
        }
    }
    Ok(())
}

fn validate_time_window(created_epoch: u64, expires_epoch: u64) -> Result<(), AppError> {
    if expires_epoch <= created_epoch {
        return Err(AppError::bad_request("bundle expiry must exceed creation"));
    }
    if expires_epoch - created_epoch > MAX_BUNDLE_LIFETIME_SECS {
        return Err(AppError::bad_request("bundle lifetime exceeds limit"));
    }
    if created_epoch > now_epoch() + 300 {
        return Err(AppError::bad_request("bundle creation time too far in future"));
    }
    Ok(())
}

fn verify_signature(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), AppError> {
    let point = EncodedPoint::from_bytes(public_key_bytes)
        .map_err(|_| AppError::bad_request("invalid public key encoding"))?;
    let verifying_key = VerifyingKey::from_encoded_point(&point)
        .map_err(|_| AppError::bad_request("invalid public key"))?;
    let signature =
        Signature::from_der(signature_bytes).map_err(|_| AppError::bad_request("invalid signature"))?;
    verifying_key
        .verify(message, &signature)
        .map_err(|_| AppError::bad_request("signature verification failed"))
}

fn validate_hash_string(value: &str) -> Result<(), AppError> {
    let decoded = decode_hex_exact(value, Some(32), "hash")?;
    if decoded.len() != 32 {
        return Err(AppError::bad_request("invalid hash length"));
    }
    Ok(())
}

fn decode_hex_exact(
    value: &str,
    expected_len: Option<usize>,
    field: &'static str,
) -> Result<Vec<u8>, AppError> {
    let decoded = hex::decode(value).map_err(|_| AppError::bad_request(format!("invalid {field}")))?;
    if let Some(expected_len) = expected_len {
        if decoded.len() != expected_len {
            return Err(AppError::bad_request(format!("invalid {field} length")));
        }
    }
    Ok(decoded)
}

fn now_epoch() -> u64 {
    Utc::now().timestamp().max(0) as u64
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[derive(Debug)]
pub struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn internal(error: impl Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

impl Display for AppError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.status, Json(serde_json::json!({ "error": self.message }))).into_response()
    }
}

pub fn default_addr() -> SocketAddr {
    SocketAddr::from_str("127.0.0.1:8080").expect("valid default address")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use p256::ecdsa::{SigningKey, signature::Signer};
    use rusqlite::params;
    use tower::ServiceExt;

    fn signed_bundle(profile_count: usize) -> BeaconBundle {
        let signing_key = SigningKey::from_slice(&[7_u8; 32]).expect("valid key");
        let public_key = signing_key.verifying_key().to_encoded_point(false);
        let public_key_hex = hex::encode(public_key.as_bytes());
        let publisher_node_id = sha256_hex(public_key.as_bytes());
        let mut profiles = Vec::new();
        for idx in 0..profile_count {
            profiles.push(BeaconProfile {
                version: 1,
                bssid: format!("02aa00bb00{:02x}", idx),
                ssid: b"Privacy-Test-01".to_vec(),
                beacon_interval_tu: 100,
                capability_flags: 0x0431,
                security_type: SecurityType::Open,
                band: Band::Ghz2_4,
                phy_flags: 0,
                channel_class: ChannelClass::NonDfs24,
                vendor_ie_digest: None,
                feature_flags: 0,
                source_class: SourceClass::Synthetic,
            });
        }
        let created_epoch = now_epoch();
        let mut bundle = BeaconBundle {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            bundle_version: CURRENT_BUNDLE_VERSION,
            publisher_node_id,
            publisher_public_key: public_key_hex,
            created_epoch,
            expires_epoch: created_epoch + 3600,
            nonce: "abcd1234".into(),
            profiles,
            metadata: BundleMetadata::default(),
            signature: String::new(),
        };
        let unsigned = UnsignedBeaconBundle {
            protocol_version: bundle.protocol_version,
            bundle_version: bundle.bundle_version,
            publisher_node_id: &bundle.publisher_node_id,
            publisher_public_key: &bundle.publisher_public_key,
            created_epoch: bundle.created_epoch,
            expires_epoch: bundle.expires_epoch,
            nonce: &bundle.nonce,
            profiles: &bundle.profiles,
            metadata: &bundle.metadata,
        };
        let bytes = serde_json::to_vec(&unsigned).expect("serialize unsigned bundle");
        let signature: Signature = signing_key.sign(&bytes);
        bundle.signature = hex::encode(signature.to_der().as_bytes());
        bundle
    }

    #[test]
    fn bundle_validation_generates_object_id() {
        let bundle = signed_bundle(1);
        let validated = ValidatedBundle::from_bundle(bundle).expect("validated");
        assert_eq!(validated.object_id.len(), 64);
    }

    #[test]
    fn bundle_validation_rejects_too_many_profiles() {
        let bundle = signed_bundle(MAX_PROFILES_PER_BUNDLE + 1);
        let error = ValidatedBundle::from_bundle(bundle).expect_err("must reject");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn bundle_validation_rejects_node_id_mismatch() {
        let mut bundle = signed_bundle(1);
        bundle.publisher_node_id = "00".repeat(32);
        let error = ValidatedBundle::from_bundle(bundle).expect_err("must reject");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn relay_round_trip_stores_and_fetches_bundle() {
        let state = AppState::new_in_memory().expect("state");
        let app = app(state);
        let bundle = signed_bundle(1);
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::post("/v1/bundles")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&bundle).expect("serialize bundle"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.expect("body").to_bytes();
        let accepted: AcceptedObject = serde_json::from_slice(&bytes).expect("accepted body");
        let object_response = app
            .oneshot(
                axum::http::Request::get(format!("/v1/objects/{}", accepted.object_id))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(object_response.status(), StatusCode::OK);
    }

    #[test]
    fn expire_storage_removes_expired_bundles_and_stale_peers() {
        let state = AppState::new_in_memory().expect("state");
        let conn = state.db.lock().expect("db lock");
        let bundle = signed_bundle(1);
        conn.execute(
            "INSERT INTO bundles (object_id, payload, publisher_node_id, created_epoch, expires_epoch)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                "aa".repeat(32),
                serde_json::to_string(&bundle).expect("bundle json"),
                bundle.publisher_node_id,
                1_i64,
                (now_epoch().saturating_sub(1)) as i64
            ],
        )
        .expect("insert bundle");
        conn.execute(
            "INSERT INTO peers (node_id, payload, last_seen_epoch, expires_epoch)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                "bb".repeat(32),
                r#"{"protocol_version":1,"node_id":"bb"}"#,
                (now_epoch().saturating_sub(MAX_PEER_STALENESS_SECS + 1)) as i64,
                Option::<i64>::None
            ],
        )
        .expect("insert peer");

        expire_storage(&conn).expect("expire storage");

        let bundle_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM bundles", [], |row| row.get(0))
            .expect("bundle count");
        let peer_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM peers", [], |row| row.get(0))
            .expect("peer count");
        assert_eq!(bundle_count, 0);
        assert_eq!(peer_count, 0);
    }

    #[tokio::test]
    async fn get_peers_filters_stale_entries() {
        let state = AppState::new_in_memory().expect("state");
        {
            let conn = state.db.lock().expect("db lock");
            conn.execute(
                "INSERT INTO peers (node_id, payload, last_seen_epoch, expires_epoch)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    "11".repeat(32),
                    r#"{"protocol_version":1,"node_id":"1111111111111111111111111111111111111111111111111111111111111111","public_key":"04aa","addresses":["https://relay.example"]}"#,
                    now_epoch() as i64,
                    Option::<i64>::None
                ],
            )
            .expect("insert fresh peer");
            conn.execute(
                "INSERT INTO peers (node_id, payload, last_seen_epoch, expires_epoch)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    "22".repeat(32),
                    r#"{"protocol_version":1,"node_id":"2222222222222222222222222222222222222222222222222222222222222222","public_key":"04bb","addresses":["https://expired.example"]}"#,
                    (now_epoch().saturating_sub(MAX_PEER_STALENESS_SECS + 1)) as i64,
                    Option::<i64>::None
                ],
            )
            .expect("insert stale peer");
        }
        let app = app(state);

        let response = app
            .oneshot(
                axum::http::Request::get("/v1/peers")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.expect("body").to_bytes();
        let peers: PeerList = serde_json::from_slice(&bytes).expect("peer list");
        assert_eq!(peers.peers.len(), 1);
        assert_eq!(peers.peers[0].node_id, "11".repeat(32));
    }
}
