use alloc::{string::String as RustString, vec::Vec as RustVec};
use soroban_sdk::{
    contract, contractimpl, contracttype, panic_with_error, symbol_short, xdr::ToXdr, Address,
    Bytes, BytesN, Env, String, Symbol, Vec,
};
extern crate alloc;

use crate::deterministic_hash::{compute_payload_hash, make_storage_key, verify_payload_hash};
use crate::errors::ErrorCode;
use crate::rate_limiter::RateLimiter;
use crate::sep10_jwt;
use crate::transaction_state_tracker::{TransactionState, TransactionStateRecord};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
pub struct Session {
    pub session_id: u64,
    pub initiator: Address,
    pub created_at: u64,
    pub nonce: u64,
    pub operation_count: u64,
    pub session_ttl_seconds: u64,
    pub closed: bool,
}

#[contracttype]
#[derive(Clone)]
pub struct Quote {
    pub quote_id: u64,
    pub anchor: Address,
    pub base_asset: String,
    pub quote_asset: String,
    pub rate: u64,
    pub fee_percentage: u32,
    pub minimum_amount: u64,
    pub maximum_amount: u64,
    pub valid_until: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct OperationContext {
    pub session_id: u64,
    pub operation_index: u64,
    pub operation_type: String,
    pub timestamp: u64,
    pub status: String,
    pub result_data: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct AuditLog {
    pub log_id: u64,
    pub session_id: u64,
    pub actor: Address,
    pub operation: OperationContext,
}

#[contracttype]
#[derive(Clone)]
pub struct RequestId {
    pub id: Bytes,
    pub created_at: u64,
}

/// Carries the root request ID and the ordered chain of operation names
/// performed under that root request. Every sub-operation appends its name
/// to `operation_chain` rather than creating a new root ID.
#[contracttype]
#[derive(Clone)]
pub struct RequestContext {
    /// The root request ID that initiated this chain of operations.
    pub root_request_id: RequestId,
    /// Ordered list of operation names performed under this root request.
    pub operation_chain: Vec<String>,
    /// Ledger timestamp when this context was first created.
    pub created_at: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct Attestation {
    pub id: u64,
    pub issuer: Address,
    pub subject: Address,
    pub timestamp: u64,
    pub payload_hash: Bytes,
    pub signature: Bytes,
}

#[contracttype]
#[derive(Clone)]
pub struct TracingSpan {
    pub request_id: RequestId,
    pub operation: String,
    pub actor: Address,
    pub started_at: u64,
    pub completed_at: u64,
    pub status: String,
    /// Raw bytes of the parent span's request_id.id, or empty Bytes if this is a root span.
    pub parent_request_id_bytes: Bytes,
    /// Zero-based index of this span within the trace, used for ordering.
    pub span_index: u32,
}

/// Holds the root request ID bytes and the current span index counter for a trace.
#[contracttype]
#[derive(Clone)]
pub struct TracingContext {
    pub root_request_id_bytes: Bytes,
    pub next_span_index: u32,
}

#[contracttype]
#[derive(Clone)]
pub struct AnchorServices {
    pub anchor: Address,
    pub services: Vec<u32>,
}

pub const SERVICE_DEPOSITS: u32 = 1;
pub const SERVICE_WITHDRAWALS: u32 = 2;
pub const SERVICE_QUOTES: u32 = 3;
pub const SERVICE_KYC: u32 = 4;

/// Typed representation of a service capability an anchor can support.
///
/// Each variant maps to a stable `u32` discriminant stored on-chain.
/// Use [`ServiceType::as_u32`] to convert before passing to contract functions.
#[derive(Clone, PartialEq)]
pub enum ServiceType {
    Deposits,
    Withdrawals,
    Quotes,
    KYC,
}

impl ServiceType {
    pub fn as_u32(&self) -> u32 {
        match self {
            ServiceType::Deposits => SERVICE_DEPOSITS,
            ServiceType::Withdrawals => SERVICE_WITHDRAWALS,
            ServiceType::Quotes => SERVICE_QUOTES,
            ServiceType::KYC => SERVICE_KYC,
        }
    }
}

// ---------------------------------------------------------------------------
// Routing types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
pub struct RoutingAnchorMeta {
    pub anchor: Address,
    pub reputation_score: u32,
    pub average_settlement_time: u64,
    pub liquidity_score: u32,
    pub uptime_percentage: u32,
    pub total_volume: u64,
    pub is_active: bool,
}

#[contracttype]
#[derive(Clone)]
pub struct RoutingRequest {
    pub base_asset: String,
    pub quote_asset: String,
    pub amount: u64,
    pub operation_type: u32,
}

#[contracttype]
#[derive(Clone)]
pub struct RoutingOptions {
    pub request: RoutingRequest,
    pub strategy: Vec<Symbol>,
    pub min_reputation: u32,
    pub max_anchors: u32,
    pub require_kyc: bool,
    pub require_compliance: bool,
    pub subject: Address,
}

/// Composite weighted routing strategy.
/// `fee_weight + speed_weight + reputation_weight` must equal 1.0.
pub struct WeightedRoutingStrategy {
    pub fee_weight: f32,
    pub speed_weight: f32,
    pub reputation_weight: f32,
}

impl WeightedRoutingStrategy {
    /// Validate that weights sum to 1.0 (within floating-point tolerance).
    pub fn validate(&self) -> bool {
        let sum = self.fee_weight + self.speed_weight + self.reputation_weight;
        (sum - 1.0_f32).abs() < 1e-4
    }

    /// Compute a normalized composite score in [0.0, 1.0].
    /// Lower fee and faster settlement are better; higher reputation is better.
    /// Each dimension is normalised against the provided max values.
    pub fn score_anchor(
        &self,
        fee_pct: u32,
        settlement_time: u64,
        reputation: u32,
        max_fee: u32,
        max_settlement: u64,
        max_reputation: u32,
    ) -> f32 {
        let fee_score = if max_fee == 0 {
            1.0_f32
        } else {
            1.0_f32 - (fee_pct as f32 / max_fee as f32)
        };
        let speed_score = if max_settlement == 0 {
            1.0_f32
        } else {
            1.0_f32 - (settlement_time as f32 / max_settlement as f32)
        };
        let rep_score = if max_reputation == 0 {
            0.0_f32
        } else {
            reputation as f32 / max_reputation as f32
        };
        self.fee_weight * fee_score
            + self.speed_weight * speed_score
            + self.reputation_weight * rep_score
    }
}

// ---------------------------------------------------------------------------
// KYC and Compliance types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum KycStatus {
    NotSubmitted = 0,
    Pending = 1,
    Approved = 2,
    Rejected = 3,
    Expired = 4,
}

#[contracttype]
#[derive(Clone)]
pub struct ComplianceCheck {
    pub subject: Address,
    pub check_type: String,
    pub result: u32,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct KycRecord {
    pub subject: Address,
    pub status: u32,
    pub submitted_at: u64,
    pub reviewed_at: Option<u64>,
    pub expiry: Option<u64>,
    pub rejection_reason_hash: Option<Bytes>,
}

// ---------------------------------------------------------------------------
// Metadata cache types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
pub struct AnchorMetadata {
    pub anchor: Address,
    pub reputation_score: u32,
    pub liquidity_score: u32,
    pub uptime_percentage: u32,
    pub total_volume: u64,
    pub average_settlement_time: u64,
    pub is_active: bool,
}

#[contracttype]
#[derive(Clone)]
pub struct MetadataCache {
    pub metadata: AnchorMetadata,
    pub cached_at: u64,
    pub ttl_seconds: u64,
    /// Grace period after `ttl_seconds` during which stale data may be served.
    pub stale_ttl_seconds: u64,
    /// Set to `true` when the entry is within the stale window; caller should refresh.
    pub needs_refresh: bool,
}

#[contracttype]
#[derive(Clone)]
pub struct CapabilitiesCache {
    pub toml_url: String,
    pub capabilities: String,
    pub cached_at: u64,
    pub ttl_seconds: u64,
}

// ---------------------------------------------------------------------------
// Anchor Info Discovery types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
pub struct AssetInfo {
    pub code: String,
    pub issuer: String,
    pub deposit_enabled: bool,
    pub withdrawal_enabled: bool,
    pub deposit_fee_fixed: u64,
    pub deposit_fee_percent: u32,
    pub withdrawal_fee_fixed: u64,
    pub withdrawal_fee_percent: u32,
    pub deposit_min_amount: u64,
    pub deposit_max_amount: u64,
    pub withdrawal_min_amount: u64,
    pub withdrawal_max_amount: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct StellarToml {
    pub version: String,
    pub network_passphrase: String,
    pub accounts: Vec<String>,
    pub signing_key: String,
    pub currencies: Vec<AssetInfo>,
    pub transfer_server: String,
    pub transfer_server_sep0024: String,
    pub kyc_server: String,
    pub web_auth_endpoint: String,
}

#[contracttype]
#[derive(Clone)]
pub struct CachedToml {
    pub toml: StellarToml,
    pub cached_at: u64,
    pub ttl_seconds: u64,
}

const MIN_TEMP_TTL: u32 = 15; // min_temp_entry_ttl - 1

// ---------------------------------------------------------------------------
// Event structs
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
struct SessionCreatedEvent {
    session_id: u64,
    initiator: Address,
    timestamp: u64,
}

#[contracttype]
#[derive(Clone)]
struct SessionClosedEvent {
    session_id: u64,
    initiator: Address,
    timestamp: u64,
}

#[contracttype]
#[derive(Clone)]
struct QuoteSubmitEvent {
    quote_id: u64,
    anchor: Address,
    base_asset: String,
    quote_asset: String,
    rate: u64,
    valid_until: u64,
}

#[contracttype]
#[derive(Clone)]
struct QuoteReceivedEvent {
    quote_id: u64,
    receiver: Address,
    timestamp: u64,
}

#[contracttype]
#[derive(Clone)]
struct AuditLogEvent {
    log_id: u64,
    session_id: u64,
    operation_index: u64,
    operation_type: String,
    status: String,
}

#[contracttype]
#[derive(Clone)]
struct AttestEvent {
    payload_hash: Bytes,
    timestamp: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct EndpointUpdated {
    pub attestor: Address,
    pub endpoint: String,
}

#[contracttype]
#[derive(Clone)]
struct TxStateChangedEvent {
    transaction_id: u64,
    old_state: u32,
    new_state: u32,
    timestamp: u64,
}

#[contracttype]
#[derive(Clone)]
struct WebhookEvent {
    event_type: String,
    transaction_id: u64,
    timestamp: u64,
    payload_hash: Bytes,
}

// ---------------------------------------------------------------------------
// Contract upgrade types (#200)
// Provides admin-controlled WASM upgrade with version tracking and audit events.
// ---------------------------------------------------------------------------

/// Semantic version stored in persistent contract storage after each upgrade.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ContractVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    /// Ledger timestamp of the most recent upgrade (0 = never upgraded).
    pub upgraded_at: u64,
}

impl ContractVersion {
    /// Increment the patch component and record the upgrade timestamp.
    pub fn bump_patch(self, upgraded_at: u64) -> Self {
        ContractVersion {
            major: self.major,
            minor: self.minor,
            patch: self.patch + 1,
            upgraded_at,
        }
    }
}

/// Event emitted after a successful contract upgrade.
#[contracttype]
#[derive(Clone)]
struct UpgradeEvent {
    old_wasm_hash: BytesN<32>,
    new_wasm_hash: BytesN<32>,
    new_major: u32,
    new_minor: u32,
    new_patch: u32,
    upgraded_at: u64,
}

// ---------------------------------------------------------------------------
// TTLs (in ledgers)
// ---------------------------------------------------------------------------
const PERSISTENT_TTL: u32 = 1_555_200;
const SPAN_TTL: u32 = 17_280;
const INSTANCE_TTL: u32 = 518_400;

/// Default session lifetime in seconds (1 hour). Used when session_ttl_seconds is zero.
pub const DEFAULT_SESSION_TTL: u64 = 3600;

/// Maximum operations allowed per session before it is considered exhausted.
pub const MAX_OPS_PER_SESSION: u64 = 100;

/// Minimum TTL for replay-protection entries (7 days in ledgers at ~5 s/ledger).
pub const REPLAY_TTL: u32 = 120_960;

// ---------------------------------------------------------------------------
// Storage key helpers — all keys go through make_storage_key for collision
// resistance (#229). Each namespace uses a unique prefix byte slice.
// ---------------------------------------------------------------------------

fn admin_key(env: &Env) -> BytesN<32> {
    make_storage_key(env, &[b"ADMIN"])
}

fn initialized_key(env: &Env) -> BytesN<32> {
    make_storage_key(env, &[b"INITIALIZED"])
}

fn kyc_record_key(env: &Env, subject: &Address) -> BytesN<32> {
    let xdr = subject.clone().to_xdr(env);
    let raw = xdr_to_vec(&xdr);
    make_storage_key(env, &[b"KYC", &raw])
}

fn compliance_check_key(env: &Env, subject: &Address, check_type: &String) -> BytesN<32> {
    let xdr = subject.clone().to_xdr(env);
    let raw = xdr_to_vec(&xdr);
    let mut ct_bytes = alloc::vec![0u8; check_type.len() as usize];
    check_type.copy_into_slice(&mut ct_bytes);
    make_storage_key(env, &[b"COMP", &raw, &ct_bytes])
}

fn anchor_meta_key(env: &Env, anchor: &Address) -> BytesN<32> {
    let xdr = anchor.clone().to_xdr(env);
    let raw = xdr_to_vec(&xdr);
    make_storage_key(env, &[b"ANCHMETA", &raw])
}

/// Convert a Soroban `Bytes` value to a native `Vec<u8>` for use in key helpers.
fn xdr_to_vec(b: &Bytes) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec::Vec::with_capacity(b.len() as usize);
    for i in 0..b.len() {
        v.push(b.get(i).unwrap_or(0));
    }
    v
}

fn anchor_meta_opt(env: &Env, anchor: &Address) -> Option<RoutingAnchorMeta> {
    env.storage().persistent().get(&anchor_meta_key(env, anchor))
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct AnchorKitContract;

#[contractimpl]
impl AnchorKitContract {
    // -----------------------------------------------------------------------
    // Initialization
    // -----------------------------------------------------------------------

    /// Initialize the contract with an admin address. Can only be called once.
    /// Panics with `AlreadyInitialized` on any subsequent call.
    pub fn initialize(env: Env, admin: Address) {
        admin.require_auth();
        // #228: dedicated initialized flag in persistent storage prevents
        // re-initialization after upgrade.
        let init_key = initialized_key(&env);
        if env.storage().persistent().has(&init_key) {
            panic_with_error!(&env, ErrorCode::AlreadyInitialized);
        }
        env.storage().persistent().set(&init_key, &true);
        env.storage().persistent().extend_ttl(&init_key, PERSISTENT_TTL, PERSISTENT_TTL);
        env.storage().instance().set(&admin_key(&env), &admin);
        env.storage().instance().extend_ttl(INSTANCE_TTL, INSTANCE_TTL);
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get::<_, Address>(&admin_key(&env))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::NotInitialized))
    }

    // -----------------------------------------------------------------------
    // Contract upgrade (#200)
    // -----------------------------------------------------------------------

    /// Storage key for the contract version record.
    fn version_key(env: &Env) -> BytesN<32> {
        make_storage_key(env, &[b"VERSION"])
    }

    /// Return the current contract version.
    /// Returns `ContractVersion { major: 0, minor: 1, patch: 0, upgraded_at: 0 }` if
    /// no version has been stored yet (i.e. the contract has never been upgraded).
    pub fn get_version(env: Env) -> ContractVersion {
        env.storage()
            .instance()
            .get::<_, ContractVersion>(&Self::version_key(&env))
            .unwrap_or(ContractVersion {
                major: 0,
                minor: 1,
                patch: 0,
                upgraded_at: 0,
            })
    }

    /// Upgrade the contract WASM to `new_wasm_hash`.
    /// Requires admin authorization and that the contract is already initialized.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        // #228: must be initialized before upgrade is permitted
        if !env.storage().persistent().has(&initialized_key(&env)) {
            panic_with_error!(&env, ErrorCode::NotInitialized);
        }
        Self::require_admin(&env);

        let now = env.ledger().timestamp();
        let old_version = Self::get_version(env.clone());

        let old_hash_key = make_storage_key(&env, &[b"OLDHASH"]);
        let old_wasm_hash: BytesN<32> = env
            .storage()
            .instance()
            .get::<_, BytesN<32>>(&old_hash_key)
            .unwrap_or_else(|| BytesN::from_array(&env, &[0u8; 32]));

        env.deployer().update_current_contract_wasm(new_wasm_hash.clone());

        let new_version = old_version.bump_patch(now);
        env.storage()
            .instance()
            .set(&Self::version_key(&env), &new_version);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL, INSTANCE_TTL);

        env.storage()
            .instance()
            .set(&old_hash_key, &new_wasm_hash.clone());

        env.events().publish(
            (symbol_short!("contract"), symbol_short!("upgraded")),
            UpgradeEvent {
                old_wasm_hash,
                new_wasm_hash,
                new_major: new_version.major,
                new_minor: new_version.minor,
                new_patch: new_version.patch,
                upgraded_at: now,
            },
        );
    }

    /// Idempotent post-upgrade migration hook.
    /// Requires admin authorization and that the contract is already initialized.
    pub fn migrate(env: Env) {
        // #228: migrate must not run before initialization
        if !env.storage().persistent().has(&initialized_key(&env)) {
            panic_with_error!(&env, ErrorCode::NotInitialized);
        }
        Self::require_admin(&env);

        let version = Self::get_version(env.clone());
        let nonce_key = make_storage_key(&env, &[b"MIGNONCE", &version.patch.to_be_bytes()]);
        if env.storage().instance().has(&nonce_key) {
            return;
        }

        env.storage().instance().set(&nonce_key, &true);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL, INSTANCE_TTL);
    }

    // -----------------------------------------------------------------------
    // Request ID generation
    // -----------------------------------------------------------------------

    /// Generate a deterministic request ID: sha256(timestamp_u64_be || sequence_number_u32_be)[:16]
    pub fn generate_request_id(env: Env) -> RequestId {
        let ts = env.ledger().timestamp();
        let seq = env.ledger().sequence() as u32;

        // Build input: 8-byte timestamp || 4-byte sequence number (big-endian)
        let mut input = Bytes::new(&env);
        for b in ts.to_be_bytes().iter() {
            input.push_back(*b);
        }
        for b in seq.to_be_bytes().iter() {
            input.push_back(*b);
        }

        let hash = env.crypto().sha256(&input);
        let mut id = Bytes::new(&env);
        let hash_bytes = hash.to_array();
        for b in hash_bytes.iter().take(16) {
            id.push_back(*b);
        }

        RequestId { id, created_at: ts }
    }

    // -----------------------------------------------------------------------
    // Attestor management
    // -----------------------------------------------------------------------

    /// Stores the 32-byte Ed25519 public key used to verify SEP-10 JWTs for `issuer`
    /// (the anchor identity whose signing key appears in stellar.toml / SEP-10 flow).
    pub fn set_sep10_jwt_verifying_key(env: Env, issuer: Address, public_key: Bytes) {
        Self::require_admin(&env);
        if public_key.len() != 32 {
            panic_with_error!(&env, ErrorCode::ValidationError);
        }
        let xdr = issuer.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let storage_key = make_storage_key(&env, &[b"SEP10KEY", &raw]);
        env.storage().persistent().set(&storage_key, &public_key);
        env.storage()
            .persistent()
            .extend_ttl(&storage_key, PERSISTENT_TTL, PERSISTENT_TTL);
    }

    /// Configure the maximum JWT length accepted by `verify_sep10_jwt` (issue #64).
    /// Must be between 2048 and 16384. Admin-only.
    pub fn set_jwt_max_len(env: Env, max_len: u32) {
        Self::require_admin(&env);
        if max_len < sep10_jwt::MAX_JWT_LEN || max_len > 16384 {
            panic_with_error!(&env, ErrorCode::ValidationError);
        }
        env.storage()
            .instance()
            .set(&symbol_short!("JWTMAXLEN"), &max_len);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL, INSTANCE_TTL);
    }

    /// Return the currently configured JWT max length (defaults to 2048).
    pub fn get_jwt_max_len(env: Env) -> u32 {
        env.storage()
            .instance()
            .get::<_, u32>(&symbol_short!("JWTMAXLEN"))
            .unwrap_or(sep10_jwt::MAX_JWT_LEN)
    }

    /// Configure the clock skew tolerance (seconds) used by `verify_sep10_jwt`. Admin-only.
    /// Falls back to 60 s when not set. Maximum allowed value is 300 s.
    pub fn set_jwt_skew(env: Env, skew_seconds: u64) {
        Self::require_admin(&env);
        if skew_seconds > 300 {
            panic_with_error!(&env, ErrorCode::ValidationError);
        }
        env.storage()
            .instance()
            .set(&symbol_short!("JWTSKEW"), &skew_seconds);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL, INSTANCE_TTL);
    }

    /// Return the currently configured JWT clock skew tolerance in seconds (defaults to 60).
    pub fn get_jwt_skew(env: Env) -> u64 {
        env.storage()
            .instance()
            .get::<_, u64>(&symbol_short!("JWTSKEW"))
            .unwrap_or(sep10_jwt::DEFAULT_CLOCK_SKEW)
    }

    /// Verifies a SEP-10 JWT (JWS compact, EdDSA) using the stored key for `issuer`: signature, `exp`, and `sub`.
    pub fn verify_sep10_token(env: Env, token: String, issuer: Address) {
        let xdr = issuer.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let pk: Bytes = env
            .storage()
            .persistent()
            .get(&make_storage_key(&env, &[b"SEP10KEY", &raw]))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::InvalidSep10Token));
        if sep10_jwt::verify_sep10_jwt(&env, &token, &pk, None).is_err() {
            panic_with_error!(&env, ErrorCode::InvalidSep10Token);
        }
    }

    fn verify_sep10_token_matches_attestor(
        env: &Env,
        token: &String,
        issuer: &Address,
        attestor: &Address,
    ) {
        let xdr = issuer.clone().to_xdr(env);
        let raw = xdr_to_vec(&xdr);
        let pk: Bytes = env
            .storage()
            .persistent()
            .get(&make_storage_key(env, &[b"SEP10KEY", &raw]))
            .unwrap_or_else(|| panic_with_error!(env, ErrorCode::InvalidSep10Token));
        let expected = attestor.to_string();
        if sep10_jwt::verify_sep10_jwt(env, token, &pk, Some(&expected)).is_err() {
            panic_with_error!(env, ErrorCode::InvalidSep10Token);
        }
    }

    pub fn verify_sep10_token_for_subject(
        env: Env,
        token: String,
        issuer: Address,
        subject: Address,
    ) {
        let xdr = issuer.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let pk: Bytes = env
            .storage()
            .persistent()
            .get(&make_storage_key(&env, &[b"SEP10KEY", &raw]))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::InvalidSep10Token));
        let expected = subject.to_string();
        if sep10_jwt::verify_sep10_jwt(&env, &token, &pk, Some(&expected)).is_err() {
            panic_with_error!(&env, ErrorCode::InvalidSep10Token);
        }
    }

    pub fn register_attestor(env: Env, attestor: Address, sep10_token: String, sep10_issuer: Address, public_key: BytesN<32>) {
        Self::require_admin(&env);
        Self::verify_sep10_token_matches_attestor(&env, &sep10_token, &sep10_issuer, &attestor);
        let xdr = attestor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let key = make_storage_key(&env, &[b"ATTESTOR", &raw]);
        if env.storage().persistent().has(&key) {
            panic_with_error!(&env, ErrorCode::AttestorAlreadyRegistered);
        }
        env.storage().persistent().set(&key, &true);
        env.storage()
            .persistent()
            .extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);
        let pk_key = make_storage_key(&env, &[b"ATPUBKEY", &raw]);
        env.storage().persistent().set(&pk_key, &public_key);
        env.storage()
            .persistent()
            .extend_ttl(&pk_key, PERSISTENT_TTL, PERSISTENT_TTL);
        env.events().publish(
            (symbol_short!("attestor"), symbol_short!("added"), attestor),
            (),
        );
    }

    pub fn revoke_attestor(env: Env, attestor: Address) {
        Self::require_admin(&env);
        let xdr = attestor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let key = make_storage_key(&env, &[b"ATTESTOR", &raw]);
        if !env.storage().persistent().has(&key) {
            panic_with_error!(&env, ErrorCode::AttestorNotRegistered);
        }
        env.storage().persistent().remove(&key);
        let pk_key = make_storage_key(&env, &[b"ATPUBKEY", &raw]);
        env.storage().persistent().remove(&pk_key);
        env.events().publish(
            (symbol_short!("attestor"), symbol_short!("removed"), attestor),
            (),
        );
    }

    pub fn is_attestor(env: Env, attestor: Address) -> bool {
        let xdr = attestor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        env.storage()
            .persistent()
            .get::<_, bool>(&make_storage_key(&env, &[b"ATTESTOR", &raw]))
            .unwrap_or(false)
    }

    // -----------------------------------------------------------------------
    // Attestor endpoint management
    // -----------------------------------------------------------------------

    pub fn set_endpoint(env: Env, attestor: Address, endpoint: String) {
        attestor.require_auth();
        Self::check_attestor(&env, &attestor);
        let endpoint_str = Self::soroban_string_to_rust_string(&env, &endpoint);
        crate::validate_anchor_domain(&endpoint_str)
            .unwrap_or_else(|_| panic_with_error!(&env, ErrorCode::InvalidEndpointFormat));
        let key = (symbol_short!("ENDPOINT"), attestor.clone());
        env.storage().persistent().set(&key, &endpoint);
        env.storage().persistent().extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);
        env.events().publish(
            (symbol_short!("endpoint"), symbol_short!("updated")),
            EndpointUpdated { attestor, endpoint },
        );
    }

    pub fn get_endpoint(env: Env, attestor: Address) -> String {
        if !Self::is_attestor(env.clone(), attestor.clone()) {
            panic_with_error!(&env, ErrorCode::AttestorNotRegistered);
        }
        let xdr = attestor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        env.storage().persistent()
            .get::<_, String>(&make_storage_key(&env, &[b"ENDPOINT", &raw]))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::AttestorNotRegistered))
    }

    pub fn register_webhook(env: Env, attestor: Address, webhook_url: String) {
        attestor.require_auth();
        Self::check_attestor(&env, &attestor);
        let webhook_url_str = Self::soroban_string_to_rust_string(&env, &webhook_url);
        crate::validate_anchor_domain(&webhook_url_str)
            .unwrap_or_else(|_| panic_with_error!(&env, ErrorCode::InvalidEndpointFormat));
        let key = (symbol_short!("WEBHOOK"), attestor.clone());
        env.storage().persistent().set(&key, &webhook_url);
        env.storage().persistent().extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);
        env.events().publish(
            (symbol_short!("webhook"), symbol_short!("reg")),
            EndpointUpdated {
                attestor,
                endpoint: webhook_url,
            },
        );
    }

    pub fn get_webhook_url(env: Env, attestor: Address) -> String {
        if !Self::is_attestor(env.clone(), attestor.clone()) {
            panic_with_error!(&env, ErrorCode::AttestorNotRegistered);
        }
        let xdr = attestor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        env.storage().persistent()
            .get::<_, String>(&make_storage_key(&env, &[b"WEBHOOK", &raw]))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::AttestorNotRegistered))
    }

    // -----------------------------------------------------------------------
    // Service configuration
    // -----------------------------------------------------------------------

    pub fn configure_services(env: Env, anchor: Address, services: Vec<u32>) {
        anchor.require_auth();
        let xdr = anchor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        if !env.storage().persistent().has(&make_storage_key(&env, &[b"ATTESTOR", &raw])) {
            panic_with_error!(&env, ErrorCode::AttestorNotRegistered);
        }
        if services.is_empty() {
            panic_with_error!(&env, ErrorCode::InvalidServiceType);
        }
        let mut seen = Vec::new(&env);
        for s in services.iter() {
            if seen.contains(&s) {
                panic_with_error!(&env, ErrorCode::InvalidServiceType);
            }
            seen.push_back(s);
        }
        let record = AnchorServices { anchor: anchor.clone(), services: services.clone() };
        let key = make_storage_key(&env, &[b"SERVICES", &raw]);
        env.storage().persistent().set(&key, &record);
        env.storage().persistent().extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);
        env.events().publish((symbol_short!("services"), symbol_short!("config")), record);
    }

    pub fn get_supported_services(env: Env, anchor: Address) -> AnchorServices {
        let xdr = anchor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        env.storage()
            .persistent()
            .get::<_, AnchorServices>(&make_storage_key(&env, &[b"SERVICES", &raw]))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::ServicesNotConfigured))
    }

    pub fn supports_service(env: Env, anchor: Address, service: u32) -> bool {
        let xdr = anchor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let record = env
            .storage()
            .persistent()
            .get::<_, AnchorServices>(&make_storage_key(&env, &[b"SERVICES", &raw]))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::ServicesNotConfigured));
        record.services.contains(&service)
    }

    // -----------------------------------------------------------------------
    // Attestation submission (plain)
    // -----------------------------------------------------------------------

    pub fn submit_attestation(
        env: Env,
        issuer: Address,
        subject: Address,
        timestamp: u64,
        payload_hash: Bytes,
        signature: Bytes,
    ) -> u64 {
        issuer.require_auth();
        Self::check_attestor(&env, &issuer);
        Self::verify_attestation_signature(&env, &issuer, &payload_hash, &signature);
        Self::enforce_rate_limit(&env, &issuer);
        Self::check_timestamp(&env, timestamp);

        let config = RateLimiter::get_config(&env);
        if RateLimiter::check_and_increment(&env, &issuer, &config).is_err() {
            panic_with_error!(&env, ErrorCode::RateLimitExceeded);
        }

        let issuer_xdr = issuer.clone().to_xdr(&env);
        let issuer_raw = xdr_to_vec(&issuer_xdr);
        let hash_raw = xdr_to_vec(&payload_hash);
        let used_key = make_storage_key(&env, &[b"USED", &issuer_raw, &hash_raw]);
        if env.storage().persistent().has(&used_key) {
            panic_with_error!(&env, ErrorCode::ReplayAttack);
        }

        let id = Self::next_attestation_id(&env);
        Self::store_attestation(
            &env, id, issuer.clone(), subject.clone(), timestamp,
            payload_hash.clone(), signature,
        );

        env.storage().persistent().set(&used_key, &timestamp);
        env.storage().persistent().extend_ttl(&used_key, REPLAY_TTL, REPLAY_TTL);

        env.events().publish(
            (symbol_short!("attest"), symbol_short!("recorded"), id, subject),
            AttestEvent { payload_hash, timestamp },
        );
        id
    }

    // -----------------------------------------------------------------------
    // Attestation submission with KYC enforcement
    // -----------------------------------------------------------------------

    pub fn submit_attestation_kyc_check(
        env: Env,
        issuer: Address,
        subject: Address,
        timestamp: u64,
        payload_hash: Bytes,
        signature: Bytes,
        require_kyc: bool,
    ) -> u64 {
        issuer.require_auth();
        Self::check_attestor(&env, &issuer);
        Self::verify_attestation_signature(&env, &issuer, &payload_hash, &signature);
        Self::check_timestamp(&env, timestamp);

        if require_kyc {
            let kyc_status = Self::get_kyc_status(env.clone(), subject.clone());
            if kyc_status != KycStatus::Approved {
                match kyc_status {
                    KycStatus::Pending    => panic_with_error!(&env, ErrorCode::KycPending),
                    KycStatus::Rejected   => panic_with_error!(&env, ErrorCode::KycRejected),
                    KycStatus::Expired    => panic_with_error!(&env, ErrorCode::ComplianceNotMet),
                    KycStatus::NotSubmitted => panic_with_error!(&env, ErrorCode::KycNotFound),
                    _ => panic_with_error!(&env, ErrorCode::ComplianceNotMet),
                }
            }
        }

        let issuer_xdr = issuer.clone().to_xdr(&env);
        let issuer_raw = xdr_to_vec(&issuer_xdr);
        let hash_raw = xdr_to_vec(&payload_hash);
        let used_key = make_storage_key(&env, &[b"USED", &issuer_raw, &hash_raw]);
        if env.storage().persistent().has(&used_key) {
            panic_with_error!(&env, ErrorCode::ReplayAttack);
        }

        let id = Self::next_attestation_id(&env);
        Self::store_attestation(
            &env, id, issuer.clone(), subject.clone(), timestamp,
            payload_hash.clone(), signature,
        );

        env.storage().persistent().set(&used_key, &timestamp);
        env.storage().persistent().extend_ttl(&used_key, REPLAY_TTL, REPLAY_TTL);

        let now = env.ledger().timestamp();
        env.events().publish(
            (symbol_short!("attest"), symbol_short!("recorded"), id, subject),
            AttestEvent { payload_hash: payload_hash.clone(), timestamp },
        );
        env.events().publish(
            (symbol_short!("webhook"), symbol_short!("event")),
            WebhookEvent {
                event_type: String::from_str(&env, "attestation_submitted"),
                transaction_id: id, timestamp, payload_hash,
            },
        );
        id
    }

    // -----------------------------------------------------------------------
    // Attestation submission with request ID + tracing span
    // -----------------------------------------------------------------------

    pub fn submit_with_request_id(
        env: Env,
        request_id: RequestId,
        issuer: Address,
        subject: Address,
        timestamp: u64,
        payload_hash: Bytes,
        signature: Bytes,
    ) -> u64 {
        issuer.require_auth();
        Self::check_attestor(&env, &issuer);
        Self::verify_attestation_signature(&env, &issuer, &payload_hash, &signature);
        Self::enforce_rate_limit(&env, &issuer);
        Self::check_timestamp(&env, timestamp);

        let issuer_xdr = issuer.clone().to_xdr(&env);
        let issuer_raw = xdr_to_vec(&issuer_xdr);
        let hash_raw = xdr_to_vec(&payload_hash);
        let used_key = make_storage_key(&env, &[b"USED", &issuer_raw, &hash_raw]);
        if env.storage().persistent().has(&used_key) {
            panic_with_error!(&env, ErrorCode::ReplayAttack);
        }

        let id = Self::next_attestation_id(&env);
        Self::store_attestation(
            &env, id, issuer.clone(), subject.clone(), timestamp,
            payload_hash.clone(), signature,
        );

        env.storage().persistent().set(&used_key, &timestamp);
        env.storage().persistent().extend_ttl(&used_key, REPLAY_TTL, REPLAY_TTL);

        let now = env.ledger().timestamp();
        Self::store_span(
            &env, &request_id,
            String::from_str(&env, "submit_attestation"),
            issuer.clone(), now,
            String::from_str(&env, "success"),
        );

        // Propagate operation name into RequestContext
        Self::record_operation_in_context(&env, &request_id.id, String::from_str(&env, "submit_attestation"));

        env.events().publish(
            (symbol_short!("attest"), symbol_short!("recorded"), id, subject),
            AttestEvent { payload_hash: payload_hash.clone(), timestamp },
        );
        env.events().publish(
            (symbol_short!("webhook"), symbol_short!("event")),
            WebhookEvent {
                event_type: String::from_str(&env, "attestation_submitted"),
                transaction_id: id, timestamp, payload_hash,
            },
        );
        id
    }

    // -----------------------------------------------------------------------
    // Quote submission with request ID + tracing span
    // -----------------------------------------------------------------------

    #[allow(unused_variables)]
    pub fn quote_with_request_id(
        env: Env,
        request_id: RequestId,
        anchor: Address,
        from_asset: String,
        to_asset: String,
        amount: u64,
        fee_bps: u32,
        min_amount: u64,
        max_amount: u64,
        expires_at: u64,
    ) {
        anchor.require_auth();
        let xdr = anchor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let services_record = env
            .storage()
            .persistent()
            .get::<_, AnchorServices>(&make_storage_key(&env, &[b"SERVICES", &raw]))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::ServicesNotConfigured));
        if !services_record.services.contains(&SERVICE_QUOTES) {
            panic_with_error!(&env, ErrorCode::ServicesNotConfigured);
        }
        let now = env.ledger().timestamp();
        Self::store_span(
            &env, &request_id,
            String::from_str(&env, "submit_quote"),
            anchor, now,
            String::from_str(&env, "success"),
        );

        // Propagate operation name into RequestContext
        Self::record_operation_in_context(&env, &request_id.id, String::from_str(&env, "submit_quote"));
    }

    // -----------------------------------------------------------------------
    // Tracing span retrieval
    // -----------------------------------------------------------------------

    pub fn get_tracing_span(env: Env, request_id_bytes: Bytes) -> Option<TracingSpan> {
        env.storage()
            .temporary()
            .get::<_, TracingSpan>(&(symbol_short!("SPAN"), request_id_bytes))
    }

    /// Create a child span under a parent span, setting parent_request_id and
    /// incrementing the span_index from the TracingContext stored for the root.
    ///
    /// The TracingContext for the root must have been initialised by a prior
    /// `submit_with_request_id` call (which stores span_index = 0).
    pub fn propagate_span(
        env: Env,
        parent_request_id: RequestId,
        child_request_id: RequestId,
        operation: String,
        actor: Address,
    ) {
        actor.require_auth();
        let now = env.ledger().timestamp();

        // Load or create the TracingContext for this root trace
        let ctx_key = (symbol_short!("TRACECTX"), parent_request_id.id.clone());
        let mut ctx: TracingContext = env
            .storage()
            .temporary()
            .get(&ctx_key)
            .unwrap_or(TracingContext {
                root_request_id_bytes: parent_request_id.id.clone(),
                next_span_index: 1,
            });

        let span_index = ctx.next_span_index;
        ctx.next_span_index += 1;
        env.storage().temporary().set(&ctx_key, &ctx);
        env.storage().temporary().extend_ttl(&ctx_key, SPAN_TTL, SPAN_TTL);

        // Register child span ID under the root so get_trace can find it
        let child_list_key = (symbol_short!("TRACEIDS"), parent_request_id.id.clone(), span_index);
        env.storage().temporary().set(&child_list_key, &child_request_id.id.clone());
        env.storage().temporary().extend_ttl(&child_list_key, SPAN_TTL, SPAN_TTL);

        Self::store_span_with_parent(
            &env,
            &child_request_id,
            operation,
            actor,
            now,
            String::from_str(&env, "success"),
            parent_request_id.id.clone(),
            span_index,
        );
    }

    /// Retrieve all spans associated with a root request ID, ordered by span_index.
    /// Returns the root span first, followed by child spans in creation order.
    pub fn get_trace(env: Env, root_request_id_bytes: Bytes) -> Vec<TracingSpan> {
        let mut spans = Vec::new(&env);

        // Root span (span_index = 0)
        if let Some(root_span) = env
            .storage()
            .temporary()
            .get::<_, TracingSpan>(&(symbol_short!("SPAN"), root_request_id_bytes.clone()))
        {
            spans.push_back(root_span);
        }

        // Child spans registered via propagate_span
        let ctx_key = (symbol_short!("TRACECTX"), root_request_id_bytes.clone());
        let ctx: Option<TracingContext> = env.storage().temporary().get(&ctx_key);
        if let Some(ctx) = ctx {
            for i in 1..ctx.next_span_index {
                let child_list_key = (symbol_short!("TRACEIDS"), root_request_id_bytes.clone(), i);
                if let Some(child_id) = env
                    .storage()
                    .temporary()
                    .get::<_, Bytes>(&child_list_key)
                {
                    if let Some(child_span) = env
                        .storage()
                        .temporary()
                        .get::<_, TracingSpan>(&(symbol_short!("SPAN"), child_id))
                    {
                        spans.push_back(child_span);
                    }
                }
            }
        }

        spans
    }

    // -----------------------------------------------------------------------
    // RequestContext — propagation and querying
    // -----------------------------------------------------------------------

    /// Create a new `RequestContext` for a root request ID.
    ///
    /// Stores the context in temporary storage keyed by the root request ID bytes
    /// and returns it. The `operation_chain` starts empty; call
    /// `append_operation` to record each sub-operation.
    pub fn create_request_context(env: Env, root_request_id: RequestId) -> RequestContext {
        let now = env.ledger().timestamp();
        let ctx = RequestContext {
            root_request_id: root_request_id.clone(),
            operation_chain: Vec::new(&env),
            created_at: now,
        };
        let key = (symbol_short!("REQCTX"), root_request_id.id.clone());
        env.storage().temporary().set(&key, &ctx);
        env.storage()
            .temporary()
            .extend_ttl(&key, SPAN_TTL, SPAN_TTL);
        ctx
    }

    /// Append `operation_name` to the `operation_chain` of the context identified
    /// by `root_request_id_bytes`. Creates the context if it does not yet exist.
    pub fn append_operation(
        env: Env,
        root_request_id_bytes: Bytes,
        operation_name: String,
    ) {
        let key = (symbol_short!("REQCTX"), root_request_id_bytes.clone());
        let mut ctx: RequestContext = env
            .storage()
            .temporary()
            .get(&key)
            .unwrap_or_else(|| {
                // Auto-create a minimal context if none exists yet
                let now = env.ledger().timestamp();
                RequestContext {
                    root_request_id: RequestId {
                        id: root_request_id_bytes.clone(),
                        created_at: now,
                    },
                    operation_chain: Vec::new(&env),
                    created_at: now,
                }
            });
        ctx.operation_chain.push_back(operation_name);
        env.storage().temporary().set(&key, &ctx);
        env.storage()
            .temporary()
            .extend_ttl(&key, SPAN_TTL, SPAN_TTL);
    }

    /// Return the full `RequestContext` (including `operation_chain`) for a
    /// given root request ID, or `None` if no context has been stored.
    pub fn get_request_context(env: Env, root_request_id_bytes: Bytes) -> Option<RequestContext> {
        env.storage()
            .temporary()
            .get::<_, RequestContext>(&(symbol_short!("REQCTX"), root_request_id_bytes))
    }

    // -----------------------------------------------------------------------
    // Attestation retrieval
    // -----------------------------------------------------------------------

    pub fn get_attestation(env: Env, id: u64) -> Attestation {
        env.storage()
            .persistent()
            .get::<_, Attestation>(&make_storage_key(&env, &[b"ATTEST", &id.to_be_bytes()]))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::AttestationNotFound))
    }

    pub fn get_attestation_by_hash(env: Env, issuer: Address, payload_hash: Bytes) -> u64 {
        let issuer_xdr = issuer.clone().to_xdr(&env);
        let issuer_raw = xdr_to_vec(&issuer_xdr);
        let hash_raw = xdr_to_vec(&payload_hash);
        let used_key = make_storage_key(&env, &[b"USED", &issuer_raw, &hash_raw]);
        env.storage()
            .persistent()
            .get::<_, u64>(&used_key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::AttestationNotFound))
    }

    // -----------------------------------------------------------------------
    // Deterministic hash utilities (#192)
    // -----------------------------------------------------------------------

    /// Compute a canonical SHA-256 hash for an attestation payload.
    /// Field order: subject || timestamp (8-byte BE) || data.
    pub fn compute_payload_hash(
        env: Env,
        subject: Address,
        timestamp: u64,
        data: Bytes,
    ) -> BytesN<32> {
        compute_payload_hash(&env, &subject, timestamp, &data)
    }

    /// Verify that the hash stored in an attestation matches the expected hash.
    pub fn verify_payload_hash(env: Env, attestation_id: u64, expected_hash: BytesN<32>) -> bool {
        let attestation = env
            .storage()
            .persistent()
            .get::<_, Attestation>(&make_storage_key(&env, &[b"ATTEST", &attestation_id.to_be_bytes()]))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::AttestationNotFound));

        let stored: BytesN<32> = attestation.payload_hash.try_into()
            .unwrap_or_else(|_| panic_with_error!(&env, ErrorCode::ValidationError));
        verify_payload_hash(&stored, &expected_hash)
    }

    // -----------------------------------------------------------------------
    // Session management
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // KYC data management
    // -----------------------------------------------------------------------

    pub fn submit_kyc(env: Env, subject: Address, data_hash: Bytes, attestor: Address) {
        attestor.require_auth();
        Self::check_attestor(&env, &attestor);
        let now = env.ledger().timestamp();
        let key = kyc_record_key(&env, &subject);
        if env.storage().persistent().has(&key) {
            panic_with_error!(&env, ErrorCode::ComplianceNotMet);
        }
        let record = KycRecord {
            subject: subject.clone(), status: KycStatus::Pending as u32,
            submitted_at: now, reviewed_at: None, expiry: None,
            rejection_reason_hash: None,
        };
        env.storage().persistent().set(&key, &record);
        env.storage().persistent().extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);
        let data_key = make_storage_key(&env, &[b"KYCDATA", &xdr_to_vec(&subject.clone().to_xdr(&env))]);
        env.storage().persistent().set(&data_key, &data_hash);
        env.storage().persistent().extend_ttl(&data_key, PERSISTENT_TTL, PERSISTENT_TTL);
        env.events().publish(
            (symbol_short!("kyc"), symbol_short!("submitted"), subject),
            WebhookEvent {
                event_type: String::from_str(&env, "kyc_submitted"),
                transaction_id: 0, timestamp: now, payload_hash: data_hash,
            },
        );
    }

    pub fn approve_kyc(env: Env, subject: Address) {
        Self::require_admin(&env);
        let now = env.ledger().timestamp();
        let key = kyc_record_key(&env, &subject);
        let mut record: KycRecord = env.storage().persistent().get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::KycNotFound));
        if record.status != KycStatus::Pending as u32 {
            panic_with_error!(&env, ErrorCode::IllegalTransition);
        }
        record.status = KycStatus::Approved as u32;
        record.reviewed_at = Some(now);
        env.storage().persistent().set(&key, &record);
        env.storage().persistent().extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);
        env.events().publish(
            (symbol_short!("kyc"), symbol_short!("approved"), subject),
            WebhookEvent {
                event_type: String::from_str(&env, "kyc_approved"),
                transaction_id: 0, timestamp: now, payload_hash: Bytes::new(&env),
            },
        );
    }

    pub fn reject_kyc(env: Env, subject: Address, reason_hash: Bytes) {
        Self::require_admin(&env);
        let now = env.ledger().timestamp();
        let key = kyc_record_key(&env, &subject);
        let mut record: KycRecord = env.storage().persistent().get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::KycNotFound));
        if record.status != KycStatus::Pending as u32 {
            panic_with_error!(&env, ErrorCode::IllegalTransition);
        }
        record.status = KycStatus::Rejected as u32;
        record.reviewed_at = Some(now);
        record.rejection_reason_hash = Some(reason_hash.clone());
        env.storage().persistent().set(&key, &record);
        env.storage().persistent().extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);
        env.events().publish(
            (symbol_short!("kyc"), symbol_short!("rejected"), subject),
            WebhookEvent {
                event_type: String::from_str(&env, "kyc_rejected"),
                transaction_id: 0, timestamp: now, payload_hash: reason_hash,
            },
        );
    }

    pub fn get_kyc_status(env: Env, subject: Address) -> KycStatus {
        let key = kyc_record_key(&env, &subject);
        if !env.storage().persistent().has(&key) {
            return KycStatus::NotSubmitted;
        }
        let record: KycRecord = env.storage().persistent().get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::KycNotFound));
        if let Some(expiry) = record.expiry {
            if env.ledger().timestamp() > expiry {
                return KycStatus::Expired;
            }
        }
        match record.status {
            0 => KycStatus::NotSubmitted,
            1 => KycStatus::Pending,
            2 => KycStatus::Approved,
            3 => KycStatus::Rejected,
            4 => KycStatus::Expired,
            _ => KycStatus::NotSubmitted,
        }
    }

    // -----------------------------------------------------------------------
    // Compliance check recording (#37)
    // -----------------------------------------------------------------------

    /// Record a compliance check result for a subject (admin-only).
    /// Stores a `ComplianceCheck` record and emits a `compliance_checked` event.
    pub fn record_compliance_check(
        env: Env,
        subject: Address,
        check_type: String,
        passed: bool,
    ) {
        Self::require_admin(&env);
        let now = env.ledger().timestamp();
        let record = ComplianceCheck {
            subject: subject.clone(),
            check_type: check_type.clone(),
            result: if passed { 1u32 } else { 0u32 },
            timestamp: now,
        };
        let key = compliance_check_key(&env, &subject, &check_type);
        env.storage().persistent().set(&key, &record);
        env.storage().persistent().extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);
        env.events().publish(
            (symbol_short!("comp"), symbol_short!("checked"), subject),
            record,
        );
    }

    pub fn create_session(env: Env, initiator: Address) -> u64 {
        initiator.require_auth();
        let inst = env.storage().instance();
        let scnt_key = make_storage_key(&env, &[b"SCNT"]);
        let session_id: u64 = inst.get(&scnt_key).unwrap_or(0u64);
        inst.set(&scnt_key, &(session_id + 1));
        inst.extend_ttl(INSTANCE_TTL, INSTANCE_TTL);

        let now = env.ledger().timestamp();
        let session = Session {
            session_id,
            initiator: initiator.clone(),
            created_at: now,
            nonce: 0,
            operation_count: 0,
            session_ttl_seconds: DEFAULT_SESSION_TTL,
            closed: false,
        };
        let sess_key = make_storage_key(&env, &[b"SESS", &session_id.to_be_bytes()]);
        env.storage().persistent().set(&sess_key, &session);
        env.storage().persistent().extend_ttl(&sess_key, PERSISTENT_TTL, PERSISTENT_TTL);

        let snonce_key = make_storage_key(&env, &[b"SNONCE", &session_id.to_be_bytes()]);
        env.storage().persistent().set(&snonce_key, &0u64);
        env.storage().persistent().extend_ttl(&snonce_key, PERSISTENT_TTL, PERSISTENT_TTL);

        env.events().publish(
            (symbol_short!("session"), symbol_short!("created"), session_id),
            SessionCreatedEvent { session_id, initiator, timestamp: now },
        );
        session_id
    }

    pub fn close_session(env: Env, session_id: u64, initiator: Address) {
        initiator.require_auth();
        let sess_key = make_storage_key(&env, &[b"SESS", &session_id.to_be_bytes()]);
        let mut session: Session = env
            .storage()
            .persistent()
            .get(&sess_key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::AttestationNotFound));
        Self::validate_session(&env, &session);
        session.closed = true;
        env.storage().persistent().set(&sess_key, &session);
        let now = env.ledger().timestamp();
        env.events().publish(
            (symbol_short!("session"), symbol_short!("closed"), session_id),
            SessionClosedEvent { session_id, initiator, timestamp: now },
        );
    }

    fn require_session_open(env: &Env, session_id: u64) {
        let sess_key = make_storage_key(env, &[b"SESS", &session_id.to_be_bytes()]);
        let session: Session = env
            .storage()
            .persistent()
            .get(&sess_key)
            .unwrap_or_else(|| panic_with_error!(env, ErrorCode::AttestationNotFound));
        Self::validate_session(env, &session);
        // #232: enforce per-session operation limit
        let op_count: u64 = env
            .storage()
            .persistent()
            .get(&make_storage_key(env, &[b"SOPCNT", &session_id.to_be_bytes()]))
            .unwrap_or(0u64);
        if op_count >= MAX_OPS_PER_SESSION {
            panic_with_error!(env, ErrorCode::SessionOperationLimitExceeded);
        }
    }

    // -----------------------------------------------------------------------
    // Quote management
    // -----------------------------------------------------------------------

    pub fn submit_quote(
        env: Env,
        anchor: Address,
        base_asset: String,
        quote_asset: String,
        rate: u64,
        fee_percentage: u32,
        minimum_amount: u64,
        maximum_amount: u64,
        valid_until: u64,
    ) -> u64 {
        anchor.require_auth();
        if fee_percentage > 10_000 {
            panic_with_error!(&env, ErrorCode::InvalidQuote);
        }
        let inst = env.storage().instance();
        let qcnt_key = make_storage_key(&env, &[b"QCNT"]);
        let next: u64 = inst.get(&qcnt_key).unwrap_or(0u64) + 1;
        inst.set(&qcnt_key, &next);
        inst.extend_ttl(INSTANCE_TTL, INSTANCE_TTL);

        let anchor_xdr = anchor.clone().to_xdr(&env);
        let anchor_raw = xdr_to_vec(&anchor_xdr);
        let quote = Quote {
            quote_id: next, anchor: anchor.clone(),
            base_asset: base_asset.clone(), quote_asset: quote_asset.clone(),
            rate, fee_percentage, minimum_amount, maximum_amount, valid_until,
        };
        let q_key = make_storage_key(&env, &[b"QUOTE", &anchor_raw, &next.to_be_bytes()]);
        env.storage().persistent().set(&q_key, &quote);
        env.storage().persistent().extend_ttl(&q_key, PERSISTENT_TTL, PERSISTENT_TTL);

        let lq_key = make_storage_key(&env, &[b"LATESTQ", &anchor_raw]);
        env.storage().persistent().set(&lq_key, &next);
        env.storage().persistent().extend_ttl(&lq_key, PERSISTENT_TTL, PERSISTENT_TTL);

        env.events().publish(
            (symbol_short!("quote"), symbol_short!("submit"), next),
            QuoteSubmitEvent { quote_id: next, anchor, base_asset, quote_asset, rate, valid_until },
        );
        next
    }

    pub fn receive_quote(env: Env, receiver: Address, anchor: Address, quote_id: u64) -> Quote {
        receiver.require_auth();
        let anchor_xdr = anchor.clone().to_xdr(&env);
        let anchor_raw = xdr_to_vec(&anchor_xdr);
        let q_key = make_storage_key(&env, &[b"QUOTE", &anchor_raw, &quote_id.to_be_bytes()]);
        let quote: Quote = env.storage().persistent().get(&q_key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::AttestationNotFound));
        env.events().publish(
            (symbol_short!("quote"), symbol_short!("received"), quote_id),
            QuoteReceivedEvent { quote_id, receiver, timestamp: env.ledger().timestamp() },
        );
        quote
    }

    // -----------------------------------------------------------------------
    // Session-aware attestation
    // -----------------------------------------------------------------------

    pub fn submit_attestation_with_session(
        env: Env,
        session_id: u64,
        issuer: Address,
        subject: Address,
        timestamp: u64,
        payload_hash: Bytes,
        signature: Bytes,
    ) -> u64 {
        issuer.require_auth();
        Self::require_session_open(&env, session_id);
        Self::check_attestor(&env, &issuer);
        Self::verify_attestation_signature(&env, &issuer, &payload_hash, &signature);
        Self::enforce_rate_limit(&env, &issuer);
        Self::check_timestamp(&env, timestamp);

        // #232: per-session request-ID replay protection
        let hash_raw = xdr_to_vec(&payload_hash);
        let sess_req_key = make_storage_key(
            &env, &[b"SESSREQ", &session_id.to_be_bytes(), &hash_raw],
        );
        if env.storage().persistent().has(&sess_req_key) {
            panic_with_error!(&env, ErrorCode::ReplayAttack);
        }
        env.storage().persistent().set(&sess_req_key, &true);
        env.storage().persistent().extend_ttl(&sess_req_key, REPLAY_TTL, REPLAY_TTL);

        let issuer_xdr = issuer.clone().to_xdr(&env);
        let issuer_raw = xdr_to_vec(&issuer_xdr);
        let used_key = make_storage_key(&env, &[b"USED", &issuer_raw, &hash_raw]);
        if env.storage().persistent().has(&used_key) {
            panic_with_error!(&env, ErrorCode::ReplayAttack);
        }

        let id = Self::next_attestation_id(&env);
        Self::store_attestation(
            &env, id, issuer.clone(), subject.clone(), timestamp,
            payload_hash.clone(), signature,
        );

        env.storage().persistent().set(&used_key, &timestamp);
        env.storage().persistent().extend_ttl(&used_key, REPLAY_TTL, REPLAY_TTL);

        // Increment session nonce
        let sess_key = make_storage_key(&env, &[b"SESS", &session_id.to_be_bytes()]);
        let mut session: Session = env
            .storage().persistent().get(&sess_key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::AttestationNotFound));
        session.nonce += 1;
        env.storage().persistent().set(&sess_key, &session);
        env.storage().persistent().extend_ttl(&sess_key, PERSISTENT_TTL, PERSISTENT_TTL);

        let sopcnt_key = make_storage_key(&env, &[b"SOPCNT", &session_id.to_be_bytes()]);
        let op_index: u64 = env.storage().persistent().get(&sopcnt_key).unwrap_or(0u64);
        env.storage().persistent().set(&sopcnt_key, &(op_index + 1));
        env.storage().persistent().extend_ttl(&sopcnt_key, PERSISTENT_TTL, PERSISTENT_TTL);

        let inst = env.storage().instance();
        let acnt_key = make_storage_key(&env, &[b"ACNT"]);
        let log_id: u64 = inst.get(&acnt_key).unwrap_or(0u64);
        inst.set(&acnt_key, &(log_id + 1));
        inst.extend_ttl(INSTANCE_TTL, INSTANCE_TTL);

        let now = env.ledger().timestamp();
        let audit = AuditLog {
            log_id, session_id, actor: issuer.clone(),
            operation: OperationContext {
                session_id, operation_index: op_index,
                operation_type: String::from_str(&env, "attest"),
                timestamp: now, status: String::from_str(&env, "success"),
                result_data: id,
            },
        };
        let audit_key = make_storage_key(&env, &[b"AUDIT", &log_id.to_be_bytes()]);
        env.storage().persistent().set(&audit_key, &audit);
        env.storage().persistent().extend_ttl(&audit_key, PERSISTENT_TTL, PERSISTENT_TTL);
        let slog_key = make_storage_key(&env, &[b"SLOG", &session_id.to_be_bytes(), &op_index.to_be_bytes()]);
        env.storage().persistent().set(&slog_key, &log_id);
        env.storage().persistent().extend_ttl(&slog_key, PERSISTENT_TTL, PERSISTENT_TTL);

        env.events().publish(
            (symbol_short!("attest"), symbol_short!("recorded"), id, subject),
            AttestEvent { payload_hash, timestamp },
        );
        env.events().publish(
            (symbol_short!("audit"), symbol_short!("logged"), log_id),
            AuditLogEvent {
                log_id, session_id, operation_index: op_index,
                operation_type: String::from_str(&env, "attest"),
                status: String::from_str(&env, "success"),
            },
        );
        id
    }

    pub fn register_attestor_with_session(env: Env, session_id: u64, attestor: Address, public_key: BytesN<32>) {
        Self::require_admin(&env);
        Self::require_session_open(&env, session_id);
        let xdr = attestor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let key = make_storage_key(&env, &[b"ATTESTOR", &raw]);
        if env.storage().persistent().has(&key) {
            panic_with_error!(&env, ErrorCode::AttestorAlreadyRegistered);
        }
        env.storage().persistent().set(&key, &true);
        env.storage().persistent().extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);
        let pk_key = make_storage_key(&env, &[b"ATPUBKEY", &raw]);
        env.storage().persistent().set(&pk_key, &public_key);
        env.storage().persistent().extend_ttl(&pk_key, PERSISTENT_TTL, PERSISTENT_TTL);

        let sopcnt_key = make_storage_key(&env, &[b"SOPCNT", &session_id.to_be_bytes()]);
        let op_index: u64 = env.storage().persistent().get(&sopcnt_key).unwrap_or(0u64);
        env.storage().persistent().set(&sopcnt_key, &(op_index + 1));
        env.storage().persistent().extend_ttl(&sopcnt_key, PERSISTENT_TTL, PERSISTENT_TTL);

        let inst = env.storage().instance();
        let acnt_key = make_storage_key(&env, &[b"ACNT"]);
        let log_id: u64 = inst.get(&acnt_key).unwrap_or(0u64);
        inst.set(&acnt_key, &(log_id + 1));
        inst.extend_ttl(INSTANCE_TTL, INSTANCE_TTL);

        let admin: Address = inst
            .get::<_, Address>(&admin_key(&env))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::NotInitialized));
        let now = env.ledger().timestamp();
        let audit = AuditLog {
            log_id, session_id, actor: admin,
            operation: OperationContext {
                session_id, operation_index: op_index,
                operation_type: String::from_str(&env, "register"),
                timestamp: now, status: String::from_str(&env, "success"),
                result_data: 0,
            },
        };
        let audit_key = make_storage_key(&env, &[b"AUDIT", &log_id.to_be_bytes()]);
        env.storage().persistent().set(&audit_key, &audit);
        env.storage().persistent().extend_ttl(&audit_key, PERSISTENT_TTL, PERSISTENT_TTL);
        let slog_key = make_storage_key(&env, &[b"SLOG", &session_id.to_be_bytes(), &op_index.to_be_bytes()]);
        env.storage().persistent().set(&slog_key, &log_id);
        env.storage().persistent().extend_ttl(&slog_key, PERSISTENT_TTL, PERSISTENT_TTL);

        env.events().publish((symbol_short!("attestor"), symbol_short!("added"), attestor), ());
        env.events().publish(
            (symbol_short!("audit"), symbol_short!("logged"), log_id),
            AuditLogEvent {
                log_id, session_id, operation_index: op_index,
                operation_type: String::from_str(&env, "register"),
                status: String::from_str(&env, "success"),
            },
        );
    }

    pub fn revoke_attestor_with_session(env: Env, session_id: u64, attestor: Address) {
        Self::require_admin(&env);
        Self::require_session_open(&env, session_id);
        let xdr = attestor.clone().to_xdr(&env);
        let raw = xdr_to_vec(&xdr);
        let key = make_storage_key(&env, &[b"ATTESTOR", &raw]);
        if !env.storage().persistent().has(&key) {
            panic_with_error!(&env, ErrorCode::AttestorNotRegistered);
        }
        env.storage().persistent().remove(&key);
        let pk_key = make_storage_key(&env, &[b"ATPUBKEY", &raw]);
        env.storage().persistent().remove(&pk_key);

        let sopcnt_key = make_storage_key(&env, &[b"SOPCNT", &session_id.to_be_bytes()]);
        let op_index: u64 = env.storage().persistent().get(&sopcnt_key).unwrap_or(0u64);
        env.storage().persistent().set(&sopcnt_key, &(op_index + 1));
        env.storage().persistent().extend_ttl(&sopcnt_key, PERSISTENT_TTL, PERSISTENT_TTL);

        let inst = env.storage().instance();
        let acnt_key = make_storage_key(&env, &[b"ACNT"]);
        let log_id: u64 = inst.get(&acnt_key).unwrap_or(0u64);
        inst.set(&acnt_key, &(log_id + 1));
        inst.extend_ttl(INSTANCE_TTL, INSTANCE_TTL);

        let admin: Address = inst
            .get::<_, Address>(&admin_key(&env))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::NotInitialized));
        let now = env.ledger().timestamp();
        let audit = AuditLog {
            log_id, session_id, actor: admin,
            operation: OperationContext {
                session_id, operation_index: op_index,
                operation_type: String::from_str(&env, "revoke"),
                timestamp: now, status: String::from_str(&env, "success"),
                result_data: 0,
            },
        };
        let audit_key = make_storage_key(&env, &[b"AUDIT", &log_id.to_be_bytes()]);
        env.storage().persistent().set(&audit_key, &audit);
        env.storage().persistent().extend_ttl(&audit_key, PERSISTENT_TTL, PERSISTENT_TTL);
        let slog_key = make_storage_key(&env, &[b"SLOG", &session_id.to_be_bytes(), &op_index.to_be_bytes()]);
        env.storage().persistent().set(&slog_key, &log_id);
        env.storage().persistent().extend_ttl(&slog_key, PERSISTENT_TTL, PERSISTENT_TTL);

        env.events().publish((symbol_short!("attestor"), symbol_short!("removed"), attestor), ());
        env.events().publish(
            (symbol_short!("audit"), symbol_short!("logged"), log_id),
            AuditLogEvent {
                log_id, session_id, operation_index: op_index,
                operation_type: String::from_str(&env, "revoke"),
                status: String::from_str(&env, "success"),
            },
        );
    }

    pub fn get_session(env: Env, session_id: u64) -> Session {
        env.storage()
            .persistent()
            .get::<_, Session>(&make_storage_key(&env, &[b"SESS", &session_id.to_be_bytes()]))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::AttestationNotFound))
    }

    pub fn get_audit_log(env: Env, log_id: u64) -> AuditLog {
        env.storage()
            .persistent()
            .get::<_, AuditLog>(&make_storage_key(&env, &[b"AUDIT", &log_id.to_be_bytes()]))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::AttestationNotFound))
    }

    pub fn get_session_audit_logs(env: Env, session_id: u64, limit: u64) -> Vec<AuditLog> {
        let total: u64 = env
            .storage()
            .persistent()
            .get(&make_storage_key(&env, &[b"SOPCNT", &session_id.to_be_bytes()]))
            .unwrap_or(0u64);
        let mut results = Vec::new(&env);
        let start = if total > limit { total - limit } else { 0 };
        for i in start..total {
            let slog_key = make_storage_key(&env, &[b"SLOG", &session_id.to_be_bytes(), &i.to_be_bytes()]);
            if let Some(log_id) = env.storage().persistent().get::<_, u64>(&slog_key) {
                let audit_key = make_storage_key(&env, &[b"AUDIT", &log_id.to_be_bytes()]);
                if let Some(entry) = env.storage().persistent().get::<_, AuditLog>(&audit_key) {
                    results.push_back(entry);
                }
            }
        }
        results
    }

    pub fn get_session_operation_count(env: Env, session_id: u64) -> u64 {
        env.storage()
            .persistent()
            .get::<_, u64>(&make_storage_key(&env, &[b"SOPCNT", &session_id.to_be_bytes()]))
            .unwrap_or(0)
    }

    // -----------------------------------------------------------------------
    // Metadata cache
    // -----------------------------------------------------------------------

    pub fn cache_metadata(env: Env, anchor: Address, metadata: AnchorMetadata, ttl_seconds: u64) {
        Self::require_admin(&env);
        let now = env.ledger().timestamp();
        let entry = MetadataCache {
            metadata,
            cached_at: now,
            ttl_seconds,
            stale_ttl_seconds: 0,
            needs_refresh: false,
        };
        let key = (symbol_short!("METACACHE"), anchor);
        let ledger_ttl = if ttl_seconds as u32 > MIN_TEMP_TTL { ttl_seconds as u32 } else { MIN_TEMP_TTL };
        env.storage().temporary().set(&key, &entry);
        env.storage().temporary().extend_ttl(&key, ledger_ttl, ledger_ttl);
    }

    pub fn get_cached_metadata(env: Env, anchor: Address) -> AnchorMetadata {
        let key = (symbol_short!("METACACHE"), anchor);
        let entry: MetadataCache = env.storage().temporary().get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::CacheNotFound));
        let now = env.ledger().timestamp();
        if entry.cached_at + entry.ttl_seconds <= now {
            panic_with_error!(&env, ErrorCode::CacheExpired);
        }
        entry.metadata
    }

    pub fn refresh_metadata_cache(env: Env, anchor: Address) {
        Self::require_admin(&env);
        let key = (symbol_short!("METACACHE"), anchor);
        env.storage().temporary().remove(&key);
    }

    /// Store a metadata entry with a stale-while-revalidate grace period.
    /// After `ttl_seconds` the entry becomes stale; after `ttl_seconds + stale_ttl_seconds`
    /// it is fully expired and `get_cached_metadata_swr` will return an error.
    pub fn cache_metadata_swr(
        env: Env,
        anchor: Address,
        metadata: AnchorMetadata,
        ttl_seconds: u64,
        stale_ttl_seconds: u64,
    ) {
        Self::require_admin(&env);
        let now = env.ledger().timestamp();
        let entry = MetadataCache {
            metadata,
            cached_at: now,
            ttl_seconds,
            stale_ttl_seconds,
            needs_refresh: false,
        };
        let key = (symbol_short!("METACACHE"), anchor);
        let total_ttl = ttl_seconds.saturating_add(stale_ttl_seconds);
        let ledger_ttl = if total_ttl as u32 > MIN_TEMP_TTL { total_ttl as u32 } else { MIN_TEMP_TTL };
        env.storage().temporary().set(&key, &entry);
        env.storage().temporary().extend_ttl(&key, ledger_ttl, ledger_ttl);
    }

    /// Retrieve a metadata entry using the stale-while-revalidate policy.
    ///
    /// Returns `(metadata, needs_refresh)`:
    /// - `needs_refresh = false` → entry is fresh (within primary TTL)
    /// - `needs_refresh = true`  → entry is stale (within grace period); caller should refresh
    ///
    /// Panics with `CacheExpired` once both TTLs have elapsed, or `CacheNotFound` if absent.
    pub fn get_cached_metadata_swr(env: Env, anchor: Address) -> (AnchorMetadata, bool) {
        let key = (symbol_short!("METACACHE"), anchor.clone());
        let mut entry: MetadataCache = env.storage().temporary().get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::CacheNotFound));
        let now = env.ledger().timestamp();
        let age = now.saturating_sub(entry.cached_at);

        if age <= entry.ttl_seconds {
            // Fresh
            (entry.metadata, false)
        } else if age <= entry.ttl_seconds.saturating_add(entry.stale_ttl_seconds) {
            // Stale — mark needs_refresh and persist the flag
            entry.needs_refresh = true;
            env.storage().temporary().set(&key, &entry);
            (entry.metadata, true)
        } else {
            panic_with_error!(&env, ErrorCode::CacheExpired);
        }
    }

    /// Unconditionally replace the cached metadata entry, resetting both TTL clocks.
    pub fn force_refresh_metadata(
        env: Env,
        anchor: Address,
        metadata: AnchorMetadata,
        ttl_seconds: u64,
        stale_ttl_seconds: u64,
    ) {
        Self::require_admin(&env);
        let now = env.ledger().timestamp();
        let entry = MetadataCache {
            metadata,
            cached_at: now,
            ttl_seconds,
            stale_ttl_seconds,
            needs_refresh: false,
        };
        let key = (symbol_short!("METACACHE"), anchor);
        let total_ttl = ttl_seconds.saturating_add(stale_ttl_seconds);
        let ledger_ttl = if total_ttl as u32 > MIN_TEMP_TTL { total_ttl as u32 } else { MIN_TEMP_TTL };
        env.storage().temporary().set(&key, &entry);
        env.storage().temporary().extend_ttl(&key, ledger_ttl, ledger_ttl);
    }

    // -----------------------------------------------------------------------
    // Capabilities cache
    // -----------------------------------------------------------------------

    pub fn cache_capabilities(env: Env, anchor: Address, toml_url: String, capabilities: String, ttl_seconds: u64) {
        Self::require_admin(&env);
        let now = env.ledger().timestamp();
        let entry = CapabilitiesCache { toml_url, capabilities, cached_at: now, ttl_seconds };
        let key = (symbol_short!("CAPCACHE"), anchor);
        let ledger_ttl = if ttl_seconds as u32 > MIN_TEMP_TTL { ttl_seconds as u32 } else { MIN_TEMP_TTL };
        env.storage().temporary().set(&key, &entry);
        env.storage().temporary().extend_ttl(&key, ledger_ttl, ledger_ttl);
    }

    pub fn get_cached_capabilities(env: Env, anchor: Address) -> CapabilitiesCache {
        let key = (symbol_short!("CAPCACHE"), anchor);
        let entry: CapabilitiesCache = env.storage().temporary().get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::CacheNotFound));
        let now = env.ledger().timestamp();
        if entry.cached_at + entry.ttl_seconds <= now {
            panic_with_error!(&env, ErrorCode::CacheExpired);
        }
        entry
    }

    pub fn refresh_capabilities_cache(env: Env, anchor: Address) {
        Self::require_admin(&env);
        let key = (symbol_short!("CAPCACHE"), anchor);
        env.storage().temporary().remove(&key);
    }

    // -----------------------------------------------------------------------
    // Routing
    // -----------------------------------------------------------------------

    pub fn get_quote(env: Env, anchor: Address, quote_id: u64) -> Quote {
        let anchor_xdr = anchor.clone().to_xdr(&env);
        let anchor_raw = xdr_to_vec(&anchor_xdr);
        let key = make_storage_key(&env, &[b"QUOTE", &anchor_raw, &quote_id.to_be_bytes()]);
        env.storage().persistent().get::<_, Quote>(&key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::NoQuotesAvailable))
    }

    pub fn set_anchor_metadata(
        env: Env,
        anchor: Address,
        reputation_score: u32,
        average_settlement_time: u64,
        liquidity_score: u32,
        uptime_percentage: u32,
        total_volume: u64,
    ) {
        Self::require_admin(&env);
        let meta = RoutingAnchorMeta {
            anchor: anchor.clone(),
            reputation_score,
            average_settlement_time,
            liquidity_score,
            uptime_percentage,
            total_volume,
            is_active: true,
        };
        let meta_key = anchor_meta_key(&env, &anchor);
        env.storage().persistent().set(&meta_key, &meta);
        env.storage().persistent().extend_ttl(&meta_key, PERSISTENT_TTL, PERSISTENT_TTL);

        // Maintain ANCHLIST — stored under a deterministic key (#229)
        let list_key = make_storage_key(&env, &[b"ANCHLIST"]);
        let mut list: Vec<Address> = env.storage().persistent()
            .get::<_, Vec<Address>>(&list_key)
            .unwrap_or_else(|| Vec::new(&env));
        if !list.contains(&anchor) {
            list.push_back(anchor);
            env.storage().persistent().set(&list_key, &list);
            env.storage().persistent().extend_ttl(&list_key, PERSISTENT_TTL, PERSISTENT_TTL);
        }
    }

    /// Reactivate a previously deactivated anchor (admin-only). Sets `is_active = true`.
    pub fn reactivate_anchor(env: Env, anchor: Address) {
        Self::require_admin(&env);
        let meta_key = anchor_meta_key(&env, &anchor);
        let mut meta: RoutingAnchorMeta = env
            .storage()
            .persistent()
            .get(&meta_key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::AttestorNotRegistered));
        meta.is_active = true;
        env.storage().persistent().set(&meta_key, &meta);
        env.storage()
            .persistent()
            .extend_ttl(&meta_key, PERSISTENT_TTL, PERSISTENT_TTL);
    }

    /// Return the full `RoutingAnchorMeta` for an anchor.
    pub fn get_anchor_metadata(env: Env, anchor: Address) -> RoutingAnchorMeta {
        env.storage()
            .persistent()
            .get::<_, RoutingAnchorMeta>(&anchor_meta_key(&env, &anchor))
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::AttestorNotRegistered))
    }

    /// Return all anchors in ANCHLIST where `is_active == true`.
    pub fn list_active_anchors(env: Env) -> Vec<Address> {
        let list_key = make_storage_key(&env, &[b"ANCHLIST"]);
        let anchors: Vec<Address> = env
            .storage()
            .persistent()
            .get::<_, Vec<Address>>(&list_key)
            .unwrap_or_else(|| Vec::new(&env));
        let mut active = Vec::new(&env);
        for anchor in anchors.iter() {
            if let Some(meta) = env
                .storage()
                .persistent()
                .get::<_, RoutingAnchorMeta>(&anchor_meta_key(&env, &anchor))
            {
                if meta.is_active {
                    active.push_back(anchor);
                }
            }
        }
        active
    }

    pub fn route_transaction(env: Env, options: RoutingOptions) -> Quote {
        let now = env.ledger().timestamp();
        let list_key = make_storage_key(&env, &[b"ANCHLIST"]);
        let anchors: Vec<Address> = env.storage().persistent()
            .get::<_, Vec<Address>>(&list_key)
            .unwrap_or_else(|| Vec::new(&env));

        // Collect valid quotes from active anchors
        let mut candidates: Vec<Quote> = Vec::new(&env);
        for anchor in anchors.iter() {
            // Check reputation filter
            let meta: RoutingAnchorMeta = match env.storage().persistent().get(&anchor_meta_key(&env, &anchor)) {
                Some(m) => m,
                None => continue,
            };
            if !meta.is_active { continue; }
            if meta.reputation_score < options.min_reputation { continue; }

            // Get latest quote for this anchor
            let anchor_xdr = anchor.clone().to_xdr(&env);
            let anchor_raw = xdr_to_vec(&anchor_xdr);
            let lq_key = make_storage_key(&env, &[b"LATESTQ", &anchor_raw]);
            let quote_id: u64 = match env.storage().persistent().get(&lq_key) {
                Some(id) => id,
                None => continue,
            };
            let q_key = make_storage_key(&env, &[b"QUOTE", &anchor_raw, &quote_id.to_be_bytes()]);
            let quote: Quote = match env.storage().persistent().get(&q_key) {
                Some(q) => q,
                None => continue,
            };

            // Filter expired quotes
            if quote.valid_until <= now { continue; }

            // Filter by amount limits
            if options.request.amount < quote.minimum_amount
                || options.request.amount > quote.maximum_amount
            {
                continue;
            }

            candidates.push_back(quote);
        }

        if candidates.is_empty() {
            panic_with_error!(&env, ErrorCode::NoQuotesAvailable);
        }

        // Enforce compliance check (#38)
        if options.require_compliance {
            // Look for any passing compliance record for this subject
            // We check the generic "kyc" check_type as the standard compliance gate
            let comp_key = compliance_check_key(&env, &options.subject, &String::from_str(&env, "kyc"));
            let passed = env.storage().persistent()
                .get::<_, ComplianceCheck>(&comp_key)
                .map(|r| r.result == 1u32)
                .unwrap_or(false);
            if !passed {
                panic_with_error!(&env, ErrorCode::ComplianceNotMet);
            }
        }

        // Enforce KYC check (#439)
        if options.require_kyc {
            let kyc_status = Self::get_kyc_status(env.clone(), options.subject.clone());
            if kyc_status != KycStatus::Approved {
                match kyc_status {
                    KycStatus::Pending      => panic_with_error!(&env, ErrorCode::KycPending),
                    KycStatus::Rejected     => panic_with_error!(&env, ErrorCode::KycRejected),
                    KycStatus::Expired      => panic_with_error!(&env, ErrorCode::ComplianceNotMet),
                    KycStatus::NotSubmitted => panic_with_error!(&env, ErrorCode::KycNotFound),
                    _ => panic_with_error!(&env, ErrorCode::ComplianceNotMet),
                }
            }
        }

        // Apply strategy: pick best candidate
        let strategy_sym = options.strategy.get(0)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::NoQuotesAvailable));

        let lowest_fee_sym = Symbol::new(&env, "LowestFee");
        let fastest_sym = Symbol::new(&env, "FastestSettlement");
        let reputation_sym = Symbol::new(&env, "HighestReputation");

        let mut best: Quote = match candidates.get(0) {
            Some(q) => q,
            None => panic_with_error!(&env, ErrorCode::NoQuotesAvailable),
        };

        if strategy_sym == lowest_fee_sym {
            for q in candidates.iter() {
                if q.fee_percentage < best.fee_percentage {
                    best = q;
                }
            }
        } else if strategy_sym == fastest_sym {
            // Need settlement time from metadata
            let mut best_time: u64 = anchor_meta_opt(&env, &best.anchor)
                .map(|m| m.average_settlement_time)
                .unwrap_or(u64::MAX);
            for q in candidates.iter() {
                let t = anchor_meta_opt(&env, &q.anchor)
                    .map(|m| m.average_settlement_time)
                    .unwrap_or(u64::MAX);
                if t < best_time {
                    best_time = t;
                    best = q;
                }
            }
        } else if strategy_sym == reputation_sym {
            let mut best_rep: u32 = anchor_meta_opt(&env, &best.anchor)
                .map(|m| m.reputation_score)
                .unwrap_or(0);
            for q in candidates.iter() {
                let rep = anchor_meta_opt(&env, &q.anchor)
                    .map(|m| m.reputation_score)
                    .unwrap_or(0);
                if rep > best_rep {
                    best_rep = rep;
                    best = q;
                }
            }
        } else if strategy_sym == Symbol::new(&env, "WeightedScore") {
            // Issue #55: weighted score = reputation(40%) + liquidity(30%) + uptime(20%) - fee(10%)
            let weighted_score = |meta: &RoutingAnchorMeta, fee_pct: u32| -> u64 {
                let fee_factor = if fee_pct <= 100 { 100 - fee_pct } else { 0 };
                (meta.reputation_score as u64) * 40
                    + (meta.liquidity_score as u64) * 30
                    + (meta.uptime_percentage as u64) * 20
                    + (fee_factor as u64) * 10
            };
            let mut best_score: u64 = anchor_meta_opt(&env, &best.anchor)
                .map(|m| weighted_score(&m, best.fee_percentage))
                .unwrap_or(0);
            for q in candidates.iter() {
                let score = anchor_meta_opt(&env, &q.anchor)
                    .map(|m| weighted_score(&m, q.fee_percentage))
                    .unwrap_or(0);
                if score > best_score {
                    best_score = score;
                    best = q;
                }
            }
        }

        env.events().publish(
            (symbol_short!("webhook"), symbol_short!("event")),
            WebhookEvent {
                event_type: String::from_str(&env, "transaction_routed"),
                transaction_id: best.quote_id,
                timestamp: now,
                payload_hash: Bytes::new(&env),
            },
        );

        best
    }

    /// Return up to `max_results` quotes sorted by descending weighted composite score.
    /// Weights (scaled ×1000) must sum to 1000; panics with `InvalidWeights` otherwise.
    pub fn route_anchors(
        env: Env,
        fee_weight: u32,       // scaled ×1000, e.g. 333 = 0.333
        speed_weight: u32,
        reputation_weight: u32,
        max_results: u32,
        min_reputation: u32,
    ) -> Vec<Quote> {
        let fw = fee_weight as f32 / 1000.0_f32;
        let sw = speed_weight as f32 / 1000.0_f32;
        let rw = reputation_weight as f32 / 1000.0_f32;
        let strategy = WeightedRoutingStrategy {
            fee_weight: fw,
            speed_weight: sw,
            reputation_weight: rw,
        };
        if !strategy.validate() {
            panic_with_error!(&env, ErrorCode::ValidationError);
        }

        let now = env.ledger().timestamp();
        let list_key = make_storage_key(&env, &[b"ANCHLIST"]);
        let anchors: Vec<Address> = env.storage().persistent()
            .get::<_, Vec<Address>>(&list_key)
            .unwrap_or_else(|| Vec::new(&env));

        // First pass: find max values for normalisation
        let mut max_fee: u32 = 1;
        let mut max_settlement: u64 = 1;
        let mut max_reputation: u32 = 1;

        for anchor in anchors.iter() {
            let meta: RoutingAnchorMeta = match anchor_meta_opt(&env, &anchor) {
                Some(m) if m.is_active && m.reputation_score >= min_reputation => m,
                _ => continue,
            };
            let anchor_xdr = anchor.clone().to_xdr(&env);
            let anchor_raw = xdr_to_vec(&anchor_xdr);
            let lq_key = make_storage_key(&env, &[b"LATESTQ", &anchor_raw]);
            let quote_id: u64 = match env.storage().persistent().get(&lq_key) {
                Some(id) => id,
                None => continue,
            };
            let q_key = make_storage_key(&env, &[b"QUOTE", &anchor_raw, &quote_id.to_be_bytes()]);
            let quote: Quote = match env.storage().persistent().get(&q_key) {
                Some(q) => q,
                None => continue,
            };
            if quote.valid_until <= now { continue; }
            if meta.average_settlement_time > max_settlement { max_settlement = meta.average_settlement_time; }
            if meta.reputation_score > max_reputation { max_reputation = meta.reputation_score; }
            if quote.fee_percentage > max_fee { max_fee = quote.fee_percentage; }
        }

        // Second pass: score into a native vec, then sort
        let mut scored: alloc::vec::Vec<(u32, Quote)> = alloc::vec::Vec::new();

        for anchor in anchors.iter() {
            let meta: RoutingAnchorMeta = match anchor_meta_opt(&env, &anchor) {
                Some(m) if m.is_active && m.reputation_score >= min_reputation => m,
                _ => continue,
            };
            let anchor_xdr = anchor.clone().to_xdr(&env);
            let anchor_raw = xdr_to_vec(&anchor_xdr);
            let lq_key = make_storage_key(&env, &[b"LATESTQ", &anchor_raw]);
            let quote_id: u64 = match env.storage().persistent().get(&lq_key) {
                Some(id) => id,
                None => continue,
            };
            let q_key = make_storage_key(&env, &[b"QUOTE", &anchor_raw, &quote_id.to_be_bytes()]);
            let quote: Quote = match env.storage().persistent().get(&q_key) {
                Some(q) => q,
                None => continue,
            };
            if quote.valid_until <= now { continue; }

            let score = strategy.score_anchor(
                quote.fee_percentage,
                meta.average_settlement_time,
                meta.reputation_score,
                max_fee,
                max_settlement,
                max_reputation,
            );
            scored.push(((score * 1_000_000.0_f32) as u32, quote));
        }

        // Sort descending by score
        scored.sort_unstable_by(|a, b| b.0.cmp(&a.0));

        // Return top max_results quotes as a Soroban Vec
        let limit = if max_results == 0 { 3u32 } else { max_results };
        let mut result: Vec<Quote> = Vec::new(&env);
        for (_, quote) in scored.into_iter().take(limit as usize) {
            result.push_back(quote);
        }
        result
    }

    // -----------------------------------------------------------------------
    // Anchor Info Discovery
    // -----------------------------------------------------------------------

    pub fn fetch_anchor_info(
        env: Env,
        anchor: Address,
        toml_data: StellarToml,
        ttl_seconds: u64,
    ) {
        anchor.require_auth();
        let now = env.ledger().timestamp();
        let cached = CachedToml {
            toml: toml_data,
            cached_at: now,
            ttl_seconds,
        };
        let key = (symbol_short!("TOMLCACHE"), anchor);
        let ledger_ttl = if ttl_seconds as u32 > MIN_TEMP_TTL { ttl_seconds as u32 } else { MIN_TEMP_TTL };
        env.storage().temporary().set(&key, &cached);
        env.storage().temporary().extend_ttl(&key, ledger_ttl, ledger_ttl);
    }

    pub fn get_anchor_toml(env: Env, anchor: Address) -> StellarToml {
        let key = (symbol_short!("TOMLCACHE"), anchor);
        let cached: CachedToml = env.storage().temporary().get(&key)
            .unwrap_or_else(|| panic_with_error!(&env, ErrorCode::CacheNotFound));
        let now = env.ledger().timestamp();
        if cached.cached_at + cached.ttl_seconds <= now {
            panic_with_error!(&env, ErrorCode::CacheExpired);
        }
        cached.toml
    }

    pub fn refresh_anchor_info(env: Env, anchor: Address) {
        anchor.require_auth();
        let key = (symbol_short!("TOMLCACHE"), anchor);
        env.storage().temporary().remove(&key);
    }

    pub fn get_anchor_assets(env: Env, anchor: Address) -> Vec<String> {
        let toml = Self::get_anchor_toml(env.clone(), anchor);
        let mut assets = Vec::new(&env);
        for asset in toml.currencies.iter() {
            assets.push_back(asset.code.clone());
        }
        assets
    }

    pub fn get_anchor_asset_info(
        env: Env,
        anchor: Address,
        asset_code: String,
    ) -> AssetInfo {
        let toml = Self::get_anchor_toml(env.clone(), anchor);
        for asset in toml.currencies.iter() {
            if asset.code == asset_code {
                return asset;
            }
        }
        panic_with_error!(&env, ErrorCode::ValidationError);
    }

    pub fn get_anchor_deposit_limits(
        env: Env,
        anchor: Address,
        asset_code: String,
    ) -> (u64, u64) {
        let asset = Self::get_anchor_asset_info(env, anchor, asset_code);
        (asset.deposit_min_amount, asset.deposit_max_amount)
    }

    pub fn get_anchor_withdrawal_limits(
        env: Env,
        anchor: Address,
        asset_code: String,
    ) -> (u64, u64) {
        let asset = Self::get_anchor_asset_info(env, anchor, asset_code);
        (asset.withdrawal_min_amount, asset.withdrawal_max_amount)
    }

    pub fn get_anchor_deposit_fees(
        env: Env,
        anchor: Address,
        asset_code: String,
    ) -> (u64, u32) {
        let asset = Self::get_anchor_asset_info(env, anchor, asset_code);
        (asset.deposit_fee_fixed, asset.deposit_fee_percent)
    }

    pub fn get_anchor_withdrawal_fees(
        env: Env,
        anchor: Address,
        asset_code: String,
    ) -> (u64, u32) {
        let asset = Self::get_anchor_asset_info(env, anchor, asset_code);
        (asset.withdrawal_fee_fixed, asset.withdrawal_fee_percent)
    }

    pub fn anchor_supports_deposits(
        env: Env,
        anchor: Address,
        asset_code: String,
    ) -> bool {
        match Self::get_anchor_asset_info(env, anchor, asset_code) {
            asset => asset.deposit_enabled,
        }
    }

    pub fn anchor_supports_withdrawals(
        env: Env,
        anchor: Address,
        asset_code: String,
    ) -> bool {
        match Self::get_anchor_asset_info(env, anchor, asset_code) {
            asset => asset.withdrawal_enabled,
        }
    }

    // -----------------------------------------------------------------------
    // Transaction state
    // -----------------------------------------------------------------------

    pub fn create_transaction_record(
        env: Env,
        transaction_id: u64,
        initiator: Address,
    ) -> TransactionStateRecord {
        let now = env.ledger().timestamp();
        let mut history = soroban_sdk::Vec::new(&env);
        history.push_back((TransactionState::Pending, now));
        let record = TransactionStateRecord {
            transaction_id,
            state: TransactionState::Pending,
            initiator,
            timestamp: now,
            last_updated: now,
            error_message: None,
            state_history: history,
        };
        let key = (symbol_short!("TXSTATE"), transaction_id);
        env.storage().persistent().set(&key, &record);
        env.storage().persistent().extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);
        record
    }

    // -----------------------------------------------------------------------
    // Rate limit configuration
    // -----------------------------------------------------------------------

    pub fn set_rate_limit_config(
        env: Env,
        max_submissions: u32,
        window_length: u32,
        burst_capacity: u32,
        min_interval_ledgers: u32,
    ) {
        Self::require_admin(&env);
        let config = crate::rate_limiter::RateLimitConfig {
            max_submissions,
            window_length,
            burst_capacity,
            min_interval_ledgers,
        };
        RateLimiter::update_config(&env, &Self::get_admin(env.clone()), &config)
            .unwrap_or_else(|_| panic_with_error!(&env, ErrorCode::ValidationError));
    }

    /// Set a per-attestor rate limit override (admin only). See
    /// [`RateLimiter::set_override`] for how overrides interact with the
    /// global config.
    pub fn set_attestor_rate_override(
        env: Env,
        attestor: Address,
        max_submissions: u32,
        window_length: u32,
        burst_capacity: u32,
        min_interval_ledgers: u32,
    ) {
        Self::require_admin(&env);
        let config = crate::rate_limiter::RateLimitConfig {
            max_submissions,
            window_length,
            burst_capacity,
            min_interval_ledgers,
        };
        RateLimiter::set_override(&env, &Self::get_admin(env.clone()), &attestor, &config)
            .unwrap_or_else(|_| panic_with_error!(&env, ErrorCode::ValidationError));
    }

    /// Remove a per-attestor rate limit override (admin only), reverting that
    /// attestor to the global rate limit config.
    pub fn remove_attestor_rate_override(env: Env, attestor: Address) {
        Self::require_admin(&env);
        RateLimiter::remove_override(&env, &Self::get_admin(env.clone()), &attestor)
            .unwrap_or_else(|_| panic_with_error!(&env, ErrorCode::ValidationError));
    }

    /// Get the rate limit config that actually governs `attestor`: their
    /// override if one is set, otherwise the global config.
    pub fn get_attestor_rate_config(env: Env, attestor: Address) -> crate::rate_limiter::RateLimitConfig {
        RateLimiter::effective_config(&env, &attestor)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Validate that a session is neither expired nor closed.
    /// Panics with `SessionExpired` if `current_time > created_at + ttl`,
    /// or `SessionClosed` if `session.closed == true`.
    fn validate_session(env: &Env, session: &Session) {
        let ttl = if session.session_ttl_seconds == 0 {
            DEFAULT_SESSION_TTL
        } else {
            session.session_ttl_seconds
        };
        let now = env.ledger().timestamp();
        if now > session.created_at + ttl {
            panic_with_error!(env, ErrorCode::SessionExpired);
        }
        if session.closed {
            panic_with_error!(env, ErrorCode::SessionClosed);
        }
    }

    fn enforce_rate_limit(env: &Env, attestor: &Address) {
        let config = RateLimiter::effective_config(env, attestor);
        if RateLimiter::check_and_increment(env, attestor, &config).is_err() {
            panic_with_error!(env, ErrorCode::RateLimitExceeded);
        }
    }

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .instance()
            .get::<_, Address>(&admin_key(env))
            .unwrap_or_else(|| panic_with_error!(env, ErrorCode::NotInitialized));
        admin.require_auth();
    }

    fn check_attestor(env: &Env, attestor: &Address) {
        let xdr = attestor.clone().to_xdr(env);
        let raw = xdr_to_vec(&xdr);
        if !env
            .storage()
            .persistent()
            .has(&make_storage_key(env, &[b"ATTESTOR", &raw]))
        {
            panic_with_error!(env, ErrorCode::AttestorNotRegistered);
        }
    }

    fn soroban_string_to_rust_string(env: &Env, value: &String) -> RustString {
        let len = value.len() as usize;
        let mut buffer = RustVec::new();
        buffer.resize(len, 0u8);
        value.copy_into_slice(&mut buffer);
        RustString::from_utf8(buffer).unwrap_or_else(|_| {
            panic_with_error!(env, ErrorCode::InvalidEndpointFormat)
        })
    }

    fn verify_attestation_signature(env: &Env, issuer: &Address, payload_hash: &Bytes, signature: &Bytes) {
        let xdr = issuer.clone().to_xdr(env);
        let raw = xdr_to_vec(&xdr);
        let pk: BytesN<32> = env
            .storage()
            .persistent()
            .get(&make_storage_key(env, &[b"ATPUBKEY", &raw]))
            .unwrap_or_else(|| panic_with_error!(env, ErrorCode::UnauthorizedAttestor));
        if signature.len() != 64 {
            panic_with_error!(env, ErrorCode::UnauthorizedAttestor);
        }
        let signature_bytes: BytesN<64> = signature.clone().try_into().unwrap_or_else(|_| {
            panic_with_error!(env, ErrorCode::UnauthorizedAttestor)
        });
        env.crypto()
            .ed25519_verify(&pk, payload_hash, &signature_bytes);
    }

    fn check_timestamp(env: &Env, timestamp: u64) {
        if timestamp == 0 {
            panic_with_error!(env, ErrorCode::InvalidTimestamp);
        }
    }

    fn next_attestation_id(env: &Env) -> u64 {
        let inst = env.storage().instance();
        let ck = soroban_sdk::vec![env, symbol_short!("COUNTER")];
        let id: u64 = inst.get(&ck).unwrap_or(0u64);
        inst.set(&ck, &(id + 1));
        inst.extend_ttl(INSTANCE_TTL, INSTANCE_TTL);
        id
    }

    fn store_attestation(
        env: &Env,
        id: u64,
        issuer: Address,
        subject: Address,
        timestamp: u64,
        payload_hash: Bytes,
        signature: Bytes,
    ) {
        let attestation = Attestation { id, issuer, subject, timestamp, payload_hash, signature };
        let key = make_storage_key(env, &[b"ATTEST", &id.to_be_bytes()]);
        env.storage().persistent().set(&key, &attestation);
        env.storage().persistent().extend_ttl(&key, PERSISTENT_TTL, PERSISTENT_TTL);
    }

    fn store_span(
        env: &Env,
        request_id: &RequestId,
        operation: String,
        actor: Address,
        now: u64,
        status: String,
    ) {
        Self::store_span_with_parent(env, request_id, operation, actor, now, status, Bytes::new(env), 0);
    }

    fn store_span_with_parent(
        env: &Env,
        request_id: &RequestId,
        operation: String,
        actor: Address,
        now: u64,
        status: String,
        parent_request_id_bytes: Bytes,
        span_index: u32,
    ) {
        let span = TracingSpan {
            request_id: request_id.clone(),
            operation,
            actor,
            started_at: now,
            completed_at: now,
            status,
            parent_request_id_bytes,
            span_index,
        };
        let key = (symbol_short!("SPAN"), request_id.id.clone());
        env.storage().temporary().set(&key, &span);
        env.storage()
            .temporary()
            .extend_ttl(&key, SPAN_TTL, SPAN_TTL);
    }

    /// Append `operation_name` to the `RequestContext` stored under `root_id_bytes`.
    /// Creates a minimal context if none exists yet (e.g. for the root operation itself).
    fn record_operation_in_context(env: &Env, root_id_bytes: &Bytes, operation_name: String) {
        let key = (symbol_short!("REQCTX"), root_id_bytes.clone());
        let now = env.ledger().timestamp();
        let mut ctx: RequestContext = env
            .storage()
            .temporary()
            .get(&key)
            .unwrap_or_else(|| RequestContext {
                root_request_id: RequestId {
                    id: root_id_bytes.clone(),
                    created_at: now,
                },
                operation_chain: Vec::new(env),
                created_at: now,
            });
        ctx.operation_chain.push_back(operation_name);
        env.storage().temporary().set(&key, &ctx);
        env.storage()
            .temporary()
            .extend_ttl(&key, SPAN_TTL, SPAN_TTL);
    }
}
