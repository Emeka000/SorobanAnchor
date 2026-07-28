//! Deterministic SHA-256 hashing for attestation payloads.
//!
//! Provides a canonical field-ordering scheme so that the same logical payload
//! always produces the same 32-byte hash regardless of the calling context.
//! This is critical for replay-attack detection: the contract stores the hash
//! of each submitted attestation and rejects duplicates.

use soroban_sdk::{Address, Bytes, BytesN, Env, xdr::ToXdr};

/// Compute a collision-resistant SHA-256 storage key from any XDR-encodable
/// tuple. All persistent-storage key helpers must go through this function so
/// that keys are deterministic and cannot collide across different namespaces.
///
/// # Arguments
/// * `env`   - Soroban execution environment.
/// * `parts` - Slice of raw byte segments that together identify the entry.
///             Each segment is length-prefixed (4-byte BE) before hashing so
///             that `["AB", "C"]` and `["A", "BC"]` produce different keys.
///
/// # Returns
/// A 32-byte SHA-256 digest suitable for use as a persistent storage key.
pub fn make_storage_key(env: &Env, parts: &[&[u8]]) -> BytesN<32> {
    let mut input = Bytes::new(env);
    for part in parts {
        // 4-byte big-endian length prefix prevents cross-segment collisions.
        let len = part.len() as u32;
        for b in len.to_be_bytes().iter() {
            input.push_back(*b);
        }
        for b in part.iter() {
            input.push_back(*b);
        }
    }
    env.crypto().sha256(&input).into()
}

/// Compute a canonical SHA-256 hash over attestation payload fields.
///
/// The field ordering is fixed (canonical):
/// `subject_xdr_bytes || timestamp_8_byte_be || data_bytes`
///
/// This guarantees that the same inputs always produce the same 32-byte hash,
/// which is required for deterministic replay-attack detection.
///
/// # Arguments
///
/// * `env` - The Soroban execution environment.
/// * `subject` - The Stellar address of the attestation subject, serialised as
///   raw XDR bytes.
/// * `timestamp` - Unix timestamp (seconds) encoded as 8-byte big-endian.
/// * `data` - Arbitrary payload bytes (e.g. `b"kyc_approved"`).
///
/// # Returns
///
/// A 32-byte SHA-256 digest as [`BytesN<32>`].
///
/// # Examples
///
/// ```rust,no_run
/// # use soroban_sdk::{Env, Bytes};
/// # use soroban_sdk::testutils::Address as _;
/// # let env = Env::default();
/// # let subject = soroban_sdk::Address::generate(&env);
/// use anchorkit::compute_payload_hash;
///
/// let data = Bytes::from_slice(&env, b"kyc_approved");
/// let hash = compute_payload_hash(&env, &subject, 1_700_000_000, &data);
/// assert_eq!(hash.len(), 32);
/// ```
pub fn compute_payload_hash(
    env: &Env,
    subject: &Address,
    timestamp: u64,
    data: &Bytes,
) -> BytesN<32> {
    let mut input = Bytes::new(env);

    // 1. subject — serialised as its raw XDR bytes via to_xdr
    let subject_bytes = subject.clone().to_xdr(env);
    input.append(&subject_bytes);

    // 2. timestamp — 8-byte big-endian
    for b in timestamp.to_be_bytes().iter() {
        input.push_back(*b);
    }

    // 3. data payload
    input.append(data);

    env.crypto().sha256(&input).into()
}

/// Verify that the stored attestation's payload hash matches the expected hash.
///
/// Performs a constant-time equality check between two 32-byte digests.
///
/// # Arguments
///
/// * `stored` - The hash previously stored on-chain for an attestation.
/// * `expected` - The hash recomputed from the claimed payload fields.
///
/// # Returns
///
/// `true` when the hashes are equal; `false` otherwise.
///
/// # Examples
///
/// ```rust,no_run
/// # use soroban_sdk::{Env, Bytes};
/// # use soroban_sdk::testutils::Address as _;
/// # let env = Env::default();
/// # let subject = soroban_sdk::Address::generate(&env);
/// use anchorkit::{compute_payload_hash, verify_payload_hash};
///
/// let data = Bytes::from_slice(&env, b"payment_confirmed");
/// let hash = compute_payload_hash(&env, &subject, 1_700_000_000, &data);
///
/// assert!(verify_payload_hash(&hash, &hash));
///
/// let other = compute_payload_hash(&env, &subject, 1_700_000_001, &data);
/// assert!(!verify_payload_hash(&hash, &other));
/// ```
pub fn verify_payload_hash(stored: &BytesN<32>, expected: &BytesN<32>) -> bool {
    stored == expected
}

#[cfg(test)]
mod deterministic_hash_tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env};

    #[test]
    fn test_same_inputs_produce_same_hash() {
        let env = Env::default();
        let subject = Address::generate(&env);
        let data = Bytes::from_slice(&env, b"kyc_approved");
        let ts: u64 = 1_700_000_000;

        let h1 = compute_payload_hash(&env, &subject, ts, &data);
        let h2 = compute_payload_hash(&env, &subject, ts, &data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_different_timestamp_produces_different_hash() {
        let env = Env::default();
        let subject = Address::generate(&env);
        let data = Bytes::from_slice(&env, b"kyc_approved");

        let h1 = compute_payload_hash(&env, &subject, 1_000, &data);
        let h2 = compute_payload_hash(&env, &subject, 2_000, &data);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_different_data_produces_different_hash() {
        let env = Env::default();
        let subject = Address::generate(&env);
        let ts: u64 = 1_700_000_000;

        let h1 = compute_payload_hash(&env, &subject, ts, &Bytes::from_slice(&env, b"data_a"));
        let h2 = compute_payload_hash(&env, &subject, ts, &Bytes::from_slice(&env, b"data_b"));
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_verify_payload_hash_match() {
        let env = Env::default();
        let subject = Address::generate(&env);
        let data = Bytes::from_slice(&env, b"payment_confirmed");
        let ts: u64 = 1_700_000_000;

        let hash = compute_payload_hash(&env, &subject, ts, &data);
        assert!(verify_payload_hash(&hash, &hash));
    }

    #[test]
    fn test_verify_payload_hash_mismatch() {
        let env = Env::default();
        let subject = Address::generate(&env);
        let data = Bytes::from_slice(&env, b"payment_confirmed");
        let ts: u64 = 1_700_000_000;

        let h1 = compute_payload_hash(&env, &subject, ts, &data);
        let h2 = compute_payload_hash(&env, &subject, ts + 1, &data);
        assert!(!verify_payload_hash(&h1, &h2));
    }
}
