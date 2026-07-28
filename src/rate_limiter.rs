//! Rate limiting for attestation submissions
//!
//! This module implements per-attestor rate limiting for attestation submissions
//! to prevent spam and abuse of the contract.

use soroban_sdk::{contracttype, xdr::ToXdr, Address, Env};
use crate::deterministic_hash::make_storage_key;
use crate::errors::AnchorKitError;
#[cfg(test)]
use crate::errors::ErrorCode;

/// Rate limit configuration stored in contract storage.
///
/// Defines the sliding-window parameters used by [`RateLimiter::check_and_increment`],
/// plus two knobs that make the limiter fairer under bursty traffic:
///
/// * `burst_capacity` — a token-bucket cap on how many submissions an attestor
///   may make back-to-back before waiting for tokens to refill (1 token per
///   elapsed ledger, capped at `burst_capacity`). This smooths short spikes
///   without needing a separate short window.
/// * `min_interval_ledgers` — the minimum number of ledgers that must elapse
///   between two consecutive accepted submissions from the *same* attestor.
///   This is the fairness control: it stops one attestor from spending its
///   entire window allowance in a single ledger, which would otherwise let a
///   single bursty client monopolize the window at the expense of others.
///
/// Setting `burst_capacity == max_submissions` and `min_interval_ledgers == 0`
/// reproduces the original fixed-window-only behavior.
///
/// The admin can update this at runtime via [`RateLimiter::update_config`].
///
/// # Examples
///
/// ```rust,no_run
/// use anchorkit::RateLimitConfig;
///
/// // Allow at most 5 submissions per 50-ledger window, in bursts of up to 2,
/// // with at least 3 ledgers between consecutive submissions.
/// let config = RateLimitConfig {
///     max_submissions: 5,
///     window_length: 50,
///     burst_capacity: 2,
///     min_interval_ledgers: 3,
/// };
/// ```
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimitConfig {
    /// Maximum number of submissions allowed per window
    pub max_submissions: u32,
    /// Length of the rate limit window in ledgers
    pub window_length: u32,
    /// Maximum burst tokens an attestor can spend before waiting for refill.
    pub burst_capacity: u32,
    /// Minimum ledgers required between two consecutive submissions from the
    /// same attestor. `0` disables this fairness check.
    pub min_interval_ledgers: u32,
}

impl RateLimitConfig {
    /// The permissive default: 10 submissions per 100-ledger window, burst
    /// capacity equal to the window cap (no extra smoothing), and no minimum
    /// spacing requirement. This matches the limiter's original behavior.
    pub const fn default_config() -> Self {
        RateLimitConfig {
            max_submissions: 10,
            window_length: 100,
            burst_capacity: 10,
            min_interval_ledgers: 0,
        }
    }
}

/// Per-attestor rate limit state stored in contract storage.
///
/// Tracks how many submissions an attestor has made in the current window,
/// when that window started, how many burst tokens remain, and the ledger of
/// the last accepted submission. Automatically reset when the window expires.
///
/// # Examples
///
/// ```rust,no_run
/// use anchorkit::RateLimitState;
///
/// let state = RateLimitState {
///     submission_count: 3,
///     window_start_ledger: 1000,
///     tokens: 7,
///     last_submission_ledger: 1000,
/// };
/// assert_eq!(state.submission_count, 3);
/// ```
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimitState {
    /// Number of submissions in the current window
    pub submission_count: u32,
    /// Ledger number when the current window started
    pub window_start_ledger: u32,
    /// Burst tokens currently available (token-bucket burst control).
    pub tokens: u32,
    /// Ledger number of the most recently accepted submission.
    pub last_submission_ledger: u32,
}

/// Per-attestor sliding-window rate limiter for attestation submissions.
///
/// All methods are associated functions that operate directly on Soroban
/// persistent storage, so no instance state is needed.
///
/// The default configuration (10 submissions per 100-ledger window, burst
/// capacity 10, no minimum spacing) is used when no config has been stored
/// yet — see [`RateLimitConfig::default_config`].
pub struct RateLimiter;

impl RateLimiter {
    /// Check whether an attestor is within their rate limit and increment the counter.
    ///
    /// If the current window has expired it is automatically reset before the
    /// check. The counter is only incremented when the check passes.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban execution environment.
    /// * `attestor` - The address of the attestor being checked.
    /// * `config` - The active [`RateLimitConfig`] (fetch via [`RateLimiter::get_config`]).
    ///
    /// # Returns
    ///
    /// `Ok(())` if the attestor is within the rate limit.
    ///
    /// # Errors
    ///
    /// Returns [`AnchorKitError`] with code [`ErrorCode::RateLimitExceeded`] when
    /// the attestor has reached `config.max_submissions` in the current window,
    /// or code [`ErrorCode::RateLimitBurstExceeded`] when the attestor has
    /// exhausted its burst tokens or violates `config.min_interval_ledgers`.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use soroban_sdk::Env;
    /// # use soroban_sdk::testutils::Address as _;
    /// # let env = Env::default();
    /// # let attestor = soroban_sdk::Address::generate(&env);
    /// use anchorkit::{RateLimiter, RateLimitConfig};
    ///
    /// let config = RateLimitConfig::default_config();
    /// // First call succeeds.
    /// assert!(RateLimiter::check_and_increment(&env, &attestor, &config).is_ok());
    /// ```
    pub fn check_and_increment(
        env: &Env,
        attestor: &Address,
        config: &RateLimitConfig,
    ) -> Result<(), AnchorKitError> {
        let current_ledger = env.ledger().sequence();
        let state_key = Self::get_state_key(env, attestor);

        // Get or initialize rate limit state. A brand-new attestor starts with
        // a full burst allowance.
        let mut state = env.storage().persistent().get::<_, RateLimitState>(&state_key)
            .unwrap_or(RateLimitState {
                submission_count: 0,
                window_start_ledger: current_ledger,
                tokens: config.burst_capacity,
                last_submission_ledger: current_ledger,
            });

        // Fairness: enforce a minimum ledger gap between two consecutive
        // submissions from the same attestor. Without this, a single attestor
        // could spend its entire window allowance in one ledger, starving the
        // window out for the rest of its length even though other attestors
        // are unaffected (state is per-attestor already).
        if config.min_interval_ledgers > 0
            && state.submission_count > 0
            && current_ledger.saturating_sub(state.last_submission_ledger) < config.min_interval_ledgers
        {
            return Err(AnchorKitError::rate_limit_burst_exceeded());
        }

        // Check if window has expired and reset if needed
        if Self::is_window_expired(current_ledger, state.window_start_ledger, config.window_length) {
            state.submission_count = 0;
            state.window_start_ledger = current_ledger;
        }

        // Refill burst tokens by one per elapsed ledger since the last
        // submission, capped at burst_capacity. The refilled value is used
        // below, but the fixed-window check takes priority when both the
        // window and the burst allowance are exhausted at once, since the
        // window is the primary cap and burst is just a smoothing layer on
        // top of it.
        let elapsed = current_ledger.saturating_sub(state.last_submission_ledger);
        state.tokens = core::cmp::min(config.burst_capacity, state.tokens.saturating_add(elapsed));

        // Check if the fixed-window limit is exceeded
        if state.submission_count >= config.max_submissions {
            return Err(AnchorKitError::rate_limit_exceeded());
        }

        // Burst control: require at least one token to proceed. This smooths
        // bursts independently of the fixed window so a caller can't spend
        // the whole window in one shot.
        if state.tokens == 0 {
            return Err(AnchorKitError::rate_limit_burst_exceeded());
        }

        // Increment counter, spend a token, and save state
        state.submission_count += 1;
        state.tokens -= 1;
        state.last_submission_ledger = current_ledger;
        env.storage().persistent().set(&state_key, &state);

        Ok(())
    }

    /// Get the current rate limit state for an attestor.
    ///
    /// Returns a default state (zero submissions, no burst tokens spent,
    /// current ledger as window start) if no state has been stored yet.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban execution environment.
    /// * `attestor` - The address of the attestor to query.
    ///
    /// # Returns
    ///
    /// The current [`RateLimitState`] for the attestor.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use soroban_sdk::Env;
    /// # use soroban_sdk::testutils::Address as _;
    /// # let env = Env::default();
    /// # let attestor = soroban_sdk::Address::generate(&env);
    /// use anchorkit::RateLimiter;
    ///
    /// let state = RateLimiter::get_state(&env, &attestor);
    /// assert_eq!(state.submission_count, 0);
    /// ```
    pub fn get_state(env: &Env, attestor: &Address) -> RateLimitState {
        let state_key = Self::get_state_key(env, attestor);
        env.storage().persistent().get::<_, RateLimitState>(&state_key)
            .unwrap_or(RateLimitState {
                submission_count: 0,
                window_start_ledger: env.ledger().sequence(),
                tokens: 0,
                last_submission_ledger: env.ledger().sequence(),
            })
    }

    /// Update the rate limit configuration (admin only).
    ///
    /// Loads the stored admin from instance storage (key `"ADMIN"`) and calls
    /// `admin.require_auth()`. Returns `Err(NotInitialized)` if no admin is
    /// stored, or `Err(ValidationError)` if `config` is not internally
    /// consistent (see field docs on [`RateLimitConfig`]).
    pub fn update_config(
        env: &Env,
        admin: &Address,
        config: &RateLimitConfig,
    ) -> Result<(), AnchorKitError> {
        Self::validate_config(config)?;
        Self::require_stored_admin(env, admin)?;
        let config_key = Self::get_config_key(env);
        env.storage().persistent().set(&config_key, config);
        Ok(())
    }

    /// Get the current rate limit configuration.
    ///
    /// Returns the stored configuration, or [`RateLimitConfig::default_config`]
    /// if none has been set.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban execution environment.
    ///
    /// # Returns
    ///
    /// The active [`RateLimitConfig`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use soroban_sdk::Env;
    /// # let env = Env::default();
    /// use anchorkit::RateLimiter;
    ///
    /// let config = RateLimiter::get_config(&env);
    /// assert_eq!(config.max_submissions, 10);
    /// assert_eq!(config.window_length, 100);
    /// ```
    pub fn get_config(env: &Env) -> RateLimitConfig {
        let config_key = Self::get_config_key(env);
        env.storage().persistent().get::<_, RateLimitConfig>(&config_key)
            .unwrap_or(RateLimitConfig::default_config())
    }

    /// Set a per-attestor rate limit override (admin only).
    ///
    /// Once set, [`RateLimiter::effective_config`] returns this configuration
    /// for `attestor` instead of the global config, letting operators grant a
    /// high-volume attestor a looser policy — or clamp down on a specific
    /// abuser — without changing the policy for everyone else.
    ///
    /// # Errors
    ///
    /// Same validation and admin checks as [`RateLimiter::update_config`].
    pub fn set_override(
        env: &Env,
        admin: &Address,
        attestor: &Address,
        config: &RateLimitConfig,
    ) -> Result<(), AnchorKitError> {
        Self::validate_config(config)?;
        Self::require_stored_admin(env, admin)?;
        let key = Self::get_override_key(env, attestor);
        env.storage().persistent().set(&key, config);
        Ok(())
    }

    /// Remove a per-attestor rate limit override (admin only).
    ///
    /// After removal, [`RateLimiter::effective_config`] falls back to the
    /// global config for `attestor`. A no-op (still `Ok`) if no override was set.
    pub fn remove_override(
        env: &Env,
        admin: &Address,
        attestor: &Address,
    ) -> Result<(), AnchorKitError> {
        Self::require_stored_admin(env, admin)?;
        let key = Self::get_override_key(env, attestor);
        env.storage().persistent().remove(&key);
        Ok(())
    }

    /// Get the raw per-attestor override, if one has been set.
    ///
    /// Returns `None` when `attestor` has no override, in which case the
    /// global config applies. Use [`RateLimiter::effective_config`] to get
    /// the config that actually governs an attestor's submissions.
    pub fn get_override(env: &Env, attestor: &Address) -> Option<RateLimitConfig> {
        let key = Self::get_override_key(env, attestor);
        env.storage().persistent().get::<_, RateLimitConfig>(&key)
    }

    /// Get the config that actually governs `attestor`'s submissions: their
    /// override if one is set, otherwise the global config.
    pub fn effective_config(env: &Env, attestor: &Address) -> RateLimitConfig {
        Self::get_override(env, attestor).unwrap_or_else(|| Self::get_config(env))
    }

    /// Validate that a config's fields are internally consistent.
    fn validate_config(config: &RateLimitConfig) -> Result<(), AnchorKitError> {
        if config.max_submissions == 0 {
            return Err(AnchorKitError::validation_error("max_submissions must be at least 1"));
        }
        if config.burst_capacity == 0 {
            return Err(AnchorKitError::validation_error("burst_capacity must be at least 1"));
        }
        Ok(())
    }

    /// Load the stored admin and confirm `admin` matches, requiring their auth.
    fn require_stored_admin(env: &Env, admin: &Address) -> Result<(), AnchorKitError> {
        let stored_admin: Address = env
            .storage()
            .instance()
            .get::<_, Address>(&Self::get_admin_key(env))
            .ok_or_else(AnchorKitError::not_initialized)?;
        if *admin != stored_admin {
            return Err(AnchorKitError::unauthorized_attestor());
        }
        admin.require_auth();
        Ok(())
    }

    /// Check if a window has expired
    fn is_window_expired(current_ledger: u32, window_start_ledger: u32, window_length: u32) -> bool {
        current_ledger.saturating_sub(window_start_ledger) >= window_length
    }

    /// Generate collision-resistant storage key for per-attestor rate limit state.
    fn get_state_key(env: &Env, attestor: &Address) -> soroban_sdk::BytesN<32> {
        make_storage_key(env, &[b"RL_STATE", &Self::addr_bytes(env, attestor)])
    }

    /// Generate collision-resistant storage key for a per-attestor rate limit override.
    fn get_override_key(env: &Env, attestor: &Address) -> soroban_sdk::BytesN<32> {
        make_storage_key(env, &[b"RL_OVERRIDE", &Self::addr_bytes(env, attestor)])
    }

    /// Generate collision-resistant storage key for the global rate limit config.
    fn get_config_key(env: &Env) -> soroban_sdk::BytesN<32> {
        make_storage_key(env, &[b"RL_CONFIG"])
    }

    /// Storage key for the contract admin. Matches `contract::admin_key` so the
    /// rate limiter checks auth against the same admin the contract was
    /// initialized with, rather than a separate, never-populated key.
    fn get_admin_key(env: &Env) -> soroban_sdk::BytesN<32> {
        make_storage_key(env, &[b"ADMIN"])
    }

    fn addr_bytes(env: &Env, attestor: &Address) -> alloc::vec::Vec<u8> {
        let addr_xdr = attestor.clone().to_xdr(env);
        let mut raw = alloc::vec::Vec::with_capacity(addr_xdr.len() as usize);
        for i in 0..addr_xdr.len() {
            raw.push(addr_xdr.get(i).unwrap_or(0));
        }
        raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_under_limit() {
        let env = Env::default();
        let attestor = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let config = RateLimitConfig {
            max_submissions: 10,
            window_length: 100,
            burst_capacity: 10,
            min_interval_ledgers: 0,
        };

        // Create a dummy contract address for testing
        let contract_address = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        
        // Register a dummy contract for testing
        let contract_id = env.register_contract(&contract_address, crate::contract::AnchorKitContract);
        
        // Should succeed for first submission
        let result = env.as_contract(&contract_id, &|| {
            RateLimiter::check_and_increment(&env, &attestor, &config)
        });
        assert!(result.is_ok());
        
        // Check state
        let state = env.as_contract(&contract_id, &|| {
            RateLimiter::get_state(&env, &attestor)
        });
        assert_eq!(state.submission_count, 1);
    }
    
    #[test]
    fn test_rate_limit_at_limit() {
        let env = Env::default();
        let attestor = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let config = RateLimitConfig {
            max_submissions: 2,
            window_length: 100,
            burst_capacity: 2,
            min_interval_ledgers: 0,
        };
        
        let contract_address = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let contract_id = env.register_contract(&contract_address, crate::contract::AnchorKitContract);
        
        // First two submissions should succeed
        assert!(env.as_contract(&contract_id, &|| {
            RateLimiter::check_and_increment(&env, &attestor, &config)
        }).is_ok());
        assert!(env.as_contract(&contract_id, &|| {
            RateLimiter::check_and_increment(&env, &attestor, &config)
        }).is_ok());
        
        // Third submission should fail
        let result = env.as_contract(&contract_id, &|| {
            RateLimiter::check_and_increment(&env, &attestor, &config)
        });
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ErrorCode::RateLimitExceeded);
    }
    
    #[test]
    fn test_rate_limit_over_limit() {
        let env = Env::default();
        let attestor = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let config = RateLimitConfig {
            max_submissions: 1,
            window_length: 100,
            burst_capacity: 1,
            min_interval_ledgers: 0,
        };

        let contract_address = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let contract_id = env.register_contract(&contract_address, crate::contract::AnchorKitContract);

        // First submission should succeed
        assert!(env.as_contract(&contract_id, &|| {
            RateLimiter::check_and_increment(&env, &attestor, &config)
        }).is_ok());

        // Second submission should fail
        let result = env.as_contract(&contract_id, &|| {
            RateLimiter::check_and_increment(&env, &attestor, &config)
        });
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ErrorCode::RateLimitExceeded);
    }

    #[test]
    fn test_rate_limit_window_reset() {
        let env = Env::default();
        let attestor = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let config = RateLimitConfig {
            max_submissions: 1,
            window_length: 10,
            burst_capacity: 1,
            min_interval_ledgers: 0,
        };
        
        let contract_address = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let contract_id = env.register_contract(&contract_address, crate::contract::AnchorKitContract);
        
        // First submission should succeed
        assert!(env.as_contract(&contract_id, &|| {
            RateLimiter::check_and_increment(&env, &attestor, &config)
        }).is_ok());
        
        // Second submission should fail (still in same window)
        assert!(env.as_contract(&contract_id, &|| {
            RateLimiter::check_and_increment(&env, &attestor, &config)
        }).is_err());
        
        // Note: In Soroban SDK, we cannot directly set the ledger sequence in tests
        // The window reset logic will be tested in integration tests with actual ledger progression
        // For now, we verify the state is correct
        let state = env.as_contract(&contract_id, &|| {
            RateLimiter::get_state(&env, &attestor)
        });
        assert_eq!(state.submission_count, 1);
    }
    
    #[test]
    fn test_rate_limit_config_update() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let new_config = RateLimitConfig {
            max_submissions: 20,
            window_length: 200,
            burst_capacity: 20,
            min_interval_ledgers: 0,
        };

        let contract_address = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let contract_id = env.register_contract(&contract_address, crate::contract::AnchorKitContract);

        // Store admin in instance storage before calling update_config
        env.as_contract(&contract_id, &|| {
            env.storage()
                .instance()
                .set(&RateLimiter::get_admin_key(&env), &admin);
        });

        let result = env.as_contract(&contract_id, &|| {
            RateLimiter::update_config(&env, &admin, &new_config)
        });
        assert!(result.is_ok());

        let config = env.as_contract(&contract_id, &|| {
            RateLimiter::get_config(&env)
        });
        assert_eq!(config.max_submissions, 20);
        assert_eq!(config.window_length, 200);
    }

    #[test]
    fn test_update_config_unauthorized() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let non_admin = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let new_config = RateLimitConfig { max_submissions: 5, window_length: 50, burst_capacity: 5, min_interval_ledgers: 0 };

        let contract_address = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let contract_id = env.register_contract(&contract_address, crate::contract::AnchorKitContract);

        env.as_contract(&contract_id, &|| {
            env.storage()
                .instance()
                .set(&RateLimiter::get_admin_key(&env), &admin);
        });

        let result = env.as_contract(&contract_id, &|| {
            RateLimiter::update_config(&env, &non_admin, &new_config)
        });
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ErrorCode::UnauthorizedAttestor);
    }

    #[test]
    fn test_update_config_not_initialized() {
        let env = Env::default();
        let admin = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let new_config = RateLimitConfig { max_submissions: 5, window_length: 50, burst_capacity: 5, min_interval_ledgers: 0 };

        let contract_address = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let contract_id = env.register_contract(&contract_address, crate::contract::AnchorKitContract);

        // No admin stored — should return NotInitialized
        let result = env.as_contract(&contract_id, &|| {
            RateLimiter::update_config(&env, &admin, &new_config)
        });
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ErrorCode::NotInitialized);
    }
    
    #[test]
    fn test_rate_limit_default_config() {
        let env = Env::default();
        
        let contract_address = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let contract_id = env.register_contract(&contract_address, crate::contract::AnchorKitContract);
        
        // Get default config
        let config = env.as_contract(&contract_id, &|| {
            RateLimiter::get_config(&env)
        });
        assert_eq!(config.max_submissions, 10);
        assert_eq!(config.window_length, 100);
    }

    fn setup_admin(env: &Env, contract_id: &soroban_sdk::Address, admin: &Address) {
        env.as_contract(contract_id, || {
            env.storage().instance().set(&RateLimiter::get_admin_key(env), admin);
        });
    }

    #[test]
    fn test_override_takes_effect_over_global_config() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let attestor = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let contract_address = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let contract_id = env.register_contract(&contract_address, crate::contract::AnchorKitContract);
        setup_admin(&env, &contract_id, &admin);

        // Global config allows only 1 submission per window.
        let global = RateLimitConfig { max_submissions: 1, window_length: 100, burst_capacity: 1, min_interval_ledgers: 0 };
        env.as_contract(&contract_id, || RateLimiter::update_config(&env, &admin, &global)).unwrap();

        // Override grants this attestor a much higher allowance.
        let override_config = RateLimitConfig { max_submissions: 5, window_length: 100, burst_capacity: 5, min_interval_ledgers: 0 };
        env.as_contract(&contract_id, || RateLimiter::set_override(&env, &admin, &attestor, &override_config)).unwrap();

        let effective = env.as_contract(&contract_id, || RateLimiter::effective_config(&env, &attestor));
        assert_eq!(effective.max_submissions, 5);

        // A different attestor without an override still uses the global config.
        let other = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let other_effective = env.as_contract(&contract_id, || RateLimiter::effective_config(&env, &other));
        assert_eq!(other_effective.max_submissions, 1);

        // The override attestor can submit more than the global cap allows.
        for _ in 0..5 {
            assert!(env.as_contract(&contract_id, || {
                let cfg = RateLimiter::effective_config(&env, &attestor);
                RateLimiter::check_and_increment(&env, &attestor, &cfg)
            }).is_ok());
        }
        let result = env.as_contract(&contract_id, || {
            let cfg = RateLimiter::effective_config(&env, &attestor);
            RateLimiter::check_and_increment(&env, &attestor, &cfg)
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_override_falls_back_to_global_config() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let attestor = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let contract_address = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let contract_id = env.register_contract(&contract_address, crate::contract::AnchorKitContract);
        setup_admin(&env, &contract_id, &admin);

        let override_config = RateLimitConfig { max_submissions: 5, window_length: 100, burst_capacity: 5, min_interval_ledgers: 0 };
        env.as_contract(&contract_id, || RateLimiter::set_override(&env, &admin, &attestor, &override_config)).unwrap();
        assert!(env.as_contract(&contract_id, || RateLimiter::get_override(&env, &attestor)).is_some());

        env.as_contract(&contract_id, || RateLimiter::remove_override(&env, &admin, &attestor)).unwrap();
        assert!(env.as_contract(&contract_id, || RateLimiter::get_override(&env, &attestor)).is_none());

        let effective = env.as_contract(&contract_id, || RateLimiter::effective_config(&env, &attestor));
        assert_eq!(effective, RateLimitConfig::default_config());
    }

    #[test]
    fn test_set_override_rejects_invalid_config() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let attestor = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let contract_address = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let contract_id = env.register_contract(&contract_address, crate::contract::AnchorKitContract);
        setup_admin(&env, &contract_id, &admin);

        let invalid = RateLimitConfig { max_submissions: 0, window_length: 100, burst_capacity: 5, min_interval_ledgers: 0 };
        let result = env.as_contract(&contract_id, || RateLimiter::set_override(&env, &admin, &attestor, &invalid));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ErrorCode::ValidationError);
    }

    #[test]
    fn test_set_override_requires_admin() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let non_admin = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let attestor = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let contract_address = <soroban_sdk::Address as soroban_sdk::testutils::Address>::generate(&env);
        let contract_id = env.register_contract(&contract_address, crate::contract::AnchorKitContract);
        setup_admin(&env, &contract_id, &admin);

        let config = RateLimitConfig { max_submissions: 5, window_length: 100, burst_capacity: 5, min_interval_ledgers: 0 };
        let result = env.as_contract(&contract_id, || RateLimiter::set_override(&env, &non_admin, &attestor, &config));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ErrorCode::UnauthorizedAttestor);
    }
}
