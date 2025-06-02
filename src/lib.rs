//! AeroNyx Crypto Library - Production-grade cryptographic operations for DePIN network
//! 
//! This library provides secure, cross-platform cryptographic primitives optimized for
//! decentralized privacy computing networks. It supports mobile platforms (iOS/Android),
//! desktop platforms (Windows/macOS/Linux), and provides hardware acceleration where available.
//! 
//! # Features
//! 
//! - **Cross-platform**: Native support for Windows, macOS, Linux, iOS, and Android
//! - **Hardware acceleration**: AES-NI, AVX2, NEON optimizations
//! - **Secure storage**: Platform-specific key storage (Keychain, Credential Manager, etc.)
//! - **Memory safety**: Automatic zeroing of sensitive data
//! - **Standards compliant**: FIPS 140-3, NIST SP 800-57 compliance
//! - **Mobile optimized**: Power-aware encryption and network-adaptive algorithms
//! 
//! # Example
//! 
//! ```rust
//! use aeronyx_crypto::{generate_keypair, sign_message, verify_signature};
//! 
//! // Generate a keypair
//! let (private_key, public_key) = generate_keypair().unwrap();
//! 
//! // Sign a message
//! let message = b"Hello, AeroNyx!";
//! let signature = sign_message(&private_key, message).unwrap();
//! 
//! // Verify the signature
//! let is_valid = verify_signature(&public_key, message, &signature).unwrap();
//! assert!(is_valid);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![forbid(unsafe_code)] // Override with allow where necessary
#![deny(
    clippy::all,
    clippy::cargo,
    clippy::nursery,
    clippy::pedantic,
    nonstandard_style,
    rust_2018_idioms,
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc
)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

// Core modules
mod crypto;
mod errors;
mod secure_memory;
mod key_derivation;
mod crypto_provider;
mod standards;
mod protocol_support;
mod crypto_extensions;

// Conditional modules
#[cfg(feature = "ffi")]
mod ffi;

// SIMD optimizations
#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
mod simd;

// Authentication modules
/// Authentication and access control subsystem
pub mod auth {
    //! Authentication components for AeroNyx nodes
    
    pub mod challenge;
    pub mod acl;
    pub mod manager;
    
    pub use challenge::{
        Challenge, ChallengeManager, 
        CHALLENGE_SIZE, CHALLENGE_TIMEOUT, MAX_CHALLENGES_PER_IP
    };
    pub use acl::{
        AccessControlList, AccessControlEntry, AccessControlManager, 
        Permissions, ResourceQuota
    };
    pub use manager::{
        AuthManager, AuthConfig, AuthStats
    };
}

// Protocol modules
/// Protocol implementation for AeroNyx network
pub mod protocol {
    //! Protocol types and state management
    
    pub mod state;
    
    pub use state::{ClientState, ClientSession, StateManager};
    
    // Re-export protocol types
    pub use crate::protocol_support::{
        PacketType, ProtocolCrypto
    };
}

// Platform-specific modules
/// Platform-specific implementations
pub mod platform;

// Transport optimization
/// Transport layer optimizations for mobile networks
pub mod transport;

// Power management
/// Power-aware cryptographic operations
#[cfg(feature = "power")]
pub mod power;

// Examples module (only included in debug/test builds)
#[cfg(any(debug_assertions, test, doc))]
pub mod examples;

// Benchmarks module
#[cfg(feature = "benchmarks")]
mod benchmarks;

// Re-export core cryptographic functions
pub use crypto::{
    // Key generation
    generate_keypair,
    get_public_key_base58,
    
    // Encryption/Decryption
    encrypt_chacha20,
    decrypt_chacha20,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    
    // Signing/Verification
    sign_message,
    verify_signature,
    
    // Key exchange
    ed25519_to_x25519_public,
    ed25519_to_x25519_private,
    derive_shared_secret,
};

// Re-export error types
pub use errors::{CryptoError, Result};

// Re-export FFI interface
#[cfg(feature = "ffi")]
pub use ffi::*;

// Export enhanced features
pub use secure_memory::{SecureBuffer, secure_random};
pub use key_derivation::{HierarchicalKeyDerivation, PathComponent, password};
pub use crypto_provider::{
    CryptoProvider, SymmetricCipher, SignatureAlgorithm, KeyAgreement,
    CRYPTO_PROVIDER
};
pub use standards::{ComplianceChecker, StandardCompliance};
pub use crypto_extensions::{MobileCrypto, MobileKeypair, MobileSessionManager, StorageHint};

// Add missing password module export
pub use key_derivation::password::derive_key_from_password;

// Version information
/// Library version string
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Git commit hash
pub const GIT_HASH: &str = option_env!("AERONYX_GIT_HASH").unwrap_or("unknown");

/// Build timestamp
pub const BUILD_TIME: &str = option_env!("AERONYX_BUILD_TIME").unwrap_or("unknown");

/// Get comprehensive version information
#[must_use]
pub fn version_info() -> VersionInfo {
    VersionInfo {
        version: VERSION,
        git_hash: GIT_HASH,
        build_time: BUILD_TIME,
        platform: platform::get_platform_info(),
        features: get_enabled_features(),
    }
}

/// Version and platform information
#[derive(Debug, Clone)]
pub struct VersionInfo {
    /// Library version
    pub version: &'static str,
    /// Git commit hash
    pub git_hash: &'static str,
    /// Build timestamp
    pub build_time: &'static str,
    /// Platform information
    pub platform: platform::PlatformInfo,
    /// Enabled features
    pub features: Vec<&'static str>,
}

/// Get list of enabled features
fn get_enabled_features() -> Vec<&'static str> {
    let mut features = Vec::new();
    
    #[cfg(feature = "serde")]
    features.push("serde");
    
    #[cfg(feature = "ffi")]
    features.push("ffi");
    
    #[cfg(feature = "wasm")]
    features.push("wasm");
    
    #[cfg(feature = "benchmarks")]
    features.push("benchmarks");
    
    #[cfg(feature = "std")]
    features.push("std");
    
    #[cfg(feature = "power")]
    features.push("power");
    
    #[cfg(feature = "logging")]
    features.push("logging");
    
    features
}

// Compatibility layer for AeroNyx node
/// Compatibility layer for seamless integration with AeroNyx nodes
pub mod compat {
    //! Compatibility functions for AeroNyx node integration
    
    use super::*;
    
    /// Encryption algorithms supported by the network
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum EncryptionAlgorithm {
        /// ChaCha20-Poly1305 AEAD
        ChaCha20Poly1305,
        /// AES-256-GCM AEAD
        Aes256Gcm,
    }
    
    impl EncryptionAlgorithm {
        /// Convert to string representation
        #[must_use]
        pub const fn as_str(&self) -> &'static str {
            match self {
                Self::ChaCha20Poly1305 => "chacha20-poly1305",
                Self::Aes256Gcm => "aes-256-gcm",
            }
        }
        
        /// Parse from string
        #[must_use]
        pub fn from_str(s: &str) -> Option<Self> {
            match s {
                "chacha20-poly1305" => Some(Self::ChaCha20Poly1305),
                "aes-256-gcm" => Some(Self::Aes256Gcm),
                _ => None,
            }
        }
    }
    
    /// Encrypt session key with flexible algorithm (matching node's flexible_encryption.rs)
    pub fn encrypt_session_key_flexible(
        session_key: &[u8],
        shared_secret: &[u8],
        preferred_algorithm: &str,
    ) -> Result<(Vec<u8>, Vec<u8>, String)> {
        let algorithm = EncryptionAlgorithm::from_str(preferred_algorithm)
            .ok_or_else(|| CryptoError::InvalidFormat(
                format!("Unsupported algorithm: {}", preferred_algorithm)
            ))?;
        
        match algorithm {
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                let (encrypted, nonce) = encrypt_chacha20(session_key, shared_secret)?;
                Ok((encrypted, nonce, algorithm.as_str().to_string()))
            }
            EncryptionAlgorithm::Aes256Gcm => {
                let (encrypted, nonce) = encrypt_aes_gcm(session_key, shared_secret, None)?;
                Ok((encrypted, nonce, algorithm.as_str().to_string()))
            }
        }
    }
    
    /// Decrypt with flexible algorithm (matching node's flexible_encryption.rs)
    pub fn decrypt_flexible(
        encrypted: &[u8],
        nonce: &[u8],
        key: &[u8],
        algorithm: &str,
        aad: Option<&[u8]>,
        fallback: bool,
    ) -> Result<Vec<u8>> {
        let algo = EncryptionAlgorithm::from_str(algorithm);
        
        match algo {
            Some(EncryptionAlgorithm::ChaCha20Poly1305) => {
                decrypt_chacha20(encrypted, key, nonce)
            }
            Some(EncryptionAlgorithm::Aes256Gcm) => {
                decrypt_aes_gcm(encrypted, key, nonce, aad)
            }
            None if fallback => {
                // Try both algorithms if fallback is enabled
                decrypt_chacha20(encrypted, key, nonce)
                    .or_else(|_| decrypt_aes_gcm(encrypted, key, nonce, aad))
            }
            None => {
                Err(CryptoError::InvalidFormat(
                    format!("Unsupported algorithm: {}", algorithm)
                ))
            }
        }
    }
    
    /// Generate shared secret for ECDH (matching node's keys.rs)
    pub fn generate_shared_secret(
        local_private: &[u8],
        remote_public: &[u8],
    ) -> Result<Vec<u8>> {
        derive_shared_secret(local_private, remote_public)
    }
    
    /// Create authentication challenge (matching node's challenge.rs)
    #[must_use]
    pub fn create_auth_challenge() -> Vec<u8> {
        crypto_extensions::MobileCrypto::create_auth_challenge()
    }
    
    /// Verify challenge response (matching node's challenge.rs)
    pub fn verify_challenge_response(
        challenge: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool> {
        crypto_extensions::MobileCrypto::verify_challenge_response(
            challenge,
            signature,
            public_key,
        )
    }
}

use std::sync::atomic::{AtomicBool, Ordering};

static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the library with platform-specific features
/// 
/// This function should be called once at application startup to ensure
/// all platform-specific components are properly initialized.
/// 
/// # Errors
/// 
/// Returns an error if platform initialization fails.
pub fn initialize() -> Result<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(()); // Already initialized
    }
    
    // Initialize logging if enabled
    #[cfg(all(feature = "std", feature = "logging"))]
    {
        use std::sync::Once;
        static INIT: Once = Once::new();
        
        INIT.call_once(|| {
            let _ = env_logger::builder()
                .filter_level(log::LevelFilter::Info)
                .format_timestamp_millis()
                .try_init();
        });
    }
    
    // Platform-specific initialization
    #[cfg(target_os = "windows")]
    initialize_windows()?;
    
    #[cfg(target_os = "android")]
    initialize_android()?;
    
    #[cfg(target_os = "ios")]
    initialize_ios()?;
    
    // Initialize SIMD if available
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
    {
        let _ = simd::get_simd_impl();
    }
    
    // Verify crypto provider is available
    let _ = CRYPTO_PROVIDER.get_cipher("chacha20-poly1305")
        .ok_or_else(|| CryptoError::InvalidFormat("Crypto provider initialization failed".into()))?;
    
    // Run self-test in debug mode
    #[cfg(debug_assertions)]
    self_test()?;
    
    Ok(())
}

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn initialize_windows() -> Result<()> {
    // Ensure Windows crypto providers are available
    use winapi::um::wincrypt::*;
    use std::ptr;
    
    unsafe {
        let mut h_prov: HCRYPTPROV = 0;
        let result = CryptAcquireContextW(
            &mut h_prov,
            ptr::null(),
            ptr::null(),
            PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT,
        );
        
        if result == 0 {
            return Err(CryptoError::InvalidFormat(
                "Failed to initialize Windows crypto provider".into()
            ));
        }
        
        let _ = CryptReleaseContext(h_prov, 0);
    }
    
    Ok(())
}

#[cfg(target_os = "android")]
fn initialize_android() -> Result<()> {
    // Android-specific initialization would go here
    // This is a placeholder for JNI initialization if needed
    Ok(())
}

#[cfg(target_os = "ios")]
fn initialize_ios() -> Result<()> {
    // iOS-specific initialization would go here
    Ok(())
}

/// Global library configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Enable hardware acceleration
    pub use_hardware_acceleration: bool,
    /// Enable power saving mode
    pub power_saving_mode: bool,
    /// Maximum memory usage in bytes
    pub max_memory_usage: Option<usize>,
    /// Custom secure storage path
    pub secure_storage_path: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            use_hardware_acceleration: true,
            power_saving_mode: false,
            max_memory_usage: None,
            secure_storage_path: None,
        }
    }
}

/// Configure global library settings
pub fn configure(config: Config) -> Result<()> {
    // Apply configuration settings
    #[cfg(feature = "power")]
    if config.power_saving_mode {
        use crate::power::PowerAwareCrypto;
        use std::sync::Arc;
        let power_manager = Arc::new(PowerAwareCrypto::new());
        power_manager.set_low_power_mode(true);
    }
    
    // Configure secure storage path if provided
    #[cfg(feature = "std")]
    if let Some(path) = config.secure_storage_path {
        std::env::set_var("AERONYX_SECURE_STORAGE_PATH", path);
    }
    
    Ok(())
}

/// Perform self-tests to verify cryptographic operations
/// 
/// This function runs a comprehensive test suite to ensure all
/// cryptographic operations are working correctly.
pub fn self_test() -> Result<()> {
    // Test key generation
    let (private_key, public_key) = generate_keypair()?;
    
    // Test signing and verification
    let message = b"self test message";
    let signature = sign_message(&private_key, message)?;
    let is_valid = verify_signature(&public_key, message, &signature)?;
    if !is_valid {
        return Err(CryptoError::AuthenticationFailed);
    }
    
    // Test encryption/decryption
    let key = [0u8; 32];
    let plaintext = b"test plaintext";
    
    // Test ChaCha20-Poly1305
    let (ciphertext, nonce) = encrypt_chacha20(plaintext, &key)?;
    let decrypted = decrypt_chacha20(&ciphertext, &key, &nonce)?;
    if decrypted != plaintext {
        return Err(CryptoError::DecryptionFailed("ChaCha20 self-test failed".into()));
    }
    
    // Test AES-GCM
    let (ciphertext, nonce) = encrypt_aes_gcm(plaintext, &key, None)?;
    let decrypted = decrypt_aes_gcm(&ciphertext, &key, &nonce, None)?;
    if decrypted != plaintext {
        return Err(CryptoError::DecryptionFailed("AES-GCM self-test failed".into()));
    }
    
    // Test key derivation
    let shared_secret = derive_shared_secret(&private_key, &public_key)?;
    if shared_secret.is_empty() {
        return Err(CryptoError::KeyError("Key derivation failed".into()));
    }
    
    // Test secure memory
    let secure_buf = SecureBuffer::<u8>::from_vec(vec![1, 2, 3, 4, 5]);
    if secure_buf.len() != 5 {
        return Err(CryptoError::InvalidFormat("Secure buffer test failed".into()));
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_version_info() {
        let info = version_info();
        assert!(!info.version.is_empty());
        assert!(!info.platform.os.is_empty());
    }
    
    #[test]
    fn test_self_test() {
        assert!(self_test().is_ok());
    }
    
    #[test]
    fn test_initialize() {
        assert!(initialize().is_ok());
    }
    
    #[test]
    fn test_compat_layer() {
        let (private_key, _public_key) = generate_keypair().unwrap();
        
        // Test flexible encryption
        let session_key = vec![0u8; 32];
        let shared_secret = vec![1u8; 32];
        
        let (encrypted, nonce, algo) = compat::encrypt_session_key_flexible(
            &session_key,
            &shared_secret,
            "chacha20-poly1305",
        ).unwrap();
        
        assert_eq!(algo, "chacha20-poly1305");
        
        let decrypted = compat::decrypt_flexible(
            &encrypted,
            &nonce,
            &shared_secret,
            &algo,
            None,
            false,
        ).unwrap();
        
        assert_eq!(decrypted, session_key);
    }
    
    #[test]
    fn test_auth_integration() {
        use auth::{AuthManager, AuthConfig, AccessControlEntry, Permissions};
        
        let config = AuthConfig::default();
        let auth_manager = AuthManager::new(config);
        
        // Generate test keypair
        let (private_key, public_key) = generate_keypair().unwrap();
        let pubkey_str = bs58::encode(&public_key).into_string();
        
        // Add to ACL
        let entry = AccessControlEntry::new(pubkey_str.clone(), Permissions::full());
        auth_manager.acl_manager().add_entry(entry).unwrap();
        
        // Generate challenge
        let challenge = auth_manager.generate_challenge("127.0.0.1:8080").unwrap();
        
        // Sign challenge
        let signature = sign_message(&private_key, &challenge.challenge).unwrap();
        let sig_str = bs58::encode(&signature).into_string();
        
        // Verify challenge
        let session_id = auth_manager.verify_challenge(
            &challenge.id,
            &sig_str,
            &pubkey_str,
            "127.0.0.1:8080",
        ).unwrap();
        
        // Verify session
        let session = auth_manager.get_session(&session_id).unwrap();
        assert_eq!(session.public_key, pubkey_str);
        assert!(session.state.is_authenticated());
    }
    
    #[test]
    fn test_config() {
        let config = Config {
            use_hardware_acceleration: false,
            power_saving_mode: true,
            max_memory_usage: Some(1024 * 1024 * 100), // 100MB
            secure_storage_path: Some("/tmp/aeronyx".to_string()),
        };
        
        assert!(configure(config).is_ok());
    }
}

// Re-export Result type for convenience
pub type Result<T> = core::result::Result<T, CryptoError>;
