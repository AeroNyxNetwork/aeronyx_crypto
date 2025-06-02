//! AeroNyx Crypto Library - Mobile-compatible cryptographic operations
//! Fully compatible with existing AeroNyx node implementation

// Re-export existing modules
mod crypto;
mod errors;
mod ffi;

// New enhanced modules
mod secure_memory;
mod key_derivation;
mod crypto_provider;
mod standards;
mod simd;

// Re-export existing public interface
pub use crypto::*;
pub use errors::*;
pub use ffi::*;

// Export new enhanced features
pub use secure_memory::{SecureBuffer, secure_random};
pub use key_derivation::{HierarchicalKeyDerivation, PathComponent};
pub use crypto_provider::{CryptoProvider, CRYPTO_PROVIDER};
pub use standards::ComplianceChecker;

// Compatibility layer for AeroNyx node
pub mod compat {
    use super::*;
    
    /// Encrypt session key with flexible algorithm (matching node's flexible_encryption.rs)
    pub fn encrypt_session_key_flexible(
        session_key: &[u8],
        shared_secret: &[u8],
        preferred_algorithm: &str,
    ) -> Result<(Vec<u8>, Vec<u8>, String), CryptoError> {
        match preferred_algorithm {
            "chacha20-poly1305" => {
                let (encrypted, nonce) = encrypt_chacha20(session_key, shared_secret)?;
                Ok((encrypted, nonce, "chacha20-poly1305".to_string()))
            }
            "aes-256-gcm" => {
                let (encrypted, nonce) = encrypt_aes_gcm(session_key, shared_secret, None)?;
                Ok((encrypted, nonce, "aes-256-gcm".to_string()))
            }
            _ => Err(CryptoError::InvalidFormat(format!("Unsupported algorithm: {}", preferred_algorithm)))
        }
    }
    
    /// Decrypt with flexible algorithm (matching node's flexible_encryption.rs)
    pub fn decrypt_flexible(
        encrypted: &[u8],
        nonce: &[u8],
        key: &[u8],
        algorithm: &str,
        aad: Option<&[u8]>,
        _fallback: bool,
    ) -> Result<Vec<u8>, CryptoError> {
        match algorithm {
            "chacha20-poly1305" => decrypt_chacha20(encrypted, key, nonce),
            "aes-256-gcm" => decrypt_aes_gcm(encrypted, key, nonce, aad),
            _ => Err(CryptoError::InvalidFormat(format!("Unsupported algorithm: {}", algorithm)))
        }
    }
    
    /// Generate shared secret for ECDH (matching node's keys.rs)
    pub fn generate_shared_secret(
        local_private: &[u8],
        remote_public: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        derive_shared_secret(local_private, remote_public)
    }
}
