//! Extensions that enhance but don't break existing functionality

use crate::{crypto, errors::CryptoError};
use solana_sdk::signature::{Keypair, Signer};

/// Extended crypto operations for mobile platforms
pub struct MobileCrypto;

impl MobileCrypto {
    /// Generate a Solana-compatible keypair with secure storage hints
    pub fn generate_mobile_keypair() -> Result<MobileKeypair, CryptoError> {
        let (private_key, public_key) = crypto::generate_keypair()?;
        
        Ok(MobileKeypair {
            private_key,
            public_key,
            storage_hint: StorageHint::SecureEnclave,
        })
    }
    
    /// Create a challenge for mobile authentication (compatible with node's challenge.rs)
    pub fn create_auth_challenge() -> Vec<u8> {
        let mut challenge = vec![0u8; 32]; // CHALLENGE_SIZE from constants.rs
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut challenge);
        challenge
    }
    
    /// Verify challenge response (compatible with node's challenge.rs)
    pub fn verify_challenge_response(
        challenge: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, CryptoError> {
        crypto::verify_signature(public_key, challenge, signature)
    }
}

pub struct MobileKeypair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub storage_hint: StorageHint,
}

pub enum StorageHint {
    SecureEnclave,
    Keychain,
    AndroidKeystore,
}

/// Session key manager for mobile (compatible with node's session.rs)
pub struct MobileSessionManager {
    sessions: std::collections::HashMap<String, Vec<u8>>,
}

impl MobileSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
        }
    }
    
    /// Generate session key (matching node's SessionKeyManager::generate_key)
    pub fn generate_session_key() -> Vec<u8> {
        let mut key = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        key
    }
    
    /// Store session key (matching node's SessionKeyManager::store_key)
    pub fn store_key(&mut self, client_id: &str, key: Vec<u8>) {
        self.sessions.insert(client_id.to_string(), key);
    }
    
    /// Get session key (matching node's SessionKeyManager::get_key)
    pub fn get_key(&self, client_id: &str) -> Option<&Vec<u8>> {
        self.sessions.get(client_id)
    }
}
