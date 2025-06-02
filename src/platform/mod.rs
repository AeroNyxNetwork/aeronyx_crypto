//! Platform-specific secure storage implementations

#[cfg(target_os = "ios")]
pub mod ios;

#[cfg(target_os = "android")]
pub mod android;

#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub mod generic;

use crate::errors::CryptoError;

/// Platform-specific secure key storage
pub trait SecureStorage: Send + Sync {
    /// Store a key securely
    fn store_key(&self, key_id: &str, key_data: &[u8]) -> Result<(), CryptoError>;
    
    /// Retrieve a key
    fn get_key(&self, key_id: &str) -> Result<Vec<u8>, CryptoError>;
    
    /// Delete a key
    fn delete_key(&self, key_id: &str) -> Result<(), CryptoError>;
    
    /// Check if key exists
    fn key_exists(&self, key_id: &str) -> Result<bool, CryptoError>;
}

/// Get platform-specific storage implementation
pub fn get_secure_storage() -> Box<dyn SecureStorage> {
    #[cfg(target_os = "ios")]
    return Box::new(ios::KeychainStorage::new());
    
    #[cfg(target_os = "android")]
    return Box::new(android::KeystoreStorage::new());
    
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    return Box::new(generic::FileStorage::new());
}
