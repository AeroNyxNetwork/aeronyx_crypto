//! Pluggable crypto provider architecture for algorithm flexibility
//! Allows runtime selection and custom algorithm implementations

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use crate::errors::CryptoError;

/// Trait for symmetric encryption algorithms
pub trait SymmetricCipher: Send + Sync {
    /// Encrypt data with optional AAD
    fn encrypt(
        &self,
        plaintext: &[u8],
        key: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError>;
    
    /// Decrypt data with optional AAD
    fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError>;
    
    /// Get the required key size in bytes
    fn key_size(&self) -> usize;
    
    /// Get the nonce size in bytes
    fn nonce_size(&self) -> usize;
}

/// Trait for digital signature algorithms
pub trait SignatureAlgorithm: Send + Sync {
    /// Generate a new keypair
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError>;
    
    /// Sign a message
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError>;
    
    /// Verify a signature
    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError>;
}

/// Trait for key agreement algorithms
pub trait KeyAgreement: Send + Sync {
    /// Perform key agreement
    fn agree(
        &self,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}

/// Crypto provider registry
pub struct CryptoProvider {
    ciphers: Arc<RwLock<HashMap<String, Box<dyn SymmetricCipher>>>>,
    signatures: Arc<RwLock<HashMap<String, Box<dyn SignatureAlgorithm>>>>,
    key_agreements: Arc<RwLock<HashMap<String, Box<dyn KeyAgreement>>>>,
}

impl CryptoProvider {
    /// Create a new crypto provider with default algorithms
    pub fn new() -> Self {
        let provider = Self {
            ciphers: Arc::new(RwLock::new(HashMap::new())),
            signatures: Arc::new(RwLock::new(HashMap::new())),
            key_agreements: Arc::new(RwLock::new(HashMap::new())),
        };
        
        // Register default algorithms
        provider.register_defaults();
        provider
    }
    
    /// Register default algorithms
    fn register_defaults(&self) {
        use crate::algorithms::*;
        
        // Register ciphers
        self.register_cipher("chacha20-poly1305", Box::new(ChaCha20Poly1305Provider));
        self.register_cipher("aes-256-gcm", Box::new(AesGcmProvider));
        self.register_cipher("xchacha20-poly1305", Box::new(XChaCha20Poly1305Provider));
        
        // Register signatures
        self.register_signature("ed25519", Box::new(Ed25519Provider));
        self.register_signature("ed448", Box::new(Ed448Provider));
        
        // Register key agreements
        self.register_key_agreement("x25519", Box::new(X25519Provider));
        self.register_key_agreement("x448", Box::new(X448Provider));
    }
    
    /// Register a custom cipher
    pub fn register_cipher(&self, name: &str, cipher: Box<dyn SymmetricCipher>) {
        self.ciphers.write().unwrap().insert(name.to_string(), cipher);
    }
    
    /// Register a custom signature algorithm
    pub fn register_signature(&self, name: &str, algorithm: Box<dyn SignatureAlgorithm>) {
        self.signatures.write().unwrap().insert(name.to_string(), algorithm);
    }
    
    /// Register a custom key agreement algorithm
    pub fn register_key_agreement(&self, name: &str, algorithm: Box<dyn KeyAgreement>) {
        self.key_agreements.write().unwrap().insert(name.to_string(), algorithm);
    }
    
    /// Get a cipher by name
    pub fn get_cipher(&self, name: &str) -> Option<Arc<dyn SymmetricCipher>> {
        self.ciphers.read().unwrap().get(name).map(|c| Arc::from(c.as_ref()))
    }
    
    /// Get a signature algorithm by name
    pub fn get_signature(&self, name: &str) -> Option<Arc<dyn SignatureAlgorithm>> {
        self.signatures.read().unwrap().get(name).map(|s| Arc::from(s.as_ref()))
    }
    
    /// Get a key agreement algorithm by name
    pub fn get_key_agreement(&self, name: &str) -> Option<Arc<dyn KeyAgreement>> {
        self.key_agreements.read().unwrap().get(name).map(|k| Arc::from(k.as_ref()))
    }
}

/// Algorithm implementations module
mod algorithms {
    use super::*;
    
    /// ChaCha20-Poly1305 implementation
    pub struct ChaCha20Poly1305Provider;
    
    impl SymmetricCipher for ChaCha20Poly1305Provider {
        fn encrypt(
            &self,
            plaintext: &[u8],
            key: &[u8],
            aad: Option<&[u8]>,
        ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
            crate::crypto::encrypt_chacha20(plaintext, key)
        }
        
        fn decrypt(
            &self,
            ciphertext: &[u8],
            key: &[u8],
            nonce: &[u8],
            _aad: Option<&[u8]>,
        ) -> Result<Vec<u8>, CryptoError> {
            crate::crypto::decrypt_chacha20(ciphertext, key, nonce)
        }
        
        fn key_size(&self) -> usize { 32 }
        fn nonce_size(&self) -> usize { 12 }
    }
    
    /// AES-256-GCM implementation
    pub struct AesGcmProvider;
    
    impl SymmetricCipher for AesGcmProvider {
        fn encrypt(
            &self,
            plaintext: &[u8],
            key: &[u8],
            aad: Option<&[u8]>,
        ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
            crate::crypto::encrypt_aes_gcm(plaintext, key, aad)
        }
        
        fn decrypt(
            &self,
            ciphertext: &[u8],
            key: &[u8],
            nonce: &[u8],
            aad: Option<&[u8]>,
        ) -> Result<Vec<u8>, CryptoError> {
            crate::crypto::decrypt_aes_gcm(ciphertext, key, nonce, aad)
        }
        
        fn key_size(&self) -> usize { 32 }
        fn nonce_size(&self) -> usize { 12 }
    }
    
    /// XChaCha20-Poly1305 implementation (extended nonce)
    pub struct XChaCha20Poly1305Provider;
    
    impl SymmetricCipher for XChaCha20Poly1305Provider {
        fn encrypt(
            &self,
            plaintext: &[u8],
            key: &[u8],
            aad: Option<&[u8]>,
        ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
            // Implementation using xchacha20poly1305 crate
            unimplemented!("XChaCha20-Poly1305 encryption")
        }
        
        fn decrypt(
            &self,
            ciphertext: &[u8],
            key: &[u8],
            nonce: &[u8],
            aad: Option<&[u8]>,
        ) -> Result<Vec<u8>, CryptoError> {
            unimplemented!("XChaCha20-Poly1305 decryption")
        }
        
        fn key_size(&self) -> usize { 32 }
        fn nonce_size(&self) -> usize { 24 } // Extended nonce
    }
    
    /// Ed25519 signature implementation
    pub struct Ed25519Provider;
    
    impl SignatureAlgorithm for Ed25519Provider {
        fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
            crate::crypto::generate_keypair()
        }
        
        fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
            crate::crypto::sign_message(private_key, message)
        }
        
        fn verify(
            &self,
            public_key: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool, CryptoError> {
            crate::crypto::verify_signature(public_key, message, signature)
        }
    }
    
    /// Ed448 signature implementation (placeholder)
    pub struct Ed448Provider;
    
    impl SignatureAlgorithm for Ed448Provider {
        fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
            unimplemented!("Ed448 keypair generation")
        }
        
        fn sign(&self, _private_key: &[u8], _message: &[u8]) -> Result<Vec<u8>, CryptoError> {
            unimplemented!("Ed448 signing")
        }
        
        fn verify(
            &self,
            _public_key: &[u8],
            _message: &[u8],
            _signature: &[u8],
        ) -> Result<bool, CryptoError> {
            unimplemented!("Ed448 verification")
        }
    }
    
    /// X25519 key agreement implementation
    pub struct X25519Provider;
    
    impl KeyAgreement for X25519Provider {
        fn agree(
            &self,
            private_key: &[u8],
            public_key: &[u8],
        ) -> Result<Vec<u8>, CryptoError> {
            crate::crypto::derive_shared_secret(private_key, public_key)
        }
    }
    
    /// X448 key agreement implementation (placeholder)
    pub struct X448Provider;
    
    impl KeyAgreement for X448Provider {
        fn agree(
            &self,
            _private_key: &[u8],
            _public_key: &[u8],
        ) -> Result<Vec<u8>, CryptoError> {
            unimplemented!("X448 key agreement")
        }
    }
}

/// Global crypto provider instance
lazy_static::lazy_static! {
    pub static ref CRYPTO_PROVIDER: CryptoProvider = CryptoProvider::new();
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_provider_registration() {
        let provider = CryptoProvider::new();
        
        // Default algorithms should be registered
        assert!(provider.get_cipher("chacha20-poly1305").is_some());
        assert!(provider.get_cipher("aes-256-gcm").is_some());
        assert!(provider.get_signature("ed25519").is_some());
        assert!(provider.get_key_agreement("x25519").is_some());
    }
}
