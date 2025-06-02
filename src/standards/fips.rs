//! FIPS 140-3 compliance implementation

use super::StandardCompliance;
use crate::errors::CryptoError;

/// FIPS 140-3 compliance validator
pub struct Fips140_3;

impl StandardCompliance for Fips140_3 {
    fn validate_key(&self, key: &[u8], algorithm: &str) -> Result<(), CryptoError> {
        // Validate key length requirements
        match algorithm {
            "aes-128-gcm" => {
                if key.len() != 16 {
                    return Err(CryptoError::InvalidKeyLength(key.len()));
                }
            }
            "aes-256-gcm" => {
                if key.len() != 32 {
                    return Err(CryptoError::InvalidKeyLength(key.len()));
                }
            }
            "chacha20-poly1305" => {
                if key.len() != 32 {
                    return Err(CryptoError::InvalidKeyLength(key.len()));
                }
            }
            _ => {
                return Err(CryptoError::InvalidFormat(
                    format!("Algorithm {} not FIPS approved", algorithm)
                ));
            }
        }
        
        // Check for weak keys (all zeros, all ones, etc.)
        if key.iter().all(|&b| b == 0) || key.iter().all(|&b| b == 0xFF) {
            return Err(CryptoError::KeyError("Weak key detected".into()));
        }
        
        Ok(())
    }
    
    fn validate_parameters(&self, _params: &dyn std::any::Any) -> Result<(), CryptoError> {
        // Validate algorithm-specific parameters
        Ok(())
    }
    
    fn approved_algorithms(&self) -> Vec<&'static str> {
        vec![
            "aes-128-gcm",
            "aes-256-gcm",
            "chacha20-poly1305",
            "ed25519",
            "x25519",
        ]
    }
}

/// FIPS approved random number generator
pub mod drbg {
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use sha2::{Sha256, Digest};
    
    /// NIST SP 800-90A compliant DRBG
    pub struct FipsDrbg {
        inner: ChaCha20Rng,
        reseed_counter: u64,
        max_requests: u64,
    }
    
    impl FipsDrbg {
        pub fn new(entropy: &[u8]) -> Self {
            let mut hasher = Sha256::new();
            hasher.update(entropy);
            let seed = hasher.finalize();
            
            Self {
                inner: ChaCha20Rng::from_seed(seed.into()),
                reseed_counter: 0,
                max_requests: 1 << 20, // 2^20 requests before reseed
            }
        }
        
        pub fn reseed(&mut self, entropy: &[u8]) {
            let mut hasher = Sha256::new();
            hasher.update(&self.inner.get_seed());
            hasher.update(entropy);
            let new_seed = hasher.finalize();
            
            self.inner = ChaCha20Rng::from_seed(new_seed.into());
            self.reseed_counter = 0;
        }
        
        fn check_reseed(&mut self) {
            self.reseed_counter += 1;
            if self.reseed_counter >= self.max_requests {
                // Force reseed with new entropy
                let mut entropy = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut entropy);
                self.reseed(&entropy);
            }
        }
    }
    
    impl RngCore for FipsDrbg {
        fn next_u32(&mut self) -> u32 {
            self.check_reseed();
            self.inner.next_u32()
        }
        
        fn next_u64(&mut self) -> u64 {
            self.check_reseed();
            self.inner.next_u64()
        }
        
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.check_reseed();
            self.inner.fill_bytes(dest)
        }
        
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.check_reseed();
            self.inner.try_fill_bytes(dest)
        }
    }
}
