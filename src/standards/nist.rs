//! NIST SP 800-57 compliance implementation
//! 
//! Implements key management recommendations from NIST Special Publication 800-57

use super::StandardCompliance;
use crate::errors::CryptoError;
use std::collections::HashMap;

/// NIST SP 800-57 compliance validator
pub struct NistSP800_57 {
    /// Minimum key lengths by algorithm (in bits)
    min_key_lengths: HashMap<&'static str, usize>,
    /// Key strength equivalencies
    strength_equivalencies: HashMap<usize, Vec<(&'static str, usize)>>,
}

impl Default for NistSP800_57 {
    fn default() -> Self {
        let mut min_key_lengths = HashMap::new();
        
        // Symmetric algorithms
        min_key_lengths.insert("aes-128-gcm", 128);
        min_key_lengths.insert("aes-192-gcm", 192);
        min_key_lengths.insert("aes-256-gcm", 256);
        min_key_lengths.insert("chacha20-poly1305", 256);
        
        // Asymmetric algorithms
        min_key_lengths.insert("rsa-2048", 2048);
        min_key_lengths.insert("rsa-3072", 3072);
        min_key_lengths.insert("rsa-4096", 4096);
        min_key_lengths.insert("ed25519", 256);
        min_key_lengths.insert("x25519", 256);
        min_key_lengths.insert("p-256", 256);
        min_key_lengths.insert("p-384", 384);
        min_key_lengths.insert("p-521", 521);
        
        let mut strength_equivalencies = HashMap::new();
        
        // 128-bit security strength
        strength_equivalencies.insert(128, vec![
            ("aes-128-gcm", 128),
            ("rsa-3072", 3072),
            ("p-256", 256),
            ("ed25519", 256),
        ]);
        
        // 192-bit security strength
        strength_equivalencies.insert(192, vec![
            ("aes-192-gcm", 192),
            ("rsa-7680", 7680),
            ("p-384", 384),
        ]);
        
        // 256-bit security strength
        strength_equivalencies.insert(256, vec![
            ("aes-256-gcm", 256),
            ("chacha20-poly1305", 256),
            ("rsa-15360", 15360),
            ("p-521", 521),
        ]);
        
        Self {
            min_key_lengths,
            strength_equivalencies,
        }
    }
}

impl NistSP800_57 {
    /// Create a new NIST validator
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Get the security strength in bits for a given algorithm and key size
    pub fn get_security_strength(&self, algorithm: &str, key_bits: usize) -> usize {
        match algorithm {
            // Symmetric algorithms - security strength equals key size
            "aes-128-gcm" => 128,
            "aes-192-gcm" => 192,
            "aes-256-gcm" | "chacha20-poly1305" => 256,
            
            // ECC algorithms
            "ed25519" | "x25519" | "p-256" => 128,
            "p-384" => 192,
            "p-521" => 256,
            
            // RSA - approximate strength based on key size
            alg if alg.starts_with("rsa-") => {
                match key_bits {
                    2048 => 112,
                    3072 => 128,
                    4096 => 140,
                    7680 => 192,
                    15360 => 256,
                    _ => 0,
                }
            }
            
            _ => 0,
        }
    }
    
    /// Check if key size meets minimum requirements for a target security strength
    pub fn meets_strength_requirement(
        &self,
        algorithm: &str,
        key_bits: usize,
        target_strength: usize,
    ) -> bool {
        self.get_security_strength(algorithm, key_bits) >= target_strength
    }
    
    /// Get recommended algorithms for a given security strength
    pub fn get_recommended_algorithms(&self, security_strength: usize) -> Vec<(&'static str, usize)> {
        self.strength_equivalencies
            .get(&security_strength)
            .cloned()
            .unwrap_or_default()
    }
    
    /// Validate key lifetime based on NIST recommendations
    pub fn validate_key_lifetime(
        &self,
        algorithm: &str,
        key_usage: KeyUsage,
        lifetime_days: u32,
    ) -> Result<(), CryptoError> {
        let max_lifetime = match (algorithm, key_usage) {
            // Symmetric keys
            (alg, KeyUsage::DataEncryption) if alg.contains("aes") || alg.contains("chacha") => {
                365 * 2 // 2 years for data encryption keys
            }
            (alg, KeyUsage::KeyEncryption) if alg.contains("aes") || alg.contains("chacha") => {
                365 * 3 // 3 years for key encryption keys
            }
            
            // Signature keys
            ("ed25519", KeyUsage::DigitalSignature) => 365 * 3, // 3 years
            
            // Key agreement
            ("x25519", KeyUsage::KeyAgreement) => 365 * 2, // 2 years
            
            _ => 365, // Default to 1 year
        };
        
        if lifetime_days > max_lifetime {
            return Err(CryptoError::InvalidFormat(format!(
                "Key lifetime {} days exceeds NIST recommendation of {} days for {} with {}",
                lifetime_days, max_lifetime, algorithm, key_usage.as_str()
            )));
        }
        
        Ok(())
    }
}

/// Key usage types as defined by NIST
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUsage {
    /// Keys used for encrypting data
    DataEncryption,
    /// Keys used for encrypting other keys
    KeyEncryption,
    /// Keys used for digital signatures
    DigitalSignature,
    /// Keys used for key agreement/exchange
    KeyAgreement,
    /// Keys used for authentication
    Authentication,
}

impl KeyUsage {
    /// Get string representation
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::DataEncryption => "data encryption",
            Self::KeyEncryption => "key encryption",
            Self::DigitalSignature => "digital signature",
            Self::KeyAgreement => "key agreement",
            Self::Authentication => "authentication",
        }
    }
}

impl StandardCompliance for NistSP800_57 {
    fn validate_key(&self, key: &[u8], algorithm: &str) -> Result<(), CryptoError> {
        let key_bits = key.len() * 8;
        
        // Check minimum key length
        if let Some(&min_bits) = self.min_key_lengths.get(algorithm) {
            if key_bits < min_bits {
                return Err(CryptoError::InvalidKeyLength(key.len()));
            }
        } else {
            // Unknown algorithm, check common cases
            if algorithm.contains("256") && key_bits < 256 {
                return Err(CryptoError::InvalidKeyLength(key.len()));
            } else if algorithm.contains("128") && key_bits < 128 {
                return Err(CryptoError::InvalidKeyLength(key.len()));
            }
        }
        
        // Check for weak keys
        if key.iter().all(|&b| b == 0) {
            return Err(CryptoError::KeyError("All-zero key detected".into()));
        }
        
        if key.iter().all(|&b| b == 0xFF) {
            return Err(CryptoError::KeyError("All-ones key detected".into()));
        }
        
        // Check for obvious patterns
        if key.len() >= 4 {
            let pattern = &key[..4];
            if key.chunks(4).all(|chunk| chunk.starts_with(pattern)) {
                return Err(CryptoError::KeyError("Repeating pattern detected in key".into()));
            }
        }
        
        Ok(())
    }
    
    fn validate_parameters(&self, params: &dyn std::any::Any) -> Result<(), CryptoError> {
        // Validate algorithm-specific parameters
        // This would check things like:
        // - IV/nonce uniqueness requirements
        // - Counter overflow protection
        // - Proper padding schemes
        Ok(())
    }
    
    fn approved_algorithms(&self) -> Vec<&'static str> {
        vec![
            // Symmetric encryption
            "aes-128-gcm",
            "aes-192-gcm", 
            "aes-256-gcm",
            "chacha20-poly1305",
            
            // Digital signatures
            "ed25519",
            "ecdsa-p256",
            "ecdsa-p384",
            "ecdsa-p521",
            "rsa-pss",
            
            // Key agreement
            "x25519",
            "ecdh-p256",
            "ecdh-p384",
            "ecdh-p521",
            
            // Hash functions
            "sha256",
            "sha384",
            "sha512",
            "sha3-256",
            "sha3-384",
            "sha3-512",
        ]
    }
}

/// Key derivation function parameters validator
pub struct KdfValidator;

impl KdfValidator {
    /// Validate PBKDF2 parameters according to NIST recommendations
    pub fn validate_pbkdf2(
        iterations: u32,
        salt_len: usize,
        output_len: usize,
    ) -> Result<(), CryptoError> {
        // NIST recommends at least 10,000 iterations for PBKDF2
        if iterations < 10_000 {
            return Err(CryptoError::InvalidFormat(format!(
                "PBKDF2 iterations {} below NIST minimum of 10,000",
                iterations
            )));
        }
        
        // Salt should be at least 128 bits (16 bytes)
        if salt_len < 16 {
            return Err(CryptoError::InvalidFormat(format!(
                "Salt length {} bytes below NIST minimum of 16 bytes",
                salt_len
            )));
        }
        
        // Output length should be reasonable
        if output_len > 512 {
            return Err(CryptoError::InvalidFormat(
                "Output length exceeds reasonable maximum".into()
            ));
        }
        
        Ok(())
    }
    
    /// Validate Argon2 parameters
    pub fn validate_argon2(
        memory_cost: u32,
        time_cost: u32,
        parallelism: u32,
        salt_len: usize,
    ) -> Result<(), CryptoError> {
        // Minimum memory cost: 64 MB
        if memory_cost < 65536 {
            return Err(CryptoError::InvalidFormat(
                "Argon2 memory cost below recommended minimum".into()
            ));
        }
        
        // Minimum time cost: 3 iterations
        if time_cost < 3 {
            return Err(CryptoError::InvalidFormat(
                "Argon2 time cost below recommended minimum".into()
            ));
        }
        
        // Parallelism should be reasonable
        if parallelism == 0 || parallelism > 16 {
            return Err(CryptoError::InvalidFormat(
                "Argon2 parallelism out of reasonable range".into()
            ));
        }
        
        // Salt requirements same as PBKDF2
        if salt_len < 16 {
            return Err(CryptoError::InvalidFormat(format!(
                "Salt length {} bytes below minimum of 16 bytes",
                salt_len
            )));
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_nist_key_validation() {
        let validator = NistSP800_57::new();
        
        // Valid AES-256 key
        let valid_key = vec![0x42u8; 32];
        assert!(validator.validate_key(&valid_key, "aes-256-gcm").is_ok());
        
        // Invalid - too short
        let short_key = vec![0x42u8; 16];
        assert!(validator.validate_key(&short_key, "aes-256-gcm").is_err());
        
        // Invalid - all zeros
        let zero_key = vec![0u8; 32];
        assert!(validator.validate_key(&zero_key, "aes-256-gcm").is_err());
    }
    
    #[test]
    fn test_security_strength() {
        let validator = NistSP800_57::new();
        
        assert_eq!(validator.get_security_strength("aes-128-gcm", 128), 128);
        assert_eq!(validator.get_security_strength("aes-256-gcm", 256), 256);
        assert_eq!(validator.get_security_strength("ed25519", 256), 128);
        assert_eq!(validator.get_security_strength("rsa-3072", 3072), 128);
    }
    
    #[test]
    fn test_kdf_validation() {
        // Valid PBKDF2 parameters
        assert!(KdfValidator::validate_pbkdf2(100_000, 16, 32).is_ok());
        
        // Invalid - too few iterations
        assert!(KdfValidator::validate_pbkdf2(1000, 16, 32).is_err());
        
        // Invalid - salt too short
        assert!(KdfValidator::validate_pbkdf2(100_000, 8, 32).is_err());
        
        // Valid Argon2 parameters
        assert!(KdfValidator::validate_argon2(65536, 3, 4, 16).is_ok());
        
        // Invalid - memory too low
        assert!(KdfValidator::validate_argon2(1024, 3, 4, 16).is_err());
    }
}
