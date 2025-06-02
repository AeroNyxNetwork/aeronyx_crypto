//! Advanced key derivation functions for hierarchical and deterministic key generation
//! Implements BIP32-like derivation for Ed25519 keys

use crate::secure_memory::SecureBuffer;
use crate::errors::CryptoError;
use ed25519_dalek::{SecretKey, PublicKey};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512, Digest};
use zeroize::Zeroize;

/// Key derivation path component
#[derive(Debug, Clone, Copy)]
pub enum PathComponent {
    /// Normal derivation (non-hardened)
    Normal(u32),
    /// Hardened derivation
    Hardened(u32),
}

impl PathComponent {
    pub fn to_index(&self) -> u32 {
        match self {
            PathComponent::Normal(i) => *i,
            PathComponent::Hardened(i) => 0x80000000 | i,
        }
    }
}

/// Hierarchical deterministic key derivation for Ed25519
pub struct HierarchicalKeyDerivation {
    master_key: SecureBuffer<u8>,
    chain_code: [u8; 32],
}

impl HierarchicalKeyDerivation {
    /// Create a new HD wallet from seed
    pub fn from_seed(seed: &[u8]) -> Result<Self, CryptoError> {
        if seed.len() < 16 || seed.len() > 64 {
            return Err(CryptoError::InvalidKeyLength(seed.len()));
        }
        
        // Use HMAC-SHA512 to derive master key and chain code
        let mut mac = Hmac::<Sha512>::new_from_slice(b"ed25519 seed")
            .map_err(|_| CryptoError::KeyError("HMAC initialization failed".into()))?;
        mac.update(seed);
        let result = mac.finalize();
        let bytes = result.into_bytes();
        
        let mut master_key = SecureBuffer::new(32);
        master_key[..32].copy_from_slice(&bytes[..32]);
        
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&bytes[32..64]);
        
        Ok(Self {
            master_key,
            chain_code,
        })
    }
    
    /// Derive a child key using the given path
    pub fn derive_path(&self, path: &[PathComponent]) -> Result<DerivedKey, CryptoError> {
        let mut current_key = self.master_key.to_vec();
        let mut current_chain = self.chain_code;
        
        for component in path {
            let (new_key, new_chain) = self.derive_child(
                &current_key,
                &current_chain,
                component.to_index()
            )?;
            
            current_key.zeroize();
            current_key = new_key;
            current_chain = new_chain;
        }
        
        let secret = SecretKey::from_bytes(&current_key)
            .map_err(|e| CryptoError::KeyError(e.to_string()))?;
        let public = PublicKey::from(&secret);
        
        current_key.zeroize();
        
        Ok(DerivedKey {
            secret_key: secret,
            public_key: public,
            chain_code: current_chain,
        })
    }
    
    /// Derive a single child key
    fn derive_child(
        &self,
        parent_key: &[u8],
        parent_chain: &[u8],
        index: u32,
    ) -> Result<(Vec<u8>, [u8; 32]), CryptoError> {
        let mut mac = Hmac::<Sha512>::new_from_slice(parent_chain)
            .map_err(|_| CryptoError::KeyError("HMAC initialization failed".into()))?;
        
        if index >= 0x80000000 {
            // Hardened derivation
            mac.update(&[0x00]);
            mac.update(parent_key);
        } else {
            // Non-hardened derivation
            let secret = SecretKey::from_bytes(parent_key)
                .map_err(|e| CryptoError::KeyError(e.to_string()))?;
            let public = PublicKey::from(&secret);
            mac.update(public.as_bytes());
        }
        
        mac.update(&index.to_be_bytes());
        let result = mac.finalize();
        let bytes = result.into_bytes();
        
        let mut child_key = vec![0u8; 32];
        child_key.copy_from_slice(&bytes[..32]);
        
        let mut child_chain = [0u8; 32];
        child_chain.copy_from_slice(&bytes[32..64]);
        
        Ok((child_key, child_chain))
    }
}

/// A derived key with its chain code
pub struct DerivedKey {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
    pub chain_code: [u8; 32],
}

/// Password-based key derivation using Argon2id
pub mod password {
    use super::*;
    use argon2::{Argon2, PasswordHasher, PasswordVerifier};
    use argon2::password_hash::{PasswordHash, SaltString};
    
    /// Derive a key from password using Argon2id
    pub fn derive_key_from_password(
        password: &str,
        salt: Option<&[u8]>,
        output_len: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let argon2 = Argon2::default();
        
        let salt = if let Some(s) = salt {
            SaltString::b64_encode(s)
                .map_err(|e| CryptoError::KeyError(e.to_string()))?
        } else {
            SaltString::generate(&mut rand::rngs::OsRng)
        };
        
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| CryptoError::KeyError(e.to_string()))?;
        
        let hash = password_hash.hash.unwrap();
        let mut output = vec![0u8; output_len];
        
        if hash.len() >= output_len {
            output.copy_from_slice(&hash.as_bytes()[..output_len]);
        } else {
            // Use HKDF to expand if needed
            let hkdf = hkdf::Hkdf::<Sha256>::new(None, hash.as_bytes());
            hkdf.expand(b"aeronyx-key-expansion", &mut output)
                .map_err(|_| CryptoError::KeyError("HKDF expansion failed".into()))?;
        }
        
        Ok((output, salt.as_bytes().to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hierarchical_derivation() {
        let seed = b"test seed for hierarchical key derivation";
        let hd = HierarchicalKeyDerivation::from_seed(seed).unwrap();
        
        // Derive m/0'/1/2'
        let path = vec![
            PathComponent::Hardened(0),
            PathComponent::Normal(1),
            PathComponent::Hardened(2),
        ];
        
        let derived = hd.derive_path(&path).unwrap();
        assert_eq!(derived.public_key.as_bytes().len(), 32);
    }
}
