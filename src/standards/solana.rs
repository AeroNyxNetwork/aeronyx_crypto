//! Solana blockchain standard compliance

use super::StandardCompliance;
use crate::errors::CryptoError;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;

/// Solana blockchain standard validator
pub struct SolanaStandard;

impl StandardCompliance for SolanaStandard {
    fn validate_key(&self, key: &[u8], algorithm: &str) -> Result<(), CryptoError> {
        match algorithm {
            "ed25519" => {
                // Validate Ed25519 key format
                if key.len() != 32 && key.len() != 64 {
                    return Err(CryptoError::InvalidKeyLength(key.len()));
                }
                
                // Validate it's a valid Solana pubkey if it's 32 bytes
                if key.len() == 32 {
                    Pubkey::new_from_array(
                        key.try_into()
                            .map_err(|_| CryptoError::InvalidFormat("Invalid key format".into()))?
                    );
                }
                
                Ok(())
            }
            _ => Ok(()),
        }
    }
    
    fn validate_parameters(&self, _params: &dyn std::any::Any) -> Result<(), CryptoError> {
        Ok(())
    }
    
    fn approved_algorithms(&self) -> Vec<&'static str> {
        vec!["ed25519", "x25519", "chacha20-poly1305"]
    }
}

/// Solana-specific utilities
pub mod utils {
    use super::*;
    use bs58;
    
    /// Convert Solana pubkey to base58
    pub fn pubkey_to_base58(pubkey: &[u8]) -> Result<String, CryptoError> {
        if pubkey.len() != 32 {
            return Err(CryptoError::InvalidKeyLength(pubkey.len()));
        }
        
        Ok(bs58::encode(pubkey).into_string())
    }
    
    /// Convert base58 to pubkey bytes
    pub fn base58_to_pubkey(base58: &str) -> Result<Vec<u8>, CryptoError> {
        bs58::decode(base58)
            .into_vec()
            .map_err(|e| CryptoError::InvalidFormat(e.to_string()))
    }
    
    /// Validate Solana address
    pub fn validate_address(address: &str) -> Result<(), CryptoError> {
        Pubkey::from_str(address)
            .map_err(|e| CryptoError::InvalidFormat(e.to_string()))?;
        Ok(())
    }
}
