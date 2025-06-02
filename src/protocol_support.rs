//! Protocol support matching AeroNyx node's protocol module

use crate::errors::CryptoError;
use serde::{Serialize, Deserialize};

/// Packet types matching node's protocol/types.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PacketType {
    Auth { public_key: String },
    Challenge { challenge: String },
    ChallengeResponse { challenge_id: String, signature: String },
    IpAssign { ip: String, subnet: String, dns: Vec<String> },
    Data { data: Vec<u8> },
    KeyRotation { new_key: Vec<u8> },
    Disconnect { reason: u16, message: String },
    Error { code: u16, message: String },
}

/// Crypto operations for protocol messages
pub struct ProtocolCrypto;

impl ProtocolCrypto {
    /// Encrypt a data packet (matching node's routing.rs)
    pub fn encrypt_packet(
        packet: &[u8],
        session_key: &[u8],
        algorithm: Option<&str>,
    ) -> Result<Vec<u8>, CryptoError> {
        let algo = algorithm.unwrap_or("chacha20-poly1305");
        
        match algo {
            "chacha20-poly1305" => {
                let (encrypted, nonce) = crate::crypto::encrypt_chacha20(packet, session_key)?;
                // Prepend nonce to ciphertext for transmission
                let mut result = nonce;
                result.extend_from_slice(&encrypted);
                Ok(result)
            }
            "aes-256-gcm" => {
                let (encrypted, nonce) = crate::crypto::encrypt_aes_gcm(packet, session_key, None)?;
                let mut result = nonce;
                result.extend_from_slice(&encrypted);
                Ok(result)
            }
            _ => Err(CryptoError::InvalidFormat("Unsupported algorithm".into()))
        }
    }
    
    /// Decrypt a data packet (matching node's routing.rs)
    pub fn decrypt_packet(
        encrypted_packet: &[u8],
        session_key: &[u8],
        algorithm: Option<&str>,
    ) -> Result<Vec<u8>, CryptoError> {
        if encrypted_packet.len() < 12 {
            return Err(CryptoError::InvalidFormat("Packet too short".into()));
        }
        
        let algo = algorithm.unwrap_or("chacha20-poly1305");
        let (nonce, ciphertext) = encrypted_packet.split_at(12);
        
        match algo {
            "chacha20-poly1305" => {
                crate::crypto::decrypt_chacha20(ciphertext, session_key, nonce)
            }
            "aes-256-gcm" => {
                crate::crypto::decrypt_aes_gcm(ciphertext, session_key, nonce, None)
            }
            _ => Err(CryptoError::InvalidFormat("Unsupported algorithm".into()))
        }
    }
}
