//! Challenge-response authentication system for AeroNyx nodes
//! Implements secure challenge generation and verification with timeout management

use crate::errors::CryptoError;
use crate::crypto::{verify_signature, generate_keypair};
use crate::secure_memory::SecureBuffer;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use rand::{RngCore, rngs::OsRng};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

/// Size of challenge in bytes (matching node requirements)
pub const CHALLENGE_SIZE: usize = 32;

/// Default challenge timeout duration
pub const CHALLENGE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of active challenges per IP
pub const MAX_CHALLENGES_PER_IP: usize = 5;

/// Challenge structure for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// Unique challenge identifier
    pub id: String,
    /// Challenge bytes to be signed
    pub challenge: Vec<u8>,
    /// Client socket address
    pub client_addr: SocketAddr,
    /// Challenge creation timestamp
    pub created_at: Instant,
    /// Expected public key (if pre-registered)
    pub expected_pubkey: Option<String>,
    /// Number of verification attempts
    pub attempts: u32,
}

impl Challenge {
    /// Create a new challenge
    pub fn new(client_addr: SocketAddr, expected_pubkey: Option<String>) -> Self {
        let mut challenge_bytes = vec![0u8; CHALLENGE_SIZE];
        OsRng.fill_bytes(&mut challenge_bytes);
        
        // Generate unique ID
        let mut hasher = Sha256::new();
        hasher.update(&challenge_bytes);
        hasher.update(client_addr.to_string().as_bytes());
        hasher.update(&Instant::now().elapsed().as_nanos().to_le_bytes());
        let id = bs58::encode(hasher.finalize()).into_string();
        
        Self {
            id,
            challenge: challenge_bytes,
            client_addr,
            created_at: Instant::now(),
            expected_pubkey,
            attempts: 0,
        }
    }
    
    /// Check if the challenge has expired
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > CHALLENGE_TIMEOUT
    }
    
    /// Get remaining time before expiration
    pub fn time_remaining(&self) -> Duration {
        CHALLENGE_TIMEOUT.saturating_sub(self.created_at.elapsed())
    }
}

/// Challenge manager for handling authentication challenges
pub struct ChallengeManager {
    /// Active challenges indexed by challenge ID
    challenges: Arc<RwLock<HashMap<String, Challenge>>>,
    /// Challenge count per IP address for rate limiting
    ip_challenge_count: Arc<RwLock<HashMap<SocketAddr, usize>>>,
    /// Custom timeout duration
    timeout: Duration,
    /// Maximum attempts allowed per challenge
    max_attempts: u32,
}

impl ChallengeManager {
    /// Create a new challenge manager
    pub fn new() -> Self {
        Self::with_config(CHALLENGE_TIMEOUT, 3)
    }
    
    /// Create a challenge manager with custom configuration
    pub fn with_config(timeout: Duration, max_attempts: u32) -> Self {
        let manager = Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
            ip_challenge_count: Arc::new(RwLock::new(HashMap::new())),
            timeout,
            max_attempts,
        };
        
        // Start cleanup task
        manager.start_cleanup_task();
        manager
    }
    
    /// Generate a new challenge for a client
    pub fn generate_challenge(
        &self,
        client_addr: SocketAddr,
        expected_pubkey: Option<String>,
    ) -> Result<Challenge, CryptoError> {
        // Check rate limiting
        self.check_rate_limit(&client_addr)?;
        
        // Create new challenge
        let challenge = Challenge::new(client_addr, expected_pubkey);
        
        // Store challenge
        {
            let mut challenges = self.challenges.write();
            challenges.insert(challenge.id.clone(), challenge.clone());
        }
        
        // Update IP challenge count
        {
            let mut ip_counts = self.ip_challenge_count.write();
            *ip_counts.entry(client_addr).or_insert(0) += 1;
        }
        
        Ok(challenge)
    }
    
    /// Verify a challenge response
    pub fn verify_challenge(
        &self,
        challenge_id: &str,
        client_addr: SocketAddr,
        signature: &str,
        public_key: &str,
    ) -> Result<bool, CryptoError> {
        // Get and validate challenge
        let mut challenges = self.challenges.write();
        let challenge = challenges.get_mut(challenge_id)
            .ok_or_else(|| CryptoError::InvalidFormat("Challenge not found".into()))?;
        
        // Security checks
        if challenge.client_addr != client_addr {
            return Err(CryptoError::AuthenticationFailed);
        }
        
        if challenge.is_expired() {
            challenges.remove(challenge_id);
            return Err(CryptoError::InvalidFormat("Challenge expired".into()));
        }
        
        if challenge.attempts >= self.max_attempts {
            challenges.remove(challenge_id);
            return Err(CryptoError::InvalidFormat("Too many attempts".into()));
        }
        
        challenge.attempts += 1;
        
        // Verify expected public key if specified
        if let Some(expected) = &challenge.expected_pubkey {
            if expected != public_key {
                return Ok(false);
            }
        }
        
        // Decode signature
        let signature_bytes = bs58::decode(signature)
            .into_vec()
            .map_err(|_| CryptoError::InvalidFormat("Invalid signature encoding".into()))?;
        
        // Decode public key
        let pubkey_bytes = bs58::decode(public_key)
            .into_vec()
            .map_err(|_| CryptoError::InvalidFormat("Invalid public key encoding".into()))?;
        
        // Verify signature
        let is_valid = crate::crypto::verify_signature(
            &pubkey_bytes,
            &challenge.challenge,
            &signature_bytes,
        )?;
        
        // Remove challenge after successful verification
        if is_valid {
            challenges.remove(challenge_id);
            self.decrement_ip_count(&client_addr);
        }
        
        Ok(is_valid)
    }
    
    /// Remove expired challenges and clean up
    pub fn cleanup_expired(&self) {
        let mut challenges = self.challenges.write();
        let mut ip_counts = self.ip_challenge_count.write();
        
        // Find expired challenges
        let expired: Vec<_> = challenges
            .iter()
            .filter(|(_, c)| c.is_expired())
            .map(|(id, c)| (id.clone(), c.client_addr))
            .collect();
        
        // Remove expired challenges
        for (id, addr) in expired {
            challenges.remove(&id);
            if let Some(count) = ip_counts.get_mut(&addr) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    ip_counts.remove(&addr);
                }
            }
        }
    }
    
    /// Get active challenge count
    pub fn active_challenges(&self) -> usize {
        self.challenges.read().len()
    }
    
    /// Get challenge by ID
    pub fn get_challenge(&self, challenge_id: &str) -> Option<Challenge> {
        self.challenges.read().get(challenge_id).cloned()
    }
    
    /// Check rate limiting for an IP
    fn check_rate_limit(&self, client_addr: &SocketAddr) -> Result<(), CryptoError> {
        let ip_counts = self.ip_challenge_count.read();
        if let Some(&count) = ip_counts.get(client_addr) {
            if count >= MAX_CHALLENGES_PER_IP {
                return Err(CryptoError::InvalidFormat("Too many active challenges".into()));
            }
        }
        Ok(())
    }
    
    /// Decrement IP challenge count
    fn decrement_ip_count(&self, client_addr: &SocketAddr) {
        let mut ip_counts = self.ip_challenge_count.write();
        if let Some(count) = ip_counts.get_mut(client_addr) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                ip_counts.remove(client_addr);
            }
        }
    }
    
    /// Start background cleanup task
    fn start_cleanup_task(&self) {
        let challenges = Arc::clone(&self.challenges);
        let ip_counts = Arc::clone(&self.ip_challenge_count);
        let timeout = self.timeout;
        
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(timeout / 2);
                
                let mut challenges = challenges.write();
                let mut ip_counts = ip_counts.write();
                
                // Clean up expired challenges
                let expired: Vec<_> = challenges
                    .iter()
                    .filter(|(_, c)| c.is_expired())
                    .map(|(id, c)| (id.clone(), c.client_addr))
                    .collect();
                
                for (id, addr) in expired {
                    challenges.remove(&id);
                    if let Some(count) = ip_counts.get_mut(&addr) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            ip_counts.remove(&addr);
                        }
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    
    #[test]
    fn test_challenge_generation() {
        let manager = ChallengeManager::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        
        let challenge = manager.generate_challenge(addr, None).unwrap();
        assert_eq!(challenge.challenge.len(), CHALLENGE_SIZE);
        assert!(!challenge.id.is_empty());
        assert!(!challenge.is_expired());
    }
    
    #[test]
    fn test_challenge_verification() {
        let manager = ChallengeManager::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        
        // Generate keypair for testing
        let (private_key, public_key) = generate_keypair().unwrap();
        let pubkey_str = bs58::encode(&public_key).into_string();
        
        // Generate challenge
        let challenge = manager.generate_challenge(addr, Some(pubkey_str.clone())).unwrap();
        
        // Sign challenge
        let signature = crate::crypto::sign_message(&private_key, &challenge.challenge).unwrap();
        let sig_str = bs58::encode(&signature).into_string();
        
        // Verify challenge
        let result = manager.verify_challenge(
            &challenge.id,
            addr,
            &sig_str,
            &pubkey_str,
        ).unwrap();
        
        assert!(result);
        
        // Verify challenge is removed after successful verification
        assert!(manager.get_challenge(&challenge.id).is_none());
    }
    
    #[test]
    fn test_rate_limiting() {
        let manager = ChallengeManager::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        
        // Generate maximum allowed challenges
        for _ in 0..MAX_CHALLENGES_PER_IP {
            manager.generate_challenge(addr, None).unwrap();
        }
        
        // Next one should fail
        assert!(manager.generate_challenge(addr, None).is_err());
    }
}
