//! Central authentication manager for AeroNyx nodes
//! Coordinates challenge generation, verification, and session management

use crate::auth::{ChallengeManager, AccessControlManager, Challenge};
use crate::crypto::{generate_keypair, sign_message, verify_signature};
use crate::errors::CryptoError;
use crate::protocol::state::{StateManager, ClientState};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Authentication configuration
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Challenge timeout duration
    pub challenge_timeout: Duration,
    /// Maximum authentication attempts
    pub max_auth_attempts: u32,
    /// Session timeout duration
    pub session_timeout: Duration,
    /// Idle timeout duration
    pub idle_timeout: Duration,
    /// Enable strict ACL mode
    pub strict_acl: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            challenge_timeout: Duration::from_secs(30),
            max_auth_attempts: 3,
            session_timeout: Duration::from_secs(3600),
            idle_timeout: Duration::from_secs(300),
            strict_acl: false,
        }
    }
}

/// Central authentication manager
pub struct AuthManager {
    /// Challenge manager
    challenge_manager: Arc<ChallengeManager>,
    /// Access control manager
    acl_manager: Arc<AccessControlManager>,
    /// State manager
    state_manager: Arc<StateManager>,
    /// Authentication attempts tracking
    auth_attempts: Arc<RwLock<HashMap<SocketAddr, u32>>>,
    /// Configuration
    config: AuthConfig,
}

impl AuthManager {
    /// Create a new authentication manager
    pub fn new(config: AuthConfig) -> Self {
        let acl_manager = if config.strict_acl {
            Arc::new(AccessControlManager::strict())
        } else {
            Arc::new(AccessControlManager::new())
        };
        
        Self {
            challenge_manager: Arc::new(ChallengeManager::with_config(
                config.challenge_timeout,
                config.max_auth_attempts,
            )),
            acl_manager,
            state_manager: Arc::new(StateManager::new(
                config.session_timeout,
                config.idle_timeout,
            )),
            auth_attempts: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }
    
    /// Create with ACL persistence
    pub fn with_acl_persistence(config: AuthConfig, acl_path: String) -> Result<Self, CryptoError> {
        let acl_manager = Arc::new(AccessControlManager::with_persistence(acl_path)?);
        
        Ok(Self {
            challenge_manager: Arc::new(ChallengeManager::with_config(
                config.challenge_timeout,
                config.max_auth_attempts,
            )),
            acl_manager,
            state_manager: Arc::new(StateManager::new(
                config.session_timeout,
                config.idle_timeout,
            )),
            auth_attempts: Arc::new(RwLock::new(HashMap::new())),
            config,
        })
    }
    
    /// Generate a challenge for a client
    pub fn generate_challenge(
        &self,
        client_addr: &str,
    ) -> Result<Challenge, CryptoError> {
        let addr: SocketAddr = client_addr.parse()
            .map_err(|_| CryptoError::InvalidFormat("Invalid client address".into()))?;
        
        // Check authentication attempts
        self.check_auth_attempts(&addr)?;
        
        // Generate challenge
        self.challenge_manager.generate_challenge(addr, None)
    }
    
    /// Verify a challenge response
    pub fn verify_challenge(
        &self,
        challenge_id: &str,
        signature: &str,
        public_key: &str,
        client_addr: &str,
    ) -> Result<String, CryptoError> {
        let addr: SocketAddr = client_addr.parse()
            .map_err(|_| CryptoError::InvalidFormat("Invalid client address".into()))?;
        
        // Verify the challenge
        let is_valid = self.challenge_manager.verify_challenge(
            challenge_id,
            addr,
            signature,
            public_key,
        )?;
        
        if !is_valid {
            self.increment_auth_attempts(&addr);
            return Err(CryptoError::AuthenticationFailed);
        }
        
        // Check ACL
        if !self.acl_manager.is_allowed(public_key) {
            return Err(CryptoError::InvalidFormat("Access denied".into()));
        }
        
        // Create session
        let session_id = self.state_manager.create_session(addr);
        
        // Update session with authentication info
        self.state_manager.update_session(&session_id, |session| {
            session.public_key = public_key.to_string();
            session.transition_to(ClientState::Active)?;
            Ok(())
        })?;
        
        // Clear authentication attempts
        self.clear_auth_attempts(&addr);
        
        Ok(session_id)
    }
    
    /// Get session info
    pub fn get_session(&self, session_id: &str) -> Option<crate::protocol::state::ClientSession> {
        self.state_manager.get_session(session_id)
    }
    
    /// Update session state
    pub fn update_session_state(
        &self,
        session_id: &str,
        new_state: ClientState,
    ) -> Result<(), CryptoError> {
        self.state_manager.update_session(session_id, |session| {
            session.transition_to(new_state)
        })
    }
    
    /// Disconnect a session
    pub fn disconnect_session(&self, session_id: &str) -> Result<(), CryptoError> {
        self.state_manager.update_session(session_id, |session| {
            session.transition_to(ClientState::Disconnected)
        })?;
        
        self.state_manager.remove_session(session_id);
        Ok(())
    }
    
    /// Get active session count
    pub fn active_sessions(&self) -> usize {
        self.state_manager.get_active_sessions().len()
    }
    
    /// Get authentication statistics
    pub fn get_auth_stats(&self) -> AuthStats {
        AuthStats {
            active_challenges: self.challenge_manager.active_challenges(),
            active_sessions: self.active_sessions(),
            session_stats: self.state_manager.get_session_stats(),
            auth_attempts: self.auth_attempts.read().len(),
        }
    }
    
    /// Check authentication attempts for rate limiting
    fn check_auth_attempts(&self, addr: &SocketAddr) -> Result<(), CryptoError> {
        let attempts = self.auth_attempts.read();
        if let Some(&count) = attempts.get(addr) {
            if count >= self.config.max_auth_attempts {
                return Err(CryptoError::InvalidFormat("Too many authentication attempts".into()));
            }
        }
        Ok(())
    }
    
    /// Increment authentication attempts
    fn increment_auth_attempts(&self, addr: &SocketAddr) {
        let mut attempts = self.auth_attempts.write();
        *attempts.entry(*addr).or_insert(0) += 1;
    }
    
    /// Clear authentication attempts
    fn clear_auth_attempts(&self, addr: &SocketAddr) {
        self.auth_attempts.write().remove(addr);
    }
    
    /// Get ACL manager
    pub fn acl_manager(&self) -> &Arc<AccessControlManager> {
        &self.acl_manager
    }
}

/// Authentication statistics
#[derive(Debug)]
pub struct AuthStats {
    pub active_challenges: usize,
    pub active_sessions: usize,
    pub session_stats: HashMap<ClientState, usize>,
    pub auth_attempts: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::acl::{AccessControlEntry, Permissions};
    
    #[test]
    fn test_auth_flow() {
        let config = AuthConfig::default();
        let manager = AuthManager::new(config);
        
        // Generate keypair for testing
        let (private_key, public_key) = generate_keypair().unwrap();
        let pubkey_str = bs58::encode(&public_key).into_string();
        
        // Add to ACL
        let entry = AccessControlEntry::new(pubkey_str.clone(), Permissions::full());
        manager.acl_manager().add_entry(entry).unwrap();
        
        // Generate challenge
        let client_addr = "127.0.0.1:8080";
        let challenge = manager.generate_challenge(client_addr).unwrap();
        
        // Sign challenge
        let signature = sign_message(&private_key, &challenge.challenge).unwrap();
        let sig_str = bs58::encode(&signature).into_string();
        
        // Verify challenge
        let session_id = manager.verify_challenge(
            &challenge.id,
            &sig_str,
            &pubkey_str,
            client_addr,
        ).unwrap();
        
        // Check session
        let session = manager.get_session(&session_id).unwrap();
        assert_eq!(session.public_key, pubkey_str);
        assert_eq!(session.state, ClientState::Active);
    }
    
    #[test]
    fn test_rate_limiting() {
        let config = AuthConfig {
            max_auth_attempts: 2,
            ..Default::default()
        };
        let manager = AuthManager::new(config);
        
        let client_addr = "127.0.0.1:8080";
        
        // Generate challenges up to limit
        manager.generate_challenge(client_addr).unwrap();
        manager.generate_challenge(client_addr).unwrap();
        
        // Increment attempts
        let addr: SocketAddr = client_addr.parse().unwrap();
        manager.increment_auth_attempts(&addr);
        manager.increment_auth_attempts(&addr);
        
        // Next challenge should fail
        assert!(manager.generate_challenge(client_addr).is_err());
    }
}
