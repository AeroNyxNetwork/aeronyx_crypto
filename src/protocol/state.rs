//! Client state management for AeroNyx protocol

use crate::errors::CryptoError;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Client connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    /// Initial connection established
    Connecting,
    /// Authentication in progress
    Authenticating,
    /// Fully authenticated and active
    Active,
    /// Graceful disconnection in progress
    Disconnecting,
    /// Connection closed
    Disconnected,
}

impl ClientState {
    /// Check if client is in a connected state
    pub fn is_connected(&self) -> bool {
        matches!(self, 
            ClientState::Connecting | 
            ClientState::Authenticating | 
            ClientState::Active
        )
    }
    
    /// Check if client is authenticated
    pub fn is_authenticated(&self) -> bool {
        matches!(self, ClientState::Active)
    }
}

/// Client session information
#[derive(Debug, Clone)]
pub struct ClientSession {
    /// Unique session ID
    pub id: String,
    /// Client public key
    pub public_key: String,
    /// Current state
    pub state: ClientState,
    /// Client socket address
    pub address: SocketAddr,
    /// Session start time
    pub connected_at: Instant,
    /// Last activity time
    pub last_activity: Instant,
    /// Assigned resources (e.g., IP address)
    pub assigned_resources: HashMap<String, String>,
    /// Session metadata
    pub metadata: HashMap<String, String>,
}

impl ClientSession {
    /// Create a new client session
    pub fn new(id: String, address: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            id,
            public_key: String::new(),
            state: ClientState::Connecting,
            address,
            connected_at: now,
            last_activity: now,
            assigned_resources: HashMap::new(),
            metadata: HashMap::new(),
        }
    }
    
    /// Update last activity time
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }
    
    /// Get session duration
    pub fn duration(&self) -> Duration {
        self.connected_at.elapsed()
    }
    
    /// Get idle time
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }
    
    /// Transition to a new state
    pub fn transition_to(&mut self, new_state: ClientState) -> Result<(), CryptoError> {
        // Validate state transitions
        match (self.state, new_state) {
            (ClientState::Connecting, ClientState::Authenticating) => Ok(()),
            (ClientState::Authenticating, ClientState::Active) => Ok(()),
            (ClientState::Active, ClientState::Disconnecting) => Ok(()),
            (_, ClientState::Disconnected) => Ok(()), // Can disconnect from any state
            _ => Err(CryptoError::InvalidFormat(
                format!("Invalid state transition from {:?} to {:?}", self.state, new_state)
            )),
        }?;
        
        self.state = new_state;
        self.touch();
        Ok(())
    }
}

/// State manager for all client sessions
pub struct StateManager {
    /// Active sessions indexed by session ID
    sessions: Arc<RwLock<HashMap<String, ClientSession>>>,
    /// Session timeout duration
    session_timeout: Duration,
    /// Maximum idle time before disconnect
    idle_timeout: Duration,
}

impl StateManager {
    /// Create a new state manager
    pub fn new(session_timeout: Duration, idle_timeout: Duration) -> Self {
        let manager = Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            session_timeout,
            idle_timeout,
        };
        
        // Start cleanup task
        manager.start_cleanup_task();
        manager
    }
    
    /// Create a new session
    pub fn create_session(&self, address: SocketAddr) -> String {
        let session_id = generate_session_id();
        let session = ClientSession::new(session_id.clone(), address);
        
        self.sessions.write().insert(session_id.clone(), session);
        session_id
    }
    
    /// Get a session by ID
    pub fn get_session(&self, session_id: &str) -> Option<ClientSession> {
        self.sessions.read().get(session_id).cloned()
    }
    
    /// Update a session
    pub fn update_session<F>(&self, session_id: &str, updater: F) -> Result<(), CryptoError>
    where
        F: FnOnce(&mut ClientSession) -> Result<(), CryptoError>,
    {
        let mut sessions = self.sessions.write();
        let session = sessions.get_mut(session_id)
            .ok_or_else(|| CryptoError::InvalidFormat("Session not found".into()))?;
        
        updater(session)?;
        session.touch();
        Ok(())
    }
    
    /// Remove a session
    pub fn remove_session(&self, session_id: &str) -> Option<ClientSession> {
        self.sessions.write().remove(session_id)
    }
    
    /// Get all active sessions
    pub fn get_active_sessions(&self) -> Vec<ClientSession> {
        self.sessions.read()
           .values()
           .filter(|s| s.state.is_connected())
           .cloned()
           .collect()
   }
   
   /// Get session count by state
   pub fn get_session_stats(&self) -> HashMap<ClientState, usize> {
       let mut stats = HashMap::new();
       
       for session in self.sessions.read().values() {
           *stats.entry(session.state).or_insert(0) += 1;
       }
       
       stats
   }
   
   /// Clean up expired and idle sessions
   pub fn cleanup_sessions(&self) {
       let mut sessions = self.sessions.write();
       let now = Instant::now();
       
       sessions.retain(|_, session| {
           // Remove disconnected sessions
           if session.state == ClientState::Disconnected {
               return false;
           }
           
           // Remove timed out sessions
           if now.duration_since(session.connected_at) > self.session_timeout {
               return false;
           }
           
           // Remove idle sessions
           if now.duration_since(session.last_activity) > self.idle_timeout {
               return false;
           }
           
           true
       });
   }
   
   /// Start background cleanup task
   fn start_cleanup_task(&self) {
       let sessions = Arc::clone(&self.sessions);
       let session_timeout = self.session_timeout;
       let idle_timeout = self.idle_timeout;
       
       std::thread::spawn(move || {
           loop {
               std::thread::sleep(Duration::from_secs(30));
               
               let mut sessions = sessions.write();
               let now = Instant::now();
               
               sessions.retain(|_, session| {
                   if session.state == ClientState::Disconnected {
                       return false;
                   }
                   
                   if now.duration_since(session.connected_at) > session_timeout {
                       return false;
                   }
                   
                   if now.duration_since(session.last_activity) > idle_timeout {
                       return false;
                   }
                   
                   true
               });
           }
       });
   }
}

/// Generate a unique session ID
fn generate_session_id() -> String {
   use rand::{Rng, thread_rng};
   use sha2::{Sha256, Digest};
   
   let mut rng = thread_rng();
   let random_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
   let timestamp = std::time::SystemTime::now()
       .duration_since(std::time::UNIX_EPOCH)
       .unwrap()
       .as_nanos();
   
   let mut hasher = Sha256::new();
   hasher.update(&random_bytes);
   hasher.update(&timestamp.to_le_bytes());
   
   bs58::encode(hasher.finalize()).into_string()
}

#[cfg(test)]
mod tests {
   use super::*;
   use std::net::{IpAddr, Ipv4Addr};
   
   #[test]
   fn test_client_state_transitions() {
       let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
       let mut session = ClientSession::new("test".to_string(), addr);
       
       // Valid transitions
       assert_eq!(session.state, ClientState::Connecting);
       session.transition_to(ClientState::Authenticating).unwrap();
       assert_eq!(session.state, ClientState::Authenticating);
       session.transition_to(ClientState::Active).unwrap();
       assert_eq!(session.state, ClientState::Active);
       
       // Invalid transition
       assert!(session.transition_to(ClientState::Connecting).is_err());
   }
   
   #[test]
   fn test_state_manager() {
       let manager = StateManager::new(
           Duration::from_secs(3600),
           Duration::from_secs(300),
       );
       
       let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
       let session_id = manager.create_session(addr);
       
       // Get session
       let session = manager.get_session(&session_id).unwrap();
       assert_eq!(session.state, ClientState::Connecting);
       
       // Update session
       manager.update_session(&session_id, |s| {
           s.public_key = "test_pubkey".to_string();
           s.transition_to(ClientState::Active)
       }).unwrap();
       
       // Verify update
       let updated = manager.get_session(&session_id).unwrap();
       assert_eq!(updated.public_key, "test_pubkey");
       assert_eq!(updated.state, ClientState::Active);
       
       // Get stats
       let stats = manager.get_session_stats();
       assert_eq!(stats.get(&ClientState::Active), Some(&1));
   }
}
