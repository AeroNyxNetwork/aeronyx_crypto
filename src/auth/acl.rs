//! Access Control List (ACL) management for AeroNyx nodes
//! Provides fine-grained permission control for network resources

use crate::errors::CryptoError;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Resource access permissions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permissions {
    /// Can read/receive data
    pub read: bool,
    /// Can write/send data
    pub write: bool,
    /// Can execute commands
    pub execute: bool,
    /// Can manage other permissions
    pub admin: bool,
}

impl Permissions {
    /// Create read-only permissions
    pub fn read_only() -> Self {
        Self {
            read: true,
            write: false,
            execute: false,
            admin: false,
        }
    }
    
    /// Create read-write permissions
    pub fn read_write() -> Self {
        Self {
            read: true,
            write: true,
            execute: false,
            admin: false,
        }
    }
    
    /// Create full permissions
    pub fn full() -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
            admin: false,
        }
    }
    
    /// Create admin permissions
    pub fn admin() -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
            admin: true,
        }
    }
    
    /// Check if any permission is granted
    pub fn has_any(&self) -> bool {
        self.read || self.write || self.execute || self.admin
    }
}

/// Resource quota limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceQuota {
    /// Maximum bandwidth in bytes per second
    pub bandwidth_limit: Option<u64>,
    /// Maximum connections allowed
    pub connection_limit: Option<u32>,
    /// Maximum storage in bytes
    pub storage_limit: Option<u64>,
    /// Maximum compute units per hour
    pub compute_limit: Option<u64>,
}

impl Default for ResourceQuota {
    fn default() -> Self {
        Self {
            bandwidth_limit: Some(100 * 1024 * 1024), // 100 MB/s
            connection_limit: Some(100),
            storage_limit: Some(10 * 1024 * 1024 * 1024), // 10 GB
            compute_limit: Some(1000),
        }
    }
}

/// Access control entry for a client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlEntry {
    /// Public key of the client
    pub public_key: String,
    /// Granted permissions
    pub permissions: Permissions,
    /// Resource quotas
    pub quota: ResourceQuota,
    /// Optional IP whitelist
    pub allowed_ips: Option<Vec<IpAddr>>,
    /// Entry creation time
    pub created_at: u64,
    /// Entry expiration time (0 = never expires)
    pub expires_at: u64,
    /// Human-readable description
    pub description: Option<String>,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Is entry enabled
    pub enabled: bool,
}

impl AccessControlEntry {
    /// Create a new ACL entry
    pub fn new(public_key: String, permissions: Permissions) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        Self {
            public_key,
            permissions,
            quota: ResourceQuota::default(),
            allowed_ips: None,
            created_at: now,
            expires_at: 0,
            description: None,
            tags: Vec::new(),
            enabled: true,
        }
    }
    
    /// Set expiration duration from now
    pub fn with_expiration(mut self, duration: Duration) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.expires_at = now + duration.as_secs();
        self
    }
    
    /// Set resource quota
    pub fn with_quota(mut self, quota: ResourceQuota) -> Self {
        self.quota = quota;
        self
    }
    
    /// Set allowed IPs
    pub fn with_allowed_ips(mut self, ips: Vec<IpAddr>) -> Self {
        self.allowed_ips = Some(ips);
        self
    }
    
    /// Check if entry is expired
    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false;
        }
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        now > self.expires_at
    }
    
    /// Check if IP is allowed
    pub fn is_ip_allowed(&self, ip: &IpAddr) -> bool {
        match &self.allowed_ips {
            Some(allowed) => allowed.contains(ip),
            None => true, // No IP restriction
        }
    }
}

/// Access Control List manager
pub struct AccessControlList {
    /// ACL entries indexed by public key
    entries: Arc<RwLock<HashMap<String, AccessControlEntry>>>,
    /// Default permissions for unknown clients
    default_permissions: Permissions,
    /// Enable strict mode (deny by default)
    strict_mode: bool,
}

impl AccessControlList {
    /// Create a new ACL with default permissions
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            default_permissions: Permissions::read_only(),
            strict_mode: false,
        }
    }
    
    /// Create a new ACL in strict mode (deny by default)
    pub fn strict() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            default_permissions: Permissions {
                read: false,
                write: false,
                execute: false,
                admin: false,
            },
            strict_mode: true,
        }
    }
    
    /// Add or update an ACL entry
    pub fn add_entry(&self, entry: AccessControlEntry) -> Result<(), CryptoError> {
        // Validate public key format
        if entry.public_key.is_empty() {
            return Err(CryptoError::InvalidFormat("Empty public key".into()));
        }
        
        // Validate the public key is base58 encoded
        if bs58::decode(&entry.public_key).into_vec().is_err() {
            return Err(CryptoError::InvalidFormat("Invalid public key encoding".into()));
        }
        
        let mut entries = self.entries.write();
        entries.insert(entry.public_key.clone(), entry);
        Ok(())
    }
    
    /// Remove an ACL entry
    pub fn remove_entry(&self, public_key: &str) -> Result<(), CryptoError> {
        let mut entries = self.entries.write();
        entries.remove(public_key)
            .ok_or_else(|| CryptoError::InvalidFormat("Entry not found".into()))?;
        Ok(())
    }
    
    /// Get an ACL entry
    pub fn get_entry(&self, public_key: &str) -> Option<AccessControlEntry> {
        let entries = self.entries.read();
        entries.get(public_key).cloned()
    }
    
    /// Check if a client is allowed with specific permission
    pub fn is_allowed(&self, public_key: &str, permission: &str) -> bool {
        let entries = self.entries.read();
        
        if let Some(entry) = entries.get(public_key) {
            // Check if entry is valid
            if !entry.enabled || entry.is_expired() {
                return false;
            }
            
            // Check specific permission
            match permission {
                "read" => entry.permissions.read,
                "write" => entry.permissions.write,
                "execute" => entry.permissions.execute,
                "admin" => entry.permissions.admin,
                _ => false,
            }
        } else {
            // Use default permissions if not in strict mode
            if !self.strict_mode {
                match permission {
                    "read" => self.default_permissions.read,
                    "write" => self.default_permissions.write,
                    "execute" => self.default_permissions.execute,
                    "admin" => self.default_permissions.admin,
                    _ => false,
                }
            } else {
                false
            }
        }
    }
    
    /// Check if a client has any permissions
    pub fn has_access(&self, public_key: &str) -> bool {
        let entries = self.entries.read();
        
        if let Some(entry) = entries.get(public_key) {
            entry.enabled && !entry.is_expired() && entry.permissions.has_any()
        } else {
            !self.strict_mode && self.default_permissions.has_any()
        }
    }
    
    /// Get permissions for a client
    pub fn get_permissions(&self, public_key: &str) -> Permissions {
        let entries = self.entries.read();
        
        if let Some(entry) = entries.get(public_key) {
            if entry.enabled && !entry.is_expired() {
                entry.permissions
            } else {
                Permissions {
                    read: false,
                    write: false,
                    execute: false,
                    admin: false,
                }
            }
        } else if !self.strict_mode {
            self.default_permissions
        } else {
            Permissions {
                read: false,
                write: false,
                execute: false,
                admin: false,
            }
        }
    }
    
    /// List all active entries
    pub fn list_entries(&self) -> Vec<AccessControlEntry> {
        let entries = self.entries.read();
        entries.values()
            .filter(|e| e.enabled && !e.is_expired())
            .cloned()
            .collect()
    }
    
    /// Clean up expired entries
    pub fn cleanup_expired(&self) {
        let mut entries = self.entries.write();
        entries.retain(|_, entry| !entry.is_expired());
    }
    
    /// Export ACL to JSON
    pub fn export(&self) -> Result<String, CryptoError> {
        let entries = self.entries.read();
        let export_data = entries.values().cloned().collect::<Vec<_>>();
        serde_json::to_string_pretty(&export_data)
            .map_err(|e| CryptoError::InvalidFormat(e.to_string()))
    }
    
    /// Import ACL from JSON
    pub fn import(&self, json: &str) -> Result<(), CryptoError> {
        let import_data: Vec<AccessControlEntry> = serde_json::from_str(json)
            .map_err(|e| CryptoError::InvalidFormat(e.to_string()))?;
            
        let mut entries = self.entries.write();
        for entry in import_data {
            entries.insert(entry.public_key.clone(), entry);
        }
        
        Ok(())
    }
}

/// ACL manager with persistence support
pub struct AccessControlManager {
    acl: AccessControlList,
    persistence_path: Option<String>,
}

impl AccessControlManager {
    /// Create a new ACL manager
    pub fn new() -> Self {
        Self {
            acl: AccessControlList::new(),
            persistence_path: None,
        }
    }
    
    /// Create a new ACL manager with persistence
    pub fn with_persistence(path: String) -> Result<Self, CryptoError> {
        let mut manager = Self {
            acl: AccessControlList::new(),
            persistence_path: Some(path.clone()),
        };
        
        // Try to load existing ACL
        if std::path::Path::new(&path).exists() {
            manager.load()?;
        }
        
        Ok(manager)
    }
    
    /// Add or update an ACL entry
    pub fn add_entry(&self, entry: AccessControlEntry) -> Result<(), CryptoError> {
        self.acl.add_entry(entry)?;
        self.save()?;
        Ok(())
    }
    
    /// Check if a client is allowed
    pub fn is_allowed(&self, public_key: &str) -> bool {
        self.acl.has_access(public_key)
    }
    
    /// Save ACL to disk
    fn save(&self) -> Result<(), CryptoError> {
        if let Some(path) = &self.persistence_path {
            let json = self.acl.export()?;
            std::fs::write(path, json)
                .map_err(|e| CryptoError::InvalidFormat(e.to_string()))?;
        }
        Ok(())
    }
    
    /// Load ACL from disk
    fn load(&mut self) -> Result<(), CryptoError> {
        if let Some(path) = &self.persistence_path {
            let json = std::fs::read_to_string(path)
                .map_err(|e| CryptoError::InvalidFormat(e.to_string()))?;
            self.acl.import(&json)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_permissions() {
        let perms = Permissions::read_write();
        assert!(perms.read);
        assert!(perms.write);
        assert!(!perms.execute);
        assert!(!perms.admin);
        assert!(perms.has_any());
    }
    
    #[test]
    fn test_acl_basic() {
        let acl = AccessControlList::new();
        let pubkey = bs58::encode("test_key").into_string();
        
        // Add entry
        let entry = AccessControlEntry::new(pubkey.clone(), Permissions::full());
        acl.add_entry(entry).unwrap();
        
        // Check permissions
        assert!(acl.is_allowed(&pubkey, "read"));
        assert!(acl.is_allowed(&pubkey, "write"));
        assert!(acl.is_allowed(&pubkey, "execute"));
        assert!(!acl.is_allowed(&pubkey, "admin"));
    }
    
    #[test]
    fn test_acl_expiration() {
        let acl = AccessControlList::new();
        let pubkey = bs58::encode("test_key").into_string();
        
        // Add entry that expires immediately
        let entry = AccessControlEntry::new(pubkey.clone(), Permissions::full())
            .with_expiration(Duration::from_secs(0));
        acl.add_entry(entry).unwrap();
        
        // Should be expired
        assert!(!acl.has_access(&pubkey));
    }
    
    #[test]
    fn test_strict_mode() {
        let acl = AccessControlList::strict();
        let unknown_key = bs58::encode("unknown").into_string();
        
        // Unknown keys should be denied in strict mode
        assert!(!acl.has_access(&unknown_key));
        assert!(!acl.is_allowed(&unknown_key, "read"));
    }
}
