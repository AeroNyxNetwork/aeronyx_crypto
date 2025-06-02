//! Platform-specific secure storage implementations

#[cfg(target_os = "ios")]
pub mod ios;

#[cfg(target_os = "android")]
pub mod android;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(not(any(
    target_os = "ios", 
    target_os = "android", 
    target_os = "windows",
    target_os = "macos",
    target_os = "linux"
)))]
pub mod generic;

use crate::errors::CryptoError;

/// Platform-specific secure key storage
pub trait SecureStorage: Send + Sync {
    /// Store a key securely
    fn store_key(&self, key_id: &str, key_data: &[u8]) -> Result<(), CryptoError>;
    
    /// Retrieve a key
    fn get_key(&self, key_id: &str) -> Result<Vec<u8>, CryptoError>;
    
    /// Delete a key
    fn delete_key(&self, key_id: &str) -> Result<(), CryptoError>;
    
    /// Check if key exists
    fn key_exists(&self, key_id: &str) -> Result<bool, CryptoError>;
}

/// Get platform-specific storage implementation
pub fn get_secure_storage() -> Box<dyn SecureStorage> {
    #[cfg(target_os = "ios")]
    return Box::new(ios::KeychainStorage::new());
    
    #[cfg(target_os = "android")]
    return Box::new(android::KeystoreStorage::new());
    
    #[cfg(target_os = "windows")]
    return Box::new(windows::WindowsCredentialStorage::new());
    
    #[cfg(target_os = "macos")]
    return Box::new(macos::KeychainStorage::new());
    
    #[cfg(target_os = "linux")]
    {
        // Try to use Secret Service, fall back to file storage
        if linux::SecretServiceStorage::is_available() {
            return Box::new(linux::SecretServiceStorage::new());
        }
    }
    
    #[cfg(not(any(
        target_os = "ios", 
        target_os = "android", 
        target_os = "windows",
        target_os = "macos"
    )))]
    return Box::new(generic::FileStorage::new());
}

/// Platform information
pub fn get_platform_info() -> PlatformInfo {
    PlatformInfo {
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        family: std::env::consts::FAMILY,
        secure_storage: get_secure_storage_type(),
        features: get_platform_features(),
    }
}

#[derive(Debug, Clone)]
pub struct PlatformInfo {
    pub os: &'static str,
    pub arch: &'static str,
    pub family: &'static str,
    pub secure_storage: &'static str,
    pub features: Vec<&'static str>,
}

fn get_secure_storage_type() -> &'static str {
    #[cfg(target_os = "ios")]
    return "iOS Keychain";
    
    #[cfg(target_os = "android")]
    return "Android Keystore";
    
    #[cfg(target_os = "windows")]
    return "Windows Credential Manager";
    
    #[cfg(target_os = "macos")]
    return "macOS Keychain";
    
    #[cfg(target_os = "linux")]
    {
        if linux::SecretServiceStorage::is_available() {
            return "Linux Secret Service";
        }
    }
    
    #[cfg(not(any(
        target_os = "ios", 
        target_os = "android", 
        target_os = "windows",
        target_os = "macos"
    )))]
    return "File Storage";
}

fn get_platform_features() -> Vec<&'static str> {
    let mut features = Vec::new();
    
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    features.push("Secure Enclave");
    
    #[cfg(target_os = "windows")]
    {
        features.push("DPAPI");
        features.push("Credential Manager");
    }
    
    #[cfg(target_os = "android")]
    {
        features.push("Hardware-backed Keystore");
        features.push("StrongBox");
    }
    
    // Check for hardware acceleration
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if is_x86_feature_detected!("aes") {
            features.push("AES-NI");
        }
        if is_x86_feature_detected!("avx2") {
            features.push("AVX2");
        }
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("aes") {
            features.push("ARM AES");
        }
        if std::arch::is_aarch64_feature_detected!("neon") {
            features.push("NEON");
        }
    }
    
    features
}
