//! iOS Keychain and Secure Enclave integration
//! 
//! Provides secure key storage using iOS Keychain Services and
//! hardware-backed encryption via the Secure Enclave when available.

use crate::errors::CryptoError;
use crate::platform::SecureStorage;
use objc::{class, msg_send, sel, sel_impl, runtime::Object};
use objc_foundation::{INSString, NSString};
use std::collections::HashMap;
use parking_lot::RwLock;
use std::ffi::c_void;

/// Keychain error codes
const ERR_SEC_SUCCESS: i32 = 0;
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;
const ERR_SEC_AUTH_FAILED: i32 = -25293;

/// Keychain attributes
const K_SEC_CLASS: &str = "kSecClass";
const K_SEC_CLASS_KEY: &str = "kSecClassKey";
const K_SEC_ATTR_APPLICATION_TAG: &str = "kSecAttrApplicationTag";
const K_SEC_ATTR_KEY_TYPE: &str = "kSecAttrKeyType";
const K_SEC_ATTR_KEY_SIZE_IN_BITS: &str = "kSecAttrKeySizeInBits";
const K_SEC_ATTR_TOKEN_ID: &str = "kSecAttrTokenID";
const K_SEC_ATTR_TOKEN_ID_SECURE_ENCLAVE: &str = "kSecAttrTokenIDSecureEnclave";
const K_SEC_VALUE_DATA: &str = "kSecValueData";
const K_SEC_RETURN_DATA: &str = "kSecReturnData";
const K_SEC_ATTR_ACCESSIBLE: &str = "kSecAttrAccessible";
const K_SEC_ATTR_ACCESSIBLE_WHEN_UNLOCKED_THIS_DEVICE_ONLY: &str = "kSecAttrAccessibleWhenUnlockedThisDeviceOnly";

/// iOS Keychain storage implementation
pub struct KeychainStorage {
    /// Cache for performance
    cache: RwLock<HashMap<String, Vec<u8>>>,
    /// Service name for keychain items
    service_name: String,
    /// Whether to use Secure Enclave when available
    use_secure_enclave: bool,
}

impl KeychainStorage {
    /// Create a new keychain storage instance
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            service_name: "com.aeronyx.crypto".to_string(),
            use_secure_enclave: Self::is_secure_enclave_available(),
        }
    }
    
    /// Check if Secure Enclave is available on this device
    fn is_secure_enclave_available() -> bool {
        // Check if running on a device with Secure Enclave
        // This requires iOS 9.0+ and specific hardware
        #[cfg(target_os = "ios")]
        unsafe {
            let process_info: *mut Object = msg_send![class!(NSProcessInfo), processInfo];
            let version: *mut Object = msg_send![process_info, operatingSystemVersion];
            let major: i64 = msg_send![version, majorVersion];
            
            // Secure Enclave requires iOS 9.0+
            if major >= 9 {
                // Additional hardware check could be performed here
                true
            } else {
                false
            }
        }
        
        #[cfg(not(target_os = "ios"))]
        false
    }
    
    /// Convert error code to CryptoError
    fn error_from_osstatus(status: i32) -> CryptoError {
        match status {
            ERR_SEC_ITEM_NOT_FOUND => CryptoError::KeyError("Key not found in keychain".into()),
            ERR_SEC_DUPLICATE_ITEM => CryptoError::KeyError("Key already exists in keychain".into()),
            ERR_SEC_AUTH_FAILED => CryptoError::AuthenticationFailed,
            _ => CryptoError::KeyError(format!("Keychain error: {}", status)),
        }
    }
    
    /// Create keychain query dictionary
    #[allow(unsafe_code)]
    unsafe fn create_query(&self, key_id: &str) -> *mut Object {
        let query: *mut Object = msg_send![class!(NSMutableDictionary), new];
        
        // Set class to key
        let class_key = NSString::from_str(K_SEC_CLASS);
        let class_value = NSString::from_str(K_SEC_CLASS_KEY);
        let _: () = msg_send![query, setObject:class_value forKey:class_key];
        
        // Set application tag (key identifier)
        let tag_key = NSString::from_str(K_SEC_ATTR_APPLICATION_TAG);
        let tag_data = NSString::from_str(&format!("{}.{}", self.service_name, key_id));
        let tag_value: *mut Object = msg_send![tag_data, dataUsingEncoding:4]; // UTF8
        let _: () = msg_send![query, setObject:tag_value forKey:tag_key];
        
        // Set accessibility
        let accessible_key = NSString::from_str(K_SEC_ATTR_ACCESSIBLE);
        let accessible_value = NSString::from_str(K_SEC_ATTR_ACCESSIBLE_WHEN_UNLOCKED_THIS_DEVICE_ONLY);
        let _: () = msg_send![query, setObject:accessible_value forKey:accessible_key];
        
        query
    }
    
    /// Store key in keychain
    #[allow(unsafe_code)]
    fn keychain_store(&self, key_id: &str, key_data: &[u8]) -> Result<(), CryptoError> {
        unsafe {
            let query = self.create_query(key_id);
            
            // Add the key data
            let value_key = NSString::from_str(K_SEC_VALUE_DATA);
            let data: *mut Object = msg_send![class!(NSData), dataWithBytes:key_data.as_ptr() length:key_data.len()];
            let _: () = msg_send![query, setObject:data forKey:value_key];
            
            // If using Secure Enclave, set additional attributes
            if self.use_secure_enclave {
                let token_key = NSString::from_str(K_SEC_ATTR_TOKEN_ID);
                let token_value = NSString::from_str(K_SEC_ATTR_TOKEN_ID_SECURE_ENCLAVE);
                let _: () = msg_send![query, setObject:token_value forKey:token_key];
            }
            
            // Add to keychain
            let status = SecItemAdd(query as *const c_void, std::ptr::null_mut());
            
            // Clean up
            let _: () = msg_send![query, release];
            
            if status == ERR_SEC_SUCCESS {
                Ok(())
            } else if status == ERR_SEC_DUPLICATE_ITEM {
                // Item already exists, update it
                self.keychain_update(key_id, key_data)
            } else {
                Err(Self::error_from_osstatus(status))
            }
        }
    }
    
    /// Update existing key in keychain
    #[allow(unsafe_code)]
    fn keychain_update(&self, key_id: &str, key_data: &[u8]) -> Result<(), CryptoError> {
        unsafe {
            let query = self.create_query(key_id);
            
            // Create update dictionary
            let update_dict: *mut Object = msg_send![class!(NSMutableDictionary), new];
            let value_key = NSString::from_str(K_SEC_VALUE_DATA);
            let data: *mut Object = msg_send![class!(NSData), dataWithBytes:key_data.as_ptr() length:key_data.len()];
            let _: () = msg_send![update_dict, setObject:data forKey:value_key];
            
            // Update the item
            let status = SecItemUpdate(query as *const c_void, update_dict as *const c_void);
            
            // Clean up
            let _: () = msg_send![query, release];
            let _: () = msg_send![update_dict, release];
            
            if status == ERR_SEC_SUCCESS {
                Ok(())
            } else {
                Err(Self::error_from_osstatus(status))
            }
        }
    }
    
    /// Retrieve key from keychain
    #[allow(unsafe_code)]
    fn keychain_get(&self, key_id: &str) -> Result<Vec<u8>, CryptoError> {
        unsafe {
            let query = self.create_query(key_id);
            
            // Request data to be returned
            let return_key = NSString::from_str(K_SEC_RETURN_DATA);
            let return_value: *mut Object = msg_send![class!(NSNumber), numberWithBool:1];
            let _: () = msg_send![query, setObject:return_value forKey:return_key];
            
            // Get the item
            let mut result: *mut Object = std::ptr::null_mut();
            let status = SecItemCopyMatching(query as *const c_void, &mut result as *mut _ as *mut c_void);
            
            // Clean up query
            let _: () = msg_send![query, release];
            
            if status == ERR_SEC_SUCCESS && !result.is_null() {
                // Extract data
                let length: usize = msg_send![result, length];
                let bytes: *const u8 = msg_send![result, bytes];
                let data = std::slice::from_raw_parts(bytes, length).to_vec();
                
                // Clean up result
                let _: () = msg_send![result, release];
                
                Ok(data)
            } else {
                Err(Self::error_from_osstatus(status))
            }
        }
    }
    
    /// Delete key from keychain
    #[allow(unsafe_code)]
    fn keychain_delete(&self, key_id: &str) -> Result<(), CryptoError> {
        unsafe {
            let query = self.create_query(key_id);
            let status = SecItemDelete(query as *const c_void);
            let _: () = msg_send![query, release];
            
            if status == ERR_SEC_SUCCESS || status == ERR_SEC_ITEM_NOT_FOUND {
                Ok(())
            } else {
                Err(Self::error_from_osstatus(status))
            }
        }
    }
}

impl SecureStorage for KeychainStorage {
    fn store_key(&self, key_id: &str, key_data: &[u8]) -> Result<(), CryptoError> {
        // Store in keychain
        self.keychain_store(key_id, key_data)?;
        
        // Update cache
        self.cache.write().insert(key_id.to_string(), key_data.to_vec());
        
        Ok(())
    }
    
    fn get_key(&self, key_id: &str) -> Result<Vec<u8>, CryptoError> {
        // Check cache first
        if let Some(data) = self.cache.read().get(key_id) {
            return Ok(data.clone());
        }
        
        // Get from keychain
        let data = self.keychain_get(key_id)?;
        
        // Update cache
        self.cache.write().insert(key_id.to_string(), data.clone());
        
        Ok(data)
    }
    
    fn delete_key(&self, key_id: &str) -> Result<(), CryptoError> {
        // Remove from cache
        self.cache.write().remove(key_id);
        
        // Delete from keychain
        self.keychain_delete(key_id)
    }
    
    fn key_exists(&self, key_id: &str) -> Result<bool, CryptoError> {
        // Check cache first
        if self.cache.read().contains_key(key_id) {
            return Ok(true);
        }
        
        // Check keychain
        match self.keychain_get(key_id) {
            Ok(_) => Ok(true),
            Err(CryptoError::KeyError(ref msg)) if msg.contains("not found") => Ok(false),
            Err(e) => Err(e),
        }
    }
}

// External functions from Security framework
#[allow(improper_ctypes)]
extern "C" {
    fn SecItemAdd(attributes: *const c_void, result: *mut c_void) -> i32;
    fn SecItemUpdate(query: *const c_void, attributes: *const c_void) -> i32;
    fn SecItemCopyMatching(query: *const c_void, result: *mut c_void) -> i32;
    fn SecItemDelete(query: *const c_void) -> i32;
}

/// Secure Enclave operations for hardware-backed cryptography
pub mod secure_enclave {
    use super::*;
    
    /// Generate a key pair in the Secure Enclave
    #[allow(unsafe_code)]
    pub fn generate_secure_key_pair(key_id: &str) -> Result<(), CryptoError> {
        unsafe {
            // Create attributes dictionary
            let attributes: *mut Object = msg_send![class!(NSMutableDictionary), new];
            
            // Set key type and size
            let type_key = NSString::from_str(K_SEC_ATTR_KEY_TYPE);
            let type_value = NSString::from_str("kSecAttrKeyTypeECSECPrimeRandom");
            let _: () = msg_send![attributes, setObject:type_value forKey:type_key];
            
            let size_key = NSString::from_str(K_SEC_ATTR_KEY_SIZE_IN_BITS);
            let size_value: *mut Object = msg_send![class!(NSNumber), numberWithInt:256];
            let _: () = msg_send![attributes, setObject:size_value forKey:size_key];
            
            // Set token ID for Secure Enclave
            let token_key = NSString::from_str(K_SEC_ATTR_TOKEN_ID);
            let token_value = NSString::from_str(K_SEC_ATTR_TOKEN_ID_SECURE_ENCLAVE);
            let _: () = msg_send![attributes, setObject:token_value forKey:token_key];
            
            // Set application tag
            let tag_key = NSString::from_str(K_SEC_ATTR_APPLICATION_TAG);
            let tag_string = NSString::from_str(&format!("com.aeronyx.se.{}", key_id));
            let tag_data: *mut Object = msg_send![tag_string, dataUsingEncoding:4];
            let _: () = msg_send![attributes, setObject:tag_data forKey:tag_key];
            
            // Generate the key
            let mut error: *mut Object = std::ptr::null_mut();
            let private_key: *mut Object = SecKeyCreateRandomKey(
                attributes as *const c_void,
                &mut error as *mut _ as *mut c_void
            );
            
            // Clean up
            let _: () = msg_send![attributes, release];
            
            if private_key.is_null() {
                if !error.is_null() {
                    let desc: *mut Object = msg_send![error, localizedDescription];
                    let _: () = msg_send![error, release];
                    // Convert NSString to Rust String for error message
                    Err(CryptoError::KeyError("Failed to generate Secure Enclave key".into()))
                } else {
                    Err(CryptoError::KeyError("Unknown error generating Secure Enclave key".into()))
                }
            } else {
                let _: () = msg_send![private_key, release];
                Ok(())
            }
        }
    }
    
    // External function from Security framework
    #[allow(improper_ctypes)]
    extern "C" {
        fn SecKeyCreateRandomKey(parameters: *const c_void, error: *mut c_void) -> *mut Object;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_keychain_storage() {
        let storage = KeychainStorage::new();
        let key_id = "test_key_ios";
        let key_data = b"secret_key_data_ios";
        
        // Store key
        storage.store_key(key_id, key_data).unwrap();
        
        // Retrieve key
        let retrieved = storage.get_key(key_id).unwrap();
        assert_eq!(retrieved, key_data);
        
        // Check existence
        assert!(storage.key_exists(key_id).unwrap());
        
        // Delete key
        storage.delete_key(key_id).unwrap();
        assert!(!storage.key_exists(key_id).unwrap());
    }
}
