//! Windows platform-specific secure storage implementation
//! Uses Windows Credential Manager and DPAPI for key protection

use crate::errors::CryptoError;
use crate::platform::SecureStorage;
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use winapi::shared::minwindef::{DWORD, TRUE, FALSE};
use winapi::shared::winerror::{ERROR_NOT_FOUND, ERROR_SUCCESS};
use winapi::um::dpapi::{CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN};
use winapi::um::wincred::*;
use winapi::um::winnt::LPWSTR;
use std::ptr;
use std::mem;
use parking_lot::Mutex;
use std::collections::HashMap;

/// Convert Rust string to Windows wide string
fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// Convert Windows wide string to Rust string
fn from_wide_ptr(ptr: LPWSTR) -> String {
    unsafe {
        let len = (0..).take_while(|&i| *ptr.offset(i) != 0).count();
        let slice = std::slice::from_raw_parts(ptr, len);
        OsString::from_wide(slice).to_string_lossy().into_owned()
    }
}

/// Windows Credential Manager storage
pub struct WindowsCredentialStorage {
    /// Target name prefix for credentials
    target_prefix: String,
    /// Cache for performance
    cache: Mutex<HashMap<String, Vec<u8>>>,
}

impl WindowsCredentialStorage {
    pub fn new() -> Self {
        Self {
            target_prefix: "AeroNyx_".to_string(),
            cache: Mutex::new(HashMap::new()),
        }
    }
    
    /// Get full target name for a key
    fn get_target_name(&self, key_id: &str) -> String {
        format!("{}{}", self.target_prefix, key_id)
    }
    
    /// Encrypt data using DPAPI
    fn encrypt_with_dpapi(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        unsafe {
            let mut data_in = winapi::um::dpapi::DATA_BLOB {
                cbData: data.len() as DWORD,
                pbData: data.as_ptr() as *mut u8,
            };
            
            let mut data_out = winapi::um::dpapi::DATA_BLOB {
                cbData: 0,
                pbData: ptr::null_mut(),
            };
            
            let description = to_wide_string("AeroNyx Protected Key");
            
            let result = CryptProtectData(
                &mut data_in,
                description.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut data_out,
            );
            
            if result == TRUE {
                let encrypted = std::slice::from_raw_parts(
                    data_out.pbData,
                    data_out.cbData as usize,
                ).to_vec();
                
                // Free the allocated memory
                winapi::um::winbase::LocalFree(data_out.pbData as *mut _);
                
                Ok(encrypted)
            } else {
                Err(CryptoError::KeyError("DPAPI encryption failed".into()))
            }
        }
    }
    
    /// Decrypt data using DPAPI
    fn decrypt_with_dpapi(&self, encrypted: &[u8]) -> Result<Vec<u8>, CryptoError> {
        unsafe {
            let mut data_in = winapi::um::dpapi::DATA_BLOB {
                cbData: encrypted.len() as DWORD,
                pbData: encrypted.as_ptr() as *mut u8,
            };
            
            let mut data_out = winapi::um::dpapi::DATA_BLOB {
                cbData: 0,
                pbData: ptr::null_mut(),
            };
            
            let result = CryptUnprotectData(
                &mut data_in,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut data_out,
            );
            
            if result == TRUE {
                let decrypted = std::slice::from_raw_parts(
                    data_out.pbData,
                    data_out.cbData as usize,
                ).to_vec();
                
                // Free the allocated memory
                winapi::um::winbase::LocalFree(data_out.pbData as *mut _);
                
                Ok(decrypted)
            } else {
                Err(CryptoError::KeyError("DPAPI decryption failed".into()))
            }
        }
    }
}

impl SecureStorage for WindowsCredentialStorage {
    fn store_key(&self, key_id: &str, key_data: &[u8]) -> Result<(), CryptoError> {
        let target = to_wide_string(&self.get_target_name(key_id));
        let username = to_wide_string("AeroNyx");
        
        // Encrypt the key data with DPAPI for additional protection
        let encrypted_data = self.encrypt_with_dpapi(key_data)?;
        
        let credential = CREDENTIALW {
            Flags: 0,
            Type: CRED_TYPE_GENERIC,
            TargetName: target.as_ptr() as LPWSTR,
            Comment: ptr::null_mut(),
            LastWritten: unsafe { mem::zeroed() },
            CredentialBlobSize: encrypted_data.len() as DWORD,
            CredentialBlob: encrypted_data.as_ptr() as *mut u8,
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: ptr::null_mut(),
            TargetAlias: ptr::null_mut(),
            UserName: username.as_ptr() as LPWSTR,
        };
        
        let result = unsafe { CredWriteW(&credential, 0) };
        
        if result == TRUE {
            // Update cache
            self.cache.lock().insert(key_id.to_string(), key_data.to_vec());
            Ok(())
        } else {
            let error = unsafe { winapi::um::errhandlingapi::GetLastError() };
            Err(CryptoError::KeyError(format!("Failed to store key: {}", error)))
        }
    }
    
    fn get_key(&self, key_id: &str) -> Result<Vec<u8>, CryptoError> {
        // Check cache first
        if let Some(data) = self.cache.lock().get(key_id) {
            return Ok(data.clone());
        }
        
        let target = to_wide_string(&self.get_target_name(key_id));
        let mut credential: *mut CREDENTIALW = ptr::null_mut();
        
        let result = unsafe {
            CredReadW(
                target.as_ptr(),
                CRED_TYPE_GENERIC,
                0,
                &mut credential,
            )
        };
        
        if result == TRUE && !credential.is_null() {
            unsafe {
                let cred = &*credential;
                let encrypted_data = std::slice::from_raw_parts(
                    cred.CredentialBlob,
                    cred.CredentialBlobSize as usize,
                );
                
                // Decrypt the data
                let decrypted = self.decrypt_with_dpapi(encrypted_data)?;
                
                // Free the credential
                CredFree(credential as *mut _);
                
                // Update cache
                self.cache.lock().insert(key_id.to_string(), decrypted.clone());
                
                Ok(decrypted)
            }
        } else {
            let error = unsafe { winapi::um::errhandlingapi::GetLastError() };
            if error == ERROR_NOT_FOUND {
                Err(CryptoError::KeyError("Key not found".into()))
            } else {
                Err(CryptoError::KeyError(format!("Failed to retrieve key: {}", error)))
            }
        }
    }
    
    fn delete_key(&self, key_id: &str) -> Result<(), CryptoError> {
        let target = to_wide_string(&self.get_target_name(key_id));
        
        let result = unsafe {
            CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0)
        };
        
        if result == TRUE {
            // Remove from cache
            self.cache.lock().remove(key_id);
            Ok(())
        } else {
            let error = unsafe { winapi::um::errhandlingapi::GetLastError() };
            if error == ERROR_NOT_FOUND {
                // Key doesn't exist, not an error
                Ok(())
            } else {
                Err(CryptoError::KeyError(format!("Failed to delete key: {}", error)))
            }
        }
    }
    
    fn key_exists(&self, key_id: &str) -> Result<bool, CryptoError> {
        // Check cache first
        if self.cache.lock().contains_key(key_id) {
            return Ok(true);
        }
        
        let target = to_wide_string(&self.get_target_name(key_id));
        let mut credential: *mut CREDENTIALW = ptr::null_mut();
        
        let result = unsafe {
            CredReadW(
                target.as_ptr(),
                CRED_TYPE_GENERIC,
                0,
                &mut credential,
            )
        };
        
        if result == TRUE && !credential.is_null() {
            unsafe { CredFree(credential as *mut _) };
            Ok(true)
        } else {
            let error = unsafe { winapi::um::errhandlingapi::GetLastError() };
            if error == ERROR_NOT_FOUND {
                Ok(false)
            } else {
                Err(CryptoError::KeyError(format!("Failed to check key existence: {}", error)))
            }
        }
    }
}

/// Windows memory protection utilities
pub mod memory {
    use super::*;
    use winapi::um::memoryapi::{VirtualLock, VirtualUnlock};
    use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};
    use winapi::shared::basetsd::SIZE_T;
    
    /// Lock memory pages to prevent swapping
    pub fn lock_memory(ptr: *const u8, len: usize) -> Result<(), CryptoError> {
        unsafe {
            // Get system page size
            let mut sys_info: SYSTEM_INFO = mem::zeroed();
            GetSystemInfo(&mut sys_info);
            let page_size = sys_info.dwPageSize as usize;
            
            // Align to page boundaries
            let offset = ptr as usize % page_size;
            let aligned_ptr = (ptr as usize - offset) as *const u8;
            let aligned_len = len + offset;
            
            if VirtualLock(aligned_ptr as *mut _, aligned_len as SIZE_T) == TRUE {
                Ok(())
            } else {
                Err(CryptoError::KeyError("Failed to lock memory".into()))
            }
        }
    }
    
    /// Unlock memory pages
    pub fn unlock_memory(ptr: *const u8, len: usize) -> Result<(), CryptoError> {
        unsafe {
            // Get system page size
            let mut sys_info: SYSTEM_INFO = mem::zeroed();
            GetSystemInfo(&mut sys_info);
            let page_size = sys_info.dwPageSize as usize;
            
            // Align to page boundaries
            let offset = ptr as usize % page_size;
            let aligned_ptr = (ptr as usize - offset) as *const u8;
            let aligned_len = len + offset;
            
            if VirtualUnlock(aligned_ptr as *mut _, aligned_len as SIZE_T) == TRUE {
                Ok(())
            } else {
                Err(CryptoError::KeyError("Failed to unlock memory".into()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_credential_storage() {
        let storage = WindowsCredentialStorage::new();
        let key_id = "test_key_windows";
        let key_data = b"secret_key_data";
        
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
    
    #[test]
    fn test_dpapi_encryption() {
        let storage = WindowsCredentialStorage::new();
        let data = b"sensitive_data";
        
        // Encrypt
        let encrypted = storage.encrypt_with_dpapi(data).unwrap();
        assert_ne!(encrypted, data);
        
        // Decrypt
        let decrypted = storage.decrypt_with_dpapi(&encrypted).unwrap();
        assert_eq!(decrypted, data);
    }
}
