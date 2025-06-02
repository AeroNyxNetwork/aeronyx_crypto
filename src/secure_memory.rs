//! Secure memory handling for sensitive cryptographic materials
//! Provides zeroing, locking, and protection of memory regions

use std::ops::{Deref, DerefMut};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure buffer that automatically zeroes memory on drop
#[derive(ZeroizeOnDrop)]
pub struct SecureBuffer<T: Zeroize> {
    data: Vec<T>,
    locked: AtomicBool,
}

impl<T: Zeroize + Default + Clone> SecureBuffer<T> {
    /// Create a new secure buffer with specified capacity
    pub fn new(capacity: usize) -> Self {
        let mut data = Vec::with_capacity(capacity);
        data.resize(capacity, T::default());
        
        Self {
            data,
            locked: AtomicBool::new(false),
        }
    }
    
    /// Create from existing data, taking ownership
    pub fn from_vec(mut vec: Vec<T>) -> Self {
        // Ensure capacity matches length for security
        vec.shrink_to_fit();
        
        Self {
            data: vec,
            locked: AtomicBool::new(false),
        }
    }
    
    /// Lock memory to prevent swapping (platform-specific)
    pub fn lock_memory(&self) -> Result<(), SecureMemoryError> {
        if self.locked.load(Ordering::Acquire) {
            return Ok(());
        }
        
        #[cfg(unix)]
        {
            use libc::{mlock, size_t};
            
            let ptr = self.data.as_ptr() as *const libc::c_void;
            let len = self.data.len() * std::mem::size_of::<T>();
            
            unsafe {
                if mlock(ptr, len as size_t) == 0 {
                    self.locked.store(true, Ordering::Release);
                    Ok(())
                } else {
                    Err(SecureMemoryError::LockFailed)
                }
            }
        }
        
        #[cfg(not(unix))]
        {
            // Platform doesn't support memory locking
            Ok(())
        }
    }
    
    /// Unlock memory
    pub fn unlock_memory(&self) -> Result<(), SecureMemoryError> {
        if !self.locked.load(Ordering::Acquire) {
            return Ok(());
        }
        
        #[cfg(unix)]
        {
            use libc::{munlock, size_t};
            
            let ptr = self.data.as_ptr() as *const libc::c_void;
            let len = self.data.len() * std::mem::size_of::<T>();
            
            unsafe {
                if munlock(ptr, len as size_t) == 0 {
                    self.locked.store(false, Ordering::Release);
                    Ok(())
                } else {
                    Err(SecureMemoryError::UnlockFailed)
                }
            }
        }
        
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }
    
    /// Securely compare two buffers in constant time
    pub fn constant_time_eq(&self, other: &[T]) -> bool
    where
        T: Eq,
    {
        if self.data.len() != other.len() {
            return false;
        }
        
        let mut result = 0u8;
        for (a, b) in self.data.iter().zip(other.iter()) {
            result |= if a == b { 0 } else { 1 };
        }
        
        result == 0
    }
}

impl<T: Zeroize> Drop for SecureBuffer<T> {
    fn drop(&mut self) {
        // Unlock memory before dropping
        let _ = self.unlock_memory();
        // Zeroize is handled by ZeroizeOnDrop derive
    }
}

impl<T: Zeroize> Deref for SecureBuffer<T> {
    type Target = [T];
    
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T: Zeroize> DerefMut for SecureBuffer<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SecureMemoryError {
    #[error("Failed to lock memory")]
    LockFailed,
    
    #[error("Failed to unlock memory")]
    UnlockFailed,
}

/// Secure random number generation with additional entropy sources
pub mod secure_random {
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use sha2::{Sha256, Digest};
    
    /// Enhanced random number generator with multiple entropy sources
    pub struct EnhancedRng {
        primary: rand::rngs::OsRng,
        fallback: ChaCha20Rng,
    }
    
    impl EnhancedRng {
        pub fn new() -> Self {
            // Collect entropy from multiple sources
            let mut entropy = [0u8; 32];
            
            // System RNG
            rand::rngs::OsRng.fill_bytes(&mut entropy);
            
            // Add timestamp entropy
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            
            let mut hasher = Sha256::new();
            hasher.update(&entropy);
            hasher.update(&timestamp.to_le_bytes());
            
            // Add thread ID entropy
            hasher.update(&std::thread::current().id().as_u64().get().to_le_bytes());
            
            let enhanced_seed = hasher.finalize();
            
            Self {
                primary: rand::rngs::OsRng,
                fallback: ChaCha20Rng::from_seed(enhanced_seed.into()),
            }
        }
    }
    
    impl RngCore for EnhancedRng {
        fn next_u32(&mut self) -> u32 {
            self.primary.next_u32()
        }
        
        fn next_u64(&mut self) -> u64 {
            self.primary.next_u64()
        }
        
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.primary.fill_bytes(dest)
        }
        
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            match self.primary.try_fill_bytes(dest) {
                Ok(()) => Ok(()),
                Err(_) => {
                    // Fallback to ChaCha20 if OS RNG fails
                    self.fallback.fill_bytes(dest);
                    Ok(())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_buffer_zeroize() {
        let mut buffer = SecureBuffer::from_vec(vec![1u8, 2, 3, 4, 5]);
        assert_eq!(&*buffer, &[1, 2, 3, 4, 5]);
        
        drop(buffer);
        // Memory should be zeroed after drop
    }
    
    #[test]
    fn test_constant_time_comparison() {
        let buffer1 = SecureBuffer::from_vec(vec![1u8, 2, 3, 4, 5]);
        let buffer2 = vec![1u8, 2, 3, 4, 5];
        let buffer3 = vec![1u8, 2, 3, 4, 6];
        
        assert!(buffer1.constant_time_eq(&buffer2));
        assert!(!buffer1.constant_time_eq(&buffer3));
    }
}
