//! SIMD-accelerated cryptographic operations
//! Provides optimized implementations for supported platforms

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86;

#[cfg(target_arch = "aarch64")]
pub mod arm;

use crate::errors::CryptoError;

/// Trait for SIMD-accelerated operations
pub trait SimdOps {
    /// XOR two byte arrays using SIMD
    fn xor_blocks(a: &mut [u8], b: &[u8]) -> Result<(), CryptoError>;
    
    /// Constant-time comparison using SIMD
    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool;
    
    /// Parallel AES rounds (if supported)
    fn aes_encrypt_blocks(blocks: &mut [u8], key: &[u8]) -> Result<(), CryptoError>;
}

/// Get the best available SIMD implementation
pub fn get_simd_impl() -> Box<dyn SimdOps> {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if is_x86_feature_detected!("avx2") {
            return Box::new(x86::Avx2Ops);
        } else if is_x86_feature_detected!("sse2") {
            return Box::new(x86::Sse2Ops);
        }
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            return Box::new(arm::NeonOps);
        }
    }
    
    // Fallback to scalar implementation
    Box::new(ScalarOps)
}

/// Scalar fallback implementation
struct ScalarOps;

impl SimdOps for ScalarOps {
    fn xor_blocks(a: &mut [u8], b: &[u8]) -> Result<(), CryptoError> {
        if a.len() != b.len() {
            return Err(CryptoError::InvalidFormat("Block size mismatch".into()));
        }
        
        for (x, y) in a.iter_mut().zip(b.iter()) {
            *x ^= y;
        }
        
        Ok(())
    }
    
    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        
        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }
        
        result == 0
    }
    
    fn aes_encrypt_blocks(_blocks: &mut [u8], _key: &[u8]) -> Result<(), CryptoError> {
        Err(CryptoError::InvalidFormat("AES-NI not available".into()))
    }
}
