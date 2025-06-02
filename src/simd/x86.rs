//! x86/x86_64 SIMD implementations

use super::SimdOps;
use crate::errors::CryptoError;

#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

/// AVX2 implementation
pub struct Avx2Ops;

impl SimdOps for Avx2Ops {
    fn xor_blocks(a: &mut [u8], b: &[u8]) -> Result<(), CryptoError> {
        if a.len() != b.len() || a.len() % 32 != 0 {
            return Err(CryptoError::InvalidFormat("Block size must be multiple of 32".into()));
        }
        
        unsafe {
            let chunks_a = a.chunks_exact_mut(32);
            let chunks_b = b.chunks_exact(32);
            
            for (chunk_a, chunk_b) in chunks_a.zip(chunks_b) {
                let a_vec = _mm256_loadu_si256(chunk_a.as_ptr() as *const __m256i);
                let b_vec = _mm256_loadu_si256(chunk_b.as_ptr() as *const __m256i);
                let result = _mm256_xor_si256(a_vec, b_vec);
                _mm256_storeu_si256(chunk_a.as_mut_ptr() as *mut __m256i, result);
            }
        }
        
        Ok(())
    }
    
    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        
        unsafe {
            let mut acc = _mm256_setzero_si256();
            
            // Process 32-byte chunks
            let chunks_a = a.chunks_exact(32);
            let chunks_b = b.chunks_exact(32);
            let remainder_a = chunks_a.remainder();
            let remainder_b = chunks_b.remainder();
            
            for (chunk_a, chunk_b) in chunks_a.zip(chunks_b) {
                let a_vec = _mm256_loadu_si256(chunk_a.as_ptr() as *const __m256i);
                let b_vec = _mm256_loadu_si256(chunk_b.as_ptr() as *const __m256i);
                let diff = _mm256_xor_si256(a_vec, b_vec);
                acc = _mm256_or_si256(acc, diff);
            }
            
            // Check if any bits are set
            let zero = _mm256_setzero_si256();
            let cmp = _mm256_cmpeq_epi8(acc, zero);
            let mask = _mm256_movemask_epi8(cmp);
            
            // Process remainder
            let mut remainder_result = 0u8;
            for (x, y) in remainder_a.iter().zip(remainder_b.iter()) {
                remainder_result |= x ^ y;
            }
            
            mask == -1 && remainder_result == 0
        }
    }
    
    fn aes_encrypt_blocks(blocks: &mut [u8], key: &[u8]) -> Result<(), CryptoError> {
        if !is_x86_feature_detected!("aes") {
            return Err(CryptoError::InvalidFormat("AES-NI not available".into()));
        }
        
        // AES-NI implementation would go here
        unimplemented!("AES-NI encryption")
    }
}

/// SSE2 implementation
pub struct Sse2Ops;

impl SimdOps for Sse2Ops {
    fn xor_blocks(a: &mut [u8], b: &[u8]) -> Result<(), CryptoError> {
        if a.len() != b.len() || a.len() % 16 != 0 {
            return Err(CryptoError::InvalidFormat("Block size must be multiple of 16".into()));
        }
        
        unsafe {
            let chunks_a = a.chunks_exact_mut(16);
            let chunks_b = b.chunks_exact(16);
            
            for (chunk_a, chunk_b) in chunks_a.zip(chunks_b) {
                let a_vec = _mm_loadu_si128(chunk_a.as_ptr() as *const __m128i);
                let b_vec = _mm_loadu_si128(chunk_b.as_ptr() as *const __m128i);
                let result = _mm_xor_si128(a_vec, b_vec);
                _mm_storeu_si128(chunk_a.as_mut_ptr() as *mut __m128i, result);
            }
        }
        
        Ok(())
    }
    
    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        
        unsafe {
            let mut acc = _mm_setzero_si128();
            
            // Process 16-byte chunks
            let chunks_a = a.chunks_exact(16);
            let chunks_b = b.chunks_exact(16);
            let remainder_a = chunks_a.remainder();
            let remainder_b = chunks_b.remainder();
            
            for (chunk_a, chunk_b) in chunks_a.zip(chunks_b) {
                let a_vec = _mm_loadu_si128(chunk_a.as_ptr() as *const __m128i);
                let b_vec = _mm_loadu_si128(chunk_b.as_ptr() as *const __m128i);
                let diff = _mm_xor_si128(a_vec, b_vec);
                acc = _mm_or_si128(acc, diff);
            }
            
            // Check if any bits are set
            let zero = _mm_setzero_si128();
            let cmp = _mm_cmpeq_epi8(acc, zero);
            let mask = _mm_movemask_epi8(cmp);
            
            // Process remainder
            let mut remainder_result = 0u8;
            for (x, y) in remainder_a.iter().zip(remainder_b.iter()) {
                remainder_result |= x ^ y;
            }
            
            mask == 0xFFFF && remainder_result == 0
        }
    }
    
    fn aes_encrypt_blocks(_blocks: &mut [u8], _key: &[u8]) -> Result<(), CryptoError> {
        Err(CryptoError::InvalidFormat("AES-NI requires AVX".into()))
    }
}
