use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256, Sha512};
use std::slice;
use std::ptr;
use std::os::raw::{c_char, c_uchar, c_int, c_void};

// Helpers for memory management between C and Rust
#[repr(C)]
pub struct ByteBuffer {
    data: *mut u8,
    len: usize,
    capacity: usize,
}

impl ByteBuffer {
    pub fn new() -> ByteBuffer {
        ByteBuffer {
            data: ptr::null_mut(),
            len: 0,
            capacity: 0,
        }
    }
    
    pub fn from_vec(vec: Vec<u8>) -> ByteBuffer {
        let mut vec = vec;
        let buf = ByteBuffer {
            data: vec.as_mut_ptr(),
            len: vec.len(),
            capacity: vec.capacity(),
        };
        std::mem::forget(vec);
        buf
    }
    
    pub unsafe fn destroy(&mut self) {
        if !self.data.is_null() {
            let _ = Vec::from_raw_parts(self.data, self.len, self.capacity);
            self.data = ptr::null_mut();
            self.len = 0;
            self.capacity = 0;
        }
    }
}

// Free a ByteBuffer from C
#[no_mangle]
pub extern "C" fn aeronyx_free_buffer(buffer: *mut ByteBuffer) {
    if !buffer.is_null() {
        unsafe {
            (*buffer).destroy();
            Box::from_raw(buffer);
        }
    }
}

// Ed25519 private key to X25519 conversion
#[no_mangle]
pub extern "C" fn aeronyx_ed25519_private_to_x25519(
    ed25519_private: *const u8,
    ed25519_private_len: usize,
) -> *mut ByteBuffer {
    let private_key_bytes = unsafe { slice::from_raw_parts(ed25519_private, ed25519_private_len) };
    
    // Hash the private key with SHA-512
    let mut hash = Sha512::new();
    hash.update(private_key_bytes);
    let hash_result = hash.finalize();
    
    // Extract lower 32 bytes
    let mut x25519_private = [0u8; 32];
    x25519_private.copy_from_slice(&hash_result[0..32]);
    
    // Apply bit clamping as per RFC 7748
    x25519_private[0] &= 248;  // Clear bits 0, 1, 2
    x25519_private[31] &= 127; // Clear bit 255
    x25519_private[31] |= 64;  // Set bit 254
    
    let result = ByteBuffer::from_vec(x25519_private.to_vec());
    Box::into_raw(Box::new(result))
}

// Ed25519 public key to X25519 conversion
#[no_mangle]
pub extern "C" fn aeronyx_ed25519_public_to_x25519(
    ed25519_public: *const u8,
    ed25519_public_len: usize,
) -> *mut ByteBuffer {
    let public_key_bytes = unsafe { slice::from_raw_parts(ed25519_public, ed25519_public_len) };
    
    // Parse the Edwards point
    let compressed = CompressedEdwardsY::from_slice(public_key_bytes);
    if let Some(edwards_point) = compressed.decompress() {
        // Convert to Montgomery form
        let montgomery_bytes = edwards_point.to_montgomery().to_bytes();
        let result = ByteBuffer::from_vec(montgomery_bytes.to_vec());
        return Box::into_raw(Box::new(result));
    }
    
    // Error case - return empty buffer
    Box::into_raw(Box::new(ByteBuffer::new()))
}

// Sign data with Ed25519 key
#[no_mangle]
pub extern "C" fn aeronyx_sign_ed25519(
    private_key: *const u8,
    private_key_len: usize,
    message: *const u8,
    message_len: usize,
) -> *mut ByteBuffer {
    if private_key_len != 32 && private_key_len != 64 {
        return Box::into_raw(Box::new(ByteBuffer::new()));
    }
    
    let message_bytes = unsafe { slice::from_raw_parts(message, message_len) };
    
    // Create keypair from private key
    let result = if private_key_len == 32 {
        // Just secret key
        let secret_bytes = unsafe { slice::from_raw_parts(private_key, 32) };
        match SecretKey::from_bytes(secret_bytes) {
            Ok(secret) => {
                let public = PublicKey::from(&secret);
                let keypair = Keypair { secret, public };
                Some(keypair.sign(message_bytes).to_bytes().to_vec())
            }
            Err(_) => None
        }
    } else {
        // Full keypair (64 bytes)
        let keypair_bytes = unsafe { slice::from_raw_parts(private_key, 64) };
        match Keypair::from_bytes(keypair_bytes) {
            Ok(keypair) => Some(keypair.sign(message_bytes).to_bytes().to_vec()),
            Err(_) => None
        }
    };
    
    match result {
        Some(signature) => Box::into_raw(Box::new(ByteBuffer::from_vec(signature))),
        None => Box::into_raw(Box::new(ByteBuffer::new()))
    }
}

// Verify Ed25519 signature
#[no_mangle]
pub extern "C" fn aeronyx_verify_ed25519(
    public_key: *const u8,
    public_key_len: usize,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> c_int {
    if public_key_len != 32 || signature_len != 64 {
        return 0;
    }
    
    let public_bytes = unsafe { slice::from_raw_parts(public_key, public_key_len) };
    let message_bytes = unsafe { slice::from_raw_parts(message, message_len) };
    let signature_bytes = unsafe { slice::from_raw_parts(signature, signature_len) };
    
    match PublicKey::from_bytes(public_bytes) {
        Ok(public) => {
            match Signature::from_bytes(signature_bytes) {
                Ok(signature) => {
                    match public.verify(message_bytes, &signature) {
                        Ok(_) => 1,
                        Err(_) => 0
                    }
                }
                Err(_) => 0
            }
        }
        Err(_) => 0
    }
}

// Encrypt using ChaCha20-Poly1305
#[no_mangle]
pub extern "C" fn aeronyx_encrypt_chacha20poly1305(
    data: *const u8,
    data_len: usize,
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
) -> *mut ByteBuffer {
    if key_len != 32 || (nonce != ptr::null() && nonce_len != 12) {
        return Box::into_raw(Box::new(ByteBuffer::new()));
    }
    
    let data_bytes = unsafe { slice::from_raw_parts(data, data_len) };
    let key_bytes = unsafe { slice::from_raw_parts(key, key_len) };
    
    // Create the cipher
    let cipher_key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(cipher_key);
    
    // Generate or use provided nonce
    let nonce_bytes = if nonce == ptr::null() {
        let mut random_nonce = [0u8; 12];
        OsRng.fill_bytes(&mut random_nonce);
        random_nonce.to_vec()
    } else {
        unsafe { slice::from_raw_parts(nonce, nonce_len).to_vec() }
    };
    
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Encrypt the data
    match cipher.encrypt(nonce, data_bytes) {
        Ok(ciphertext) => {
            // Return combined ciphertext+nonce
            let mut result = nonce_bytes.clone();
            result.extend_from_slice(&ciphertext);
            Box::into_raw(Box::new(ByteBuffer::from_vec(result)))
        }
        Err(_) => Box::into_raw(Box::new(ByteBuffer::new()))
    }
}

// Decrypt using ChaCha20-Poly1305
#[no_mangle]
pub extern "C" fn aeronyx_decrypt_chacha20poly1305(
    data: *const u8,
    data_len: usize,
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
) -> *mut ByteBuffer {
    if key_len != 32 || nonce_len != 12 || data_len <= 16 {  // 16 for tag
        return Box::into_raw(Box::new(ByteBuffer::new()));
    }
    
    let data_bytes = unsafe { slice::from_raw_parts(data, data_len) };
    let key_bytes = unsafe { slice::from_raw_parts(key, key_len) };
    let nonce_bytes = unsafe { slice::from_raw_parts(nonce, nonce_len) };
    
    // Create the cipher
    let cipher_key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // Decrypt the data
    match cipher.decrypt(nonce, data_bytes) {
        Ok(plaintext) => Box::into_raw(Box::new(ByteBuffer::from_vec(plaintext))),
        Err(_) => Box::into_raw(Box::new(ByteBuffer::new()))
    }
}

// Derive key using HKDF
#[no_mangle]
pub extern "C" fn aeronyx_derive_key(
    key_material: *const u8,
    key_material_len: usize,
    salt: *const u8,
    salt_len: usize,
    info: *const u8,
    info_len: usize,
    output_length: usize,
) -> *mut ByteBuffer {
    let key_material_bytes = unsafe { slice::from_raw_parts(key_material, key_material_len) };
    let salt_bytes = if salt == ptr::null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(salt, salt_len) }
    };
    let info_bytes = if info == ptr::null() {
        &[]
    } else {
        unsafe { slice::from_raw_parts(info, info_len) }
    };
    
    // Create HKDF
    let hk = Hkdf::<Sha256>::new(Some(salt_bytes), key_material_bytes);
    let mut output = vec![0u8; output_length];
    
    match hk.expand(info_bytes, &mut output) {
        Ok(_) => Box::into_raw(Box::new(ByteBuffer::from_vec(output))),
        Err(_) => Box::into_raw(Box::new(ByteBuffer::new()))
    }
}
