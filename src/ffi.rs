use std::slice;
use std::os::raw::{c_char, c_int, c_uchar, c_uint, c_void};
use std::ffi::{CStr, CString};

use crate::crypto;
use crate::errors::CryptoError;

// Utility to safely handle pointers
unsafe fn slice_from_raw_parts<'a>(data: *const c_uchar, len: usize) -> &'a [u8] {
    if data.is_null() || len == 0 {
        &[]
    } else {
        slice::from_raw_parts(data, len)
    }
}

// Helper to extract Option<&[u8]> from nullable pointer
unsafe fn optional_slice(data: *const c_uchar, len: usize) -> Option<&[u8]> {
    if data.is_null() {
        None
    } else {
        Some(slice_from_raw_parts(data, len))
    }
}

// Result codes
#[repr(C)]
pub enum ResultCode {
    Success = 0,
    InvalidKeyLength = 1,
    InvalidFormat = 2,
    EncryptionFailed = 3,
    DecryptionFailed = 4,
    AuthenticationFailed = 5,
    KeyError = 6,
    UnknownError = 7,
}

impl From<CryptoError> for ResultCode {
    fn from(error: CryptoError) -> Self {
        match error {
            CryptoError::InvalidKeyLength(_) => ResultCode::InvalidKeyLength,
            CryptoError::InvalidFormat(_) => ResultCode::InvalidFormat,
            CryptoError::EncryptionFailed(_) => ResultCode::EncryptionFailed,
            CryptoError::DecryptionFailed(_) => ResultCode::DecryptionFailed,
            CryptoError::AuthenticationFailed => ResultCode::AuthenticationFailed,
            CryptoError::KeyError(_) => ResultCode::KeyError,
        }
    }
}

// -------- Key Generation --------

#[no_mangle]
pub extern "C" fn generate_keypair(
    private_key_out: *mut c_uchar,
    private_key_len: *mut c_uint,
    public_key_out: *mut c_uchar,
    public_key_len: *mut c_uint,
) -> ResultCode {
    match crypto::generate_keypair() {
        Ok((private_key, public_key)) => {
            unsafe {
                if !private_key_out.is_null() && *private_key_len as usize >= private_key.len() {
                    std::ptr::copy_nonoverlapping(private_key.as_ptr(), private_key_out, private_key.len());
                    *private_key_len = private_key.len() as c_uint;
                }
                
                if !public_key_out.is_null() && *public_key_len as usize >= public_key.len() {
                    std::ptr::copy_nonoverlapping(public_key.as_ptr(), public_key_out, public_key.len());
                    *public_key_len = public_key.len() as c_uint;
                }
            }
            ResultCode::Success
        },
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn get_public_key_base58(
    public_key: *const c_uchar,
    public_key_len: c_uint,
    base58_out: *mut c_char,
    base58_len: *mut c_uint,
) -> ResultCode {
    let public_key_slice = unsafe { slice_from_raw_parts(public_key, public_key_len as usize) };
    
    match crypto::get_public_key_base58(public_key_slice) {
        Ok(base58) => {
            match CString::new(base58) {
                Ok(c_base58) => {
                    let bytes = c_base58.as_bytes_with_nul();
                    unsafe {
                        if !base58_out.is_null() && *base58_len as usize >= bytes.len() {
                            std::ptr::copy_nonoverlapping(bytes.as_ptr(), base58_out as *mut u8, bytes.len());
                            *base58_len = bytes.len() as c_uint;
                        } else {
                            *base58_len = bytes.len() as c_uint;
                            return ResultCode::InvalidFormat;
                        }
                    }
                    ResultCode::Success
                },
                Err(_) => ResultCode::InvalidFormat,
            }
        },
        Err(e) => e.into(),
    }
}

// -------- Encryption Functions --------

#[no_mangle]
pub extern "C" fn encrypt_chacha20(
    data: *const c_uchar,
    data_len: c_uint,
    key: *const c_uchar,
    key_len: c_uint,
    ciphertext_out: *mut c_uchar,
    ciphertext_len: *mut c_uint,
    nonce_out: *mut c_uchar,
    nonce_len: *mut c_uint,
) -> ResultCode {
    let data_slice = unsafe { slice_from_raw_parts(data, data_len as usize) };
    let key_slice = unsafe { slice_from_raw_parts(key, key_len as usize) };
    
    match crypto::encrypt_chacha20(data_slice, key_slice) {
        Ok((ciphertext, nonce)) => {
            unsafe {
                if !ciphertext_out.is_null() && *ciphertext_len as usize >= ciphertext.len() {
                    std::ptr::copy_nonoverlapping(ciphertext.as_ptr(), ciphertext_out, ciphertext.len());
                    *ciphertext_len = ciphertext.len() as c_uint;
                } else {
                    *ciphertext_len = ciphertext.len() as c_uint;
                    return ResultCode::InvalidFormat;
                }
                
                if !nonce_out.is_null() && *nonce_len as usize >= nonce.len() {
                    std::ptr::copy_nonoverlapping(nonce.as_ptr(), nonce_out, nonce.len());
                    *nonce_len = nonce.len() as c_uint;
                } else {
                    *nonce_len = nonce.len() as c_uint;
                    return ResultCode::InvalidFormat;
                }
            }
            ResultCode::Success
        },
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn decrypt_chacha20(
    ciphertext: *const c_uchar,
    ciphertext_len: c_uint,
    key: *const c_uchar,
    key_len: c_uint,
    nonce: *const c_uchar,
    nonce_len: c_uint,
    plaintext_out: *mut c_uchar,
    plaintext_len: *mut c_uint,
) -> ResultCode {
    let ciphertext_slice = unsafe { slice_from_raw_parts(ciphertext, ciphertext_len as usize) };
    let key_slice = unsafe { slice_from_raw_parts(key, key_len as usize) };
    let nonce_slice = unsafe { slice_from_raw_parts(nonce, nonce_len as usize) };
    
    match crypto::decrypt_chacha20(ciphertext_slice, key_slice, nonce_slice) {
        Ok(plaintext) => {
            unsafe {
                if !plaintext_out.is_null() && *plaintext_len as usize >= plaintext.len() {
                    std::ptr::copy_nonoverlapping(plaintext.as_ptr(), plaintext_out, plaintext.len());
                    *plaintext_len = plaintext.len() as c_uint;
                } else {
                    *plaintext_len = plaintext.len() as c_uint;
                    return ResultCode::InvalidFormat;
                }
            }
            ResultCode::Success
        },
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn encrypt_aes_gcm(
    data: *const c_uchar,
    data_len: c_uint,
    key: *const c_uchar,
    key_len: c_uint,
    aad: *const c_uchar,
    aad_len: c_uint,
    ciphertext_out: *mut c_uchar,
    ciphertext_len: *mut c_uint,
    nonce_out: *mut c_uchar,
    nonce_len: *mut c_uint,
) -> ResultCode {
    let data_slice = unsafe { slice_from_raw_parts(data, data_len as usize) };
    let key_slice = unsafe { slice_from_raw_parts(key, key_len as usize) };
    let aad_slice = unsafe { optional_slice(aad, aad_len as usize) };
    
    match crypto::encrypt_aes_gcm(data_slice, key_slice, aad_slice) {
        Ok((ciphertext, nonce)) => {
            unsafe {
                if !ciphertext_out.is_null() && *ciphertext_len as usize >= ciphertext.len() {
                    std::ptr::copy_nonoverlapping(ciphertext.as_ptr(), ciphertext_out, ciphertext.len());
                    *ciphertext_len = ciphertext.len() as c_uint;
                } else {
                    *ciphertext_len = ciphertext.len() as c_uint;
                    return ResultCode::InvalidFormat;
                }
                
                if !nonce_out.is_null() && *nonce_len as usize >= nonce.len() {
                    std::ptr::copy_nonoverlapping(nonce.as_ptr(), nonce_out, nonce.len());
                    *nonce_len = nonce.len() as c_uint;
                } else {
                    *nonce_len = nonce.len() as c_uint;
                    return ResultCode::InvalidFormat;
                }
            }
            ResultCode::Success
        },
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn decrypt_aes_gcm(
    ciphertext: *const c_uchar,
    ciphertext_len: c_uint,
    key: *const c_uchar,
    key_len: c_uint,
    nonce: *const c_uchar,
    nonce_len: c_uint,
    aad: *const c_uchar,
    aad_len: c_uint,
    plaintext_out: *mut c_uchar,
    plaintext_len: *mut c_uint,
) -> ResultCode {
    let ciphertext_slice = unsafe { slice_from_raw_parts(ciphertext, ciphertext_len as usize) };
    let key_slice = unsafe { slice_from_raw_parts(key, key_len as usize) };
    let nonce_slice = unsafe { slice_from_raw_parts(nonce, nonce_len as usize) };
    let aad_slice = unsafe { optional_slice(aad, aad_len as usize) };
    
    match crypto::decrypt_aes_gcm(ciphertext_slice, key_slice, nonce_slice, aad_slice) {
        Ok(plaintext) => {
            unsafe {
                if !plaintext_out.is_null() && *plaintext_len as usize >= plaintext.len() {
                    std::ptr::copy_nonoverlapping(plaintext.as_ptr(), plaintext_out, plaintext.len());
                    *plaintext_len = plaintext.len() as c_uint;
                } else {
                    *plaintext_len = plaintext.len() as c_uint;
                    return ResultCode::InvalidFormat;
                }
            }
            ResultCode::Success
        },
        Err(e) => e.into(),
    }
}

// -------- Signing Functions --------

#[no_mangle]
pub extern "C" fn sign_message(
    private_key: *const c_uchar,
    private_key_len: c_uint,
    message: *const c_uchar,
    message_len: c_uint,
    signature_out: *mut c_uchar,
    signature_len: *mut c_uint,
) -> ResultCode {
    let private_key_slice = unsafe { slice_from_raw_parts(private_key, private_key_len as usize) };
    let message_slice = unsafe { slice_from_raw_parts(message, message_len as usize) };
    
    match crypto::sign_message(private_key_slice, message_slice) {
        Ok(signature) => {
            unsafe {
                if !signature_out.is_null() && *signature_len as usize >= signature.len() {
                    std::ptr::copy_nonoverlapping(signature.as_ptr(), signature_out, signature.len());
                    *signature_len = signature.len() as c_uint;
                } else {
                    *signature_len = signature.len() as c_uint;
                    return ResultCode::InvalidFormat;
                }
            }
            ResultCode::Success
        },
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn verify_signature(
    public_key: *const c_uchar,
    public_key_len: c_uint,
    message: *const c_uchar,
    message_len: c_uint,
    signature: *const c_uchar,
    signature_len: c_uint,
) -> c_int {
    let public_key_slice = unsafe { slice_from_raw_parts(public_key, public_key_len as usize) };
    let message_slice = unsafe { slice_from_raw_parts(message, message_len as usize) };
    let signature_slice = unsafe { slice_from_raw_parts(signature, signature_len as usize) };
    
    match crypto::verify_signature(public_key_slice, message_slice, signature_slice) {
        Ok(is_valid) => {
            if is_valid { 1 } else { 0 }
        },
        Err(_) => -1,
    }
}

// -------- Key Exchange Functions --------

#[no_mangle]
pub extern "C" fn derive_shared_secret(
    private_key: *const c_uchar,
    private_key_len: c_uint,
    public_key: *const c_uchar,
    public_key_len: c_uint,
    shared_secret_out: *mut c_uchar,
    shared_secret_len: *mut c_uint,
) -> ResultCode {
    let private_key_slice = unsafe { slice_from_raw_parts(private_key, private_key_len as usize) };
    let public_key_slice = unsafe { slice_from_raw_parts(public_key, public_key_len as usize) };
    
    match crypto::derive_shared_secret(private_key_slice, public_key_slice) {
        Ok(shared_secret) => {
            unsafe {
                if !shared_secret_out.is_null() && *shared_secret_len as usize >= shared_secret.len() {
                    std::ptr::copy_nonoverlapping(shared_secret.as_ptr(), shared_secret_out, shared_secret.len());
                    *shared_secret_len = shared_secret.len() as c_uint;
                } else {
                    *shared_secret_len = shared_secret.len() as c_uint;
                    return ResultCode::InvalidFormat;
                }
            }
            ResultCode::Success
        },
        Err(e) => e.into(),
    }
}
