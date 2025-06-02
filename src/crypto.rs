use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, KeyInit};
use aes_gcm::aead::{AeadInPlace, Payload, Tag};
use rand::{RngCore, rngs::OsRng};
use ed25519_dalek::{Keypair, Signer, Verifier, PublicKey, SecretKey, Signature};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};
use curve25519_dalek::edwards::CompressedEdwardsY;
use hkdf::Hkdf;
use sha2::{Sha256, Sha512, Digest};
use solana_sdk::pubkey::Pubkey;
use crate::errors::CryptoError;

// -------- Key Generation --------

pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let mut rng = OsRng;
    let keypair = Keypair::generate(&mut rng);
    
    Ok((keypair.secret.as_bytes().to_vec(), keypair.public.as_bytes().to_vec()))
}

pub fn get_public_key_base58(public_key: &[u8]) -> Result<String, CryptoError> {
    if public_key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(public_key.len()));
    }
    
    let pubkey = Pubkey::new_from_array(<[u8; 32]>::try_from(public_key).unwrap());
    Ok(pubkey.to_string())
}

// -------- Encryption Functions --------

pub fn encrypt_chacha20(data: &[u8], key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(key.len()));
    }

    // Create ChaCha20Poly1305 cipher
    let cipher_key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(cipher_key);

    // Generate a random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the data
    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    Ok((ciphertext, nonce_bytes.to_vec()))
}

pub fn decrypt_chacha20(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(key.len()));
    }

    if nonce.len() != 12 {
        return Err(CryptoError::InvalidFormat(format!("Invalid nonce length: {} (expected 12)", nonce.len())));
    }

    // Create ChaCha20Poly1305 cipher
    let cipher_key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let nonce = Nonce::from_slice(nonce);

    // Decrypt the data
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    Ok(plaintext)
}

pub fn encrypt_aes_gcm(data: &[u8], key: &[u8], aad: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(key.len()));
    }

    // Create AES-GCM cipher
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    // Generate a random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    // Create a copy of data for encryption
    let mut buffer = data.to_vec();
    let tag = if let Some(aad_data) = aad {
        cipher.encrypt_in_place_detached(
            &nonce_bytes.into(), 
            aad_data,
            &mut buffer
        ).map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?
    } else {
        cipher.encrypt_in_place_detached(
            &nonce_bytes.into(), 
            &[], 
            &mut buffer
        ).map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?
    };

    // Append the tag to the ciphertext
    buffer.extend_from_slice(&tag);
    
    Ok((buffer, nonce_bytes.to_vec()))
}

pub fn decrypt_aes_gcm(ciphertext: &[u8], key: &[u8], nonce: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(key.len()));
    }

    if nonce.len() != 12 {
        return Err(CryptoError::InvalidFormat(format!("Invalid nonce length: {} (expected 12)", nonce.len())));
    }

    if ciphertext.len() < 16 {
        return Err(CryptoError::InvalidFormat("Ciphertext too short".into()));
    }

    // Create AES-GCM cipher
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    // Split ciphertext and tag
    let tag_start = ciphertext.len() - 16;
    let (ciphertext_data, tag_data) = ciphertext.split_at(tag_start);
    
    let tag = Tag::from_slice(tag_data);
    let mut buffer = ciphertext_data.to_vec();

    // Decrypt data
    if let Some(aad_data) = aad {
        cipher.decrypt_in_place_detached(
            &nonce.into(), 
            aad_data, 
            &mut buffer, 
            tag
        ).map_err(|_| CryptoError::AuthenticationFailed)?;
    } else {
        cipher.decrypt_in_place_detached(
            &nonce.into(), 
            &[], 
            &mut buffer, 
            tag
        ).map_err(|_| CryptoError::AuthenticationFailed)?;
    }

    Ok(buffer)
}

// -------- Signing Functions --------

pub fn sign_message(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if private_key.len() != 64 && private_key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(private_key.len()));
    }

    let keypair = if private_key.len() == 64 {
        // Assume keypair bytes (private + public)
        Keypair::from_bytes(private_key)
            .map_err(|e| CryptoError::KeyError(e.to_string()))?
    } else {
        // Assume only private key
        let secret = SecretKey::from_bytes(private_key)
            .map_err(|e| CryptoError::KeyError(e.to_string()))?;
        let public = PublicKey::from(&secret);
        Keypair { secret, public }
    };

    let signature = keypair.sign(message);
    Ok(signature.to_bytes().to_vec())
}

pub fn verify_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
    if public_key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(public_key.len()));
    }

    if signature.len() != 64 {
        return Err(CryptoError::InvalidFormat("Invalid signature length".into()));
    }

    let pubkey = PublicKey::from_bytes(public_key)
        .map_err(|e| CryptoError::KeyError(e.to_string()))?;
    
    let sig = Signature::from_bytes(signature)
        .map_err(|e| CryptoError::KeyError(e.to_string()))?;

    Ok(pubkey.verify(message, &sig).is_ok())
}

// -------- Key Exchange Functions --------

pub fn ed25519_to_x25519_public(ed25519_public: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ed25519_public.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(ed25519_public.len()));
    }

    let compressed = CompressedEdwardsY::from_slice(ed25519_public);
    let edwards_point = compressed.decompress()
        .ok_or_else(|| CryptoError::KeyError("Invalid Ed25519 point".into()))?;

    let montgomery_bytes = edwards_point.to_montgomery().to_bytes();
    Ok(montgomery_bytes.to_vec())
}

pub fn ed25519_to_x25519_private(ed25519_private: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ed25519_private.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(ed25519_private.len()));
    }

    let mut h = Sha512::digest(ed25519_private);
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&h[..32]);

    // Clear bits according to RFC 7748
    key_bytes[0] &= 248;
    key_bytes[31] &= 127;
    key_bytes[31] |= 64;

    Ok(key_bytes.to_vec())
}

pub fn derive_shared_secret(private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Convert keys to x25519 format
    let x25519_private = ed25519_to_x25519_private(private_key)?;
    let x25519_public = ed25519_to_x25519_public(public_key)?;

    // Convert to x25519-dalek types
    let secret_key = X25519SecretKey::from(<[u8; 32]>::try_from(x25519_private.as_slice()).unwrap());
    let public_key = X25519PublicKey::from(<[u8; 32]>::try_from(x25519_public.as_slice()).unwrap());

    // Perform Diffie-Hellman
    let shared_secret = secret_key.diffie_hellman(&public_key);

    // Derive key using HKDF
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut output = [0u8; 32];
    hkdf.expand(b"AERONYX-VPN-KEY", &mut output)
        .map_err(|_| CryptoError::KeyError("HKDF expansion failed".into()))?;

    Ok(output.to_vec())
}
