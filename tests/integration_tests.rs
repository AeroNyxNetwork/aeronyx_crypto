//! Integration tests for mobile platform compatibility

#[cfg(test)]
mod tests {
    use aeronyx_crypto::*;
    
    #[test]
    fn test_full_encryption_flow() {
        // Generate keypair
        let (private_key, public_key) = generate_keypair().unwrap();
        
        // Test message
        let message = b"Hello from AeroNyx!";
        
        // Sign message
        let signature = sign_message(&private_key, message).unwrap();
        
        // Verify signature
        assert!(verify_signature(&public_key, message, &signature).unwrap());
        
        // Encrypt data
        let key = [0u8; 32];
        let (ciphertext, nonce) = encrypt_chacha20(message, &key).unwrap();
        
        // Decrypt data
        let plaintext = decrypt_chacha20(&ciphertext, &key, &nonce).unwrap();
        assert_eq!(plaintext, message);
    }
    
    #[test]
    fn test_key_derivation() {
        let password = "strong_password_123!@#";
        let (key, salt) = derive_key_from_password(password, None, 32).unwrap();
        
        assert_eq!(key.len(), 32);
        assert!(!salt.is_empty());
        
        // Verify deterministic derivation
        let (key2, _) = derive_key_from_password(password, Some(&salt), 32).unwrap();
        assert_eq!(key, key2);
    }
}
