//! Mobile-specific integration tests

#[cfg(test)]
mod tests {
    use aeronyx_crypto::*;
    
    #[test]
    fn test_full_mobile_auth_flow() {
        // 1. Generate keypair
        let (private_key, public_key) = generate_keypair().unwrap();
        
        // 2. Simulate node challenge
        let challenge = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut challenge);
        
        // 3. Sign challenge
        let signature = sign_message(&private_key, &challenge).unwrap();
        
        // 4. Verify signature (as node would)
        assert!(verify_signature(&public_key, &challenge, &signature).unwrap());
        
        // 5. Generate session key
        let session_key = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut session_key);
        
        // 6. Encrypt data packet
        let data = b"Hello AeroNyx Network!";
        let (encrypted, nonce) = encrypt_chacha20(data, &session_key).unwrap();
        
        // 7. Decrypt data packet
        let decrypted = decrypt_chacha20(&encrypted, &session_key, &nonce).unwrap();
        assert_eq!(decrypted, data);
    }
    
    #[test]
    fn test_network_adaptive_encryption() {
        use transport::NetworkQualityDetector;
        
        let mut detector = NetworkQualityDetector::new();
        
        // Simulate good network
        detector.add_latency_sample(std::time::Duration::from_millis(20));
        detector.add_bandwidth_sample(5_000_000.0); // 5MB/s
        assert_eq!(detector.recommend_algorithm(), "aes-256-gcm");
        
        // Simulate poor network
        detector.add_latency_sample(std::time::Duration::from_millis(200));
        detector.add_bandwidth_sample(50_000.0); // 50KB/s
        assert_eq!(detector.recommend_algorithm(), "chacha20-poly1305");
    }
    
    #[test]
    fn test_power_aware_batch_operations() {
        use power::PowerAwareCrypto;
        
        let power_crypto = PowerAwareCrypto::new();
        power_crypto.set_low_power_mode(true);
        
        let messages = vec![
            b"Message 1".as_ref(),
            b"Message 2".as_ref(),
            b"Message 3".as_ref(),
        ];
        
        let key = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        
        let results = power_crypto.batch_encrypt(&messages, &key).unwrap();
        assert_eq!(results.len(), 3);
        
        // Verify each can be decrypted
        for (i, (ciphertext, nonce)) in results.iter().enumerate() {
            let decrypted = decrypt_chacha20(ciphertext, &key, nonce).unwrap();
            assert_eq!(decrypted, messages[i]);
        }
    }
    
    #[cfg(any(target_os = "ios", target_os = "android"))]
    #[test]
    fn test_secure_storage() {
        use platform::get_secure_storage;
        
        let storage = get_secure_storage();
        let key_id = "test_key_001";
        let key_data = vec![1, 2, 3, 4, 5];
        
        // Store key
        storage.store_key(key_id, &key_data).unwrap();
        
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
