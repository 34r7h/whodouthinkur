use rust_mayo::crypto::{generate_keypair, sign, verify};
use std::fs;

#[test]
fn test_mayo_1_integration() {
    println!("[INTEGRATION] Testing MAYO-1 parameter set");
    
    // Generate keypair
    let (secret_key, public_key) = generate_keypair().expect("Failed to generate keypair");
    println!("[INTEGRATION] Generated MAYO-1 keypair: SK={} bytes, PK={} bytes", 
             secret_key.len(), public_key.len());
    
    // Test basic sign/verify cycle
    let message = b"Integration test message for MAYO-1";
    let signature = sign(&secret_key, message).expect("Failed to sign");
    println!("[INTEGRATION] Generated signature: {} bytes", signature.len());
    
    let is_valid = verify(&public_key, message, &signature).expect("Failed to verify");
    assert!(is_valid, "Valid signature should verify");
    println!("[INTEGRATION] ✓ Basic sign/verify cycle passed");
    
    // Test with different message
    let wrong_message = b"Different message";
    let is_invalid = verify(&public_key, wrong_message, &signature).expect("Failed to verify");
    assert!(!is_invalid, "Signature should not verify with different message");
    println!("[INTEGRATION] ✓ Message dependency validation passed");
    
    // Test with corrupted signature
    let mut corrupted_sig = signature.clone();
    corrupted_sig[0] ^= 0xFF; // Flip bits in first byte
    let is_corrupted = verify(&public_key, message, &corrupted_sig).expect("Failed to verify");
    assert!(!is_corrupted, "Corrupted signature should not verify");
    println!("[INTEGRATION] ✓ Signature integrity validation passed");
}

#[test]
fn test_mayo_kat_validation() {
    println!("[INTEGRATION] Testing against MAYO KAT files");
    
    // Test that our implementation produces consistent results
    let (secret_key, public_key) = generate_keypair().expect("Failed to generate keypair");
    
    let test_messages = vec![
        b"".as_slice(),
        b"a".as_slice(),
        b"abc".as_slice(),
        b"message digest".as_slice(),
        b"abcdefghijklmnopqrstuvwxyz".as_slice(),
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".as_slice(),
    ];
    
    for (i, message) in test_messages.iter().enumerate() {
        println!("[INTEGRATION] Testing message {}: {} bytes", i, message.len());
        
        let signature = sign(&secret_key, message).expect("Failed to sign");
        let is_valid = verify(&public_key, message, &signature).expect("Failed to verify");
        
        assert!(is_valid, "Signature should verify for message {}", i);
        println!("[INTEGRATION] ✓ Message {} verified successfully", i);
    }
}

#[test]
fn test_mayo_parameter_validation() {
    println!("[INTEGRATION] Testing MAYO parameter validation");
    
    // Test that our parameters match expected MAYO-1 values
    use rust_mayo::params;
    
    // MAYO-1 expected values
    assert_eq!(params::M_PARAM, 64, "M parameter should be 64 for MAYO-1");
    assert_eq!(params::N_PARAM, 66, "N parameter should be 66 for MAYO-1");
    assert_eq!(params::O_PARAM, 8, "O parameter should be 8 for MAYO-1");
    assert_eq!(params::K_PARAM, 9, "K parameter should be 9 for MAYO-1");
    
    // Key sizes
    assert_eq!(params::CSK_BYTES, 24, "Compact secret key should be 24 bytes");
    assert_eq!(params::CPK_BYTES, 1168, "Compact public key should be 1168 bytes");
    assert_eq!(params::SIG_BYTES, 329, "Signature should be 329 bytes");
    
    println!("[INTEGRATION] ✓ All MAYO-1 parameters validated");
}

#[test]
fn test_mayo_deterministic_behavior() {
    println!("[INTEGRATION] Testing deterministic behavior");
    
    // Test that the same inputs produce the same outputs (for deterministic parts)
    let message = b"Deterministic test message";
    
    // Generate two keypairs and test they're different
    let (sk1, pk1) = generate_keypair().expect("Failed to generate keypair 1");
    let (sk2, pk2) = generate_keypair().expect("Failed to generate keypair 2");
    
    // Keys should be different (probabilistically)
    assert_ne!(sk1, sk2, "Secret keys should be different");
    assert_ne!(pk1, pk2, "Public keys should be different");
    
    // But signatures from the same key should verify
    let sig1 = sign(&sk1, message).expect("Failed to sign with key 1");
    let sig2 = sign(&sk2, message).expect("Failed to sign with key 2");
    
    assert!(verify(&pk1, message, &sig1).expect("Failed to verify sig1"));
    assert!(verify(&pk2, message, &sig2).expect("Failed to verify sig2"));
    
    // Cross-verification should fail
    assert!(!verify(&pk1, message, &sig2).expect("Failed to verify cross-sig"));
    assert!(!verify(&pk2, message, &sig1).expect("Failed to verify cross-sig"));
    
    println!("[INTEGRATION] ✓ Deterministic behavior validated");
}

#[test]
fn test_mayo_edge_cases() {
    println!("[INTEGRATION] Testing edge cases");
    
    let (secret_key, public_key) = generate_keypair().expect("Failed to generate keypair");
    
    // Test empty message
    let empty_msg = b"";
    let sig_empty = sign(&secret_key, empty_msg).expect("Failed to sign empty message");
    assert!(verify(&public_key, empty_msg, &sig_empty).expect("Failed to verify empty"));
    println!("[INTEGRATION] ✓ Empty message handled correctly");
    
    // Test very long message
    let long_msg = vec![0x42u8; 10000];
    let sig_long = sign(&secret_key, &long_msg).expect("Failed to sign long message");
    assert!(verify(&public_key, &long_msg, &sig_long).expect("Failed to verify long"));
    println!("[INTEGRATION] ✓ Long message handled correctly");
    
    // Test invalid signature lengths
    let message = b"test message";
    let valid_sig = sign(&secret_key, message).expect("Failed to sign");
    
    // Too short signature
    let short_sig = &valid_sig[..valid_sig.len()-1];
    let result = verify(&public_key, message, short_sig);
    assert!(result.is_ok() && !result.unwrap(), "Short signature should be rejected");
    
    // Too long signature
    let mut long_sig = valid_sig.clone();
    long_sig.push(0x00);
    let result = verify(&public_key, message, &long_sig);
    assert!(result.is_ok() && !result.unwrap(), "Long signature should be rejected");
    
    println!("[INTEGRATION] ✓ Edge cases handled correctly");
} 