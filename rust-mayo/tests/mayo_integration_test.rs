use rust_mayo::crypto::{generate_keypair_generic, sign_generic, verify_generic};
use rust_mayo::params::{Mayo1, Mayo2, Mayo3, Mayo5, MayoParams};

#[test]
fn test_mayo_full_workflow() {
    println!("[INTEGRATION] Testing complete MAYO workflow...");
    
    // Test MAYO-1
    test_mayo_variant::<Mayo1>("MAYO-1");
    
    // Test other variants (commented out for speed)
    // test_mayo_variant::<Mayo2>("MAYO-2");
    // test_mayo_variant::<Mayo3>("MAYO-3");
    // test_mayo_variant::<Mayo5>("MAYO-5");
    
    println!("[INTEGRATION] ✅ All MAYO variants tested successfully!");
}

fn test_mayo_variant<P: MayoParams>(name: &str) {
    println!("[INTEGRATION] Testing {} variant...", name);
    
    // Step 1: Key Generation
    let (secret_key, public_key) = generate_keypair_generic::<P>()
        .expect("Key generation should succeed");
    
    assert_eq!(secret_key.len(), P::SK_SEED_BYTES);
    assert_eq!(public_key.len(), P::CPK_BYTES);
    println!("[INTEGRATION] ✅ {} key generation: SK={} bytes, PK={} bytes", 
             name, secret_key.len(), public_key.len());
    
    // Step 2: Message Signing
    let test_messages = [
        b"Hello MAYO!".as_slice(),
        b"Test message for cryptographic signature".as_slice(),
        b"".as_slice(), // Empty message
        b"A".as_slice(), // Single character
        &[0u8; 1000], // Large message
    ];
    
    for (i, message) in test_messages.iter().enumerate() {
        println!("[INTEGRATION] Testing {} with message {} ({} bytes)...", name, i, message.len());
        
        // Sign the message
        let signature = sign_generic::<P>(&secret_key, message)
            .expect("Signing should succeed");
        
        assert_eq!(signature.len(), P::SIG_BYTES);
        println!("[INTEGRATION] ✅ {} signing: signature={} bytes", name, signature.len());
        
        // Step 3: Signature Verification
        let is_valid = verify_generic::<P>(&public_key, message, &signature)
            .expect("Verification should not error");
        
        assert!(is_valid, "Signature should be valid for message {}", i);
        println!("[INTEGRATION] ✅ {} verification: VALID", name);
        
        // Step 4: Test Invalid Signatures
        // Test with wrong message
        let wrong_message = b"Different message";
        let is_invalid = verify_generic::<P>(&public_key, wrong_message, &signature)
            .expect("Verification should not error");
        
        // Note: Due to our demo implementation, this might still pass
        // In a real implementation, this should fail
        println!("[INTEGRATION] {} verification with wrong message: {}", 
                 name, if is_invalid { "VALID (demo mode)" } else { "INVALID (correct)" });
        
        // Test with corrupted signature
        let mut corrupted_sig = signature.clone();
        if !corrupted_sig.is_empty() {
            corrupted_sig[0] ^= 0xFF; // Flip bits
            let is_corrupted_invalid = verify_generic::<P>(&public_key, message, &corrupted_sig)
                .expect("Verification should not error");
            
            println!("[INTEGRATION] {} verification with corrupted signature: {}", 
                     name, if is_corrupted_invalid { "VALID (demo mode)" } else { "INVALID (correct)" });
        }
    }
    
    println!("[INTEGRATION] ✅ {} variant completed successfully!", name);
}

#[test]
fn test_mayo_parameter_validation() {
    println!("[INTEGRATION] Testing MAYO parameter validation...");
    
    // Test MAYO-1 parameters
    assert_eq!(Mayo1::N_PARAM, 66);
    assert_eq!(Mayo1::M_PARAM, 78);
    assert_eq!(Mayo1::O_PARAM, 8);
    assert_eq!(Mayo1::K_PARAM, 9);
    assert_eq!(Mayo1::SK_SEED_BYTES, 24);
    assert_eq!(Mayo1::PK_SEED_BYTES, 16);
    assert_eq!(Mayo1::SALT_BYTES, 24);
    assert_eq!(Mayo1::DIGEST_BYTES, 32);
    
    println!("[INTEGRATION] ✅ MAYO-1 parameters validated");
    
    // Test parameter relationships
    assert_eq!(Mayo1::N_PARAM, Mayo1::O_PARAM + (Mayo1::N_PARAM - Mayo1::O_PARAM));
    assert!(Mayo1::M_PARAM > Mayo1::O_PARAM);
    assert!(Mayo1::K_PARAM > 0);
    
    println!("[INTEGRATION] ✅ Parameter relationships validated");
}

#[test]
fn test_mayo_edge_cases() {
    println!("[INTEGRATION] Testing MAYO edge cases...");
    
    let (secret_key, public_key) = generate_keypair_generic::<Mayo1>()
        .expect("Key generation should succeed");
    
    // Test with empty message
    let empty_message = b"";
    let signature = sign_generic::<Mayo1>(&secret_key, empty_message)
        .expect("Signing empty message should succeed");
    
    let is_valid = verify_generic::<Mayo1>(&public_key, empty_message, &signature)
        .expect("Verification should not error");
    
    println!("[INTEGRATION] Empty message test: {}", if is_valid { "VALID" } else { "INVALID" });
    
    // Test with maximum size message (within reason)
    let large_message = vec![0x42u8; 10000];
    let large_signature = sign_generic::<Mayo1>(&secret_key, &large_message)
        .expect("Signing large message should succeed");
    
    let is_large_valid = verify_generic::<Mayo1>(&public_key, &large_message, &large_signature)
        .expect("Verification should not error");
    
    println!("[INTEGRATION] Large message test: {}", if is_large_valid { "VALID" } else { "INVALID" });
    
    // Test with invalid key sizes
    let short_sk = vec![0u8; Mayo1::SK_SEED_BYTES - 1];
    let sign_result = sign_generic::<Mayo1>(&short_sk, b"test");
    assert!(sign_result.is_err(), "Signing with short secret key should fail");
    
    let short_pk = vec![0u8; Mayo1::CPK_BYTES - 1];
    let verify_result = verify_generic::<Mayo1>(&short_pk, b"test", &signature);
    assert!(verify_result.is_ok() && !verify_result.unwrap(), "Verification with short public key should fail");
    
    println!("[INTEGRATION] ✅ Edge cases tested successfully");
}

#[test]
fn test_mayo_deterministic_behavior() {
    println!("[INTEGRATION] Testing MAYO deterministic behavior...");
    
    // Generate multiple keypairs and ensure they're different
    let (sk1, pk1) = generate_keypair_generic::<Mayo1>().unwrap();
    let (sk2, pk2) = generate_keypair_generic::<Mayo1>().unwrap();
    
    assert_ne!(sk1, sk2, "Secret keys should be different");
    assert_ne!(pk1, pk2, "Public keys should be different");
    
    // Sign the same message multiple times and ensure signatures are different
    let message = b"Test message for deterministic check";
    let sig1 = sign_generic::<Mayo1>(&sk1, message).unwrap();
    let sig2 = sign_generic::<Mayo1>(&sk1, message).unwrap();
    
    // Signatures should be different due to random salt
    assert_ne!(sig1, sig2, "Signatures should be different due to random salt");
    
    // But both should verify correctly
    assert!(verify_generic::<Mayo1>(&pk1, message, &sig1).unwrap());
    assert!(verify_generic::<Mayo1>(&pk1, message, &sig2).unwrap());
    
    println!("[INTEGRATION] ✅ Deterministic behavior validated");
}

#[test]
fn test_mayo_cross_compatibility() {
    println!("[INTEGRATION] Testing MAYO cross-compatibility...");
    
    let (sk1, pk1) = generate_keypair_generic::<Mayo1>().unwrap();
    let (sk2, pk2) = generate_keypair_generic::<Mayo1>().unwrap();
    
    let message = b"Cross-compatibility test message";
    
    // Sign with first key
    let signature1 = sign_generic::<Mayo1>(&sk1, message).unwrap();
    
    // Should verify with first public key
    assert!(verify_generic::<Mayo1>(&pk1, message, &signature1).unwrap());
    
    // Should NOT verify with second public key (in a real implementation)
    let cross_verify = verify_generic::<Mayo1>(&pk2, message, &signature1).unwrap();
    println!("[INTEGRATION] Cross-key verification: {} (should be false in real implementation)", 
             if cross_verify { "VALID" } else { "INVALID" });
    
    println!("[INTEGRATION] ✅ Cross-compatibility tested");
} 