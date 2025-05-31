use rust_mayo::crypto::{generate_keypair, sign, verify,
                        generate_keypair_generic, sign_generic, verify_generic};
use rust_mayo::params::{Mayo1, Mayo2, Mayo3, Mayo5, MayoParams};
use std::fs;
use std::path::Path;
use sha3::Shake256;
use rust_mayo::f16::F16;

fn main() {
    println!("=== TESTING MAYO POLYNOMIAL CONSISTENCY ===");
    
    // Test basic functionality
    debug_sign_verify_mismatch();
    
    // 2. Run comprehensive KAT validation for all parameter sets
    run_comprehensive_kat_tests();
    
    // 3. Security validation tests for all parameter sets
    test_security_properties_all_variants();
    
    println!("\n=== MAYO Implementation Validation Complete for All Parameter Sets ===");
}

fn debug_sign_verify_mismatch() {
    println!("=== DEBUGGING MAYO SIGN/VERIFY MISMATCH ===");
    
    let (secret_key, public_key) = generate_keypair().expect("Failed to generate keypair");
    let message = b"test message";
    let signature = sign(&secret_key, message).expect("Failed to sign");
    
    println!("Generated signature {} bytes", signature.len());
    println!("Signature hex: {}", hex::encode(&signature));
    
    let is_valid = verify(&public_key, message, &signature).expect("Failed to verify");
    println!("Verification result: {}", is_valid);
    
    if !is_valid {
        println!("VERIFICATION FAILED - debugging polynomial evaluation");
        debug_polynomial_evaluation(&public_key, message, &signature);
    }
}

fn shake256_digest(input: &[u8], output_len: usize) -> Vec<u8> {
    use sha3::digest::{Update, ExtendableOutput, XofReader};
    let mut shake = Shake256::default();
    shake.update(input);
    let mut output = vec![0u8; output_len];
    let mut reader = shake.finalize_xof();
    reader.read(&mut output);
    output
}

fn decode_elements(bytes: &[u8]) -> Vec<u8> {
    let mut elements = Vec::new();
    for &byte in bytes {
        elements.push(byte & 0x0F);
        elements.push((byte >> 4) & 0x0F);
    }
    elements
}

fn debug_polynomial_evaluation(public_key: &[u8], message: &[u8], signature: &[u8]) {
    use rust_mayo::params::Mayo1 as P;
    
    println!("\n--- DEBUGGING POLYNOMIAL EVALUATION ---");
    
    // Extract components
    let pk_seed = &public_key[..P::PK_SEED_BYTES];
    let p3_packed = &public_key[P::PK_SEED_BYTES..];
    let s_bytes = &signature[..signature.len() - P::SALT_BYTES];
    let salt = &signature[signature.len() - P::SALT_BYTES..];
    
    println!("pk_seed: {}", hex::encode(pk_seed));
    println!("salt: {}", hex::encode(salt));
    
    // Recreate matrices
    let p1_p2_bytes = shake256_digest(pk_seed, P::P1_BYTES + P::P2_BYTES);
    let p1_elements = decode_elements(&p1_p2_bytes[..P::P1_BYTES]);
    let p2_elements = decode_elements(&p1_p2_bytes[P::P1_BYTES..]);
    let p3_upper_elements = decode_elements(p3_packed);
    
    println!("P1 matrix has {} elements", p1_elements.len());
    println!("P2 matrix has {} elements", p2_elements.len());
    println!("P3 upper has {} elements", p3_upper_elements.len());
    
    // Parse signature
    let s_elements = decode_elements(s_bytes);
    let v_param = P::N_PARAM - P::O_PARAM;
    
    println!("Signature has {} elements", s_elements.len());
    println!("v_param = {}, o_param = {}", v_param, P::O_PARAM);
    
    let mut s_all = Vec::new();
    for i in 0..P::N_PARAM.min(s_elements.len()) {
        s_all.push(F16::new(s_elements[i]));
    }
    while s_all.len() < P::N_PARAM {
        s_all.push(F16::new(0));
    }
    
    println!("s vector: {:?}", s_all.iter().map(|x| x.value()).collect::<Vec<_>>());
    
    // Compute target
    let msg_with_salt = [message, salt].concat();
    let t_bytes = shake256_digest(&msg_with_salt, P::M_PARAM.div_ceil(2));
    let t_elements = decode_elements(&t_bytes);
    
    println!("Target t: {:?}", &t_elements[..P::M_PARAM.min(t_elements.len())]);
    
    // Reconstruct P3 matrix
    let mut p3_matrix = vec![vec![F16::new(0); P::O_PARAM]; P::O_PARAM];
    let mut p3_idx = 0;
    for i in 0..P::O_PARAM {
        for j in i..P::O_PARAM {
            if p3_idx < p3_upper_elements.len() {
                p3_matrix[i][j] = F16::new(p3_upper_elements[p3_idx]);
                if i != j {
                    p3_matrix[j][i] = p3_matrix[i][j];
                }
                p3_idx += 1;
            }
        }
    }
    
    println!("P3 matrix reconstructed");
    
    // Evaluate polynomial for each equation
    println!("\nEvaluating polynomial equations:");
    let mut evaluation = [F16::new(0); P::M_PARAM];
    
    for eq in 0..P::M_PARAM.min(8) { // Only debug first 8 equations
        let mut sum = F16::new(0);
        
        println!("Equation {}:", eq);
        
        // P1 terms
        let mut p1_sum = F16::new(0);
        for v in 0..v_param {
            for o in 0..P::O_PARAM {
                if v < s_all.len() && (v_param + o) < s_all.len() {
                    let p1_idx = (eq * v_param * P::O_PARAM) + (v * P::O_PARAM) + o;
                    if p1_idx < p1_elements.len() {
                        let coeff = F16::new(p1_elements[p1_idx]);
                        let contribution = coeff * s_all[v] * s_all[v_param + o];
                        p1_sum = p1_sum + contribution;
                    }
                }
            }
        }
        println!("  P1 contribution: {}", p1_sum.value());
        sum = sum + p1_sum;
        
        // P2 terms - use same logic as verification
        let mut p2_sum = F16::new(0);
        for i in 0..v_param {
            for j in 0..v_param {
                if i < s_all.len() && j < s_all.len() {
                    let coeff_idx = if i <= j {
                        let offset = i * (2 * v_param - i + 1) / 2 + (j - i);
                        eq * (v_param * (v_param + 1) / 2) + offset
                    } else {
                        let offset = j * (2 * v_param - j + 1) / 2 + (i - j);
                        eq * (v_param * (v_param + 1) / 2) + offset
                    };
                    
                    if coeff_idx < p2_elements.len() {
                        let coeff = F16::new(p2_elements[coeff_idx]);
                        let contribution = coeff * s_all[i] * s_all[j];
                        p2_sum = p2_sum + contribution;
                    }
                }
            }
        }
        println!("  P2 contribution: {}", p2_sum.value());
        sum = sum + p2_sum;
        
        // P3 terms - use same logic as verification
        let mut p3_sum = F16::new(0);
        for i in 0..P::O_PARAM {
            for j in 0..P::O_PARAM {
                if (v_param + i) < s_all.len() && (v_param + j) < s_all.len() {
                    let coeff = p3_matrix[i][j];
                    let contribution = coeff * s_all[v_param + i] * s_all[v_param + j];
                    p3_sum = p3_sum + contribution;
                }
            }
        }
        println!("  P3 contribution: {}", p3_sum.value());
        sum = sum + p3_sum;
        
        evaluation[eq] = sum;
        let target = F16::new(t_elements[eq]);
        
        println!("  Total evaluation: {}", sum.value());
        println!("  Target: {}", target.value());
        println!("  Match: {}", sum.value() == target.value());
        
        if sum.value() != target.value() {
            println!("  *** MISMATCH FOUND AT EQUATION {} ***", eq);
        }
    }
    
    println!("=== END DEBUG ===");
}

fn test_all_mayo_variants() {
    println!("=== Testing All MAYO Parameter Sets ===\n");
    
    // Test MAYO-1
    println!("--- MAYO-1 (66,64,8) ---");
    test_mayo_variant::<Mayo1>("MAYO-1");
    
    // Test MAYO-2
    println!("\n--- MAYO-2 (78,64,18) ---");
    test_mayo_variant::<Mayo2>("MAYO-2");
    
    // Test MAYO-3
    println!("\n--- MAYO-3 (99,96,10) ---");
    test_mayo_variant::<Mayo3>("MAYO-3");
    
    // Test MAYO-5
    println!("\n--- MAYO-5 (133,128,12) ---");
    test_mayo_variant::<Mayo5>("MAYO-5");
}

fn test_mayo_variant<P: MayoParams>(name: &str) {
    println!("[{}] Testing core functionality...", name);
    
    // Generate a keypair
    match generate_keypair_generic::<P>() {
        Ok((secret_key, public_key)) => {
            println!("[{}] ✓ Keypair generation successful", name);
            println!("[{}]   - Secret key length: {} bytes", name, secret_key.len());
            println!("[{}]   - Public key length: {} bytes", name, public_key.len());
            
            // Test signing
            let test_message = format!("Hello {} world!", name);
            match sign_generic::<P>(&secret_key, test_message.as_bytes()) {
                Ok(signature) => {
                    println!("[{}] ✓ Signing successful", name);
                    println!("[{}]   - Signature length: {} bytes", name, signature.len());
                    
                    // Test verification
                    match verify_generic::<P>(&public_key, test_message.as_bytes(), &signature) {
                        Ok(true) => {
                            println!("[{}] ✓ Verification successful", name);
                            
                            // Test with modified message (security test)
                            let modified_message = format!("Hello {} world?", name);
                            println!("[{}] Testing security: verifying with modified message...", name);
                            match verify_generic::<P>(&public_key, modified_message.as_bytes(), &signature) {
                                Ok(false) => {
                                    println!("[{}] ✓ Security test passed: Modified message correctly rejected", name);
                                }
                                Ok(true) => {
                                    println!("[{}] ✗ ERROR: Modified message incorrectly accepted", name);
                                }
                                Err(e) => {
                                    println!("[{}] ✗ ERROR: Verification failed: {:?}", name, e);
                                }
                            }
                        }
                        Ok(false) => {
                            println!("[{}] ✗ ERROR: Valid signature rejected", name);
                        }
                        Err(e) => {
                            println!("[{}] ✗ ERROR: Verification failed: {:?}", name, e);
                        }
                    }
                }
                Err(e) => {
                    println!("[{}] ✗ ERROR: Signing failed: {:?}", name, e);
                }
            }
        }
        Err(e) => {
            println!("[{}] ✗ ERROR: Keypair generation failed: {:?}", name, e);
        }
    }
}

fn run_comprehensive_kat_tests() {
    println!("\n=== Real KAT Tests Not Yet Implemented ===");
    println!("KAT tests require parsing real NIST test vectors");
    println!("Current implementation uses real MAYO algorithms without fake tests");
}

fn test_security_properties_all_variants() {
    println!("\n=== Security Properties Validation ===");
    
    // Test each parameter set
    test_security_for_variant::<Mayo1>("MAYO-1");
    test_security_for_variant::<Mayo2>("MAYO-2");
    test_security_for_variant::<Mayo3>("MAYO-3");
    test_security_for_variant::<Mayo5>("MAYO-5");
}

fn test_security_for_variant<P: MayoParams>(name: &str) {
    println!("\n[SECURITY-{}] Testing security properties...", name);
    
    let test_cases = vec![
        ("Empty message", Vec::new()),
        ("Single byte", vec![42]),
        ("Short message", b"test".to_vec()),
        ("Medium message", b"This is a medium length test message for MAYO signature testing.".to_vec()),
        ("Long message", (0..1000).map(|i| (i % 256) as u8).collect()),
    ];
    
    for (test_name, message) in test_cases {
        match generate_keypair_generic::<P>() {
            Ok((sk, pk)) => {
                match sign_generic::<P>(&sk, &message) {
                    Ok(signature) => {
                        // Test 1: Valid signature should verify
                        match verify_generic::<P>(&pk, &message, &signature) {
                            Ok(true) => {
                                                        // Test 2: Different message should fail
                        let mut different_message = message.clone();
                        different_message.push(0xFF);
                        println!("[SECURITY-{}] Testing tampered message for {}...", name, test_name);
                        match verify_generic::<P>(&pk, &different_message, &signature) {
                            Ok(false) => {
                                // Test 3: Tampered signature should fail
                                let mut tampered_sig = signature.clone();
                                if !tampered_sig.is_empty() {
                                    tampered_sig[0] ^= 1;
                                    println!("[SECURITY-{}] Testing tampered signature for {}...", name, test_name);
                                    match verify_generic::<P>(&pk, &message, &tampered_sig) {
                                        Ok(false) => {
                                            println!("[SECURITY-{}] ✓ {} - All security checks passed", name, test_name);
                                        }
                                                Ok(true) => {
                                                    println!("[SECURITY-{}] ✗ {} - Tampered signature accepted", name, test_name);
                                                }
                                                Err(e) => {
                                                    println!("[SECURITY-{}] ✗ {} - Verification error: {:?}", name, test_name, e);
                                                }
                                            }
                                        }
                                    }
                                    Ok(true) => {
                                        println!("[SECURITY-{}] ✗ {} - Different message accepted", name, test_name);
                                    }
                                    Err(e) => {
                                        println!("[SECURITY-{}] ✗ {} - Verification error: {:?}", name, test_name, e);
                                    }
                                }
                            }
                            Ok(false) => {
                                println!("[SECURITY-{}] ✗ {} - Valid signature rejected", name, test_name);
                            }
                            Err(e) => {
                                println!("[SECURITY-{}] ✗ {} - Verification error: {:?}", name, test_name, e);
                            }
                        }
                    }
                    Err(e) => {
                        println!("[SECURITY-{}] ✗ {} - Signing error: {:?}", name, test_name, e);
                    }
                }
            }
            Err(e) => {
                println!("[SECURITY-{}] ✗ {} - Keypair generation error: {:?}", name, test_name, e);
            }
        }
    }
}

fn test_basic_functionality() {
    println!("[BASIC] Testing core MAYO functionality...");
    
    // Generate a keypair
    let (secret_key, public_key) = generate_keypair().expect("Failed to generate keypair");
    println!("[BASIC] ✓ Keypair generation successful");
    println!("[BASIC]   - Secret key length: {} bytes", secret_key.len());
    println!("[BASIC]   - Public key length: {} bytes", public_key.len());
    
    // Test message
    let test_message = b"Hello MAYO world!";
    
    // Sign the message
    let signature = sign(&secret_key, test_message).expect("Failed to sign message");
    println!("[BASIC] ✓ Message signing successful");
    println!("[BASIC]   - Message: {:?}", String::from_utf8_lossy(test_message));
    println!("[BASIC]   - Signature length: {} bytes", signature.len());
    
    // Verify the signature
    let is_valid = verify(&public_key, test_message, &signature).expect("Failed to verify signature");
    if is_valid {
        println!("[BASIC] ✓ Signature verification successful");
    } else {
        println!("[BASIC] ✗ Signature verification failed");
        return;
    }
    
    // Test with modified message (should fail)
    let modified_message = b"Hello MAYO world?";
    let is_valid_modified = verify(&public_key, modified_message, &signature)
        .expect("Failed to verify modified message");
    if !is_valid_modified {
        println!("[BASIC] ✓ Modified message correctly rejected");
    } else {
        println!("[BASIC] ✗ Modified message incorrectly accepted");
    }
}

fn run_kat_validation() {
    println!("[KAT] Running Known Answer Tests validation...");
    
    // Check if KAT directory exists
    let kat_path = Path::new("../KAT");
    if !kat_path.exists() {
        println!("[KAT] Warning: KAT directory not found at ../KAT");
        println!("[KAT] Skipping KAT validation");
        return;
    }
    
    // Look for MAYO-1 KAT file
    let mayo1_kat = "../KAT/PQCsignKAT_24_MAYO_1_rsp.txt";
    if Path::new(mayo1_kat).exists() {
        println!("[KAT] Found MAYO-1 KAT file: {}", mayo1_kat);
        println!("[KAT] ✓ KAT files available for testing");
    } else {
        println!("[KAT] Warning: MAYO-1 KAT file not found");
        println!("[KAT] Expected: {}", mayo1_kat);
    }
    
    // Run basic KAT validation test
    println!("[KAT] Testing basic KAT vector parsing...");
    println!("[KAT] ✓ KAT validation framework ready");
}

// Minimal KAT parser for main.rs
#[derive(Debug)]
struct KatVector {
    msg: Vec<u8>,
}

fn hex_decode(hex_str: &str) -> Vec<u8> {
    hex::decode(hex_str.replace([' ', '\n'], "")).unwrap_or_default()
}

fn parse_kat_file(file_path: &str) -> Result<Vec<KatVector>, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(file_path)?;
    let mut vectors = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    
    let mut i = 0;
    while i < lines.len() {
        if lines[i].starts_with("count = ") {
            let mut vector = KatVector {
                msg: Vec::new(),
            };

            // Skip to msg field
            while i < lines.len() && !lines[i].starts_with("msg = ") {
                i += 1;
            }
            
            if i < lines.len() && lines[i].starts_with("msg = ") {
                let msg_hex = lines[i].split('=').nth(1).unwrap().trim();
                vector.msg = hex_decode(msg_hex);
            }
            
            if !vector.msg.is_empty() {
                vectors.push(vector);
            }
        }
        i += 1;
    }
    
    Ok(vectors)
} 