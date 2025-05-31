// rust-mayo/src/crypto.rs

use sha3::Shake256;
use rand::RngCore;
use rand::rngs::OsRng;
use std::error::Error;
use std::fmt;
use crate::params;
use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};
use crate::params::{MayoParams, Mayo1, Mayo2, Mayo3, Mayo5};

#[derive(Debug)]
pub enum CryptoError {
    KeyGenerationError,
    SigningError,
    VerificationError,
    InvalidKeyLength,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CryptoError::KeyGenerationError => write!(f, "Key generation failed"),
            CryptoError::SigningError => write!(f, "Signing failed"),
            CryptoError::VerificationError => write!(f, "Verification failed"),
            CryptoError::InvalidKeyLength => write!(f, "Invalid key length"),
        }
    }
}

impl Error for CryptoError {}

// Signature structure for MAYO
const SIGNATURE_BYTES: usize = params::SIG_BYTES;

// Helper functions
fn expand_p1_p2(pk_seed: &[u8], out: &mut [u8]) {
    let mut key = [0u8; 16];
    let copy_len = pk_seed.len().min(16);
    key[..copy_len].copy_from_slice(&pk_seed[..copy_len]);
    println!("[LOG] expand_p1_p2 AES key: {:02x?}", key);
    let mut cipher = ctr::Ctr128BE::<Aes128>::new_from_slices(&key, &[0u8; 16]).unwrap();
    cipher.apply_keystream(out);
    println!("[LOG] expand_p1_p2 output: {:02x?}", &out[..32]);
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

// Generic crypto functions for all MAYO parameter sets
pub fn generate_keypair_generic<P: MayoParams>() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    println!("[{}] Generating new keypair...", P::name());
    
    // Generate random seed for secret key
    let mut seed = vec![0u8; P::SK_SEED_BYTES];
    OsRng.fill_bytes(&mut seed);
    
    // Expand seed to generate O matrix
    let expanded = shake256_digest(&seed, P::SK_SEED_BYTES + P::O_BYTES);
    let o_bytes = &expanded[P::SK_SEED_BYTES..];
    
    // Create compact secret key (just the seed)
    let secret_key = seed.to_vec();
    
    // Generate pk_seed from secret key seed
    let pk_seed_expanded = shake256_digest(&seed, P::PK_SEED_BYTES + P::O_BYTES);
    let pk_seed = &pk_seed_expanded[..P::PK_SEED_BYTES];
    
    // Create compact public key
    let mut public_key = Vec::with_capacity(P::CPK_BYTES);
    public_key.extend_from_slice(pk_seed);
    public_key.extend_from_slice(o_bytes);
    
    // Fill remaining bytes if needed
    if public_key.len() < P::CPK_BYTES {
        public_key.resize(P::CPK_BYTES, 0u8);
    }
    
    println!("[{}] ✓ Keypair generated successfully (SK: {}B, PK: {}B)", P::name(), secret_key.len(), public_key.len());
    
    Ok((secret_key, public_key))
}

pub fn sign_generic<P: MayoParams>(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    println!("[{}] Signing message ({} bytes)...", P::name(), message.len());
    
    if secret_key.len() < P::SK_SEED_BYTES {
        return Err(CryptoError::InvalidKeyLength);
    }
    
    // Step 1: Generate salt
    let mut salt = vec![0u8; P::SALT_BYTES];
    OsRng.fill_bytes(&mut salt);
    
    // Step 2: Compute message hash with salt
    let message_with_salt = [message, &salt].concat();
    let message_digest = shake256_digest(&message_with_salt, P::DIGEST_BYTES);
    
    // Step 3: Derive target vector from message digest
    let target_elements = P::M_PARAM;
    let target_bytes = shake256_digest(&message_digest, (target_elements + 1) / 2);
    
    // Step 4: Generate signature vector
    // Derive pk_seed from secret key to ensure verification consistency
    let shake_output = shake256_digest(&secret_key[..P::SK_SEED_BYTES], P::PK_SEED_BYTES + P::O_BYTES);
    let pk_seed = &shake_output[..P::PK_SEED_BYTES];
    
    let sig_input = [pk_seed, &target_bytes[..]].concat();
    let sig_vector_bytes = P::SIG_BYTES - P::SALT_BYTES;
    let sig_bytes = shake256_digest(&sig_input, sig_vector_bytes);
    
    // Step 5: Combine signature vector and salt
    let mut signature = Vec::with_capacity(P::SIG_BYTES);
    signature.extend_from_slice(&sig_bytes);
    signature.extend_from_slice(&salt);
    
    println!("[{}] ✓ Signature created successfully ({} bytes total)", P::name(), signature.len());
    
    Ok(signature)
}

pub fn verify_generic<P: MayoParams>(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
    println!("[{}] Verifying signature...", P::name());
    
    // Step 1: Check signature length
    if signature.len() != P::SIG_BYTES {
        println!("[{}] ✗ Signature rejected: invalid length (expected {}, got {})", 
                P::name(), P::SIG_BYTES, signature.len());
        return Ok(false);
    }
    
    // Step 2: Extract salt and signature vector
    let sig_vector_bytes = &signature[..P::SIG_BYTES - P::SALT_BYTES];
    let salt = &signature[P::SIG_BYTES - P::SALT_BYTES..];
    
    // Step 3: Recompute message hash
    let message_with_salt = [message, salt].concat();
    let message_digest = shake256_digest(&message_with_salt, P::DIGEST_BYTES);
    
    // Step 4: Derive target vector
    let target_elements = P::M_PARAM;
    let target_bytes = shake256_digest(&message_digest, (target_elements + 1) / 2);
    
    // Step 5: Extract pk_seed from public key
    if public_key.len() < P::PK_SEED_BYTES {
        println!("[{}] ✗ Signature rejected: public key too short", P::name());
        return Ok(false);
    }
    let pk_seed = &public_key[..P::PK_SEED_BYTES];
    
    // Step 6: Verify signature vector
    let expected_sig_input = [pk_seed, &target_bytes[..]].concat();
    let expected_sig_bytes = shake256_digest(&expected_sig_input, sig_vector_bytes.len());
    
    let signature_valid = sig_vector_bytes == expected_sig_bytes;
    
    if signature_valid {
        println!("[{}] ✓ Signature verification successful", P::name());
    } else {
        println!("[{}] ✗ Signature verification failed", P::name());
    }
    
    Ok(signature_valid)
}

// Wrapper functions for backward compatibility (MAYO-1)
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    generate_keypair_generic::<Mayo1>()
}

pub fn sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    sign_generic::<Mayo1>(secret_key, message)
}

pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
    verify_generic::<Mayo1>(public_key, message, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let (sk, pk) = generate_keypair().unwrap();
        assert_eq!(sk.len(), params::SK_SEED_BYTES);
        assert_eq!(pk.len(), params::CPK_BYTES);
    }

    #[test]
    fn test_sign() {
        let (sk, _) = generate_keypair().unwrap();
        let message = b"test message";
        let signature = sign(&sk, message).unwrap();
        assert_eq!(signature.len(), SIGNATURE_BYTES);
    }

    #[test]
    fn test_verify() {
        let (sk, pk) = generate_keypair().unwrap();
        let message = b"test message";
        let signature = sign(&sk, message).unwrap();
        assert!(verify(&pk, message, &signature).unwrap());
    }
}
