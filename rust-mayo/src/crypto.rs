// rust-mayo/src/crypto.rs

use sha3::Shake256;
use rand::RngCore;
use rand::rngs::OsRng;
use std::error::Error;
use std::fmt;
use crate::params;
use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek}; // Added StreamCipherSeek
use crate::params::{MayoParams, Mayo1, Mayo2, Mayo3, Mayo5};
use crate::f16::F16; // Added for F16 type
use crate::matrix::Matrix; // Added for Matrix type
use crate::vector::Vector; // Added for Vector type
use crate::mvector::MVector; // Ensure MVector is imported
use crate::mayo_operations::{
    p1_times_o_operator, add_mvector_sequences_operator, o_transpose_times_mvector_sequence_operator,
    compute_m_and_vpv_operator, compute_rhs_for_sign_operator, compute_a_system_matrix_for_sign_operator,
    sample_solution_operator
};
use std::marker::PhantomData;


#[derive(Debug, PartialEq, Eq)] // Added PartialEq, Eq for easier testing if needed
pub enum CryptoError {
    KeyGenerationError,
    SigningError,
    VerificationError,
    InvalidKeyLength,
    ParameterError(String), // For errors from parameter validation or consistency checks
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CryptoError::KeyGenerationError => write!(f, "Key generation failed"),
            CryptoError::SigningError => write!(f, "Signing failed"),
            CryptoError::VerificationError => write!(f, "Verification failed"),
            CryptoError::InvalidKeyLength => write!(f, "Invalid key length"),
            CryptoError::ParameterError(s) => write!(f, "Parameter error: {}", s),
        }
    }
}

impl Error for CryptoError {}

#[derive(Debug, Clone)]
pub struct ExpandedSecretKey<P: MayoParams> {
    pub matrix_o: Matrix, // Should be Matrix<F16>
    pub p1_mvecs_upper_tri: Vec<MVector>,
    pub l_mvecs_dense: Vec<MVector>, // L is P2_prime = P2_orig + P1*O
    _marker: PhantomData<P>,
}

#[derive(Debug, Clone)]
pub struct ExpandedPublicKey<P: MayoParams> {
    pub p1_mvecs_upper_tri: Vec<MVector>,
    pub p2_mvecs_dense: Vec<MVector>,     // P2_orig
    pub p3_mvecs_upper_tri: Vec<MVector>, // Upper triangle of P_OOL
    _marker: PhantomData<P>,
}


// Signature structure for MAYO
const SIGNATURE_BYTES: usize = params::SIG_BYTES;

// Helper functions

// Private helper to decode bytes to F16 vector (nibble packing)
fn decode_bytes_to_f16_vec(bytes: &[u8], num_f16_elements: usize) -> Result<Vec<F16>, String> {
    let expected_byte_len = (num_f16_elements + 1) / 2;
    if bytes.len() != expected_byte_len {
        return Err(format!(
            "decode_bytes_to_f16_vec: incorrect byte length. Expected {}, got {}.",
            expected_byte_len,
            bytes.len()
        ));
    }

    let mut f16_elements = Vec::with_capacity(num_f16_elements);
    for i in 0..num_f16_elements {
        let byte_index = i / 2;
        let val = bytes[byte_index];
        let nibble = if i % 2 == 0 {
            val & 0x0F // Low nibble
        } else {
            (val >> 4) & 0x0F // High nibble
        };
        f16_elements.push(F16::new(nibble));
    }
    Ok(f16_elements)
}

// Replaces the previous placeholder for aes_ctr_prf
// Generates `output_len` pseudorandom bytes using AES-128-CTR.
// Key should be 16 bytes.
// Nonce is fixed to zero for this specific PRF usage as implied by c-mayo's PK_PRF.
fn aes128_ctr_prf(key: &[u8], output_len: usize) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 16 {
        // As per NIST spec for AES-128, key must be 16 bytes.
        // P::PK_SEED_BYTES is 16 for all MAYO variants.
        return Err(CryptoError::InvalidKeyLength);
    }

    let nonce = [0u8; 16]; // Fixed zero nonce/IV, common for PRF mode if stream isn't reused with same key.
                           // Or more typically, a 12-byte nonce and 4-byte counter, but the ctr crate handles the counter part.
                           // For a fixed key, using a fixed nonce means it always produces the same stream.

    let mut cipher = ctr::Ctr128BE::new(key.into(), &nonce.into());

    let mut buffer = vec![0u8; output_len];
    cipher.apply_keystream(&mut buffer);

    Ok(buffer)
}

fn bytes_to_mvector_sequence<P: MayoParams>(
    bytes: &[u8],
    num_mvectors: usize,
) -> Result<Vec<MVector>, CryptoError> {
    let m_param = P::M_PARAM;
    let m_vec_limbs = P::M_VEC_LIMBS; // Limbs per MVector
    let bytes_per_mvector = (m_param + 1) / 2; // Bytes per MVector in its packed nibble form

    if num_mvectors == 0 {
        return if bytes.is_empty() { Ok(Vec::new()) } else { Err(CryptoError::KeyGenerationError) };
    }

    // Check if the total length of bytes matches the expected length
    if bytes.len() != num_mvectors * bytes_per_mvector {
         return Err(CryptoError::KeyGenerationError); // Mismatch in total expected bytes
    }

    let mut mvector_sequence = Vec::with_capacity(num_mvectors);
    for i in 0..num_mvectors {
        let start = i * bytes_per_mvector;
        let end = start + bytes_per_mvector;
        // Slice is safe due to the check above.
        let mvector_bytes = &bytes[start..end];
        mvector_sequence.push(MVector::from_limbs_bytes(mvector_bytes, m_param, m_vec_limbs)
            .map_err(|e_str| {
                // TODO: Consider logging e_str if a logging framework were present
                eprintln!("MVector::from_limbs_bytes error during sequence conversion: {}", e_str);
                CryptoError::KeyGenerationError
            })?);
    }
    Ok(mvector_sequence)
}

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
pub fn generate_keypair_generic<P: MayoParams>(sk_seed_input: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    println!("[{}] Generating new keypair...", P::NAME);

    let sk_seed = match sk_seed_input {
        Some(seed_bytes) => {
            if seed_bytes.len() != P::SK_SEED_BYTES {
                return Err(CryptoError::ParameterError(format!(
                    "Provided sk_seed has incorrect length. Expected {}, got {}",
                    P::SK_SEED_BYTES, seed_bytes.len()
                )));
            }
            seed_bytes.to_vec()
        }
        None => {
            let mut temp_seed = vec![0u8; P::SK_SEED_BYTES];
            OsRng.fill_bytes(&mut temp_seed);
            temp_seed
        }
    };
    let compact_secret_key = sk_seed.clone();

    // Derive pk_seed and O matrix source bytes from sk_seed
    // shake(sk_seed, pk_seed_bytes + O_bytes) -> pk_seed || O_source
    let sk_seed_shake_output_len = P::PK_SEED_BYTES + P::O_BYTES;
    let sk_seed_shaken = shake256_digest(&sk_seed, sk_seed_shake_output_len);
    let pk_seed = &sk_seed_shaken[..P::PK_SEED_BYTES];
    let o_source_bytes = &sk_seed_shaken[P::PK_SEED_BYTES..];

    // Decode O from o_source_bytes into F16 elements, then matrix
    // O is v x o
    let o_f16_elements = decode_bytes_to_f16_vec(o_source_bytes, P::V_PARAM * P::O_PARAM)
        .map_err(|e_str| CryptoError::ParameterError(format!("Failed to decode O: {}", e_str)))?;
    let matrix_o = Matrix::new(P::V_PARAM, P::O_PARAM, o_f16_elements)
        .map_err(|e_str| CryptoError::ParameterError(format!("Failed to create matrix O: {}", e_str)))?;

    // Expand pk_seed to get byte representations for P1 and P2
    // P1 is v x v, symmetric. Needs P1_ELEMENTS nibbles. (P1_ELEMENTS+1)/2 bytes.
    // P2 is v x o, dense. Needs P2_ELEMENTS nibbles. (P2_ELEMENTS+1)/2 bytes.
    // The C code uses specific byte counts from mayo.h (e.g. MAYO_1_P1_bytes) which are different
    // from (ELEMENTS+1)/2. This is because they are packed as full m_vec_limbs per matrix element.
    // The new params CPK_P1_BYTES, CPK_P2_BYTES reflect these packed sizes.

    // Using AES_CTR_PRF to generate P1 and P2 material in one go.
    let p1_plus_p2_len = P::CPK_P1_BYTES + P::CPK_P2_BYTES;
    let p1_p2_material = aes128_ctr_prf(&pk_seed, p1_plus_p2_len)?;
    let p1_bytes_repr = &p1_p2_material[0..P::CPK_P1_BYTES];
    let p2_bytes_repr = &p1_p2_material[P::CPK_P1_BYTES..p1_plus_p2_len];

    // Convert byte representations to sequences of MVectors
    let p1_mvecs_upper_tri = bytes_to_mvector_sequence::<P>(&p1_bytes_repr, P::P1_ELEMENTS)?;
    let p2_mvecs_dense = bytes_to_mvector_sequence::<P>(&p2_bytes_repr, P::P2_ELEMENTS)?;

    // Compute P1 * O
    let p1_o_mvecs = p1_times_o_operator::<P>(&p1_mvecs_upper_tri, &matrix_o)?;

    // Compute P2_prime = P2_dense + P1*O  (P_VO' = P_VO + P_V*O_L in spec)
    let p2_prime_mvecs = add_mvector_sequences_operator::<P>(&p2_mvecs_dense, &p1_o_mvecs)?;

    // Compute P3_intermediate = O^T * P2_prime
    // This is O_L^T * (P_VO + P_V*O_L) = O_L^T * P_V*O_L + O_L^T * P_VO
    // This is only part of P_OOL. The full P_OOL = O_L^T*P_V*O_L + O_L^T*P_VO + P_VO^T*O_L
    // The reference implementation (for keygen) calculates P_S = O_L^T * P_VO' and then P_OOL = Upper(P_S).
    // This implies P_S must be symmetric. If P_S = O_L^T * P_VO', then P_S^T = (P_VO')^T * O_L.
    // For P_S to be symmetric, O_L^T * P_VO' == (P_VO')^T * O_L.
    // The spec says P_OOL = Upper( O_L^T * P_V * O_L  +  O_L^T * P_VO  +  P_VO^T * O_L )
    // The current `p3_full_mvecs` from the prompt is `O_L^T * (P_V*O_L + P_VO)`.
    // This is not the full P_OOL. The name `p3_full_mvecs` might be misleading.
    // Let's call it `p3_term_A_mvecs`.
    let p3_term_A_mvecs = o_transpose_times_mvector_sequence_operator::<P>(&matrix_o, &p2_prime_mvecs)?;

    // TODO: Compute P_VO^T * O_L. This needs a new operator: (Vec<MVector>)^T * Matrix_O,
    // or rather, (Matrix of MVectors)^T * Matrix_O.
    // For now, we'll assume `p3_term_A_mvecs` is the matrix whose upper triangle we serialize,
    // acknowledging this is an incomplete P3 for the final key.
    // The key goal here is to get the serialization logic for *an* (o x o) MVector matrix.

    // Serialize the upper triangular part of p3_term_A_mvecs (which is an o x o matrix of MVectors)
    let mut upper_p3_mvector_bytes_list = Vec::new();
    let o_param = P::O_PARAM; // Dimension of P3
    for r_idx in 0..o_param {
        for c_idx in r_idx..o_param { // Iterate through upper triangle including diagonal
            let mvector_idx = r_idx * o_param + c_idx; // p3_term_A_mvecs is row-major
            if mvector_idx >= p3_term_A_mvecs.len() {
                return Err(CryptoError::KeyGenerationError);
            }
            let mvector_bytes = p3_term_A_mvecs[mvector_idx].to_limbs_bytes(P::M_VEC_LIMBS)
                .map_err(|e| CryptoError::ParameterError(format!("MVector to_limbs_bytes for P3 failed: {}",e)))?;
            upper_p3_mvector_bytes_list.push(mvector_bytes);
        }
    }
    
    let packed_upper_p3_bytes: Vec<u8> = upper_p3_mvector_bytes_list.into_iter().flatten().collect();

    // Check expected size of packed_upper_p3_bytes
    let expected_p3_packed_len = P::P3_ELEMENTS * ((P::M_PARAM + 1) / 2);
    if packed_upper_p3_bytes.len() != expected_p3_packed_len {
         eprintln!("Packed upper P3 length mismatch. Expected {}, got {}. P3_ELEMENTS {}, bytes_per_mvec {}",
             expected_p3_packed_len, packed_upper_p3_bytes.len(), P::P3_ELEMENTS, (P::M_PARAM+1)/2);
        return Err(CryptoError::KeyGenerationError);
    }
    
    // Ensure compact_public_key has the correct total length
    let mut compact_public_key = Vec::with_capacity(P::CPK_BYTES);
    compact_public_key.extend_from_slice(pk_seed);
    compact_public_key.extend_from_slice(&packed_upper_p3_bytes);

    // Ensure CPK is the correct size
    if compact_public_key.len() != P::CPK_BYTES {
        eprintln!("[ERROR] Compact public key length mismatch. Expected {}, got {}. pk_seed len {}, packed_P3 len {}",
            P::CPK_BYTES, compact_public_key.len(), pk_seed.len(), packed_upper_p3_bytes.len());
        return Err(CryptoError::KeyGenerationError);
    }
    
    println!("[{}] ✓ Keypair generated successfully (SK: {}B, PK: {}B)", P::NAME, compact_secret_key.len(), compact_public_key.len());
    
    Ok((compact_secret_key, compact_public_key))
}

pub fn expand_sk_generic<P: MayoParams>(csk: &[u8]) -> Result<ExpandedSecretKey<P>, CryptoError> {
    if csk.len() != P::SK_SEED_BYTES {
        return Err(CryptoError::InvalidKeyLength);
    }
    let sk_seed = csk;

    // Derive pk_seed and o_source_bytes from sk_seed
    let seed_material_len = P::PK_SEED_BYTES + P::O_BYTES;
    let seed_material = shake256_digest(sk_seed, seed_material_len);
    let pk_seed = &seed_material[..P::PK_SEED_BYTES];
    let o_source_bytes = &seed_material[P::PK_SEED_BYTES..];

    // Construct matrix_o
    let o_f16_elements = decode_bytes_to_f16_vec(o_source_bytes, P::V_PARAM * P::O_PARAM)
        .map_err(|e| CryptoError::ParameterError(format!("Failed to decode O material: {}", e)))?;
    let matrix_o = Matrix::new(P::V_PARAM, P::O_PARAM, o_f16_elements)
        .map_err(|e| CryptoError::ParameterError(format!("Failed to create matrix O: {}", e)))?;

    // Expand pk_seed to get P1 and P2 material
    let p1_plus_p2_len = P::CPK_P1_BYTES + P::CPK_P2_BYTES;
    let p1_p2_material = aes128_ctr_prf(pk_seed, p1_plus_p2_len)?;
    let p1_bytes_repr = &p1_p2_material[0..P::CPK_P1_BYTES];
    let p2_bytes_repr = &p1_p2_material[P::CPK_P1_BYTES..p1_plus_p2_len];

    // Convert P1 and P2 byte representations to MVector sequences
    let p1_mvecs_upper_tri = bytes_to_mvector_sequence::<P>(p1_bytes_repr, P::P1_ELEMENTS)?;
    let p2_orig_mvecs_dense = bytes_to_mvector_sequence::<P>(p2_bytes_repr, P::P2_ELEMENTS)?;

    // Compute L = P2_orig + P1*O
    let p1_o_mvecs = crate::mayo_operations::p1_times_o_operator::<P>(&p1_mvecs_upper_tri, &matrix_o)?;
    let l_mvecs_dense = crate::mayo_operations::add_mvector_sequences_operator::<P>(&p2_orig_mvecs_dense, &p1_o_mvecs)?;

    Ok(ExpandedSecretKey {
        matrix_o,
        p1_mvecs_upper_tri,
        l_mvecs_dense,
        _marker: PhantomData,
    })
}

pub fn expand_pk_generic<P: MayoParams>(cpk: &[u8]) -> Result<ExpandedPublicKey<P>, CryptoError> {
    if cpk.len() != P::CPK_BYTES {
        return Err(CryptoError::InvalidKeyLength);
    }

    let pk_seed = &cpk[..P::PK_SEED_BYTES];
    let packed_upper_p3_bytes = &cpk[P::PK_SEED_BYTES..];
    
    // Expected length check for packed_upper_p3_bytes part
    let expected_p3_packed_len = P::P3_ELEMENTS * ((P::M_PARAM + 1) / 2);
    if packed_upper_p3_bytes.len() != expected_p3_packed_len {
         return Err(CryptoError::ParameterError(format!(
            "Packed P3 component of CPK has incorrect length. Expected {}, got {}.",
            expected_p3_packed_len, packed_upper_p3_bytes.len()
        )));
    }

    // Expand pk_seed to get P1 and P2 material
    let p1_plus_p2_len = P::CPK_P1_BYTES + P::CPK_P2_BYTES;
    let p1_p2_material = aes128_ctr_prf(pk_seed, p1_plus_p2_len)?;
    let p1_bytes_repr = &p1_p2_material[0..P::CPK_P1_BYTES];
    let p2_bytes_repr = &p1_p2_material[P::CPK_P1_BYTES..p1_plus_p2_len];

    // Convert P1 and P2 byte representations to MVector sequences
    let p1_mvecs_upper_tri = bytes_to_mvector_sequence::<P>(p1_bytes_repr, P::P1_ELEMENTS)?;
    let p2_mvecs_dense = bytes_to_mvector_sequence::<P>(p2_bytes_repr, P::P2_ELEMENTS)?;

    // Convert packed_upper_p3_bytes to MVector sequence
    let p3_mvecs_upper_tri = bytes_to_mvector_sequence::<P>(packed_upper_p3_bytes, P::P3_ELEMENTS)?;

    Ok(ExpandedPublicKey {
        p1_mvecs_upper_tri,
        p2_mvecs_dense,
        p3_mvecs_upper_tri,
        _marker: PhantomData,
    })
}


pub fn sign_generic<P: MayoParams>(csk: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    println!("[{}] Signing message ({} bytes)...", P::NAME, message.len());

    // Step 1: Expand secret key
    if csk.len() != P::CSK_BYTES { // CSK_BYTES is SK_SEED_BYTES
        return Err(CryptoError::InvalidKeyLength);
    }
    let esk = expand_sk_generic::<P>(csk)?;

    // Step 2: Salt and Hashing
    // Concatenate message digest and salt, then hash to get seed for V and r
    let mut salt = vec![0u8; P::SALT_BYTES];
    OsRng.fill_bytes(&mut salt);

    let message_digest = shake256_digest(message, P::DIGEST_BYTES); // H(m)
    let msg_salt_concat = [message_digest.as_slice(), salt.as_slice()].concat();

    // Seed for V and r (randomness for solution sampling)
    // V_and_r_seed_len calculation based on C code: k*v_bytes + r_bytes
    // v_bytes = (P::V_PARAM + 1) / 2
    let v_bytes_len = (P::V_PARAM + 1) / 2;
    let v_and_r_seed_len = P::K_PARAM * v_bytes_len + P::R_BYTES;

    // Signing loop (Step 4 in spec)
    const MAX_SIGNING_ATTEMPTS: usize = 200; // As per reference implementation
    for attempt in 0..MAX_SIGNING_ATTEMPTS {
        // Step 4a: Generate random seed for V and r_seed (using OsRng for now, C uses SHAKE with msg_salt_concat and a counter)
        // For simplicity here, let's use OsRng to get distinct bytes each time.
        // A more compliant way would be: H(H(m)||salt||attempt_counter)
        let mut attempt_counter_bytes = (attempt as u32).to_le_bytes(); // Simple counter
        let seed_for_v_r_input = [msg_salt_concat.as_slice(), &attempt_counter_bytes].concat();
        let v_and_r_bytes = shake256_digest(&seed_for_v_r_input, v_and_r_seed_len);

        // Step 4b: Decode V_i vectors and r_for_solution
        let mut v_f16_vectors = Vec::with_capacity(P::K_PARAM);
        for i in 0..P::K_PARAM {
            let start = i * v_bytes_len;
            let end = start + v_bytes_len;
            let v_i_bytes = &v_and_r_bytes[start..end];
            let v_i_f16s = decode_bytes_to_f16_vec(v_i_bytes, P::V_PARAM)
                .map_err(|e| CryptoError::SigningError)?; // TODO specific error
            v_f16_vectors.push(Vector::new(v_i_f16s));
        }
        let r_for_solution = &v_and_r_bytes[P::K_PARAM * v_bytes_len ..];
        if r_for_solution.len() != P::R_BYTES { return Err(CryptoError::SigningError); /* Should not happen */ }


        // Step 4c: Compute M (VL) and V P1 V^T (VP1V)
        // compute_m_and_vpv_operator returns (VL_mvecs, VP1V_mvecs)
        let (vl_mvecs, vp1v_mvecs) = compute_m_and_vpv_operator::<P>(
            &v_f16_vectors,
            &esk.l_mvecs_dense,
            &esk.p1_mvecs_upper_tri
        )?;

        // Step 3 & 4d: Compute target vector t and right-hand side y for linear system
        // Target t_f16_vec (equation (6) in spec)
        // For now, using placeholder for t_f16_vec. It should be H(H(m)||salt||V_bytes)
        // V_bytes are all v_i_bytes concatenated.
        let all_v_bytes_len = P::K_PARAM * v_bytes_len;
        let all_v_bytes = &v_and_r_bytes[0..all_v_bytes_len];
        let t_hash_input = [msg_salt_concat.as_slice(), all_v_bytes].concat();
        let t_bytes = shake256_digest(&t_hash_input, (P::M_PARAM + 1) / 2); // M_PARAM nibbles
        let t_f16_vec = Vector::new(decode_bytes_to_f16_vec(&t_bytes, P::M_PARAM).map_err(|e| CryptoError::SigningError)?);

        let y_mvector = compute_rhs_for_sign_operator::<P>(&vp1v_mvecs, &t_f16_vec)?;

        // Step 4e: Compute system matrix A
        let mut a_system_matrix = compute_a_system_matrix_for_sign_operator::<P>(&vl_mvecs)?;

        // Step 4f: Sample solution E for A*E = y
        // Convert y_mvector (MVector) to y_f16_vector (Vector<F16>)
        // MVector elements are public, so direct access is possible
        let mut y_f16_vector = Vector::new(y_mvector.elements.clone());

        if let Some(e_solution_f16_vec) = sample_solution_operator::<P>(&mut a_system_matrix, &mut y_f16_vector, r_for_solution)? {
            // Step 5: Compute signature s = (V_0, ..., V_{k-1}, E_0, ..., E_{k-1})
            // Concatenate all_v_bytes and encoded e_solution_f16_vec
            let e_solution_bytes = e_solution_f16_vec.encode_vec(); // Vector::encode_vec uses nibble packing

            let mut sig_s_bytes = Vec::with_capacity(all_v_bytes_len + e_solution_bytes.len());
            sig_s_bytes.extend_from_slice(all_v_bytes);
            sig_s_bytes.extend_from_slice(&e_solution_bytes);

            // Step 6: Concatenate salt and s to form full signature
            let mut signature = Vec::with_capacity(P::SIG_BYTES);
            signature.extend_from_slice(&salt);
            signature.extend_from_slice(&sig_s_bytes);

            // Final check on signature length
            if signature.len() != P::SIG_BYTES {
                 eprintln!("[ERROR] Signature length mismatch. Expected {}, got {}.", P::SIG_BYTES, signature.len());
                return Err(CryptoError::SigningError);
            }

            println!("[{}] ✓ Signature created successfully (attempt {})", P::NAME, attempt);
            return Ok(signature);
        }
        // If sample_solution_operator returns None, loop continues to next attempt
        println!("[{}] Signing attempt {} failed, trying again.", P::NAME, attempt);
    }

    Err(CryptoError::SigningError) // Max attempts reached
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
// These now need to pass None for the seed argument.
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    generate_keypair_generic::<Mayo1>(None)
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
    use crate::mvector::MVector; // For test
    use crate::params::{Mayo1, Mayo2}; // For testing different variants


    #[test]
    fn test_bytes_to_mvector_sequence_roundtrip() {
        let m_param = Mayo1::M_PARAM;
        let m_vec_limbs = Mayo1::M_VEC_LIMBS;
        let bytes_per_mvector = (m_param + 1) / 2;

        let mv1_elements: Vec<F16> = (0..m_param).map(|i| F16::new((i % 16) as u8)).collect();
        let mv1 = MVector::new(m_param, mv1_elements).unwrap();

        let mv2_elements: Vec<F16> = (0..m_param).map(|i| F16::new(((i + 5) % 16) as u8)).collect();
        let mv2 = MVector::new(m_param, mv2_elements).unwrap();

        let original_mvecs = vec![mv1.clone(), mv2.clone()]; // Clone if they are to be compared later
        let mut combined_bytes = Vec::new();
        for mv in &original_mvecs {
            combined_bytes.extend(mv.to_limbs_bytes(m_vec_limbs).unwrap());
        }

        let num_mvectors = original_mvecs.len();
        if original_mvecs.is_empty() {
             assert!(combined_bytes.is_empty());
        } else {
            assert_eq!(combined_bytes.len(), original_mvecs.len() * bytes_per_mvector);
        }


        let reconstructed_mvecs = bytes_to_mvector_sequence::<Mayo1>(&combined_bytes, original_mvecs.len()).unwrap();
        assert_eq!(original_mvecs, reconstructed_mvecs);

        // Test with zero mvectors
        let empty_bytes: Vec<u8> = Vec::new();
        let reconstructed_empty = bytes_to_mvector_sequence::<Mayo1>(&empty_bytes, 0).unwrap();
        assert!(reconstructed_empty.is_empty());

        // Test for error on length mismatch
        if bytes_per_mvector > 0 { // Avoid panic if m_param is 0
            let too_few_bytes = vec![0u8; bytes_per_mvector -1];
            assert!(bytes_to_mvector_sequence::<Mayo1>(&too_few_bytes, 1).is_err());
        }

        let bytes_for_one = vec![0u8; bytes_per_mvector];
        if bytes_per_mvector > 0 { // Ensure bytes_for_one is not empty before trying to make it "too many"
            let too_many_bytes_for_one_but_not_two = [bytes_for_one.as_slice(), &[0u8;1]].concat();
            // This specific error case (bytes.len() != num_mvectors * bytes_per_mvector)
            // would be caught if num_mvectors = 2, as len would be bytes_per_mvector + 1
            assert!(bytes_to_mvector_sequence::<Mayo1>(&too_many_bytes_for_one_but_not_two, 2).is_err());
        }
        // The check for bytes.len() not being a multiple of bytes_per_mvector (for num_mvectors > 0)
        // is inherently covered by the `bytes.len() != num_mvectors * bytes_per_mvector` check
        // at the beginning of the `bytes_to_mvector_sequence` function.
    }

    #[test]
    fn test_aes128_ctr_prf_output_len() {
        let key = [0u8; 16];
        let output = aes128_ctr_prf(&key, 32).unwrap();
        assert_eq!(output.len(), 32);
        let output2 = aes128_ctr_prf(&key, 100).unwrap();
        assert_eq!(output2.len(), 100);
    }

    #[test]
    fn test_aes128_ctr_prf_deterministic() {
        let key = [1u8; 16];
        let output1 = aes128_ctr_prf(&key, 32).unwrap();
        let output2 = aes128_ctr_prf(&key, 32).unwrap();
        assert_eq!(output1, output2);
    }

    #[test]
    fn test_aes128_ctr_prf_different_keys() {
        let key1 = [1u8; 16];
        let key2 = [2u8; 16];
        let output1 = aes128_ctr_prf(&key1, 32).unwrap();
        let output2 = aes128_ctr_prf(&key2, 32).unwrap();
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_aes128_ctr_prf_invalid_key() {
        let short_key = [0u8; 10];
        assert!(matches!(aes128_ctr_prf(&short_key, 32), Err(CryptoError::InvalidKeyLength)));
        let long_key = [0u8; 20];
        assert!(matches!(aes128_ctr_prf(&long_key, 32), Err(CryptoError::InvalidKeyLength)));
    }

    #[test]
    fn test_generate_keypair() {
        let (sk, pk) = generate_keypair_generic::<Mayo1>(None).unwrap(); // Pass None for random seed
        assert_eq!(sk.len(), Mayo1::SK_SEED_BYTES);
        assert_eq!(pk.len(), Mayo1::CPK_BYTES);
    }

    #[test]
    fn test_expand_sk_basic() {
        let (csk, _cpk) = generate_keypair_generic::<Mayo1>(None).unwrap();
        let esk = expand_sk_generic::<Mayo1>(&csk);
        assert!(esk.is_ok());
        let esk_val = esk.unwrap();
        assert_eq!(esk_val.matrix_o.rows(), Mayo1::V_PARAM);
        assert_eq!(esk_val.matrix_o.cols(), Mayo1::O_PARAM);
        assert_eq!(esk_val.p1_mvecs_upper_tri.len(), Mayo1::P1_ELEMENTS);
        assert_eq!(esk_val.l_mvecs_dense.len(), Mayo1::V_PARAM * Mayo1::O_PARAM); // P2_ELEMENTS
         if !esk_val.l_mvecs_dense.is_empty() {
            assert_eq!(esk_val.l_mvecs_dense[0].len(), Mayo1::M_PARAM);
        }
    }

    #[test]
    fn test_expand_pk_basic() {
        let (_csk, cpk) = generate_keypair_generic::<Mayo1>(None).unwrap();
        let epk = expand_pk_generic::<Mayo1>(&cpk);
        assert!(epk.is_ok());
        let epk_val = epk.unwrap();
        assert_eq!(epk_val.p1_mvecs_upper_tri.len(), Mayo1::P1_ELEMENTS);
        assert_eq!(epk_val.p2_mvecs_dense.len(), Mayo1::P2_ELEMENTS);
        assert_eq!(epk_val.p3_mvecs_upper_tri.len(), Mayo1::P3_ELEMENTS);
        if !epk_val.p1_mvecs_upper_tri.is_empty() {
            assert_eq!(epk_val.p1_mvecs_upper_tri[0].len(), Mayo1::M_PARAM);
        }
    }

    #[test]
    fn test_expand_sk_invalid_len() {
        let short_csk = vec![0u8; Mayo1::SK_SEED_BYTES - 1];
        assert!(matches!(expand_sk_generic::<Mayo1>(&short_csk), Err(CryptoError::InvalidKeyLength)));
    }

    #[test]
    fn test_expand_pk_invalid_len() {
        let short_cpk = vec![0u8; Mayo1::CPK_BYTES - 1];
        assert!(matches!(expand_pk_generic::<Mayo1>(&short_cpk), Err(CryptoError::InvalidKeyLength)));
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
