// rust-mayo/src/mayo_operations.rs
use crate::f16::F16;
use crate::mvector::MVector;
use crate::matrix::Matrix; // Assuming this is Matrix<F16>
use crate::params::MayoParams;
use crate::crypto::CryptoError; // CryptoError is now pub

// Computes P1 * O where P1 is a symmetric matrix (V_PARAM x V_PARAM) represented by its
// upper triangular part as a sequence of MVectors, and O is a (V_PARAM x O_PARAM) matrix of F16 scalars.
// Returns a dense (V_PARAM x O_PARAM) matrix represented as a sequence of MVectors.
pub fn p1_times_o_operator<P: MayoParams>(
    p1_upper_mvecs: &[MVector], // Sequence of P::P1_ELEMENTS MVectors
    matrix_o: &Matrix,     // V_PARAM x O_PARAM Matrix of F16
) -> Result<Vec<MVector>, CryptoError> {
    let v = P::V_PARAM;
    let o = P::O_PARAM;
    let m = P::M_PARAM;

    if matrix_o.rows() != v || matrix_o.cols() != o {
        return Err(CryptoError::ParameterError(format!(
            "P1*O: Matrix O dimensions incorrect. Expected {}x{}, got {}x{}",
            v, o, matrix_o.rows(), matrix_o.cols()
        )));
    }
    if p1_upper_mvecs.len() != P::P1_ELEMENTS {
        return Err(CryptoError::ParameterError(format!(
            "P1*O: Incorrect number of MVectors for P1 upper. Expected {}, got {}",
            P::P1_ELEMENTS, p1_upper_mvecs.len()
        )));
    }

    let mut result_mvecs = Vec::with_capacity(v * o); // v*o MVectors, each of length m

    for r_idx in 0..v { // row of the result (and P1)
        for c_idx in 0..o { // col of the result (and O)
            let mut res_mvector = MVector::zero(m);
            for k_idx in 0..v { // k is the summation index (col of P1, row of O)
                // Get P1_rk MVector (symmetric handling)
                let p1_rk_mvector_idx: usize;
                if r_idx <= k_idx {
                    // Index for upper triangular part (row_idx, col_idx) -> (r_idx, k_idx)
                    let mut current_idx = 0;
                    for i in 0..r_idx {
                        current_idx += v - i;
                    }
                    current_idx += k_idx - r_idx;
                    p1_rk_mvector_idx = current_idx;
                } else { // r_idx > k_idx, use P1_kr (symmetry) -> (k_idx, r_idx)
                    let mut current_idx = 0;
                    for i in 0..k_idx {
                        current_idx += v - i;
                    }
                    current_idx += r_idx - k_idx;
                    p1_rk_mvector_idx = current_idx;
                }

                if p1_rk_mvector_idx >= p1_upper_mvecs.len() {
                    return Err(CryptoError::ParameterError(format!(
                        "P1*O: Calculated index {} for p1_upper_mvecs out of bounds (len {}) for P1({},{})",
                        p1_rk_mvector_idx, p1_upper_mvecs.len(), r_idx, k_idx
                    )));
                }
                let p1_rk_mvector = &p1_upper_mvecs[p1_rk_mvector_idx];

                // Get O_kc scalar
                let o_kc_scalar = matrix_o.get(k_idx, c_idx).ok_or_else(|| CryptoError::ParameterError(
                    format!("P1*O: Failed to get O({},{}) from matrix_o", k_idx, c_idx)
                ))?;

                // MVector = MVector + (scalar * MVector)
                let term = o_kc_scalar * p1_rk_mvector; // F16 * &MVector -> MVector
                res_mvector = (&res_mvector + &term).map_err(|e| CryptoError::ParameterError(format!("P1*O: MVector addition failed: {}",e)))?;
            }
            result_mvecs.push(res_mvector);
        }
    }
    if result_mvecs.len() != v * o {
         return Err(CryptoError::KeyGenerationError); // Should not happen if loops are correct
    }
    Ok(result_mvecs)
}

// Adds two sequences of MVectors element-wise.
// Assumes sequences are of the same length and MVectors have matching m_param.
pub fn add_mvector_sequences_operator<P: MayoParams>(
    seq1: &[MVector],
    seq2: &[MVector],
) -> Result<Vec<MVector>, CryptoError> {
    if seq1.len() != seq2.len() {
        return Err(CryptoError::ParameterError("MVector sequences must have the same length for addition.".to_string()));
    }
    if seq1.is_empty() {
        return Ok(Vec::new());
    }
    // Assuming all MVectors in a sequence have the same m_param, validated by their construction.
    // And that m_params match between corresponding MVectors in seq1 and seq2.

    let mut result_seq = Vec::with_capacity(seq1.len());
    for i in 0..seq1.len() {
        // The Add impl for &MVector returns Result<MVector, String>, map error.
        let sum_mvec = (&seq1[i] + &seq2[i]).map_err(|e| CryptoError::ParameterError(format!("MVector add failed: {}", e)))?;
        result_seq.push(sum_mvec);
    }
    Ok(result_seq)
}

// Computes O^T * P_prime, where O is (V_PARAM x O_PARAM) matrix of F16 scalars,
// and P_prime is a (V_PARAM x O_PARAM) matrix represented as a sequence of MVectors (row-major).
// Result P3 is (O_PARAM x O_PARAM) matrix as a sequence of MVectors (row-major).
pub fn o_transpose_times_mvector_sequence_operator<P: MayoParams>(
    matrix_o: &Matrix,         // V_PARAM x O_PARAM
    p_prime_mvecs: &[MVector],   // V_PARAM * O_PARAM MVectors, representing P_prime (V_PARAM rows, O_PARAM cols of MVectors)
) -> Result<Vec<MVector>, CryptoError> {
    let v = P::V_PARAM;
    let o = P::O_PARAM;
    let m = P::M_PARAM;

    if matrix_o.rows() != v || matrix_o.cols() != o {
        return Err(CryptoError::ParameterError("Matrix O dimensions mismatch in O^T * P'".to_string()));
    }
    if p_prime_mvecs.len() != v * o {
        return Err(CryptoError::ParameterError("P' MVector sequence length mismatch in O^T * P'".to_string()));
    }

    let mut p3_mvecs = Vec::with_capacity(o * o);

    for r_idx in 0..o { // row of P3 (and col of O^T)
        for c_idx in 0..o { // col of P3 (and col of P_prime, when viewed as o cols of v-row MVector blocks)
            let mut res_mvector = MVector::zero(m);
            for k_idx in 0..v { // sum over k (row of O^T / col of O, and row of P_prime)
                // O_transpose_rk is O_kr
                let o_kr_scalar = matrix_o.get(k_idx, r_idx).ok_or_else(|| CryptoError::ParameterError(format!("O matrix get failed at ({},{})", k_idx, r_idx)))?;

                // P_prime_kc MVector
                // p_prime_mvecs is row-major: P_prime[k_idx][c_idx]
                let p_prime_kc_mvector_idx = k_idx * o + c_idx;
                if p_prime_kc_mvector_idx >= p_prime_mvecs.len() {
                     return Err(CryptoError::ParameterError("P' MVector index out of bounds".to_string()));
                }
                let p_prime_kc_mvector = &p_prime_mvecs[p_prime_kc_mvector_idx];

                let term = o_kr_scalar * p_prime_kc_mvector; // F16 * &MVector -> MVector
                res_mvector = (&res_mvector + &term).map_err(|e| CryptoError::ParameterError(format!("MVector add failed: {}", e)))?;
            }
            p3_mvecs.push(res_mvector);
        }
    }
    Ok(p3_mvecs)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::Mayo1; // Using Mayo1 for a concrete test case
    use crate::f16::F16;
    use crate::mvector::MVector;
    use crate::matrix::Matrix;

    // Helper to create a sequence of MVectors for testing P1
    fn create_test_p1_mvecs<P: MayoParams>() -> Vec<MVector> {
        let mut mvecs = Vec::new();
        for i in 0..P::P1_ELEMENTS {
            let elements: Vec<F16> = (0..P::M_PARAM).map(|j| F16::new(((i + j) % 16) as u8)).collect();
            mvecs.push(MVector::new(P::M_PARAM, elements).unwrap());
        }
        mvecs
    }

    // Helper to create a test Matrix O
    fn create_test_matrix_o<P: MayoParams>() -> Matrix {
        let mut o_elements = Vec::new();
        for i in 0..(P::V_PARAM * P::O_PARAM) {
            o_elements.push(F16::new((i % 16) as u8));
        }
        Matrix::new(P::V_PARAM, P::O_PARAM, o_elements).unwrap()
    }

    // Helper to create a dense sequence of MVectors (e.g. for P_prime or P2)
    fn create_dense_mvector_sequence<P: MayoParams>(rows: usize, cols: usize, start_val: u8) -> Vec<MVector> {
        let mut mvecs = Vec::new();
        for i in 0..(rows * cols) {
            let elements: Vec<F16> = (0..P::M_PARAM).map(|j| F16::new(((i + j + (start_val as usize)) % 16) as u8)).collect();
            mvecs.push(MVector::new(P::M_PARAM, elements).unwrap());
        }
        mvecs
    }


    #[test]
    fn test_p1_times_o_basic_execution() {
        // This test primarily checks if the function executes without panics and produces
        // an output of the correct dimensions. Correctness of values is hard to verify
        // without a known small example and manual computation.
        type P = Mayo1;
        let p1_mvecs = create_test_p1_mvecs::<P>();
        let matrix_o = create_test_matrix_o::<P>();

        let result = p1_times_o_operator::<P>(&p1_mvecs, &matrix_o);

        match result {
            Ok(res_mvecs) => {
                assert_eq!(res_mvecs.len(), P::V_PARAM * P::O_PARAM, "Incorrect number of MVectors in result");
                for mv in res_mvecs {
                    assert_eq!(mv.len(), P::M_PARAM, "Incorrect MVector length in result");
                }
            }
            Err(e) => {
                panic!("p1_times_o_operator failed: {:?}", e);
            }
        }
    }

    #[test]
    fn test_add_mvector_sequences_basic() {
        type P = Mayo1;
        let seq1 = create_dense_mvector_sequence::<P>(P::V_PARAM, P::O_PARAM, 0);
        let seq2 = create_dense_mvector_sequence::<P>(P::V_PARAM, P::O_PARAM, 5);

        let result = add_mvector_sequences_operator::<P>(&seq1, &seq2);
        match result {
            Ok(res_seq) => {
                assert_eq!(res_seq.len(), seq1.len(), "Result sequence length mismatch");
                for i in 0..res_seq.len() {
                    assert_eq!(res_seq[i].len(), P::M_PARAM, "MVector length mismatch in result sequence");
                    // Basic check: (a+b)+b = a. Here, (seq1[i]+seq2[i]) + seq2[i] should be seq1[i]
                    // due to GF(2^n) addition.
                    let temp_sum = (&res_seq[i] + &seq2[i]).unwrap();
                    assert_eq!(temp_sum, seq1[i], "Addition property check failed");
                }
            }
            Err(e) => panic!("add_mvector_sequences_operator failed: {:?}", e),
        }

        // Test empty
        let empty_seq: Vec<MVector> = Vec::new();
        assert!(add_mvector_sequences_operator::<P>(&empty_seq, &empty_seq).unwrap().is_empty());

        // Test length mismatch
        let short_seq = vec![MVector::zero(P::M_PARAM)];
        assert!(add_mvector_sequences_operator::<P>(&seq1, &short_seq).is_err());
    }

    #[test]
    fn test_o_transpose_times_mvector_sequence_basic() {
        type P = Mayo1;
        let matrix_o = create_test_matrix_o::<P>();
        let p_prime_mvecs = create_dense_mvector_sequence::<P>(P::V_PARAM, P::O_PARAM, 0);

        let result = o_transpose_times_mvector_sequence_operator::<P>(&matrix_o, &p_prime_mvecs);
        match result {
            Ok(res_mvecs) => {
                assert_eq!(res_mvecs.len(), P::O_PARAM * P::O_PARAM, "Incorrect number of MVectors in O^T * P' result");
                for mv in res_mvecs {
                    assert_eq!(mv.len(), P::M_PARAM, "Incorrect MVector length in O^T * P' result");
                }
            }
            Err(e) => panic!("o_transpose_times_mvector_sequence_operator failed: {:?}", e),
        }
    }


    // TODO: Add a test with a small, manually verifiable P1 and O.
    // For example, P1 (2x2, 3 MVectors), O (2x1, 2 F16 scalars).
    // Result is (2x1, 2 MVectors).
    // Let P1_upper_mvecs = [mv0, mv1, mv2]
    // P1 = [[mv0, mv1], [mv1, mv2]] (conceptually, as operations are on MVecs)
    // O = [[o0], [o1]]
    // Res[0] = (mv0 * o0) + (mv1 * o1)
    // Res[1] = (mv1 * o0) + (mv2 * o1)
}

// Placeholder for compute_M_and_VPV
// Vdec is a Vec of K vinegar vectors (each Vector<F16> of length V_PARAM)
// L_mvecs is a sequence of V_PARAM * O_PARAM MVectors (from expanded SK)
// P1_mvecs is a sequence of P1_ELEMENTS MVectors (from expanded SK)
// Returns (VL_mvecs_as_bytes, VP1V_mvecs_as_bytes) or appropriate error
pub fn compute_m_and_vpv_operator<P: MayoParams>(
    _v_f16_vectors: &[crate::vector::Vector], // Changed to crate::vector::Vector
    _l_mvecs: &[MVector],
    _p1_mvecs: &[MVector],
) -> Result<(Vec<MVector>, Vec<MVector>), CryptoError> {
    // VL is k x o of MVectors. VP1V is k x k of MVectors.
    let k = P::K_PARAM;
    let o = P::O_PARAM;
    let m = P::M_PARAM;
    println!("[STUB] compute_m_and_vpv_operator called");
    Ok((
        vec![MVector::zero(m); k * o], // Placeholder for VL_mvecs
        vec![MVector::zero(m); k * k]  // Placeholder for VP1V_mvecs
    ))
    // Err(CryptoError::SigningError) // Or return dummy data for now
}

// Placeholder for compute_rhs_for_sign
// vp1v_mvecs is k x k of MVectors
// t_target_f16_vec is Vector<F16> of length M_PARAM
// Returns y_target_mvector (MVector of length M_PARAM)
pub fn compute_rhs_for_sign_operator<P: MayoParams>(
    _vp1v_mvecs: &[MVector], // k*k MVectors
    _t_target_f16_vec: &crate::vector::Vector, // Changed to crate::vector::Vector
) -> Result<MVector, CryptoError> {
    println!("[STUB] compute_rhs_for_sign_operator called");
    Ok(MVector::zero(P::M_PARAM))
    // Err(CryptoError::SigningError)
}

// Placeholder for compute_A_system_matrix_for_sign
// vl_mvecs is k x o of MVectors
// Returns A_system_matrix (Matrix<F16> of size M_PARAM x (K_PARAM * O_PARAM))
pub fn compute_a_system_matrix_for_sign_operator<P: MayoParams>(
    _vl_mvecs: &[MVector], // k*o MVectors
) -> Result<Matrix, CryptoError> { // Changed to Matrix (which is Matrix<F16>)
    println!("[STUB] compute_a_system_matrix_for_sign_operator called");
    Ok(Matrix::zero(P::M_PARAM, P::K_PARAM * P::O_PARAM))
    // Err(CryptoError::SigningError)
}

// Placeholder for sample_solution
// A is M_PARAM x (K_PARAM * O_PARAM) Matrix<F16>
// y is Vector<F16> of length M_PARAM
// r_random_bytes is a byte slice of length P::R_BYTES
// Returns x_solution_f16_vec (Vector<F16> of length K_PARAM * O_PARAM) or None if no solution
pub fn sample_solution_operator<P: MayoParams>(
    _a_matrix: &mut Matrix, // Changed to Matrix
    _y_vector: &mut crate::vector::Vector, // Changed to crate::vector::Vector
    _r_random_bytes: &[u8],
) -> Result<Option<crate::vector::Vector>, CryptoError> { // Changed to crate::vector::Vector
    // This would call matrix.transform_to_row_echelon_augmented and matrix.solve_from_row_echelon
    // And handle free variables using r_random_bytes
    println!("[STUB] sample_solution_operator called");
    // For now, pretend a solution is found for first try, or never to test loop
    if _r_random_bytes.is_empty() || _r_random_bytes[0] % 2 == 0 { // Mock behavior
         Ok(Some(crate::vector::Vector::zero(P::K_PARAM * P::O_PARAM)))
    } else {
         Ok(None)
    }
    // Err(CryptoError::SigningError)
}
