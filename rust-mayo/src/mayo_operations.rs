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

// Helper to get MVector from P1's upper triangular sequence
// r, c are 0-indexed for the conceptual v x v matrix P1
fn get_p1_symmetric_mvector<'a, P: MayoParams>(
    p1_mvecs_upper_tri: &'a [MVector],
    r: usize,
    c: usize,
    v_param: usize, // P::V_PARAM
) -> Result<&'a MVector, CryptoError> {
    let (row, col) = if r <= c { (r, c) } else { (c, r) }; // Access upper part

    // Calculate 1D index for upper triangular storage (row-major)
    // P1_ELEMENTS = v_param * (v_param + 1) / 2
    // index = sum_{i=0}^{row-1} (v_param - i) + (col - row)
    let mut current_1d_idx = 0;
    for i in 0..row {
        current_1d_idx += v_param - i;
    }
    current_1d_idx += col - row;

    if current_1d_idx >= p1_mvecs_upper_tri.len() {
        return Err(CryptoError::ParameterError(format!(
            "P1 MVector index out of bounds: r={}, c={}, 1D_idx={}, len={}",
            r, c, current_1d_idx, p1_mvecs_upper_tri.len()
        )));
    }
    Ok(&p1_mvecs_upper_tri[current_1d_idx])
}

// Computes VL = V * L and VP1V = V * P1 * V^T
// V_f16_vectors: &[Vector<F16>], k vectors, each length v (P::V_PARAM)
// l_mvecs: &[MVector], represents L (v x o of MVectors, row-major, P::P2_ELEMENTS total)
// p1_mvecs_upper_tri: &[MVector], represents upper P1 (P::P1_ELEMENTS total)
// Returns Result<(vl_mvecs, vp1v_mvecs), CryptoError>
// vl_mvecs: k*o MVectors (row-major)
// vp1v_mvecs: k*k MVectors (row-major, symmetric)
pub fn compute_m_and_vpv_operator<P: MayoParams>(
    v_f16_vectors: &[crate::vector::Vector], // k vectors, each len v
    l_mvecs: &[MVector],           // v*o MVectors for L
    p1_mvecs_upper_tri: &[MVector], // P1_ELEMENTS for upper P1
) -> Result<(Vec<MVector>, Vec<MVector>), CryptoError> {
    let k_param = P::K_PARAM;
    let v_param = P::V_PARAM;
    let o_param = P::O_PARAM;
    let m_param = P::M_PARAM;

    // Dimension checks
    if v_f16_vectors.len() != k_param { return Err(CryptoError::ParameterError("Incorrect number of V vectors".to_string())); }
    if !v_f16_vectors.is_empty() && v_f16_vectors[0].len() != v_param {
        return Err(CryptoError::ParameterError("V vectors have incorrect length".to_string()));
    }
    if l_mvecs.len() != v_param * o_param { return Err(CryptoError::ParameterError(format!("L MVector sequence has incorrect length: expected {}, got {}", v_param * o_param, l_mvecs.len()))); }
    if p1_mvecs_upper_tri.len() != P::P1_ELEMENTS { return Err(CryptoError::ParameterError(format!("P1 MVector sequence has incorrect length: expected {}, got {}", P::P1_ELEMENTS, p1_mvecs_upper_tri.len()))); }

    // 1. Compute VL = V * L  (result is k x o of MVectors)
    let mut vl_mvecs = Vec::with_capacity(k_param * o_param);
    for r_v in 0..k_param { // row from V (0 to k-1)
        for c_l in 0..o_param { // col from L (0 to o-1)
            let mut sum_mvec = MVector::zero(m_param);
            for idx in 0..v_param { // sum over v_param (col of V, row of L)
                let v_val_scalar = v_f16_vectors[r_v].get(idx)
                    .ok_or_else(|| CryptoError::SigningErrorWithMsg(format!("V_f16_vectors access failed at ({},{})", r_v, idx)))?;
                let l_mvector_idx = idx * o_param + c_l; // L is v x o of MVecs, row-major
                if l_mvector_idx >= l_mvecs.len() { return Err(CryptoError::ParameterError("L mvec index out of bounds".to_string()));}
                let l_mvector = &l_mvecs[l_mvector_idx]; // L[idx, c_l] MVector

                let term = v_val_scalar * l_mvector; // F16 * &MVector -> MVector
                sum_mvec = (&sum_mvec + &term).map_err(|e| CryptoError::SigningErrorWithMsg(format!("VL MVec add: {}",e)))?;
            }
            vl_mvecs.push(sum_mvec);
        }
    }

    // 2. Compute VP1V = V * P1 * V^T (result is k x k of MVectors, symmetric)
    // Step 2a: temp_pv = V * P1 (k x v of MVectors)
    let mut temp_pv_mvecs = Vec::with_capacity(k_param * v_param);
    for r_v_idx in 0..k_param { // row of V, and row of result temp_pv
        for c_p1_idx in 0..v_param { // col of P1, and col of result temp_pv
            let mut sum_mvec = MVector::zero(m_param);
            for k_common_idx in 0..v_param { // col of V, row of P1
                let v_scalar = v_f16_vectors[r_v_idx].get(k_common_idx)
                     .ok_or_else(|| CryptoError::SigningErrorWithMsg(format!("V_f16_vectors access failed at ({},{}) for temp_pv", r_v_idx, k_common_idx)))?;
                let p1_mvec = get_p1_symmetric_mvector::<P>(p1_mvecs_upper_tri, k_common_idx, c_p1_idx, v_param)?;

                let term = v_scalar * p1_mvec;
                sum_mvec = (&sum_mvec + &term).map_err(|e| CryptoError::SigningErrorWithMsg(format!("temp_pv MVec add: {}",e)))?;
            }
            temp_pv_mvecs.push(sum_mvec);
        }
    }

    // Step 2b: VP1V = temp_pv * V^T (k x k of MVectors)
    // temp_pv is (k x v of MVectors), V^T is (v x k of F16)
    let mut vp1v_mvecs = Vec::with_capacity(k_param * k_param);
    for r_tpv_idx in 0..k_param { // row of temp_pv, and row of result VP1V
        for c_vt_idx in 0..k_param { // col of V^T, and col of result VP1V
            let mut sum_mvec = MVector::zero(m_param);
            for k_common_idx in 0..v_param { // col of temp_pv, row of V^T
                let tpv_mvector_idx = r_tpv_idx * v_param + k_common_idx; // temp_pv is k x v of MVecs, row-major
                if tpv_mvector_idx >= temp_pv_mvecs.len() { return Err(CryptoError::ParameterError("temp_pv_mvecs index out of bounds".to_string()));}
                let tpv_mvector = &temp_pv_mvecs[tpv_mvector_idx];

                let v_scalar_for_vt = v_f16_vectors[c_vt_idx].get(k_common_idx) // V[c_vt_idx, k_common_idx] is V^T[k_common_idx, c_vt_idx]
                    .ok_or_else(|| CryptoError::SigningErrorWithMsg(format!("V_f16_vectors access failed at ({},{}) for VP1V", c_vt_idx, k_common_idx)))?;

                let term = v_scalar_for_vt * tpv_mvector;
                sum_mvec = (&sum_mvec + &term).map_err(|e| CryptoError::SigningErrorWithMsg(format!("VP1V MVec add: {}",e)))?;
            }
            vp1v_mvecs.push(sum_mvec);
        }
    }
    Ok((vl_mvecs, vp1v_mvecs))
    // Err(CryptoError::SigningError)
}

// Computes the RHS vector 'y' for the signing equation.
// y_i = t_i ^ poly_eval_i
// poly_eval = sum_{i=0..k-1, j=i..k-1} (VP1V_ij + (i!=j)*VP1V_ji) * X^(poly_deg_for_term)
// where X is an indeterminate, and reduction uses P::F_TAIL.
pub fn compute_rhs_for_sign_operator<P: MayoParams>(
    vp1v_mvecs: &[MVector],
    t_target_f16_vec: &crate::vector::Vector,
) -> Result<MVector, CryptoError> {
    let k_param = P::K_PARAM;
    let m_param = P::M_PARAM;

    if vp1v_mvecs.len() != k_param * k_param {
        return Err(CryptoError::ParameterError("VP1V MVector sequence has incorrect length for RHS".to_string()));
    }
    if t_target_f16_vec.len() != m_param {
        return Err(CryptoError::ParameterError("t_target vector has incorrect length for RHS".to_string()));
    }
    if m_param == 0 { return Ok(MVector::zero(0)); }

    let mut acc_poly_mvector = MVector::zero(m_param);

    // Loop structure from C's compute_rhs (Horner-like evaluation):
    // acc_poly = 0
    // for i from k-1 down to 0:
    //   for j from k-1 down to i:
    //     acc_poly = acc_poly * Z (poly indeterminate, with F_TAIL reduction)
    //     coeff = VPV[i*k+j]
    //     if (i < j) coeff += VPV[j*k+i] // C code adds symmetric part for P_ij
    //     acc_poly = acc_poly + coeff
    // Note: VPV is symmetric (V*P1*V^T), so VPV[i,j] == VPV[j,i].
    // Thus, for i < j, coeff = VPV[i,j] + VPV[j,i] = 0 in GF(2^n).
    // So, we only need to consider the VPV[i,j] term where j >= i (as per loop structure).
    // The C code logic `madd(coeffs, coeffs, vPv + (j * k + i /align)*m_legs*8);` when i!=j
    // implies that `coeffs` (which is `current_coeff` here) is formed by adding the symmetric counterpart.
    // If vp1v_mvecs is already symmetric, this means `current_coeff = vp1v[idx] + vp1v[transpose_idx]`.
    // Since vp1v is symmetric, this means `current_coeff = vp1v[idx] + vp1v[idx] = 0` for `i != j`.
    // This seems to simplify things greatly, meaning only diagonal terms `VPV[i,i]` contribute if my reasoning is correct.
    // However, the reference code's polynomial evaluation is `P(X) = sum P_ij X^d_ij` where `P_ij` are coefficients
    // and `d_ij` are specific degrees. The Horner method evaluates `P(X) = P_0 + X(P_1 + X(P_2 + ...))`.
    // The C code `for i=k-1..0 { for j=k-1..i { temp = temp*X + coeff(i,j) }}` implies coefficients are processed
    // from highest degree term of X down to the constant term.
    // The `coeff(i,j)` is `vp1v[i*k+j] + (i==j?0:vp1v[j*k+i])`.
    // This is the coefficient for a particular power of X in the polynomial sum.
    // The crucial part is that `poly_mul_by_x_and_add` does `prev_sum * X + current_coeff`.

    for r_idx in (0..k_param).rev() { // Iterating i from k-1 down to 0
        for c_idx in (r_idx..k_param).rev() { // Iterating j from k-1 down to i
            // This order processes coefficients for higher powers of X first in Horner's method.
            let mut current_coeff = vp1v_mvecs[r_idx * k_param + c_idx].clone();
            if r_idx != c_idx { // If VPV is stored fully (not just upper triangle)
                                // and P_ij = VPV_ij + VPV_ji for i < j
                // then we need to add the symmetric counterpart.
                // Assuming vp1v_mvecs is the full k*k matrix of MVectors.
                current_coeff = (&current_coeff + &vp1v_mvecs[c_idx * k_param + r_idx])
                    .map_err(|e| CryptoError::SigningErrorWithMsg(format!("VP1V add for symm in RHS: {}", e)))?;
            }
            // For Horner's: acc = acc * X + coeff_for_current_power
            // The coefficient for the current power of X is `current_coeff`.
            acc_poly_mvector = acc_poly_mvector.poly_mul_by_x_and_add(P::F_TAIL, &current_coeff)
                .map_err(|e| CryptoError::SigningErrorWithMsg(format!("Poly mul by X stub failed in RHS: {}", e)))?;
        }
    }

    // Final step: y_elements[i] = t_target_f16_vec.elements[i] ^ acc_poly_mvector.elements[i]
    let mut y_elements = Vec::with_capacity(m_param);
    for i in 0..m_param {
        let t_val = t_target_f16_vec.get(i)
            .ok_or_else(|| CryptoError::ParameterError("t_target_f16_vec get failed in RHS".to_string()))?;
        y_elements.push(t_val + acc_poly_mvector.elements[i]); // XOR
    }

    MVector::new(m_param, y_elements).map_err(|e| CryptoError::SigningErrorWithMsg(format!("RHS Y MVec new: {}",e)))
}

#[cfg(test)]
mod tests {
    // ... (other tests and helpers are above this)
    use crate::vector::Vector; // Ensure Vector is imported for tests

    #[test]
    fn test_compute_rhs_for_sign_basic() {
        type P = Mayo1;
        // vp1v_mvecs is k*k. For Mayo1, k=10, so 100 MVectors.
        let vp1v_mvecs = create_dense_mvector_sequence::<P>(P::K_PARAM, P::K_PARAM, 0);

        let t_elements: Vec<F16> = (0..P::M_PARAM).map(|i| F16::new((i%16) as u8)).collect();
        let t_target_f16_vec = Vector::new(t_elements);

        let result = compute_rhs_for_sign_operator::<P>(&vp1v_mvecs, &t_target_f16_vec);
        match result {
            Ok(y_mvector) => {
                assert_eq!(y_mvector.len(), P::M_PARAM);
                // Since poly_mul_by_x_and_add is a stub doing simple add (self + to_add),
                // and acc_poly_mvector starts at 0, the logic will be:
                // acc_poly = 0
                // for r_idx { for c_idx { current_coeff = ...; acc_poly = acc_poly + current_coeff } }
                // So acc_poly becomes the sum of all symmetric VPV terms.
                // y = t + sum(VPV_symm). This test mainly ensures it runs and dimensions are fine.
            }
            Err(e) => panic!("compute_rhs_for_sign_operator failed: {:?}", e),
        }
    }
}


// Placeholder for compute_A_system_matrix_for_sign
    type P = Mayo1; // Using Mayo1 for a concrete test case

    // Create dummy inputs with correct dimensions
    let v_f16_vectors: Vec<crate::vector::Vector> = (0..P::K_PARAM)
        .map(|_| crate::vector::Vector::new(
            (0..P::V_PARAM).map(|i| F16::new((i % 16) as u8)).collect()
        ))
        .collect();

    let l_mvecs = create_dense_mvector_sequence::<P>(P::V_PARAM, P::O_PARAM, 0);
    let p1_mvecs_upper_tri = create_test_p1_mvecs::<P>(); // Assuming this helper exists from previous tests

    let result = compute_m_and_vpv_operator::<P>(&v_f16_vectors, &l_mvecs, &p1_mvecs_upper_tri);

    match result {
        Ok((vl_mvecs, vp1v_mvecs)) => {
            assert_eq!(vl_mvecs.len(), P::K_PARAM * P::O_PARAM, "VL MVector sequence length mismatch");
            if !vl_mvecs.is_empty() {
                assert_eq!(vl_mvecs[0].len(), P::M_PARAM, "VL MVector element length mismatch");
            }
            assert_eq!(vp1v_mvecs.len(), P::K_PARAM * P::K_PARAM, "VP1V MVector sequence length mismatch");
            if !vp1v_mvecs.is_empty() {
                assert_eq!(vp1v_mvecs[0].len(), P::M_PARAM, "VP1V MVector element length mismatch");
            }
        }
        Err(e) => panic!("compute_m_and_vpv_operator failed: {:?}", e),
    }
}

// Computes the RHS vector 'y' for the signing equation.
// y_i = t_i ^ poly_eval_i
// poly_eval = sum_{i=0..k-1, j=i..k-1} (VP1V_ij + (i!=j)*VP1V_ji) * X^(poly_deg_for_term)
// where X is an indeterminate, and reduction uses P::F_TAIL.
pub fn compute_rhs_for_sign_operator<P: MayoParams>(
    vp1v_mvecs: &[MVector],
    t_target_f16_vec: &crate::vector::Vector,
) -> Result<MVector, CryptoError> {
    let k_param = P::K_PARAM;
    let m_param = P::M_PARAM;

    if vp1v_mvecs.len() != k_param * k_param {
        return Err(CryptoError::ParameterError("VP1V MVector sequence has incorrect length for RHS".to_string()));
    }
    if t_target_f16_vec.len() != m_param {
        return Err(CryptoError::ParameterError("t_target vector has incorrect length for RHS".to_string()));
    }
    if m_param == 0 { return Ok(MVector::zero(0)); }

    let mut acc_poly_mvector = MVector::zero(m_param);

    // This loop structure is an attempt to mirror C's compute_rhs.
    // temp = 0
    // for i from k-1 down to 0:
    //    for j from i up to k-1:
    //       temp = temp * X_poly  // This is the tricky part, happens with F_TAIL reduction
    //       current_coeff = VPV_terms[i][j] (handle symmetry: if i!=j, add VPV[j][i])
    //       temp = temp + current_coeff
    // The MVector::poly_mul_by_x_and_add is a STUB.
    // The C code builds the polynomial by repeated multiplication by X and addition.
    // The order here is crucial.

    // Corrected loop structure based on re-analysis for polynomial evaluation:
    // The polynomial is sum_{0 <= i <= j < k} P_ij Z^{ (k-1-i)k - (k-1-i)(k-i)/2 + (j-i) }
    // where P_ij = (vp1v_ij + (i!=j)vp1v_ji).
    // This is evaluated using Horner-like method in C (repeatedly mul by Z and add next coeff).
    // The C code iterates i from k-1 down to 0, and j from i up to k-1.
    // In each step, it does temp = temp * Z + coeff_for_this_power_of_Z.
    // The coeff_for_this_power_of_Z is vp1v_mvecs[i*k+j] (plus symmetric part).

    // Let's try to match the C structure more closely.
    // `temp` in C code is `acc_poly_mvector` here.
    for r_vp1v in (0..k_param).rev() { // i in C
        for c_vp1v in (r_vp1v..k_param).rev() { // j in C (iterates k-1 down to i)
                                            // This inner loop C order is: for (j = k - 1; j >= i; j--)
            let mut current_coeff = vp1v_mvecs[r_vp1v * k_param + c_vp1v].clone();
            if r_vp1v != c_vp1v { // Symmetric part for P_ij where P is (V P1 V^T)
                current_coeff = (&current_coeff + &vp1v_mvecs[c_vp1v * k_param + r_vp1v])
                    .map_err(|e| CryptoError::SigningErrorWithMsg(format!("VP1V add for symm: {}", e)))?;
            }

            // acc_poly_mvector = acc_poly_mvector * Z + current_coeff
            acc_poly_mvector = acc_poly_mvector.poly_mul_by_x_and_add(P::F_TAIL, &current_coeff)
                .map_err(|e| CryptoError::SigningErrorWithMsg(format!("Poly mul by X stub failed: {}", e)))?;
        }
    }

    // Final step: y_elements[i] = t_target_f16_vec.elements[i] ^ acc_poly_mvector.elements[i]
    let mut y_elements = Vec::with_capacity(m_param);
    for i in 0..m_param {
        let t_val = t_target_f16_vec.get(i).ok_or_else(|| CryptoError::ParameterError("t_target_f16_vec get failed".to_string()))?;
        y_elements.push(t_val + acc_poly_mvector.elements[i]); // XOR
    }

    MVector::new(m_param, y_elements).map_err(|e| CryptoError::SigningErrorWithMsg(format!("RHS Y MVec new: {}",e)))
}

#[cfg(test)]
mod tests {
    // ... (other tests and helpers)
    use crate::vector::Vector; // Ensure Vector is imported for tests

    #[test]
    fn test_compute_rhs_for_sign_basic() {
        type P = Mayo1;
        let vp1v_mvecs = create_dense_mvector_sequence::<P>(P::K_PARAM, P::K_PARAM, 0);

        let t_elements: Vec<F16> = (0..P::M_PARAM).map(|i| F16::new((i%16) as u8)).collect();
        let t_target_f16_vec = Vector::new(t_elements);

        let result = compute_rhs_for_sign_operator::<P>(&vp1v_mvecs, &t_target_f16_vec);
        match result {
            Ok(y_mvector) => {
                assert_eq!(y_mvector.len(), P::M_PARAM);
                // Since poly_mul_by_x_and_add is a stub doing simple add,
                // the result will not be cryptographically correct but should execute.
                // For the current stub (self + to_add), and acc_poly starting at 0,
                // acc_poly will become sum of all (symmetric) vp1v_mvecs terms due to the loop structure.
                // This test mainly ensures it runs and dimensions are fine.
            }
            Err(e) => panic!("compute_rhs_for_sign_operator failed: {:?}", e),
        }
    }
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
