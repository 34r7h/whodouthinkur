// rust-mayo/src/encoding.rs
use crate::f16::F16;
 // May not be directly used, but F16 is.
use crate::matrix::Matrix;
use crate::params; // Import the new params module

// Encodes a vector v ∈ Fm_16 into m/2 bytes in a bitsliced format.
// Output byte 0: bit 0 of v0, bit 0 of v1, ..., bit 0 of v7.
// Output byte 1: bit 0 of v8, bit 0 of v9, ..., bit 0 of v15.
// ...
// This is done for bit_plane=0, then bit_plane=1, etc., up to 3.
// Total bytes: 4 * (m/8) = m/2.
// Expects m to be a multiple of 8.
pub fn encode_bitsliced_vector(v: &[F16]) -> Result<Vec<u8>, String> {
    let m = v.len();
    if m == 0 {
        return Ok(Vec::new());
    }
    if m % 8 != 0 {
        // The reference implementation often pads with zeros to meet block requirements,
        // or assumes m is already suitable. Let's require m % 8 == 0 for now.
        return Err(format!("Vector length m ({}) must be a multiple of 8 for bitsliced encoding.", m));
    }

    let num_output_bytes = m / 2;
    let mut output = vec![0u8; num_output_bytes];
    let bytes_per_bit_plane = m / 8;

    for bit_plane in 0..4 { // For each bit (0 through 3) of the F16 elements
        let plane_offset = bit_plane * bytes_per_bit_plane; // Offset in output for this bit plane

        for byte_idx_in_plane in 0..bytes_per_bit_plane {
            // Each byte_idx_in_plane corresponds to a group of 8 F16 elements
            let mut current_byte: u8 = 0;
            let v_offset = byte_idx_in_plane * 8; // Offset in the input vector v

            for bit_in_byte in 0..8 { // Iterate over the 8 F16 elements that form this output byte
                let f16_element = v[v_offset + bit_in_byte];
                // Get the specific bit (from bit_plane) of the current F16 element
                if (f16_element.value() >> bit_plane) & 1 != 0 {
                    current_byte |= 1 << bit_in_byte;
                }
            }
            output[plane_offset + byte_idx_in_plane] = current_byte;
        }
    }
    Ok(output)
}

// Encodes a sequence of m matrices {A_i}, each r x c, into a byte string.
// If is_triangular is true, it skips elements A_k[i, j] where j < i.
// "For each k from 0 to r*c-1 (or r*(r+1)/2 -1 if triangular),
//  let v_k be the vector ( (A_0)_k, (A_1)_k, ..., (A_m-1)_k ).
//  The output is EncodeBitslicedVector(v_0) || EncodeBitslicedVector(v_1) || ..."
// Here, (A_i)_k refers to the k-th element of matrix A_i when read in row-major order
// (or row-major upper-triangular order).
// The length of each v_k will be m (the number of matrices).
// m must be a multiple of 8 due to encode_bitsliced_vector's current constraint.
pub fn encode_bitsliced_matrices(
    matrices: &[Matrix], // Sequence of m matrices {A_i}
    r: usize,            // Rows of each matrix A_i
    c: usize,            // Cols of each matrix A_i
    is_triangular: bool,
) -> Result<Vec<u8>, String> {
    if matrices.is_empty() {
        return Ok(Vec::new());
    }

    let m = matrices.len(); // Number of matrices in the sequence
    if m % 8 != 0 {
        return Err(format!(
            "Number of matrices m ({}) must be a multiple of 8 for bitsliced encoding.", m
        ));
    }

    for (idx, a_i) in matrices.iter().enumerate() {
        if a_i.rows() != r || a_i.cols() != c {
            return Err(format!(
                "Matrix {} has incorrect dimensions: expected {}x{}, got {}x{}",
                idx, r, c, a_i.rows(), a_i.cols()
            ));
        }
        if is_triangular && r != c {
            return Err("Triangular matrices must be square.".to_string());
        }
    }

    let num_elements_per_matrix = if is_triangular {
        r * (r + 1) / 2
    } else {
        r * c
    };

    let mut output_bytes = Vec::new();
    let mut v_k = Vec::with_capacity(m); // To store ( (A_0)_k, ..., (A_m-1)_k )

    for k_elem_idx in 0..num_elements_per_matrix {
        v_k.clear(); // Reset for the next v_k

        // Determine which (row, col) this k_elem_idx corresponds to
        let mut current_row = 0;
        let mut current_col = 0;
        if is_triangular {
            let mut current_k = 0;
            let mut found = false;
            for i_row in 0..r {
                for j_col in i_row..c { // Only upper triangle, j_col >= i_row
                    if current_k == k_elem_idx {
                        current_row = i_row;
                        current_col = j_col;
                        found = true;
                        break;
                    }
                    current_k += 1;
                }
                if found { break; }
            }
            if !found { // Should not happen if k_elem_idx is in range
                 return Err("Internal error: k_elem_idx out of bounds for triangular matrix".to_string());
            }
        } else {
            current_row = k_elem_idx / c;
            current_col = k_elem_idx % c;
        }

        // Construct v_k = ( (A_0)[current_row, current_col], ..., (A_m-1)[current_row, current_col] )
        for a_i in matrices.iter() {
            match a_i.get(current_row, current_col) {
                Some(f16_val) => v_k.push(f16_val),
                None => return Err(format!("Element access error at matrix {} for k_elem_idx {}", matrices.len(), k_elem_idx)), // Should not happen
            }
        }

        let encoded_v_k = encode_bitsliced_vector(&v_k)?;
        output_bytes.extend_from_slice(&encoded_v_k);
    }

    Ok(output_bytes)
}

pub fn encode_p1(p1_matrices: &[Matrix]) -> Result<Vec<u8>, String> {
    if p1_matrices.len() != params::M_PARAM {
        return Err(format!("Expected {} P1 matrices, got {}", params::M_PARAM, p1_matrices.len()));
    }
    encode_bitsliced_matrices(
        p1_matrices,
        params::P1_MAT_ROWS,
        params::P1_MAT_COLS,
        params::P1_IS_TRIANGULAR,
    )
}

pub fn encode_p2(p2_matrices: &[Matrix]) -> Result<Vec<u8>, String> {
    if p2_matrices.len() != params::M_PARAM {
        return Err(format!("Expected {} P2 matrices, got {}", params::M_PARAM, p2_matrices.len()));
    }
    encode_bitsliced_matrices(
        p2_matrices,
        params::P2_MAT_ROWS,
        params::P2_MAT_COLS,
        params::P2_IS_TRIANGULAR,
    )
}

pub fn encode_p3(p3_matrices: &[Matrix]) -> Result<Vec<u8>, String> {
     if p3_matrices.len() != params::M_PARAM {
        return Err(format!("Expected {} P3 matrices, got {}", params::M_PARAM, p3_matrices.len()));
    }
    encode_bitsliced_matrices(
        p3_matrices,
        params::P3_MAT_ROWS,
        params::P3_MAT_COLS,
        params::P3_IS_TRIANGULAR,
    )
}

pub fn encode_l(l_matrices: &[Matrix]) -> Result<Vec<u8>, String> {
    if l_matrices.len() != params::M_PARAM {
        return Err(format!("Expected {} L matrices, got {}", params::M_PARAM, l_matrices.len()));
    }
    // L matrices have same structure as P2 matrices for encoding purposes
    encode_bitsliced_matrices(
        l_matrices,
        params::L_MAT_ROWS,
        params::L_MAT_COLS,
        params::L_IS_TRIANGULAR,
    )
}

// Placeholder for Decode functions (to be implemented later if needed by other algorithms)
// pub fn decode_p1(bytes: &[u8]) -> Result<Vec<Matrix>, String> { Err("Not implemented".to_string()) }
// pub fn decode_p2(bytes: &[u8]) -> Result<Vec<Matrix>, String> { Err("Not implemented".to_string()) }
// pub fn decode_p3(bytes: &[u8]) -> Result<Vec<Matrix>, String> { Err("Not implemented".to_string()) }
// pub fn decode_l(bytes: &[u8]) -> Result<Vec<Matrix>, String> { Err("Not implemented".to_string()) }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::f16::F16;
    use crate::matrix::Matrix; // Ensure this is imported in tests module
    use crate::params; // Ensure this is imported in tests module

    fn f16v(vals: &[u8]) -> Vec<F16> {
        vals.iter().map(|&x| F16::new(x)).collect()
    }

    fn f16m(r: usize, c: usize, vals: &[u8]) -> Matrix {
        Matrix::new(r, c, vals.iter().map(|&x| F16::new(x)).collect()).unwrap()
    }

    // Helper to create a sequence of M_PARAM identical matrices for testing wrappers
    fn create_test_matrix_sequence(rows: usize, cols: usize, val_pattern: u8) -> Vec<Matrix> {
        let mut matrices = Vec::new();
        for i in 0..params::M_PARAM {
            // Create somewhat unique elements for each matrix in sequence to avoid trivial v_k
            let mut elements = Vec::with_capacity(rows*cols);
            for r_idx in 0..rows {
                for c_idx in 0..cols {
                    elements.push(F16::new( (val_pattern + i as u8 + r_idx as u8 + c_idx as u8) & 0xF ));
                }
            }
            matrices.push(Matrix::new(rows, cols, elements).unwrap());
        }
        matrices
    }

    #[test]
    fn test_encode_bitsliced_vector_empty() {
        assert_eq!(encode_bitsliced_vector(&[]).unwrap(), Vec::new());
    }

    #[test]
    fn test_encode_bitsliced_vector_m_not_multiple_of_8() {
        let v = f16v(&[1,2,3,4,5,6,7]);
        assert!(encode_bitsliced_vector(&v).is_err());
    }

    #[test]
    fn test_encode_bitsliced_vector_m8() {
        // m = 8. Output size = 8/2 = 4 bytes.
        // v = [1,0,0,0, 0,0,0,0] -> F16(1), F16(0)...
        // F16(1) is 0001_binary. Others are 0000_binary.
        let v = f16v(&[1, 0, 0, 0, 0, 0, 0, 0]);
        // Expected output:
        // Bit plane 0 (LSB):
        //   v[0].bit0=1, v[1].bit0=0, ..., v[7].bit0=0.  Byte 0 = 00000001_2 = 0x01
        // Bit plane 1:
        //   v[0].bit1=0, ..., v[7].bit1=0.              Byte 1 = 00000000_2 = 0x00
        // Bit plane 2:
        //   v[0].bit2=0, ..., v[7].bit2=0.              Byte 2 = 00000000_2 = 0x00
        // Bit plane 3 (MSB):
        //   v[0].bit3=0, ..., v[7].bit3=0.              Byte 3 = 00000000_2 = 0x00
        let expected = vec![0x01, 0x00, 0x00, 0x00];
        assert_eq!(encode_bitsliced_vector(&v).unwrap(), expected);

        // v = [0,0,0,0, 0,0,0, F16(0x8)] (0x8 is 1000_binary)
        let v2 = f16v(&[0,0,0,0,0,0,0, 0x8]);
        // Expected output:
        // Bit plane 0 (LSB): v2[7].bit0=0. Byte 0 = 0x00
        // Bit plane 1:       v2[7].bit1=0. Byte 1 = 0x00
        // Bit plane 2:       v2[7].bit2=0. Byte 2 = 0x00
        // Bit plane 3 (MSB): v2[7].bit3=1. Byte 3 = 10000000_2 = 0x80
        let expected2 = vec![0x00, 0x00, 0x00, 0x80];
        assert_eq!(encode_bitsliced_vector(&v2).unwrap(), expected2);

        // v = [F16(0xF), F16(0xF), ..., F16(0xF)] (all 1s: 1111_binary)
        let v3 = f16v(&[0xF,0xF,0xF,0xF,0xF,0xF,0xF,0xF]);
        // Expected: all bytes should be 0xFF
        let expected3 = vec![0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(encode_bitsliced_vector(&v3).unwrap(), expected3);
    }

    #[test]
    fn test_encode_bitsliced_vector_m16() {
        // m = 16. Output size = 16/2 = 8 bytes.
        // bytes_per_bit_plane = 16/8 = 2.
        // v = [F16(1), 0, ..., 0, F16(2), 0, ..., 0 ] (F16(1) at v[0], F16(2) at v[8])
        // F16(1) = 0001_b. F16(2) = 0010_b.
        let mut elems = vec![0u8; 16];
        elems[0] = 1;  // v[0] = F16(1)
        elems[8] = 2;  // v[8] = F16(2)
        let v = f16v(&elems);

        // Expected output:
        // Bit plane 0 (LSB of F16 elements):
        //   v[0].bit0=1, v[1-7].bit0=0.                  Byte 0 = 00000001_2 = 0x01
        //   v[8].bit0=0, v[9-15].bit0=0.                 Byte 1 = 00000000_2 = 0x00
        // Bit plane 1:
        //   v[0].bit1=0, v[1-7].bit1=0.                  Byte 2 (0 + bytes_per_bit_plane*1) = 0x00
        //   v[8].bit1=1, v[9-15].bit1=0.                 Byte 3 (1 + bytes_per_bit_plane*1) = 00000001_2 = 0x01
        // Bit plane 2:
        //   v[0].bit2=0, v[1-7].bit2=0.                  Byte 4 = 0x00
        //   v[8].bit2=0, v[9-15].bit2=0.                 Byte 5 = 0x00
        // Bit plane 3 (MSB):
        //   v[0].bit3=0, v[1-7].bit3=0.                  Byte 6 = 0x00
        //   v[8].bit3=0, v[9-15].bit3=0.                 Byte 7 = 0x00
        let expected = vec![
            0x01, 0x00, // bit plane 0
            0x00, 0x01, // bit plane 1
            0x00, 0x00, // bit plane 2
            0x00, 0x00, // bit plane 3
        ];
        assert_eq!(encode_bitsliced_vector(&v).unwrap(), expected);
    }

    #[test]
    fn test_encode_bitsliced_matrices_empty() {
        let matrices: Vec<Matrix> = Vec::new();
        assert_eq!(encode_bitsliced_matrices(&matrices, 2, 2, false).unwrap(), Vec::new());
    }

    #[test]
    fn test_encode_bitsliced_matrices_m_not_multiple_of_8() {
        let matrices = vec![f16m(1,1,&[1])]; // m=1
        assert!(encode_bitsliced_matrices(&matrices, 1, 1, false).is_err());
    }

    #[test]
    fn test_encode_bitsliced_matrices_r1_c1_m8_nontri() {
        // 8 matrices, each 1x1. is_triangular = false.
        // num_elements_per_matrix = 1*1 = 1. So only one v_k (v_0).
        // v_0 = ( (A0)_0, (A1)_0, ..., (A7)_0 )
        // Let A0=[1], A1=[0], ..., A7=[0]. So v_0 = [F16(1), 0, ..., 0]
        let mut matrices = Vec::new();
        matrices.push(f16m(1,1,&[1]));
        for _ in 0..7 { matrices.push(f16m(1,1,&[0])); }

        // v_0 = [F16(1), F16(0), ..., F16(0)] (length 8)
        // encode_bitsliced_vector(v_0) should be [0x01, 0x00, 0x00, 0x00] (from previous test)
        let expected_output = vec![0x01, 0x00, 0x00, 0x00];
        assert_eq!(encode_bitsliced_matrices(&matrices, 1, 1, false).unwrap(), expected_output);

        // Let A0=[0], ..., A7=[F16(0x8)]
        let mut matrices2 = Vec::new();
        for _ in 0..7 { matrices2.push(f16m(1,1,&[0])); }
        matrices2.push(f16m(1,1,&[0x8]));
        // v_0 = [0, ..., 0, F16(0x8)]
        // encode_bitsliced_vector(v_0) should be [0x00, 0x00, 0x00, 0x80]
        let expected_output2 = vec![0x00, 0x00, 0x00, 0x80];
        assert_eq!(encode_bitsliced_matrices(&matrices2, 1, 1, false).unwrap(), expected_output2);
    }

    #[test]
    fn test_encode_bitsliced_matrices_r2_c1_m8_nontri() {
        // 8 matrices, each 2x1. is_triangular = false.
        // num_elements_per_matrix = 2*1 = 2. So v_0, v_1.
        // A_i = [[a_i0], [a_i1]]
        // v_0 = ( (A0)_0=(a00), (A1)_0=(a10), ..., (A7)_0=(a70) )
        // v_1 = ( (A0)_1=(a01), (A1)_1=(a11), ..., (A7)_1=(a71) )
        // Output = encode_bitsliced_vector(v_0) || encode_bitsliced_vector(v_1)

        // Let A0 = [[1],[0]], A1..A7 = [[0],[0]]
        let mut matrices = Vec::new();
        matrices.push(f16m(2,1,&[1,0])); // A0
        for _ in 0..7 { matrices.push(f16m(2,1,&[0,0])); } // A1-A7

        // v_0 = [F16(1), 0,0,0,0,0,0,0] -> encodes to [0x01,0,0,0]
        // v_1 = [F16(0), 0,0,0,0,0,0,0] -> encodes to [0x00,0,0,0]
        let encoded_v0 = vec![0x01,0,0,0];
        let encoded_v1 = vec![0x00,0,0,0];
        let mut expected_output = Vec::new();
        expected_output.extend(encoded_v0);
        expected_output.extend(encoded_v1);

        assert_eq!(encode_bitsliced_matrices(&matrices, 2, 1, false).unwrap(), expected_output);
    }

    #[test]
    fn test_encode_bitsliced_matrices_r2_c2_m8_tri() {
        // 8 matrices, each 2x2, upper triangular.
        // r=2, c=2. num_elements_per_matrix = r*(r+1)/2 = 2*3/2 = 3.
        // Elements are (0,0), (0,1), (1,1) in row-major for upper triangle.
        // A_i = [[ (A_i)_00, (A_i)_01 ], [ ignored, (A_i)_11 ]]
        // v_0 (for element (0,0)): ( (A0)_00, ..., (A7)_00 )
        // v_1 (for element (0,1)): ( (A0)_01, ..., (A7)_01 )
        // v_2 (for element (1,1)): ( (A0)_11, ..., (A7)_11 )
        // Output = enc(v_0) || enc(v_1) || enc(v_2)

        // Let A0 = [[1,2],[?,3]], others are [[0,0],[?,0]]
        // (A0)_00=1, (A0)_01=2, (A0)_11=3
        let mut matrices = Vec::new();
        matrices.push(f16m(2,2,&[1,2, 99,3])); // 99 is ignored placeholder for lower triangle
        for _ in 0..7 { matrices.push(f16m(2,2,&[0,0, 99,0])); }

        // v_0 (for (0,0)): [F16(1), 0,...0] -> enc_v0 = [0x01,0,0,0]
        // v_1 (for (0,1)): [F16(2), 0,...0] -> enc_v1 = (F16(2)=0010_b) -> [0x00,0x01,0,0] (bit1 plane has 1)
        // v_2 (for (1,1)): [F16(3), 0,...0] -> enc_v2 = (F16(3)=0011_b) -> [0x01,0x01,0,0] (bit0 and bit1 planes have 1)

        let enc_v0 = vec![0x01,0x00,0x00,0x00]; // F16(1) at first pos
        let enc_v1 = vec![0x00,0x01,0x00,0x00]; // F16(2) at first pos
        let enc_v2 = vec![0x01,0x01,0x00,0x00]; // F16(3) at first pos

        let mut expected_output = Vec::new();
        expected_output.extend(enc_v0);
        expected_output.extend(enc_v1);
        expected_output.extend(enc_v2);

        assert_eq!(encode_bitsliced_matrices(&matrices, 2, 2, true).unwrap(), expected_output);
    }

    #[test]
    fn test_encode_p1_wrapper() {
        let p1_mats = create_test_matrix_sequence(params::P1_MAT_ROWS, params::P1_MAT_COLS, 1);
        let result = encode_p1(&p1_mats);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.len(), params::P1_BYTES);

        // Test wrong number of matrices
        let mut wrong_p1_mats = p1_mats.clone();
        wrong_p1_mats.pop();
        assert!(encode_p1(&wrong_p1_mats).is_err());
    }

    #[test]
    fn test_encode_p2_wrapper() {
        let p2_mats = create_test_matrix_sequence(params::P2_MAT_ROWS, params::P2_MAT_COLS, 2);
        let result = encode_p2(&p2_mats);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.len(), params::P2_BYTES);
    }

    #[test]
    fn test_encode_p3_wrapper() {
        let p3_mats = create_test_matrix_sequence(params::P3_MAT_ROWS, params::P3_MAT_COLS, 3);
        let result = encode_p3(&p3_mats);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.len(), params::P3_BYTES);
    }

    #[test]
    fn test_encode_l_wrapper() {
        let l_mats = create_test_matrix_sequence(params::L_MAT_ROWS, params::L_MAT_COLS, 4);
        let result = encode_l(&l_mats);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes.len(), params::L_BYTES);
    }
}
