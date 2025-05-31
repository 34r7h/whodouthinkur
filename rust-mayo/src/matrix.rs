// rust-mayo/src/matrix.rs
use crate::f16::F16;
use crate::vector::Vector; // For EncodeO/DecodeO
use std::ops::Add;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matrix {
    elements: Vec<F16>, // Stored in row-major order
    rows: usize,
    cols: usize,
}

impl Matrix {
    // Creates a new matrix from a Vec<F16> in row-major order, and dimensions
    pub fn new(rows: usize, cols: usize, elements: Vec<F16>) -> Result<Self, String> {
        if rows * cols != elements.len() {
            return Err(format!(
                "Invalid dimensions: {}x{} does not match element count {}",
                rows, cols, elements.len()
            ));
        }
        Ok(Matrix { elements, rows, cols })
    }

    // Creates a new zero matrix of given dimensions
    pub fn zero(rows: usize, cols: usize) -> Self {
        Matrix {
            elements: vec![F16::new(0); rows * cols],
            rows,
            cols,
        }
    }

    // Creates an identity matrix of size n x n
    pub fn identity(n: usize) -> Self {
        let mut elements = vec![F16::new(0); n * n];
        for i in 0..n {
            elements[i * n + i] = F16::new(1);
        }
        Matrix { elements, rows: n, cols: n }
    }

    pub fn rows(&self) -> usize { self.rows }
    pub fn cols(&self) -> usize { self.cols }

    // Gets an element at (row, col)
    pub fn get(&self, row: usize, col: usize) -> Option<F16> {
        if row < self.rows && col < self.cols {
            Some(self.elements[row * self.cols + col])
        } else {
            None
        }
    }

    // Sets an element at (row, col)
    pub fn set(&mut self, row: usize, col: usize, value: F16) -> Result<(), String> {
        if row < self.rows && col < self.cols {
            self.elements[row * self.cols + col] = value;
            Ok(())
        } else {
            Err(format!("Set out of bounds: ({}, {}) for {}x{} matrix", row, col, self.rows, self.cols))
        }
    }

    // Gets a specific row as a Vector
    pub fn get_row_vec(&self, row_idx: usize) -> Option<Vector> {
        if row_idx < self.rows {
            let start = row_idx * self.cols;
            let end = start + self.cols;
            Some(Vector::new(self.elements[start..end].to_vec()))
        } else {
            None
        }
    }

    // Transpose of the matrix
    pub fn transpose(&self) -> Self {
        let mut new_elements = vec![F16::new(0); self.rows * self.cols];
        for r in 0..self.rows {
            for c in 0..self.cols {
                new_elements[c * self.rows + r] = self.elements[r * self.cols + c];
            }
        }
        Matrix {
            elements: new_elements,
            rows: self.cols, // Swapped
            cols: self.rows, // Swapped
        }
    }

    // Upper(M): For a square matrix M, outputs an upper triangular matrix.
    // Upper(M)[i, i] = M[i, i]
    // Upper(M)[i, j] = M[i, j] + M[j, i] for 0 <= i < j < n
    pub fn upper(&self) -> Result<Self, String> {
        if self.rows != self.cols {
            return Err("Upper function requires a square matrix".to_string());
        }
        let n = self.rows;
        let mut upper_matrix = self.clone(); // Start with a copy

        for i in 0..n {
            for j in 0..n {
                if i == j {
                    // upper_matrix.elements[i * n + i] = self.elements[i * n + i]; // Already there from clone
                } else if i < j {
                    upper_matrix.elements[i * n + j] = self.elements[i * n + j] + self.elements[j * n + i];
                } else { // j < i (lower triangle)
                    upper_matrix.elements[i * n + j] = F16::new(0); // Zero out lower triangle
                }
            }
        }
        Ok(upper_matrix)
    }

    // Encodes an (n-o) x o matrix O in row-major order by encoding its concatenated rows as a vector.
    // Note: The spec implies using the vector encoding logic (nibbles packed into bytes).
    pub fn encode_o(&self) -> Vec<u8> {
        // Concatenate all elements into a single Vec<F16> and then use Vector's encoding.
        // This is equivalent to encoding a single long vector.
        let flat_vector = Vector::new(self.elements.clone());
        flat_vector.encode_vec()
    }

    // Decodes a byte string into an (rows) x (cols) matrix O.
    // This is the inverse of EncodeO.
    pub fn decode_o(rows: usize, cols: usize, byte_string: &[u8]) -> Result<Self, String> {
        let num_elements = rows * cols;
        let decoded_vector = Vector::decode_vec(num_elements, byte_string)?;
        Ok(Matrix {
            elements: decoded_vector.elements().to_vec(),
            rows,
            cols,
        })
    }
}

// Matrix Addition
impl Add for &Matrix {
    type Output = Result<Matrix, String>;

    fn add(self, rhs: Self) -> Self::Output {
        if self.rows != rhs.rows || self.cols != rhs.cols {
            return Err("Matrix addition requires matrices of the same dimensions".to_string());
        }
        let mut result_elements = Vec::with_capacity(self.elements.len());
        for i in 0..self.elements.len() {
            result_elements.push(self.elements[i] + rhs.elements[i]);
        }
        Ok(Matrix {
            elements: result_elements,
            rows: self.rows,
            cols: self.cols,
        })
    }
}

// Matrix Multiplication
// C[i,j] = sum_k A[i,k] * B[k,j]
impl std::ops::Mul for &Matrix {
    type Output = Result<Matrix, String>;

    fn mul(self, rhs: Self) -> Self::Output {
        if self.cols != rhs.rows {
            return Err(format!(
                "Matrix multiplication error: LHS cols ({}) must equal RHS rows ({})",
                self.cols, rhs.rows
            ));
        }

        let new_rows = self.rows;
        let new_cols = rhs.cols;
        let mut result_matrix = Matrix::zero(new_rows, new_cols);

        for r in 0..new_rows {      // Iterate over rows of the result matrix (and LHS)
            for c in 0..new_cols {  // Iterate over columns of the result matrix (and RHS)
                let mut sum = F16::new(0);
                for k in 0..self.cols { // Iterate over cols of LHS / rows of RHS
                    sum = sum + (self.get(r, k).unwrap() * rhs.get(k, c).unwrap());
                }
                result_matrix.set(r, c, sum).unwrap(); // Should not fail due to Zero init
            }
        }
        Ok(result_matrix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::f16::F16;

    fn f16m(r: usize, c: usize, vals: &[u8]) -> Matrix {
        Matrix::new(r, c, vals.iter().map(|&x| F16::new(x)).collect()).unwrap()
    }

    #[test]
    fn test_matrix_new_and_get() {
        let m = f16m(2, 2, &[1, 2, 3, 4]);
        assert_eq!(m.rows(), 2);
        assert_eq!(m.cols(), 2);
        assert_eq!(m.get(0, 0), Some(F16::new(1)));
        assert_eq!(m.get(1, 1), Some(F16::new(4)));
        assert_eq!(m.get(2, 0), None);
    }

    #[test]
    fn test_matrix_set() {
        let mut m = Matrix::zero(2,2);
        m.set(0,1, F16::new(5)).unwrap();
        assert_eq!(m.get(0,1), Some(F16::new(5)));
    }

    #[test]
    #[should_panic] // This test is designed to panic because Matrix::new returns a Result
                    // and .unwrap() is called on an Err case.
    fn test_matrix_new_panic() {
        // The original test was Matrix::new(2, 2, vec![F16::new(1)]).unwrap();
        // To make it more robust for testing tools, let's check the error type
        let result = Matrix::new(2, 2, vec![F16::new(1)]);
        assert!(result.is_err());
        if let Err(e) = result {
             assert_eq!(e, "Invalid dimensions: 2x2 does not match element count 1");
        } else {
            panic!("Expected an error but got Ok");
        }
        // To satisfy should_panic, we still need to cause a panic if the assertion fails.
        // Or, we can make the original code that would panic:
        Matrix::new(2,2, vec![F16::new(1)]).unwrap();

    }

    #[test]
    fn test_matrix_identity() {
        let id2 = Matrix::identity(2);
        assert_eq!(id2, f16m(2,2, &[1,0,0,1]));
        let m = f16m(2,2, &[1,2,3,4]);
        assert_eq!((&m * &id2).unwrap(), m);
        assert_eq!((&id2 * &m).unwrap(), m);
    }

    #[test]
    fn test_matrix_transpose() {
        let m1 = f16m(2, 3, &[1, 2, 3, 4, 5, 6]);
        // 1 2 3
        // 4 5 6
        let m1_t = f16m(3, 2, &[1, 4, 2, 5, 3, 6]);
        // 1 4
        // 2 5
        // 3 6
        assert_eq!(m1.transpose(), m1_t);
    }

    #[test]
    fn test_matrix_add() {
        let m1 = f16m(2, 2, &[1, 2, 3, 4]);
        let m2 = f16m(2, 2, &[5, 6, 7, 8]);
        let expected = f16m(2, 2, &[1^5, 2^6, 3^7, 4^8]);
        assert_eq!((&m1 + &m2).unwrap(), expected);
    }

    #[test]
    fn test_matrix_add_fail() {
        let m1 = f16m(2, 2, &[1,2,3,4]);
        let m2 = f16m(2, 3, &[1,2,3,4,5,6]);
        assert!((&m1 + &m2).is_err());
    }

    #[test]
    fn test_matrix_mul() {
        // M1 = [[1,2],[3,4]] (x values: x^0, x, x+x^0, x^2)
        // M2 = [[2,0],[1,2]] (x values: x, 0, x^0, x)
        let m1 = f16m(2,2, &[1,2,3,4]); // [[F16(1), F16(2)], [F16(3), F16(4)]]
        let m2 = f16m(2,2, &[2,0,1,2]); // [[F16(2), F16(0)], [F16(1), F16(2)]]
        // Expected:
        // C[0,0] = (1*2) + (2*1) = F16(2) + F16(2) = F16(0)
        // C[0,1] = (1*0) + (2*2) = F16(0) + F16(4) = F16(4) (x^2)
        // C[1,0] = (3*2) + (4*1) = F16(3)*F16(2) + F16(4) = F16(6) + F16(4) = F16(2) (x^2+x + x^2 = x)
        // C[1,1] = (3*0) + (4*2) = F16(0) + F16(4)*F16(2) = F16(x^2)*F16(x) = F16(x^3) = F16(8)
        let expected = f16m(2,2, &[0, 4, 2, 8]);
        assert_eq!((&m1 * &m2).unwrap(), expected);
    }

    #[test]
    fn test_matrix_mul_fail() {
        let m1 = f16m(2,3, &[1,2,3,4,5,6]);
        let m2 = f16m(2,2, &[1,2,3,4]);
        assert!((&m1 * &m2).is_err());
    }

    #[test]
    fn test_matrix_upper() {
        // M = [[1,2,3],
        //      [4,5,6],
        //      [7,8,9]]
        let m = f16m(3,3, &[1,2,3, 4,5,6, 7,8,9]);
        // Upper(M)[0,0] = 1
        // Upper(M)[0,1] = M[0,1]+M[1,0] = 2+4 = 6
        // Upper(M)[0,2] = M[0,2]+M[2,0] = 3+7 = 4
        // Upper(M)[1,1] = 5
        // Upper(M)[1,2] = M[1,2]+M[2,1] = 6+8 = 14
        // Upper(M)[2,2] = 9
        // Result: [[1, 6, 4],
        //           [0, 5, 14],
        //           [0, 0, 9]]
        let expected = f16m(3,3, &[1, F16::new(2^4).value(), F16::new(3^7).value(),  0, 5, F16::new(6^8).value(),  0,0,9]);
        assert_eq!(m.upper().unwrap(), expected);
    }

    #[test]
    fn test_matrix_upper_fail_non_square() {
        let m = f16m(2,3, &[1,2,3,4,5,6]);
        assert!(m.upper().is_err());
    }

    #[test]
    fn test_encode_decode_o_matrix() {
        // (n-o) x o matrix, e.g. 2x3 matrix
        let rows = 2;
        let cols = 3;
        let m = f16m(rows, cols, &[1,2,3, 10,11,12]); // elements are F16 values
        // Expected elements: [F16(1), F16(2), F16(3), F16(10), F16(11), F16(12)]
        // Nibbles: 0x1, 0x2, 0x3, 0xA, 0xB, 0xC
        // Bytes:
        // Byte 0: 0x1 | (0x2 << 4) = 0x21
        // Byte 1: 0x3 | (0xA << 4) = 0xA3
        // Byte 2: 0xB | (0xC << 4) = 0xCB
        let encoded = m.encode_o();
        assert_eq!(encoded, vec![0x21, 0xA3, 0xCB]);

        let decoded = Matrix::decode_o(rows, cols, &encoded).unwrap();
        assert_eq!(m, decoded);
    }

    #[test]
    fn test_encode_decode_o_matrix_odd_elements() {
        // e.g. 1x3 matrix
        let rows = 1;
        let cols = 3;
        let m = f16m(rows, cols, &[5,7,9]);
        // Nibbles: 0x5, 0x7, 0x9
        // Bytes:
        // Byte 0: 0x5 | (0x7 << 4) = 0x75
        // Byte 1: 0x9 | (0x0 << 4) = 0x09 (padded)
        let encoded = m.encode_o();
        assert_eq!(encoded, vec![0x75, 0x09]);

        let decoded = Matrix::decode_o(rows, cols, &encoded).unwrap();
        assert_eq!(m, decoded);
    }
}
