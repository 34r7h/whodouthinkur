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

    // Matrix-vector multiplication: result_vec = self * vector
    pub fn multiply_vector(&self, vector: &Vector) -> Result<Vector, String> {
        if self.cols != vector.len() {
            return Err(format!(
                "Matrix-vector multiplication error: Matrix cols ({}) must equal vector length ({}).",
                self.cols, vector.len()
            ));
        }
        let mut result_elements = Vec::with_capacity(self.rows);
        for r in 0..self.rows {
            let mut sum = F16::new(0);
            for c in 0..self.cols {
                // self.get(r,c) and vector.get(c) should not panic due to checks and loop bounds
                sum = sum + (self.get(r, c).unwrap() * vector.get(c).unwrap());
            }
            result_elements.push(sum);
        }
        Ok(Vector::new(result_elements))
    }

    // Public method for scalar multiplication
    pub fn multiply_scalar(&self, scalar: F16) -> Matrix {
        let mut new_elements = Vec::with_capacity(self.elements.len());
        for &elem in self.elements.iter() {
            new_elements.push(elem * scalar);
        }
        Matrix {
            elements: new_elements,
            rows: self.rows,
            cols: self.cols,
        }
    }

    // Helper: Swaps two rows in the matrix
    fn swap_rows(&mut self, r1: usize, r2: usize) {
        if r1 < self.rows && r2 < self.rows && r1 != r2 {
            for c in 0..self.cols {
                self.elements.swap(r1 * self.cols + c, r2 * self.cols + c);
            }
        }
    }

    // Helper: Multiplies a row by a scalar
    fn multiply_row_by_scalar(&mut self, row_idx: usize, scalar: F16) {
        if row_idx < self.rows {
            for c in 0..self.cols {
                let current_val = self.elements[row_idx * self.cols + c];
                self.elements[row_idx * self.cols + c] = current_val * scalar;
            }
        }
    }

    // Helper: Adds scalar * source_row to target_row
    // In GF(16), addition and subtraction are XOR. So row[target] += scalar * row[source]
    // is row[target] = row[target] + scalar * row[source]
    fn add_multiple_of_row_to_another(&mut self, target_row_idx: usize, source_row_idx: usize, scalar: F16) {
        if target_row_idx < self.rows && source_row_idx < self.rows {
            for c in 0..self.cols {
                let val_to_add = self.elements[source_row_idx * self.cols + c] * scalar;
                self.elements[target_row_idx * self.cols + c] = self.elements[target_row_idx * self.cols + c] + val_to_add;
            }
        }
    }

    // Transforms the augmented matrix [self | rhs_vector] into row echelon form.
    // Modifies self (the matrix A) and rhs_vector (the vector y) in place.
    // Returns the rank of the matrix.
    // This is a key part of solving Ax = y.
    pub fn transform_to_row_echelon_augmented(&mut self, rhs_vector: &mut Vector) -> Result<usize, String> {
        if self.rows != rhs_vector.len() {
            return Err("Matrix rows must match rhs_vector length for augmented system.".to_string());
        }

        let mut pivot_row = 0;
        let mut rank = 0;

        for j in 0..self.cols { // Current column to find pivot in
            if pivot_row >= self.rows {
                break; // No more rows to pivot
            }

            // Find a row with a non-zero pivot in column j, starting from pivot_row
            let mut i = pivot_row;
            while i < self.rows && self.get(i, j).unwrap() == F16::new(0) {
                i += 1;
            }

            if i < self.rows { // Found a non-zero pivot at (i, j)
                // Swap row i with pivot_row to bring pivot to (pivot_row, j)
                if i != pivot_row {
                    self.swap_rows(i, pivot_row);
                    rhs_vector.elements.swap(i, pivot_row); // Keep rhs_vector consistent
                }

                // Normalize pivot row: make pivot element self.get(pivot_row, j) equal to 1
                let pivot_val = self.get(pivot_row, j).unwrap();
                if let Some(inv_pivot) = pivot_val.inverse() {
                    self.multiply_row_by_scalar(pivot_row, inv_pivot);
                    // rhs_vector.elements is not public, so we need a method in Vector or direct access if in same module.
                    // Assuming Vector elements can be accessed and modified like this for now.
                    // If Vector::elements is private, rhs_vector.multiply_element(pivot_row, inv_pivot) would be needed.
                    let old_rhs_val = rhs_vector.get(pivot_row).unwrap(); // Assuming Vector::get() exists
                    rhs_vector.elements[pivot_row] = old_rhs_val * inv_pivot;


                } else {
                    // Should not happen if pivot_val was non-zero, but good for robustness
                    return Err(format!("Pivot element {} at ({},{}) has no inverse.", pivot_val.value(), pivot_row, j));
                }

                // Eliminate other rows: for every other row k != pivot_row,
                // make self.get(k, j) zero by row_k = row_k - self.get(k,j) * row_pivot_row
                for k in 0..self.rows {
                    if k != pivot_row {
                        let factor = self.get(k, j).unwrap();
                        if factor != F16::new(0) { // Only if there's something to eliminate
                            self.add_multiple_of_row_to_another(k, pivot_row, factor);
                            // rhs_vector.elements[k] = rhs_vector.elements[k] + (factor * rhs_vector.elements[pivot_row]);
                            // Need to use .get() for rhs_vector as well, if elements is private
                            let val_to_add_to_rhs = factor * rhs_vector.get(pivot_row).unwrap();
                            let current_rhs_k = rhs_vector.get(k).unwrap();
                            rhs_vector.elements[k] = current_rhs_k + val_to_add_to_rhs;
                        }
                    }
                }
                rank += 1;
                pivot_row += 1;
            }
        }
        Ok(rank)
    }

    // Solves for x in Ax = y, assuming A (self) is already in row echelon form
    // and y (rhs_vector) has been transformed accordingly.
    // Returns a particular solution vector x.
    // Assumes that the system is consistent (checked by rank from REF transformation).
    // Free variables are set to 0 for this particular solution.
    pub fn solve_from_row_echelon(&self, rhs_vector: &Vector) -> Result<Vector, String> {
        if self.rows != rhs_vector.len() {
            return Err("Matrix rows must match rhs_vector length.".to_string());
        }

        let num_vars = self.cols;
        let mut solution = Vector::zero(num_vars);

        // Start from the last non-zero row (based on typical REF)
        // and go upwards. A more robust way is to iterate from self.rows - 1 down to 0.
        for i in (0..self.rows).rev() {
            // Find the pivot column for this row i (first non-zero element)
            let mut pivot_col: Option<usize> = None;
            for j in 0..self.cols {
                if self.get(i, j).unwrap() != F16::new(0) {
                    pivot_col = Some(j);
                    break;
                }
            }

            if let Some(pc) = pivot_col {
                // This row has a pivot.
                // The equation is: self[i, pc]*x[pc] + sum(self[i, k]*x[k] for k > pc) = rhs_vector[i]
                // Since self[i, pc] should be 1 after REF normalization:
                // x[pc] = rhs_vector[i] - sum(self[i, k]*x[k] for k > pc)
                let mut sum_known_terms = F16::new(0);
                for k in (pc + 1)..num_vars {
                    sum_known_terms = sum_known_terms + (self.get(i, k).unwrap() * solution.elements[k]);
                }

                // Assuming pivot element self.get(i,pc) is 1 after REF
                if self.get(i,pc).unwrap() != F16::new(1) {
                    // This case implies REF was not properly normalized or it's a zero row that
                    // should not be processed for a pivot.
                    // If it's a zero row in A but rhs_vector[i] is non-zero, it's inconsistent.
                    // This check should ideally be part of REF or before calling solve.
                    if rhs_vector.elements[i] != F16::new(0) {
                         return Err(format!("Inconsistent system: zero row in matrix for non-zero RHS at row {}.", i));
                    }
                    // If both are zero, this row is 0=0, continue (free variables might be involved implicitly)
                    continue;
                }

                solution.elements[pc] = rhs_vector.elements[i] + sum_known_terms; // Using + for - in GF(2^k)
            } else {
                // This is a zero row in the matrix A for row i.
                // If rhs_vector[i] is non-zero, the system is inconsistent.
                if rhs_vector.elements[i] != F16::new(0) {
                    return Err(format!("Inconsistent system: zero row in matrix for non-zero RHS at row {}.", i));
                }
                // If rhs_vector[i] is zero, it's a 0=0 equation, meaning this row
                // doesn't constrain variables further. Any variables not yet determined
                // (typically those without pivots in their columns) are free.
                // For a particular solution, we set them to 0, which is already done by Vector::zero.
            }
        }
        Ok(solution)
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
    use crate::vector::Vector; // Ensure Vector is imported for tests

    fn f16v(vals: &[u8]) -> Vec<F16> { // Local helper for tests
        vals.iter().map(|&x| F16::new(x)).collect()
    }

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

    #[test]
    fn test_matrix_vector_mul() {
        // M = [[1,2],[3,4]]
        // V = [2,1]
        let m = f16m(2,2, &[1,2,3,4]);
        let v = Vector::new(f16v(&[2,1])); // Use local helper
        // Expected:
        // R[0] = (1*2) + (2*1) = F16(2) + F16(2) = F16(0)
        // R[1] = (3*2) + (4*1) = F16(6) + F16(4) = F16(2)
        let expected = Vector::new(f16v(&[0,2])); // Use local helper
        assert_eq!(m.multiply_vector(&v).unwrap(), expected);
    }

    #[test]
    fn test_matrix_vector_mul_fail_dim() {
        let m = f16m(2,2, &[1,2,3,4]);
        let v = Vector::new(f16v(&[1,2,3])); // Incorrect length; Use local helper
        assert!(m.multiply_vector(&v).is_err());
    }

    #[test]
    fn test_matrix_scalar_mul() {
        let m = f16m(2,2, &[1,2,3,4]);
        let s = F16::new(2); // x
        // Expected:
        // 1*x = 2 (x)
        // 2*x = 4 (x^2)
        // 3*x = 6 (x+x^0)*x = x^2+x
        // 4*x = 8 (x^2)*x = x^3
        let expected = f16m(2,2, &[2,4,6,8]);
        assert_eq!(m.multiply_scalar(s), expected);
    }

    #[test]
    fn test_swap_rows_impl() {
        let mut m = f16m(2,2, &[1,2,3,4]);
        m.swap_rows(0,1);
        assert_eq!(m, f16m(2,2, &[3,4,1,2]));

        let mut m2 = f16m(3,2, &[1,2,3,4,5,6]);
        m2.swap_rows(0,2);
        assert_eq!(m2, f16m(3,2, &[5,6,3,4,1,2]));
        m2.swap_rows(0,0); // No change
        assert_eq!(m2, f16m(3,2, &[5,6,3,4,1,2]));
    }

    #[test]
    fn test_multiply_row_by_scalar_impl() {
        let mut m = f16m(2,2, &[1,2,3,4]);
        m.multiply_row_by_scalar(0, F16::new(2)); // Row 0 *= 2
        // 1*2=2, 2*2=4
        assert_eq!(m, f16m(2,2, &[2,4,3,4]));
    }

    #[test]
    fn test_add_multiple_of_row_to_another_impl() {
        let mut m = f16m(2,2, &[1,1,1,0]); // R0=[1,1], R1=[1,0]
        // R1 = R1 + 1*R0
        // R1[0] = 1 + 1*1 = 0
        // R1[1] = 0 + 1*1 = 1
        m.add_multiple_of_row_to_another(1,0,F16::new(1));
        assert_eq!(m, f16m(2,2, &[1,1,0,1]));
    }

    #[test]
    fn test_to_row_echelon_square_invertible() {
        let mut a = f16m(2,2, &[1,1,1,0]); // A = [[1,1],[1,0]]
        let mut y_elems = f16v(&[1,0]);
        let mut y = Vector::new(y_elems);
        // Expected REF of A: [[1,0],[0,1]] (identity)
        // System:
        // 1*x0 + 1*x1 = 1
        // 1*x0 + 0*x1 = 0
        // From second eq: x0 = 0.
        // Substitute into first: 0 + x1 = 1 => x1 = 1.
        // Solution: x0=0, x1=1.
        // After REF, system should be:
        // 1*x0 + 0*x1 = 0
        // 0*x0 + 1*x1 = 1
        // So transformed y should be [0,1]^T
        let rank = a.transform_to_row_echelon_augmented(&mut y).unwrap();
        assert_eq!(rank, 2);
        assert_eq!(a, Matrix::identity(2)); // A becomes I
        assert_eq!(y, Vector::new(f16v(&[0,1]))); // y becomes solution [0,1]
    }

    #[test]
    fn test_to_row_echelon_3x3() {
        // Example from a field other than GF(16) for simplicity of setup,
        // but logic is field-agnostic.
        // A = [[2,1,-1],[ -3,-1,2],[ -2,1,2]] y = [8, -11, -3]
        // REF A = [[1,0,0],[0,1,0],[0,0,1]] y_transformed = [2,3,-1] (Solution)
        // Using GF(16) values:
        // A = [[1,2,3],[2,3,1],[3,1,2]]
        // y = [1,2,3]
        let mut a = f16m(3,3, &[1,2,3, 2,3,1, 3,1,2]);
        let mut y = Vector::new(f16v(&[1,2,3]));

        let rank = a.transform_to_row_echelon_augmented(&mut y).unwrap();
        assert_eq!(rank, 3); // Expect full rank

        // Check if 'a' is identity (or whatever REF it should be)
        // This requires knowing the expected REF form and transformed y.
        // For a full rank square matrix, REF is Identity.
        // A * x = y  => I * x = A_inv * y
        // The y vector gets transformed to A_inv * y which is the solution x.
        assert_eq!(a, Matrix::identity(3));

        // To find the expected y, we need to solve the original system:
        // x0 + 2x1 + 3x2 = 1
        // 2x0 + 3x1 +  x2 = 2
        // 3x0 +  x1 + 2x2 = 3
        // (Calculations for GF(16) are non-trivial to do by hand here for expected y)
        // Let's use a known simple one:
        // A = [[1,1,0],[0,1,1],[1,0,1]] y = [1,1,0] -> x=[0,1,0] (expected y_transformed)
        let mut a2 = f16m(3,3, &[1,1,0, 0,1,1, 1,0,1]);
        let mut y2 = Vector::new(f16v(&[1,1,0]));
        let rank2 = a2.transform_to_row_echelon_augmented(&mut y2).unwrap();
        assert_eq!(rank2, 3);
        assert_eq!(a2, Matrix::identity(3));
        assert_eq!(y2, Vector::new(f16v(&[0,1,0])));
    }

    #[test]
    fn test_to_row_echelon_rank_deficient() {
        // A = [[1,1,1],[1,1,1],[0,0,1]] y = [1,1,0]
        // R1 = R1 - R0 => [[1,1,1],[0,0,0],[0,0,1]] y = [1,0,0]
        // Swap R1, R2 => [[1,1,1],[0,0,1],[0,0,0]] y = [1,0,0]
        // R0 = R0 - R1 => [[1,1,0],[0,0,1],[0,0,0]] y = [1,0,0]
        // Rank = 2
        let mut a = f16m(3,3, &[1,1,1, 1,1,1, 0,0,1]);
        let mut y = Vector::new(f16v(&[1,1,0]));
        let rank = a.transform_to_row_echelon_augmented(&mut y).unwrap();
        assert_eq!(rank, 2);
        let expected_a_ref = f16m(3,3, &[1,1,0, 0,0,1, 0,0,0]);
        let expected_y_transformed = Vector::new(f16v(&[1,0,0]));
        assert_eq!(a, expected_a_ref);
        assert_eq!(y, expected_y_transformed);
    }

    #[test]
    fn test_to_row_echelon_already_ref() {
        let mut a = f16m(2,3, &[1,2,3, 0,1,4]); // REF
        let mut y = Vector::new(f16v(&[5,6]));

        let mut a_clone = a.clone(); // clone before modification
        let mut y_clone = y.clone();

        let rank = a.transform_to_row_echelon_augmented(&mut y).unwrap();
        assert_eq!(rank, 2);
        // Should normalize rows but structure largely same.
        // R0 = R0 - 2*R1 = [1,2,3] - 2*[0,1,4] = [1,2,3] - [0,2,8] = [1,0,3^8=B]
        // y_new[0] = 5 - 2*6 = 5 - 12 = 5 - C = 5^C = 9
        // y_new[1] = 6 (no change as R1 pivot already 1, and no rows below it)
        // This test's manual REF calculation needs to be precise.
        // The provided code normalizes the pivot row first, then eliminates others.
        // 1. Pivot (0,0) is 1.
        //    No rows below to eliminate for this pivot column.
        // 2. Pivot (1,1) is 1. (pivot_row = 1, j = 1)
        //    Eliminate R0: R0 = R0 - self.get(0,1)*R1 = R0 - 2*R1
        //    a[0,:] = [1,2,3] - 2*[0,1,4] = [1,2,3] - [0,2,8] = [1,0,11] (3^8 = B)
        //    y[0]   = 5 - 2*6 = 5 - 12 = 9

        // Expected A after full REF:
        // [[1,0,11],
        //  [0,1, 4]]
        // Expected y after:
        // [9,6]

        let expected_a_ref = f16m(2,3, &[1,0,11, 0,1,4]);
        let expected_y_transformed = Vector::new(f16v(&[9,6]));

        assert_eq!(a, expected_a_ref);
        assert_eq!(y, expected_y_transformed);
    }

    #[test]
    fn test_solve_from_ref_square_invertible() {
        // From test_to_row_echelon_square_invertible:
        // A = [[1,1],[1,0]], y = [1,0]^T
        // REF A: [[1,0],[0,1]] (identity)
        // Transformed y: [0,1]^T
        let a_ref = Matrix::identity(2);
        let y_transformed = Vector::new(f16v(&[0,1]));
        // Expected solution: x = [0,1]^T
        let solution = a_ref.solve_from_row_echelon(&y_transformed).unwrap();
        assert_eq!(solution, Vector::new(f16v(&[0,1])));
    }

    #[test]
    fn test_solve_from_ref_3x3() {
        // A = [[1,1,1],[0,1,1],[1,0,1]] y = [1,0,0]
        // From a previous test, REF A could be I, transformed y would be the solution.
        // Let's use the example from test_to_row_echelon_3x3
        // A_orig = [[1,1,0],[0,1,1],[1,0,1]] y = [1,1,0] -> x=[0,1,0]
        // This was the actual test case:
        let mut a = f16m(3,3, &[1,1,0, 0,1,1, 1,0,1]);
        let mut y = Vector::new(f16v(&[1,1,0]));
        a.transform_to_row_echelon_augmented(&mut y).unwrap(); // a is I, y is [0,1,0]

        let solution = a.solve_from_row_echelon(&y).unwrap();
        assert_eq!(solution, Vector::new(f16v(&[0,1,0]))); // solution should be y itself
    }

    #[test]
    fn test_solve_from_ref_rank_deficient_consistent() {
        // From test_to_row_echelon_rank_deficient:
        // A = [[1,1,1],[1,1,1],[0,0,1]] y = [1,1,0]
        // REF A: [[1,1,0],[0,0,1],[0,0,0]]
        // Transformed y: [1,0,0]
        let a_ref = f16m(3,3, &[1,1,0, 0,0,1, 0,0,0]);
        let y_transformed = Vector::new(f16v(&[1,0,0]));
        // System from REF:
        // 1*x0 + 1*x1 + 0*x2 = 1  => x0 + x1 = 1
        // 0*x0 + 0*x1 + 1*x2 = 0  => x2 = 0
        // 0*x0 + 0*x1 + 0*x2 = 0
        // Set free var x1 = 0. Then x0 = 1. x2 = 0. Solution [1,0,0]

        // Last row (i=2): pivot_col = None. rhs_vector.elements[2] (y_transformed[2]) is 0. OK.
        // Row i=1: pivot_col = Some(2). self.get(1,2) is 1.
        //   sum_known_terms (k from 3 to 2): loop doesn't run, sum = 0.
        //   solution.elements[2] = y_transformed.elements[1] + 0 = 0.  So x2=0.
        // Row i=0: pivot_col = Some(0). self.get(0,0) is 1.
        //   sum_known_terms (k from 1 to 2):
        //     k=1: self.get(0,1)*solution.elements[1] = 1 * (initially 0, x1 is free) = 0
        //     k=2: self.get(0,2)*solution.elements[2] = 0 * (0 from above) = 0
        //   sum = 0.
        //   solution.elements[0] = y_transformed.elements[0] + 0 = 1. So x0=1.
        // Resulting solution with free x1=0: [1,0,0]
        let solution = a_ref.solve_from_row_echelon(&y_transformed).unwrap();
        assert_eq!(solution, Vector::new(f16v(&[1,0,0])));
    }

    #[test]
    fn test_solve_from_ref_inconsistent() {
        // A = [[1,1],[0,0]] y = [1,1]
        // REF A: [[1,1],[0,0]]
        // Transformed y: [1,1] (from previous test_to_row_echelon_augmented)
        let a_ref = f16m(2,2, &[1,1,0,0]);
        let y_transformed = Vector::new(f16v(&[1,1]));
        // System: x0+x1=1, 0=1 (inconsistent from y_transformed[1])

        let result = a_ref.solve_from_row_echelon(&y_transformed);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.contains("Inconsistent system: zero row in matrix for non-zero RHS at row 1."));
        }
    }
}
