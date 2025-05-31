// rust-mayo/src/vector.rs
use crate::f16::F16;
use std::ops::Add;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vector {
    elements: Vec<F16>,
}

impl Vector {
    // Creates a new vector from a Vec<F16>
    pub fn new(elements: Vec<F16>) -> Self {
        Vector { elements }
    }

    // Creates a new zero vector of a given length
    pub fn zero(len: usize) -> Self {
        Vector {
            elements: vec![F16::new(0); len],
        }
    }

    // Returns the length of the vector
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    // Returns whether the vector is empty
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    // Gets an element at a specific index
    pub fn get(&self, index: usize) -> Option<F16> {
        self.elements.get(index).copied()
    }

    // Provides a slice to the underlying F16 elements
    pub fn elements(&self) -> &[F16] {
        &self.elements
    }

    // Encodes a vector x ∈ Fn_16 into ⌈n/2⌉ bytes.
    // Concatenates nibble encodings, pads with a zero nibble if n is odd.
    pub fn encode_vec(&self) -> Vec<u8> {
        let n = self.elements.len();
        let num_bytes = (n + 1) / 2;
        let mut byte_string = Vec::with_capacity(num_bytes);
        let mut current_byte = 0u8;

        for (i, f16_val) in self.elements.iter().enumerate() {
            let nibble = f16_val.encode_f16(); // This is just f16_val.0
            if i % 2 == 0 { // First nibble of a byte
                current_byte = nibble;
            } else { // Second nibble of a byte
                current_byte |= nibble << 4;
                byte_string.push(current_byte);
                current_byte = 0; // Reset for next potential byte
            }
        }

        // If n is odd, the last nibble is already in current_byte (lower 4 bits)
        // and needs to be pushed. The spec says "padding with a zero nibble".
        // This means the high nibble of the last byte is 0 if n is odd.
        // Our current_byte already has the last nibble in the lower 4 bits if n is odd.
        if n % 2 != 0 {
            byte_string.push(current_byte);
        }
        byte_string
    }

    // Decodes a byte string ∈ B⌈n/2⌉ into a vector in Fn_16.
    // n: target length of the vector.
    pub fn decode_vec(n: usize, byte_string: &[u8]) -> Result<Self, String> {
        let expected_num_bytes = (n + 1) / 2;
        if byte_string.len() != expected_num_bytes {
            return Err(format!(
                "Invalid byte string length: expected {}, got {}",
                expected_num_bytes,
                byte_string.len()
            ));
        }

        let mut elements = Vec::with_capacity(n);
        for i in 0..n {
            let byte_index = i / 2;
            let byte_val = byte_string[byte_index];
            let nibble = if i % 2 == 0 { // First nibble (lower 4 bits)
                byte_val & 0x0F
            } else { // Second nibble (upper 4 bits)
                (byte_val >> 4) & 0x0F
            };
            elements.push(F16::decode_f16(nibble));
        }
        Ok(Vector::new(elements))
    }
}

// Component-wise addition for Vectors
impl Add for &Vector {
    type Output = Vector;

    fn add(self, rhs: Self) -> Self::Output {
        if self.len() != rhs.len() {
            panic!("Vector addition requires vectors of the same length.");
        }
        let mut result_elements = Vec::with_capacity(self.len());
        for i in 0..self.len() {
            result_elements.push(self.elements[i] + rhs.elements[i]);
        }
        Vector::new(result_elements)
    }
}

// Scalar multiplication: Vector * F16
impl std::ops::Mul<F16> for &Vector {
    type Output = Vector;

    fn mul(self, scalar: F16) -> Vector {
        let mut result_elements = Vec::with_capacity(self.len());
        for &elem in self.elements.iter() {
            result_elements.push(elem * scalar);
        }
        Vector::new(result_elements)
    }
}

// Scalar multiplication: F16 * Vector
impl std::ops::Mul<&Vector> for F16 {
    type Output = Vector;

    fn mul(self, vector: &Vector) -> Vector {
        vector * self // Reuse the Vector * F16 implementation
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::f16::F16;

    fn f16v(vals: &[u8]) -> Vec<F16> {
        vals.iter().map(|&x| F16::new(x)).collect()
    }

    #[test]
    fn test_vector_new_and_len() {
        let v = Vector::new(f16v(&[1, 2, 3]));
        assert_eq!(v.len(), 3);
        assert_eq!(v.get(0), Some(F16::new(1)));
        assert_eq!(v.get(3), None);
    }

    #[test]
    fn test_vector_zero() {
        let v = Vector::zero(4);
        assert_eq!(v.len(), 4);
        assert_eq!(v.elements(), &[F16::new(0); 4]);
    }

    #[test]
    fn test_vector_add() {
        let v1 = Vector::new(f16v(&[1, 2, 3]));
        let v2 = Vector::new(f16v(&[4, 5, 6]));
        let expected = Vector::new(f16v(&[1^4, 2^5, 3^6]));
        assert_eq!((&v1 + &v2), expected);
    }

    #[test]
    #[should_panic]
    fn test_vector_add_panic() {
        let v1 = Vector::new(f16v(&[1, 2]));
        let v2 = Vector::new(f16v(&[4, 5, 6]));
        let _ = &v1 + &v2;
    }

    #[test]
    fn test_vector_scalar_mul() {
        let v = Vector::new(f16v(&[1, 2, 3]));
        let s = F16::new(2); // x
        // 1*x = x (2), 2*x = x^2 (4), 3*x = (x+1)x = x^2+x (4^2=6)
        let expected = Vector::new(f16v(&[
            (F16::new(1)*s).value(),
            (F16::new(2)*s).value(),
            (F16::new(3)*s).value()
        ]));
        assert_eq!(&v * s, expected);
        assert_eq!(s * &v, expected);
    }

    #[test]
    fn test_encode_vec_even_len() {
        // Vector: [F16(1), F16(2), F16(3), F16(4)]
        // Nibbles: 0x1, 0x2, 0x3, 0x4
        // Bytes: [0x21, 0x43] (second_nibble | first_nibble << 4) -> No, (first_nibble | second_nibble << 4)
        // Spec: "concatenating the nibble encodings ... padding with a zero nibble if n is odd"
        // F16(1) -> 0x1, F16(2) -> 0x2. Byte 0: 0x1 | (0x2 << 4) = 0x21.
        // F16(3) -> 0x3, F16(4) -> 0x4. Byte 1: 0x3 | (0x4 << 4) = 0x43.
        let v = Vector::new(f16v(&[1, 2, 3, 4]));
        let encoded = v.encode_vec();
        // Corrected: first nibble in lower bits, second in upper bits.
        // Byte 0: elements[0] (low), elements[1] (high) -> (nibble0) | (nibble1 << 4)
        // So for [1,2,3,4]:
        // el[0]=1, el[1]=2 => byte0 = 1 | (2<<4) = 0x21
        // el[2]=3, el[3]=4 => byte1 = 3 | (4<<4) = 0x43
        assert_eq!(encoded, vec![0x21, 0x43]);
    }

    #[test]
    fn test_encode_vec_odd_len() {
        // Vector: [F16(1), F16(2), F16(3)]
        // Nibbles: 0x1, 0x2, 0x3
        // Byte 0: F16(1) | F16(2)<<4 = 0x21
        // Byte 1: F16(3) | 0x0 << 4 = 0x03 (padded with zero nibble)
        let v = Vector::new(f16v(&[1, 2, 3]));
        let encoded = v.encode_vec();
        assert_eq!(encoded, vec![0x21, 0x03]);
    }

    #[test]
    fn test_encode_vec_single_len() {
        let v = Vector::new(f16v(&[0xA]));
        let encoded = v.encode_vec();
        assert_eq!(encoded, vec![0x0A]);
    }

    #[test]
    fn test_decode_vec_even_len() {
        // Bytes: [0x21, 0x43]
        // Expected vector: [F16(1), F16(2), F16(3), F16(4)]
        let bytes = vec![0x21, 0x43];
        let decoded = Vector::decode_vec(4, &bytes).unwrap();
        let expected = Vector::new(f16v(&[1, 2, 3, 4]));
        assert_eq!(decoded, expected);
    }

    #[test]
    fn test_decode_vec_odd_len() {
        // Bytes: [0x21, 0x03] (F16(3) padded with zero nibble)
        // Expected vector: [F16(1), F16(2), F16(3)]
        let bytes = vec![0x21, 0x03];
        let decoded = Vector::decode_vec(3, &bytes).unwrap();
        let expected = Vector::new(f16v(&[1, 2, 3]));
        assert_eq!(decoded, expected);
    }

    #[test]
    fn test_decode_vec_single_len() {
        let bytes = vec![0x0A];
        let decoded = Vector::decode_vec(1, &bytes).unwrap();
        let expected = Vector::new(f16v(&[0xA]));
        assert_eq!(decoded, expected);
    }

    #[test]
    fn test_decode_vec_invalid_len() {
        let bytes = vec![0x21];
        assert!(Vector::decode_vec(3, &bytes).is_err()); // Expected 2 bytes for len 3
        assert!(Vector::decode_vec(4, &bytes).is_err()); // Expected 2 bytes for len 4
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let v1 = Vector::new(f16v(&[1,5,2,8,10,3,7,0,15,4]));
        let encoded1 = v1.encode_vec();
        let decoded1 = Vector::decode_vec(v1.len(), &encoded1).unwrap();
        assert_eq!(v1, decoded1);

        let v2 = Vector::new(f16v(&[11,6,1,9,13,2,0,8,3]));
        let encoded2 = v2.encode_vec();
        let decoded2 = Vector::decode_vec(v2.len(), &encoded2).unwrap();
        assert_eq!(v2, decoded2);
    }
}
