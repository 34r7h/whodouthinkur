// rust-mayo/src/f16.rs
use std::ops::{Add, Sub, Mul, Div};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct F16(pub u8); // Inner u8 stores the value 0-15

impl F16 {
    // Constructor that ensures the value is within the F16 range
    pub fn new(val: u8) -> Self {
        F16(val & 0x0F) // Mask to keep only the lower 4 bits
    }

    // Returns the u8 representation of the F16 element
    pub fn value(&self) -> u8 {
        self.0
    }

    // Encodes a field element a into a 4-bit nibble.
    pub fn encode_f16(&self) -> u8 {
        self.0
    }

    // Decodes a nibble into the corresponding field element.
    pub fn decode_f16(nibble: u8) -> Self {
        F16::new(nibble) // Assumes nibble is already a valid 4-bit value
    }

    // Multiplicative inverse
    pub fn inverse(&self) -> Option<Self> {
        if self.0 == 0 {
            return None; // Inverse of 0 is undefined
        }
        // Fermat's Little Theorem: a^(q-2) = a^(16-2) = a^14
        // a^14 = a^8 * a^4 * a^2
        let a2 = *self * *self;
        let a4 = a2 * a2;
        let a8 = a4 * a4;
        Some(a8 * a4 * a2)
    }
}

impl Add for F16 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        F16::new(self.0 ^ rhs.0) // Addition in F16 is XOR
    }
}

impl Sub for F16 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        F16::new(self.0 ^ rhs.0) // Subtraction in F16 is also XOR (characteristic 2)
    }
}

impl Mul for F16 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut a = self.0;
        let mut b = rhs.0;
        let mut res: u8 = 0;
        // Irreducible polynomial for F16 is x^4 + x + 1.
        // When a term with x^3 (0x08) is shifted left, it becomes x^4 (0x10).
        // This x^4 must be replaced by (x+1) (binary 0011 or 0x03).
        let irreducible_poly_lower_bits = 0x03; // x+1

        for _ in 0..4 { // Iterate 4 times for the 4 bits of F16
            if (b & 1) == 1 { // If current LSB of b is 1
                res ^= a;     // Add (XOR) a to the result
            }

            let msb_of_a_is_set = (a & 0x08) != 0; // Check if x^3 term is present in a
            a <<= 1; // Multiply a by x (left shift)

            if msb_of_a_is_set { // If x^3 term was present, a now has an x^4 term
                a ^= irreducible_poly_lower_bits; // Reduce modulo x^4+x+1 by XORing with x+1
            }
            b >>= 1; // Consider next bit of b
        }
        F16::new(res) // Mask to ensure final result is 4 bits
    }
}

impl Div for F16 {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        if rhs.0 == 0 {
            panic!("Division by zero in F16");
        }
        // Division in finite field: a / b = a * b^(-1)
        if let Some(inv) = rhs.inverse() {
            self * inv
        } else {
            panic!("Division by zero in F16");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_f16_new() {
        assert_eq!(F16::new(0).value(), 0);
        assert_eq!(F16::new(15).value(), 15);
        assert_eq!(F16::new(16).value(), 0);
        assert_eq!(F16::new(0xAB).value(), 0x0B);
    }

    #[test]
    fn test_f16_add() {
        let a = F16::new(0x0A);
        let b = F16::new(0x03);
        assert_eq!(a + b, F16::new(0x09));
    }

    #[test]
    fn test_f16_sub() {
        let a = F16::new(0x0A);
        let b = F16::new(0x03);
        assert_eq!(a - b, F16::new(0x09));
    }

    #[test]
    fn test_f16_mul_identity() {
        let a = F16::new(0x0A);
        let identity = F16::new(0x01);
        assert_eq!(a * identity, a);
        assert_eq!(identity * a, a);
    }

    #[test]
    fn test_f16_mul_by_zero() {
        let a = F16::new(0x0A);
        let zero = F16::new(0x00);
        assert_eq!(a * zero, zero);
        assert_eq!(zero * a, zero);
    }

    #[test]
    fn test_f16_mul_x_times_x() {
        let x_val = F16::new(0b0010);
        let x_squared = F16::new(0b0100);
        assert_eq!(x_val * x_val, x_squared);
    }

    #[test]
    fn test_f16_mul_x2_times_x2() {
        let x2_val = F16::new(0b0100);
        let x_plus_1 = F16::new(0b0011);
        assert_eq!(x2_val * x2_val, x_plus_1);
    }

    #[test]
    fn test_f16_mul_complex_1() {
        let x_plus_1 = F16::new(0b0011);
        let x2_plus_1 = F16::new(0b0101);
        let expected = F16::new(0b1111);
        assert_eq!(x_plus_1 * x2_plus_1, expected, "LHS: {:?}, RHS: {:?}", (x_plus_1 * x2_plus_1), expected);
    }

    #[test]
    fn test_f16_mul_x3_times_x2() {
        let x3_val = F16::new(0b1000);
        let x2_val = F16::new(0b0100);
        let expected = F16::new(0b0110);
        assert_eq!(x3_val * x2_val, expected, "LHS: {:?}, RHS: {:?}", (x3_val*x2_val), expected);
    }

    #[test]
    fn test_f16_inverse() {
        assert_eq!(F16::new(1).inverse(), Some(F16::new(1)), "Inverse of 1");

        let x_val = F16::new(0b0010);
        let x_inv_expected = F16::new(0b1001);
        assert_eq!(x_val.inverse(), Some(x_inv_expected), "Inverse of x");
        if let Some(inv) = x_val.inverse() {
            assert_eq!(x_val * inv, F16::new(1), "x * x^-1 should be 1");
        }

        for i in 1..16 {
            let val = F16::new(i);
            match val.inverse() {
                Some(inv) => assert_eq!(val * inv, F16::new(1), "Inverse check failed for F16({})", i),
                None => panic!("Inverse not found for non-zero element F16({})", i),
            }
        }
        assert_eq!(F16::new(0).inverse(), None, "Inverse of 0");
    }

    #[test]
    fn test_f16_encode_decode() {
        for i in 0..16u8 {
            let f_element = F16::new(i);
            let encoded_val = f_element.encode_f16();
            assert_eq!(encoded_val, i, "Encoding failed for {}", i);
            let decoded_element = F16::decode_f16(encoded_val);
            assert_eq!(decoded_element, f_element, "Decoding failed for {}", i);
        }
        let decoded_masked = F16::decode_f16(0xAB);
        assert_eq!(decoded_masked, F16::new(0x0B), "Masking during decode failed");
    }
}
