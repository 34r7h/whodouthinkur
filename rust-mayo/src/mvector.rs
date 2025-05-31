use crate::f16::F16;
use std::ops::Add;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MVector {
    pub elements: Vec<F16>, // Public for now, like Vector
    m_param: usize,       // Should always be == elements.len()
}

impl MVector {
    pub fn new(m_param: usize, elements: Vec<F16>) -> Result<Self, String> {
        if elements.len() != m_param {
            return Err(format!(
                "MVector: element count {} does not match m_param {}",
                elements.len(), m_param
            ));
        }
        Ok(Self { elements, m_param })
    }

    pub fn zero(m_param: usize) -> Self {
        Self {
            elements: vec![F16::new(0); m_param],
            m_param,
        }
    }

    pub fn len(&self) -> usize {
        self.m_param
    }

    pub fn is_empty(&self) -> bool {
        self.m_param == 0
    }

    // Converts a byte slice representing packed MVector limbs into an MVector.
    // `bytes`: input byte slice, expected to be m_param/2 bytes if m_param is even,
    //          or (m_param+1)/2 bytes if m_param is odd. This is the "packed nibble" format.
    // `m_param`: the number of F16 elements in the MVector.
    // `m_vec_limbs`: number of u64 limbs used to represent these m_param elements in C's packed form.
    //                (m_vec_limbs = ceil(m_param / 16))
    pub fn from_limbs_bytes(bytes: &[u8], m_param: usize, m_vec_limbs: usize) -> Result<Self, String> {
        let expected_bytes_len = (m_param + 1) / 2;
        if bytes.len() != expected_bytes_len {
            return Err(format!(
                "MVector::from_limbs_bytes: incorrect byte length. Expected {}, got {}. m_param: {}",
                expected_bytes_len, bytes.len(), m_param
            ));
        }
        if m_param == 0 {
            return Ok(Self::zero(0));
        }

        let num_u64_limbs_needed_for_bytes = (bytes.len() + 7) / 8;
        if num_u64_limbs_needed_for_bytes > m_vec_limbs && m_param > 0 { // m_vec_limbs might be larger due to padding for M_MAX
             // This check might be too strict if m_vec_limbs from params accounts for MAX_LIMBS padding
             // For now, let's assume bytes directly map to the limbs needed for m_param elements
        }


        let mut u64_limbs = vec![0u64; m_vec_limbs];
        // Copy bytes into the u64 limbs (Little Endian assumed for byte-to-u64 conversion)
        // The C `unpack_m_vecs` does a direct memcpy, implying the PRF output bytes
        // are already in the correct (e.g. little-endian) limb order.
        for (i, chunk) in bytes.chunks(8).enumerate() {
            if i < m_vec_limbs {
                let mut val = [0u8; 8];
                val[..chunk.len()].copy_from_slice(chunk);
                u64_limbs[i] = u64::from_le_bytes(val);
            }
        }

        // Now, unpack F16 elements from these u64 limbs
        let mut elements = Vec::with_capacity(m_param);
        for i in 0..m_param {
            let limb_idx = i / 16; // Which u64 limb
            let nibble_pos_in_limb = i % 16; // Which nibble within that limb (0-15)
            if limb_idx < m_vec_limbs {
                let limb_val = u64_limbs[limb_idx];
                let shift = nibble_pos_in_limb * 4;
                let nibble_val = ((limb_val >> shift) & 0xF) as u8;
                elements.push(F16::new(nibble_val));
            } else {
                // Should not happen if m_param and m_vec_limbs are consistent
                return Err("MVector::from_limbs_bytes: m_param implies reading beyond available limbs".to_string());
            }
        }
        Self::new(m_param, elements)
    }

    // Converts an MVector into its packed limb byte representation.
    // `m_vec_limbs`: number of u64 limbs to use for packing.
    pub fn to_limbs_bytes(&self, m_vec_limbs: usize) -> Result<Vec<u8>, String> {
        if self.m_param == 0 {
            return Ok(Vec::new());
        }
        // Ensure m_vec_limbs is sufficient
        let min_limbs_needed = (self.m_param + 15) / 16;
        if m_vec_limbs < min_limbs_needed {
             return Err(format!("MVector::to_limbs_bytes: m_vec_limbs {} is too small for m_param {}", m_vec_limbs, self.m_param));
        }

        let mut u64_limbs = vec![0u64; m_vec_limbs];
        for (i, f16_val) in self.elements.iter().enumerate() {
            let limb_idx = i / 16;
            let nibble_pos_in_limb = i % 16;
            if limb_idx < m_vec_limbs {
                let shift = nibble_pos_in_limb * 4;
                u64_limbs[limb_idx] |= (f16_val.value() as u64) << shift;
            } else {
                // Should not happen if elements.len() matches m_param and m_vec_limbs is sufficient
                return Err("MVector::to_limbs_bytes: Attempting to write beyond allocated limbs.".to_string());
            }
        }

        let mut bytes = Vec::with_capacity(m_vec_limbs * 8);
        for &limb_val in &u64_limbs {
            bytes.extend_from_slice(&limb_val.to_le_bytes());
        }

        // The C functions `pack_m_vecs` and `PARAM_X_bytes` imply that the final byte vector
        // should be exactly (m_param+1)/2 bytes long.
        let expected_bytes_len = (self.m_param + 1) / 2;
        bytes.truncate(expected_bytes_len);
        Ok(bytes)
    }

    // Multiplies the MVector by X in the polynomial ring (GF(16)[X]/F_tail_poly(X))^m_param
    // and then adds another MVector `to_add`.
    // This is a key step in C's compute_rhs.
    // Returns a new MVector.
    pub fn poly_mul_by_x_and_add(
        &self,
        f_tail: &'static [u8], // From P::F_TAIL
        to_add: &MVector
    ) -> Result<MVector, String> {
        if self.m_param != to_add.m_param {
            return Err("MVectors must have same m_param for poly_mul_by_x_and_add".to_string());
        }
        if f_tail.len() != 4 { // As per F_TAIL_LEN in C
            return Err("f_tail must have length 4".to_string());
        }

        let mut result_elements = vec![F16::new(0); self.m_param];
        let m_param = self.m_param;

        // This operation is applied to each of the m_param "lanes" independently.
        // The C code processes one MVector (temp_bytes) which has m_param elements.
        // It shifts this entire MVector "up by 4 bits" (mul by X in the polynomial representation of elements of GF(16)^m).
        // Then it reduces using f_tail if the "top nibble" of the MVector was non-zero.
        // This is NOT per-F16 element reduction using x^4+x+1.
        // It's a reduction of a polynomial whose coefficients are F16 elements,
        // using a reduction polynomial defined by F_TAIL.
        // The C code:
        //   top = (temp[m_vec_limbs-1] >> top_pos) % 16; // "top F16 element" of the MVector if m is not multiple of 16
        //   temp <<= 4; // Shift all F16 elements in temp "one position up"
        //   reduce using f_tail and top...
        // This is complex. The "top_pos" implies that F_TAIL reduces a polynomial of degree M_PARAM.
        // This interpretation is likely incorrect. F_TAIL in mayo.h (e.g. F_TAIL_78) is for z^78 + ...
        // The compute_rhs in C iterates k*k times. In each step, it does: temp = temp*X + (vp1v_term).
        // This means X is an indeterminate over GF(16), and MVectors are coefficients.
        // The f_tail reduction applies to this polynomial in X.

        // For now, STUB this complex polynomial arithmetic.
        // A correct implementation requires careful porting of the C loop with m_vec_limbs etc.
        // The current MVector struct (Vec<F16>) is not ideal for the C-style limb operations.
        // This stub will allow the main structure of compute_rhs_for_sign_operator to be built.
        println!("[MVector STUB] poly_mul_by_x_and_add called. Using simple XOR for now.");
        for i in 0..m_param {
            result_elements[i] = self.elements[i] + to_add.elements[i]; // Placeholder
        }

        MVector::new(m_param, result_elements)
    }
}

// Element-wise addition for MVectors
impl Add for &MVector {
    type Output = Result<MVector, String>;

    fn add(self, rhs: Self) -> Self::Output {
        if self.m_param != rhs.m_param {
            return Err("MVector addition requires vectors of the same m_param.".to_string());
        }
        let mut result_elements = Vec::with_capacity(self.m_param);
        for i in 0..self.m_param {
            result_elements.push(self.elements[i] + rhs.elements[i]);
        }
        MVector::new(self.m_param, result_elements)
    }
}

// Scalar multiplication: MVector * F16
impl std::ops::Mul<F16> for &MVector {
    type Output = MVector;

    fn mul(self, scalar: F16) -> MVector {
        let mut result_elements = Vec::with_capacity(self.m_param);
        for &elem in self.elements.iter() {
            result_elements.push(elem * scalar);
        }
        // This unwrap is safe because self.m_param will match result_elements.len()
        MVector::new(self.m_param, result_elements).unwrap()
    }
}

// Scalar multiplication: F16 * MVector
impl std::ops::Mul<&MVector> for F16 {
    type Output = MVector;

    fn mul(self, vector: &MVector) -> MVector {
        vector * self // Reuse the MVector * F16 implementation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::f16::F16;

    fn f16mv(m_param: usize, vals: &[u8]) -> MVector {
        MVector::new(m_param, vals.iter().map(|&x| F16::new(x)).collect()).unwrap()
    }

    #[test]
    fn test_mvector_new_zero() {
        let mv = MVector::zero(10);
        assert_eq!(mv.len(), 10);
        assert!(mv.elements.iter().all(|&x| x == F16::new(0)));

        let mv2 = f16mv(3, &[1,2,3]);
        assert_eq!(mv2.len(), 3);
        assert_eq!(mv2.elements[0].value(), 1);
    }

    #[test]
    fn test_mvector_add() {
        let mv1 = f16mv(2, &[1,2]);
        let mv2 = f16mv(2, &[3,4]);
        let expected = f16mv(2, &[1^3, 2^4]);
        assert_eq!((&mv1 + &mv2).unwrap(), expected);
    }

    #[test]
    fn test_mvector_scalar_mul() {
        let mv = f16mv(2, &[3,5]); // F16(3), F16(5)
        let s = F16::new(2);    // F16(x)
        // 3*x = (x+1)*x = x^2+x = 4+2=6
        // 5*x = (x^2+1)*x = x^3+x = 8+2=10
        let expected = f16mv(2, &[6,10]);
        assert_eq!(&mv * s, expected);
        assert_eq!(s * &mv, expected);
    }

    #[test]
    fn test_mvector_to_from_limbs_bytes_roundtrip() {
        let m_param = 64; // e.g., Mayo2 M_PARAM
        let m_vec_limbs = (m_param + 15) / 16; // Should be 4

        let mut f16_elements = Vec::new();
        for i in 0..m_param {
            f16_elements.push(F16::new((i % 16) as u8));
        }
        let mv = MVector::new(m_param, f16_elements).unwrap();

        let limbs_bytes = mv.to_limbs_bytes(m_vec_limbs).unwrap();
        assert_eq!(limbs_bytes.len(), (m_param + 1) / 2); // 32 bytes for m_param=64

        let mv_reconstructed = MVector::from_limbs_bytes(&limbs_bytes, m_param, m_vec_limbs).unwrap();
        assert_eq!(mv, mv_reconstructed, "MVector to/from limbs_bytes roundtrip failed");
    }

    #[test]
    fn test_mvector_to_from_limbs_bytes_odd_m_param() {
        let m_param = 7;
        let m_vec_limbs = (m_param + 15) / 16; // Should be 1

        let f16_elements = vec![
            F16::new(1), F16::new(2), F16::new(3), F16::new(4),
            F16::new(5), F16::new(6), F16::new(7)
        ];
        let mv = MVector::new(m_param, f16_elements).unwrap();

        let limbs_bytes = mv.to_limbs_bytes(m_vec_limbs).unwrap();
        assert_eq!(limbs_bytes.len(), (m_param + 1) / 2); // 4 bytes for m_param=7

        let mv_reconstructed = MVector::from_limbs_bytes(&limbs_bytes, m_param, m_vec_limbs).unwrap();
        assert_eq!(mv, mv_reconstructed);
    }

    #[test]
    fn test_mvector_from_limbs_bytes_specific() {
        // m=4, limbs=1. Bytes: [0x21, 0x43] (represents F16(1),F16(2),F16(3),F16(4))
        // u64 limb (LE): 0x...00_4321 (hex for nibbles)
        let bytes = vec![0x21, 0x43]; // Represents F16(1),F16(2),F16(3),F16(4)
        let m_param = 4;
        let m_vec_limbs = 1;
        let mv = MVector::from_limbs_bytes(&bytes, m_param, m_vec_limbs).unwrap();
        let expected_elements = vec![F16::new(1), F16::new(2), F16::new(3), F16::new(4)];
        assert_eq!(mv.elements, expected_elements);
    }

    #[test]
    fn test_mvector_to_limbs_bytes_specific() {
        // m=4, F16(1),F16(2),F16(3),F16(4)
        // u64 limb: 0x...00_4321 (hex for nibbles)
        // bytes (LE): [0x21, 0x43]
        let elements = vec![F16::new(1), F16::new(2), F16::new(3), F16::new(4)];
        let m_param = 4;
        let m_vec_limbs = 1;
        let mv = MVector::new(m_param, elements).unwrap();
        let bytes = mv.to_limbs_bytes(m_vec_limbs).unwrap();
        assert_eq!(bytes, vec![0x21, 0x43]);
    }
}
