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
