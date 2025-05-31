// rust-mayo/src/params.rs

// MAYO parameter sets trait and implementations
pub trait MayoParams: Send + Sync + 'static {
    const NAME: &'static str;
    const SECURITY_LEVEL: usize;

    // Core MAYO parameters
    const M_PARAM: usize; // Number of equations
    const N_PARAM: usize; // Number of variables (oil + vinegar)
    const O_PARAM: usize; // Number of oil variables
    const K_PARAM: usize; // Number of vinegar variables used to build P_O_i
    const Q_PARAM: usize; // Field size (always 16 for MAYO)

    const M_VEC_LIMBS: usize; // Number of u64 limbs to store m elements

    // Coefficients for irreducible polynomial f(z) over GF(16)
    // specific to the m value. E.g., for m=78, f(z) = z^78 + F_TAIL[0]*z^3 + F_TAIL[1]*z^2 + F_TAIL[2]*z + F_TAIL[3]
    // The C code uses these as {c3, c2, c1, c0} for terms z^3, z^2, z^1, z^0 in the reduction of X^m mod f(X)
    // but mayo.h defines them as coefficients of f(z) itself, for the lowest degree terms.
    // Let's stick to mayo.h's F_TAIL interpretation for the polynomial f(z) related to m.
    // The actual f(z) for GF(16) is x^4+x+1. F_TAIL here is for a different polynomial related to m.
    // Based on c-mayo/mayo.h, these are for f(z) = z^m_val + f_tail[0]*z^3 + f_tail[1]*z^2 + f_tail[2]*z + f_tail[3]
    // The C code uses these values in compute_rhs to reduce a polynomial of degree k*k.
    // These are the coefficients of the reduction polynomial for x^m_val mod P(x) where P(x) is the field polynomial.
    // For now, storing them as defined. Their exact use in rust will need care.
    // The C code's F_TAIL_XX seem to be coefficients for specific reduction polynomials.
    const F_TAIL: &'static [u8];


    // Derived parameters
    const V_PARAM: usize = Self::N_PARAM - Self::O_PARAM; // Number of vinegar variables

    // Byte sizes for seeds, salt, digest
    const SK_SEED_BYTES: usize; // Secret key seed size
    const PK_SEED_BYTES: usize; // Public key seed size (for P1, P2 derivation)
    const SALT_BYTES: usize;
    const DIGEST_BYTES: usize;
    const R_BYTES: usize; // Random bytes for solution sampling during signing

    // Byte sizes for components of the public key and secret key (relevant for parsing KAT files and constructing keys)
    // These are from mayo.h defines (e.g. MAYO_1_P1_bytes)
    const CPK_P1_BYTES: usize; // Size of P1 component in compact public key (if applicable, usually expanded)
    const CPK_P2_BYTES: usize; // Size of P2 component in compact public key (if applicable, usually expanded)
    const CPK_P3_BYTES: usize; // Size of P3 component in compact public key (this is what's typically stored after pk_seed)
    const O_BYTES: usize;      // Size of the oil matrix O component in (expanded) secret key or derived from sk_seed for cpk

    // Sizes for compact keys and signature
    const CSK_BYTES: usize; // Compact secret key size (usually just sk_seed)
    const CPK_BYTES: usize; // Compact public key size
    const SIG_BYTES: usize; // Full signature size (salt + encoded solution)

    // Helper: Number of elements in P1, P2, P3 matrices (assuming GF(16) elements)
    // P1 is v x v, symmetric (upper triangular stored)
    const P1_ELEMENTS: usize = (Self::V_PARAM * (Self::V_PARAM + 1)) / 2;
    // P2 is v x o
    const P2_ELEMENTS: usize = Self::V_PARAM * Self::O_PARAM;
    // P3 is o x o, symmetric (upper triangular stored)
    const P3_ELEMENTS: usize = (Self::O_PARAM * (Self::O_PARAM + 1)) / 2;

    // These are informational, actual matrix layout will be more complex (vectors of m_vec_limbs)
    // For L matrix (secret, v x o)
    const L_ELEMENTS: usize = Self::V_PARAM * Self::O_PARAM;


    // Dimensions for key matrices for clarity
    const P1_MAT_ROWS: usize = Self::V_PARAM;
    const P1_MAT_COLS: usize = Self::V_PARAM;
    const P1_IS_TRIANGULAR: bool = true;

    const P2_MAT_ROWS: usize = Self::V_PARAM;
    const P2_MAT_COLS: usize = Self::O_PARAM;
    const P2_IS_TRIANGULAR: bool = false;

    const P3_MAT_ROWS: usize = Self::O_PARAM;
    const P3_MAT_COLS: usize = Self::O_PARAM;
    const P3_IS_TRIANGULAR: bool = true;

    const L_MAT_ROWS: usize = Self::V_PARAM; // Secret matrix L, part of expanded SK
    const L_MAT_COLS: usize = Self::O_PARAM;
    const L_IS_TRIANGULAR: bool = false;

    const O_MAT_ROWS: usize = Self::V_PARAM; // Secret matrix O, part of expanded SK
    const O_MAT_COLS: usize = Self::O_PARAM;
    const O_IS_TRIANGULAR: bool = false;
}

pub struct Mayo1;
impl MayoParams for Mayo1 {
    const NAME: &'static str = "MAYO_1";
    const SECURITY_LEVEL: usize = 1;
    // Core
    const M_PARAM: usize = 78;
    const N_PARAM: usize = 86;
    const O_PARAM: usize = 8;
    const K_PARAM: usize = 10;
    const Q_PARAM: usize = 16;
    const M_VEC_LIMBS: usize = 5; // ceil(78/16)
    const F_TAIL: &'static [u8] = &[8, 1, 1, 0]; // F_TAIL_78 from mayo.h
    // Seeds, salt, digest
    const SK_SEED_BYTES: usize = 24;
    const PK_SEED_BYTES: usize = 16;
    const SALT_BYTES: usize = 24; // mayo.h MAYO_1_salt_bytes
    const DIGEST_BYTES: usize = 32; // mayo.h MAYO_1_digest_bytes
    const R_BYTES: usize = 40; // MAYO_1_r_bytes
    // Component sizes (from mayo.h, P3_bytes is what's packed in cpk after seed)
    const CPK_P1_BYTES: usize = 120159; // MAYO_1_P1_bytes (for expanded P1)
    const CPK_P2_BYTES: usize = 24336;  // MAYO_1_P2_bytes (for expanded P2)
    const CPK_P3_BYTES: usize = 1404;   // MAYO_1_P3_bytes (for expanded P3)
    const O_BYTES: usize = 312;        // MAYO_1_O_bytes
    // Compact keys and signature
    const CSK_BYTES: usize = 24; // MAYO_1_csk_bytes
    const CPK_BYTES: usize = 1420; // MAYO_1_cpk_bytes
    const SIG_BYTES: usize = 454; // MAYO_1_sig_bytes
}

pub struct Mayo2;
impl MayoParams for Mayo2 {
    const NAME: &'static str = "MAYO_2";
    const SECURITY_LEVEL: usize = 1; // NIST Level 1, but different params from Mayo1
    // Core
    const M_PARAM: usize = 64;
    const N_PARAM: usize = 81;
    const O_PARAM: usize = 17;
    const K_PARAM: usize = 4;
    const Q_PARAM: usize = 16;
    const M_VEC_LIMBS: usize = 4; // ceil(64/16)
    const F_TAIL: &'static [u8] = &[8, 0, 2, 8]; // F_TAIL_64 from mayo.h
    // Seeds, salt, digest
    const SK_SEED_BYTES: usize = 24;
    const PK_SEED_BYTES: usize = 16;
    const SALT_BYTES: usize = 24; // mayo.h MAYO_2_salt_bytes
    const DIGEST_BYTES: usize = 32; // mayo.h MAYO_2_digest_bytes
    const R_BYTES: usize = 34; // MAYO_2_r_bytes
    // Component sizes
    const CPK_P1_BYTES: usize = 66560;
    const CPK_P2_BYTES: usize = 34816;
    const CPK_P3_BYTES: usize = 4896;
    const O_BYTES: usize = 544;
    // Compact keys and signature
    const CSK_BYTES: usize = 24;
    const CPK_BYTES: usize = 4912;
    const SIG_BYTES: usize = 186;
}

pub struct Mayo3;
impl MayoParams for Mayo3 {
    const NAME: &'static str = "MAYO_3";
    const SECURITY_LEVEL: usize = 3;
    // Core
    const M_PARAM: usize = 108;
    const N_PARAM: usize = 118;
    const O_PARAM: usize = 10;
    const K_PARAM: usize = 11;
    const Q_PARAM: usize = 16;
    const M_VEC_LIMBS: usize = 7; // ceil(108/16)
    const F_TAIL: &'static [u8] = &[8, 0, 1, 7]; // F_TAIL_108 from mayo.h
    // Seeds, salt, digest
    const SK_SEED_BYTES: usize = 32;
    const PK_SEED_BYTES: usize = 16;
    const SALT_BYTES: usize = 32; // mayo.h MAYO_3_salt_bytes
    const DIGEST_BYTES: usize = 48; // mayo.h MAYO_3_digest_bytes
    const R_BYTES: usize = 55; // MAYO_3_r_bytes
    // Component sizes
    const CPK_P1_BYTES: usize = 317844;
    const CPK_P2_BYTES: usize = 58320;
    const CPK_P3_BYTES: usize = 2970;
    const O_BYTES: usize = 540;
    // Compact keys and signature
    const CSK_BYTES: usize = 32;
    const CPK_BYTES: usize = 2986;
    const SIG_BYTES: usize = 681;
}

pub struct Mayo5;
impl MayoParams for Mayo5 {
    const NAME: &'static str = "MAYO_5";
    const SECURITY_LEVEL: usize = 5;
    // Core
    const M_PARAM: usize = 142;
    const N_PARAM: usize = 154;
    const O_PARAM: usize = 12;
    const K_PARAM: usize = 12;
    const Q_PARAM: usize = 16;
    const M_VEC_LIMBS: usize = 9; // ceil(142/16)
    const F_TAIL: &'static [u8] = &[4, 0, 8, 1]; // F_TAIL_142 from mayo.h
    // Seeds, salt, digest
    const SK_SEED_BYTES: usize = 40;
    const PK_SEED_BYTES: usize = 16;
    const SALT_BYTES: usize = 40; // mayo.h MAYO_5_salt_bytes
    const DIGEST_BYTES: usize = 64; // mayo.h MAYO_5_digest_bytes
    const R_BYTES: usize = 72; // MAYO_5_r_bytes
    // Component sizes
    const CPK_P1_BYTES: usize = 720863;
    const CPK_P2_BYTES: usize = 120984;
    const CPK_P3_BYTES: usize = 5538;
    const O_BYTES: usize = 852;
    // Compact keys and signature
    const CSK_BYTES: usize = 40;
    const CPK_BYTES: usize = 5554;
    const SIG_BYTES: usize = 964;
}

// Default to MAYO-1 for any legacy code that might not be generic yet.
pub type DefaultParams = Mayo1;

// Re-export constants from DefaultParams for backward compatibility if any code used them directly.
// It's better to use generic functions with P: MayoParams.
pub const M_PARAM: usize = DefaultParams::M_PARAM;
pub const N_PARAM: usize = DefaultParams::N_PARAM;
pub const O_PARAM: usize = DefaultParams::O_PARAM;
pub const K_PARAM: usize = DefaultParams::K_PARAM;
// Add other re-exports if necessary, but ideally, they should not be used.
pub const CSK_BYTES: usize = DefaultParams::CSK_BYTES;
pub const CPK_BYTES: usize = DefaultParams::CPK_BYTES;
pub const SIG_BYTES: usize = DefaultParams::SIG_BYTES;
