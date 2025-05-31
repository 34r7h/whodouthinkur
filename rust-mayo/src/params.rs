// rust-mayo/src/params.rs

// PLACEHOLDER PARAMETERS (e.g., for a MAYO1-like small instance)
// These will eventually be part of a more structured parameter set system.

pub const M_PARAM: usize = 8; // Number of matrices in sequences P1, P2, P3, L. Must be multiple of 8.
                              // Real MAYO m is larger (e.g., 64, 68, 72, 76 for MAYO1,2,3,5)

// n and o are fundamental mayo parameters
const N_PARAM_PLACEHOLDER: usize = 10;
const O_PARAM_PLACEHOLDER: usize = 4;

const N_MINUS_O: usize = N_PARAM_PLACEHOLDER - O_PARAM_PLACEHOLDER; // = 6

// --- P1 Matrices (m sequence of (n-o)x(n-o) upper triangular) ---
pub const P1_MAT_ROWS: usize = N_MINUS_O; // 6
pub const P1_MAT_COLS: usize = N_MINUS_O; // 6
pub const P1_IS_TRIANGULAR: bool = true;
const P1_ELEMS_PER_MATRIX: usize = P1_MAT_ROWS * (P1_MAT_ROWS + 1) / 2; // 6*7/2 = 21
pub const P1_BYTES: usize = P1_ELEMS_PER_MATRIX * (M_PARAM / 2);      // 21 * (8/2) = 84

// --- P2 Matrices (m sequence of (n-o)xo non-triangular) ---
pub const P2_MAT_ROWS: usize = N_MINUS_O; // 6
pub const P2_MAT_COLS: usize = O_PARAM_PLACEHOLDER; // 4
pub const P2_IS_TRIANGULAR: bool = false;
const P2_ELEMS_PER_MATRIX: usize = P2_MAT_ROWS * P2_MAT_COLS; // 6*4 = 24
pub const P2_BYTES: usize = P2_ELEMS_PER_MATRIX * (M_PARAM / 2);   // 24 * 4 = 96

// --- P3 Matrices (m sequence of oxo upper triangular) ---
pub const P3_MAT_ROWS: usize = O_PARAM_PLACEHOLDER; // 4
pub const P3_MAT_COLS: usize = O_PARAM_PLACEHOLDER; // 4
pub const P3_IS_TRIANGULAR: bool = true;
const P3_ELEMS_PER_MATRIX: usize = P3_MAT_ROWS * (P3_MAT_ROWS + 1) / 2; // 4*5/2 = 10
pub const P3_BYTES: usize = P3_ELEMS_PER_MATRIX * (M_PARAM / 2);      // 10 * 4 = 40

// --- L Matrices (m sequence of (n-o)xo non-triangular, like P2) ---
// These are derived for the expanded secret key
pub const L_MAT_ROWS: usize = N_MINUS_O; // 6
pub const L_MAT_COLS: usize = O_PARAM_PLACEHOLDER; // 4
pub const L_IS_TRIANGULAR: bool = false;
const L_ELEMS_PER_MATRIX: usize = L_MAT_ROWS * L_MAT_COLS; // 6*4 = 24
pub const L_BYTES: usize = L_ELEMS_PER_MATRIX * (M_PARAM / 2);   // 24 * 4 = 96

// Oil Matrix O is (n-o) x o
pub const O_MAT_ROWS: usize = N_MINUS_O;
pub const O_MAT_COLS: usize = O_PARAM_PLACEHOLDER;
const O_ELTS: usize = O_MAT_ROWS * O_MAT_COLS; // 6 * 4 = 24
pub const O_BYTES: usize = (O_ELTS + 1) / 2; // From Matrix::encode_o -> Vector::encode_vec logic. 24/2 = 12

// Salt bytes (example value)
pub const SALT_BYTES: usize = 32;
// Digest bytes (example value)
pub const DIGEST_BYTES: usize = 64; // Example for SHAKE256 output

// SK/PK seed bytes (example values)
pub const SK_SEED_BYTES: usize = 32;
pub const PK_SEED_BYTES: usize = 16; // Often 128-bit for AES seed

// Compact Key sizes (seed_pk + P3_bytes)
pub const CPK_BYTES: usize = PK_SEED_BYTES + P3_BYTES; // 16 + 40 = 56
// Compact SK size (seed_sk)
pub const CSK_BYTES: usize = SK_SEED_BYTES; // 32

// Expanded PK size (P1_bytes + P2_bytes + P3_bytes)
pub const EPK_BYTES: usize = P1_BYTES + P2_BYTES + P3_BYTES; // 84 + 96 + 40 = 220
// Expanded SK size (seed_sk + O_bytes + P1_bytes + L_bytes)
pub const ESK_BYTES: usize = SK_SEED_BYTES + O_BYTES + P1_BYTES + L_BYTES; // 32 + 12 + 84 + 96 = 224
