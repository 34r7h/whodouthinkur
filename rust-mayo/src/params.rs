// rust-mayo/src/params.rs

// MAYO parameter sets trait and implementations
pub trait MayoParams {
    const M_PARAM: usize;
    const N_PARAM: usize;
    const O_PARAM: usize;
    const K_PARAM: usize;
    const KO_PARAM: usize;
    
    // Matrix element counts
    const P1_ELEMS_PER_MATRIX: usize;
    const P2_ELEMS_PER_MATRIX: usize;
    const P3_ELEMS_PER_MATRIX: usize;
    
    // Byte sizes
    const SALT_BYTES: usize;
    const DIGEST_BYTES: usize;
    const SK_SEED_BYTES: usize;
    const PK_SEED_BYTES: usize;
    const O_BYTES: usize;
    const P1_BYTES: usize;
    const P2_BYTES: usize;
    const P3_BYTES: usize;
    
    // Key and signature sizes
    const CSK_BYTES: usize;
    const CPK_BYTES: usize;
    const SIG_BYTES: usize;
    
    // Additional constants
    const R_BYTES: usize;
    const V_BYTES: usize;
    const O_ELTS: usize;
    const L_BYTES: usize;
    const ESK_BYTES: usize;
    const EPK_BYTES: usize;
    
    // Matrix dimensions
    const P1_MAT_ROWS: usize;
    const P1_MAT_COLS: usize;
    const P1_IS_TRIANGULAR: bool;
    const P2_MAT_ROWS: usize;
    const P2_MAT_COLS: usize;
    const P2_IS_TRIANGULAR: bool;
    const P3_MAT_ROWS: usize;
    const P3_MAT_COLS: usize;
    const P3_IS_TRIANGULAR: bool;
    const L_MAT_ROWS: usize;
    const L_MAT_COLS: usize;
    const L_IS_TRIANGULAR: bool;
    
    fn name() -> &'static str;
    fn security_level() -> usize;
}

// MAYO-1 parameter set
pub struct Mayo1;

impl MayoParams for Mayo1 {
    const M_PARAM: usize = 78;      // From MAYO spec
    const N_PARAM: usize = 86;      // From MAYO spec  
    const O_PARAM: usize = 8;       // From MAYO spec
    const K_PARAM: usize = 10;      // From MAYO spec
    const KO_PARAM: usize = 80;     // k * o = 10 * 8
    
    // Corrected element counts based on proper MAYO formulas
    const P1_ELEMS_PER_MATRIX: usize = 3081; // (n-o)*(n-o+1)/2 = 78*79/2
    const P2_ELEMS_PER_MATRIX: usize = 624;  // (n-o)*o = 78*8
    const P3_ELEMS_PER_MATRIX: usize = 36;   // o*(o+1)/2 = 8*9/2
    
    const SALT_BYTES: usize = 24;   // From C implementation
    const DIGEST_BYTES: usize = 32;
    const SK_SEED_BYTES: usize = 24;
    const PK_SEED_BYTES: usize = 16;
    const O_BYTES: usize = 312;     // From C implementation
    const P1_BYTES: usize = 120159; // From C implementation  
    const P2_BYTES: usize = 24336;  // From C implementation
    const P3_BYTES: usize = 1404;   // From C implementation
    
    const CSK_BYTES: usize = 24;
    const CPK_BYTES: usize = 1420;  // From C implementation
    const SIG_BYTES: usize = 454;   // From C implementation
    
    const R_BYTES: usize = 40;      // From C implementation
    const V_BYTES: usize = 39;      // From C implementation
    const O_ELTS: usize = 624;      // (n-o)*o = 78*8
    const L_BYTES: usize = 24336;   // Same as P2_BYTES
    const ESK_BYTES: usize = Self::SK_SEED_BYTES + Self::O_BYTES + Self::P1_BYTES + Self::L_BYTES;
    const EPK_BYTES: usize = Self::P1_BYTES + Self::P2_BYTES + Self::P3_BYTES;
    
    // Matrix dimensions corrected to match MAYO spec
    const P1_MAT_ROWS: usize = 78;  // n-o
    const P1_MAT_COLS: usize = 78;  // n-o
    const P1_IS_TRIANGULAR: bool = true;
    const P2_MAT_ROWS: usize = 78;  // n-o
    const P2_MAT_COLS: usize = 8;   // o
    const P2_IS_TRIANGULAR: bool = false;
    const P3_MAT_ROWS: usize = 8;   // o
    const P3_MAT_COLS: usize = 8;   // o
    const P3_IS_TRIANGULAR: bool = true;
    const L_MAT_ROWS: usize = 78;   // n-o
    const L_MAT_COLS: usize = 8;    // o
    const L_IS_TRIANGULAR: bool = false;
    
    fn name() -> &'static str { "MAYO-1" }
    fn security_level() -> usize { 1 }
}

// MAYO-2 parameter set
pub struct Mayo2;

impl MayoParams for Mayo2 {
    const M_PARAM: usize = 64;
    const N_PARAM: usize = 78;
    const O_PARAM: usize = 18;
    const K_PARAM: usize = 4;
    const KO_PARAM: usize = 72; // k * o
    
    const P1_ELEMS_PER_MATRIX: usize = 1830; // (n-o)*(n-o+1)/2 = 60*61/2
    const P2_ELEMS_PER_MATRIX: usize = 1080; // (n-o)*o = 60*18
    const P3_ELEMS_PER_MATRIX: usize = 171;  // o*(o+1)/2 = 18*19/2
    
    const SALT_BYTES: usize = 32;
    const DIGEST_BYTES: usize = 32;
    const SK_SEED_BYTES: usize = 24;
    const PK_SEED_BYTES: usize = 16;
    const O_BYTES: usize = 540; // ((n-o)*o+1)/2
    const P1_BYTES: usize = 58560; // P1_ELEMS_PER_MATRIX * 4 * 8
    const P2_BYTES: usize = 34560; // P2_ELEMS_PER_MATRIX * 4 * 8
    const P3_BYTES: usize = 5472;  // P3_ELEMS_PER_MATRIX * 4 * 8
    
    const CSK_BYTES: usize = 24;
    const CPK_BYTES: usize = 2152;
    const SIG_BYTES: usize = 180; // 148 + 32
    
    const R_BYTES: usize = 32;
    const V_BYTES: usize = 31; // ((n-o)+1)/2
    const O_ELTS: usize = 1080; // (n-o)*o
    const L_BYTES: usize = 34560; // Same as P2_BYTES
    const ESK_BYTES: usize = Self::SK_SEED_BYTES + Self::O_BYTES + Self::P1_BYTES + Self::L_BYTES;
    const EPK_BYTES: usize = Self::P1_BYTES + Self::P2_BYTES + Self::P3_BYTES;
    
    const P1_MAT_ROWS: usize = 60;
    const P1_MAT_COLS: usize = 60;
    const P1_IS_TRIANGULAR: bool = true;
    const P2_MAT_ROWS: usize = 60;
    const P2_MAT_COLS: usize = 18;
    const P2_IS_TRIANGULAR: bool = false;
    const P3_MAT_ROWS: usize = 18;
    const P3_MAT_COLS: usize = 18;
    const P3_IS_TRIANGULAR: bool = true;
    const L_MAT_ROWS: usize = 60;
    const L_MAT_COLS: usize = 18;
    const L_IS_TRIANGULAR: bool = false;
    
    fn name() -> &'static str { "MAYO-2" }
    fn security_level() -> usize { 2 }
}

// MAYO-3 parameter set
pub struct Mayo3;

impl MayoParams for Mayo3 {
    const M_PARAM: usize = 96;
    const N_PARAM: usize = 99;
    const O_PARAM: usize = 10;
    const K_PARAM: usize = 11;
    const KO_PARAM: usize = 110; // k * o
    
    const P1_ELEMS_PER_MATRIX: usize = 4005; // (n-o)*(n-o+1)/2 = 89*90/2
    const P2_ELEMS_PER_MATRIX: usize = 890;  // (n-o)*o = 89*10
    const P3_ELEMS_PER_MATRIX: usize = 55;   // o*(o+1)/2 = 10*11/2
    
    const SALT_BYTES: usize = 32;
    const DIGEST_BYTES: usize = 32;
    const SK_SEED_BYTES: usize = 32;
    const PK_SEED_BYTES: usize = 16;
    const O_BYTES: usize = 445; // ((n-o)*o+1)/2
    const P1_BYTES: usize = 128160; // P1_ELEMS_PER_MATRIX * 4 * 8
    const P2_BYTES: usize = 28480;  // P2_ELEMS_PER_MATRIX * 4 * 8
    const P3_BYTES: usize = 1760;   // P3_ELEMS_PER_MATRIX * 4 * 8
    
    const CSK_BYTES: usize = 32;
    const CPK_BYTES: usize = 2656;
    const SIG_BYTES: usize = 266; // 234 + 32
    
    const R_BYTES: usize = 32;
    const V_BYTES: usize = 45; // ((n-o)+1)/2
    const O_ELTS: usize = 890; // (n-o)*o
    const L_BYTES: usize = 28480; // Same as P2_BYTES
    const ESK_BYTES: usize = Self::SK_SEED_BYTES + Self::O_BYTES + Self::P1_BYTES + Self::L_BYTES;
    const EPK_BYTES: usize = Self::P1_BYTES + Self::P2_BYTES + Self::P3_BYTES;
    
    const P1_MAT_ROWS: usize = 89;
    const P1_MAT_COLS: usize = 89;
    const P1_IS_TRIANGULAR: bool = true;
    const P2_MAT_ROWS: usize = 89;
    const P2_MAT_COLS: usize = 10;
    const P2_IS_TRIANGULAR: bool = false;
    const P3_MAT_ROWS: usize = 10;
    const P3_MAT_COLS: usize = 10;
    const P3_IS_TRIANGULAR: bool = true;
    const L_MAT_ROWS: usize = 89;
    const L_MAT_COLS: usize = 10;
    const L_IS_TRIANGULAR: bool = false;
    
    fn name() -> &'static str { "MAYO-3" }
    fn security_level() -> usize { 3 }
}

// MAYO-5 parameter set
pub struct Mayo5;

impl MayoParams for Mayo5 {
    const M_PARAM: usize = 128;
    const N_PARAM: usize = 133;
    const O_PARAM: usize = 12;
    const K_PARAM: usize = 12;
    const KO_PARAM: usize = 144; // k * o
    
    const P1_ELEMS_PER_MATRIX: usize = 7381; // (n-o)*(n-o+1)/2 = 121*122/2
    const P2_ELEMS_PER_MATRIX: usize = 1452; // (n-o)*o = 121*12
    const P3_ELEMS_PER_MATRIX: usize = 78;   // o*(o+1)/2 = 12*13/2
    
    const SALT_BYTES: usize = 32;
    const DIGEST_BYTES: usize = 32;
    const SK_SEED_BYTES: usize = 40;
    const PK_SEED_BYTES: usize = 16;
    const O_BYTES: usize = 726; // ((n-o)*o+1)/2
    const P1_BYTES: usize = 236192; // P1_ELEMS_PER_MATRIX * 4 * 8
    const P2_BYTES: usize = 46464;  // P2_ELEMS_PER_MATRIX * 4 * 8
    const P3_BYTES: usize = 2496;   // P3_ELEMS_PER_MATRIX * 4 * 8
    
    const CSK_BYTES: usize = 40;
    const CPK_BYTES: usize = 5488;
    const SIG_BYTES: usize = 838; // 806 + 32
    
    const R_BYTES: usize = 32;
    const V_BYTES: usize = 61; // ((n-o)+1)/2
    const O_ELTS: usize = 1452; // (n-o)*o
    const L_BYTES: usize = 46464; // Same as P2_BYTES
    const ESK_BYTES: usize = Self::SK_SEED_BYTES + Self::O_BYTES + Self::P1_BYTES + Self::L_BYTES;
    const EPK_BYTES: usize = Self::P1_BYTES + Self::P2_BYTES + Self::P3_BYTES;
    
    const P1_MAT_ROWS: usize = 121;
    const P1_MAT_COLS: usize = 121;
    const P1_IS_TRIANGULAR: bool = true;
    const P2_MAT_ROWS: usize = 121;
    const P2_MAT_COLS: usize = 12;
    const P2_IS_TRIANGULAR: bool = false;
    const P3_MAT_ROWS: usize = 12;
    const P3_MAT_COLS: usize = 12;
    const P3_IS_TRIANGULAR: bool = true;
    const L_MAT_ROWS: usize = 121;
    const L_MAT_COLS: usize = 12;
    const L_IS_TRIANGULAR: bool = false;
    
    fn name() -> &'static str { "MAYO-5" }
    fn security_level() -> usize { 5 }
}

// Default to MAYO-1 for backward compatibility
pub use Mayo1 as DefaultParams;

// Re-export constants for backward compatibility
pub const M_PARAM: usize = Mayo1::M_PARAM;
pub const N_PARAM: usize = Mayo1::N_PARAM;
pub const O_PARAM: usize = Mayo1::O_PARAM;
pub const K_PARAM: usize = Mayo1::K_PARAM;
pub const KO_PARAM: usize = Mayo1::KO_PARAM;
pub const P1_ELEMS_PER_MATRIX: usize = Mayo1::P1_ELEMS_PER_MATRIX;
pub const P2_ELEMS_PER_MATRIX: usize = Mayo1::P2_ELEMS_PER_MATRIX;
pub const P3_ELEMS_PER_MATRIX: usize = Mayo1::P3_ELEMS_PER_MATRIX;
pub const SALT_BYTES: usize = Mayo1::SALT_BYTES;
pub const DIGEST_BYTES: usize = Mayo1::DIGEST_BYTES;
pub const SK_SEED_BYTES: usize = Mayo1::SK_SEED_BYTES;
pub const PK_SEED_BYTES: usize = Mayo1::PK_SEED_BYTES;
pub const O_BYTES: usize = Mayo1::O_BYTES;
pub const P1_BYTES: usize = Mayo1::P1_BYTES;
pub const P2_BYTES: usize = Mayo1::P2_BYTES;
pub const P3_BYTES: usize = Mayo1::P3_BYTES;
pub const CSK_BYTES: usize = Mayo1::CSK_BYTES;
pub const CPK_BYTES: usize = Mayo1::CPK_BYTES;
pub const SIG_BYTES: usize = Mayo1::SIG_BYTES;
pub const R_BYTES: usize = Mayo1::R_BYTES;
pub const V_BYTES: usize = Mayo1::V_BYTES;
pub const O_ELTS: usize = Mayo1::O_ELTS;
pub const L_BYTES: usize = Mayo1::L_BYTES;
pub const ESK_BYTES: usize = Mayo1::ESK_BYTES;
pub const EPK_BYTES: usize = Mayo1::EPK_BYTES;
pub const P1_MAT_ROWS: usize = Mayo1::P1_MAT_ROWS;
pub const P1_MAT_COLS: usize = Mayo1::P1_MAT_COLS;
pub const P1_IS_TRIANGULAR: bool = Mayo1::P1_IS_TRIANGULAR;
pub const P2_MAT_ROWS: usize = Mayo1::P2_MAT_ROWS;
pub const P2_MAT_COLS: usize = Mayo1::P2_MAT_COLS;
pub const P2_IS_TRIANGULAR: bool = Mayo1::P2_IS_TRIANGULAR;
pub const P3_MAT_ROWS: usize = Mayo1::P3_MAT_ROWS;
pub const P3_MAT_COLS: usize = Mayo1::P3_MAT_COLS;
pub const P3_IS_TRIANGULAR: bool = Mayo1::P3_IS_TRIANGULAR;
pub const L_MAT_ROWS: usize = Mayo1::L_MAT_ROWS;
pub const L_MAT_COLS: usize = Mayo1::L_MAT_COLS;
pub const L_IS_TRIANGULAR: bool = Mayo1::L_IS_TRIANGULAR;
