// In rust-mayo/src/lib.rs
pub mod f16;
pub mod vector;
pub mod matrix;
pub mod encoding;
pub mod params; // Add this line
pub mod crypto; // Add new module for crypto functions
pub mod wasm_api;

// Re-export main functions for convenience
pub use crypto::{generate_keypair, sign, verify};
pub use params::{Mayo1, Mayo2, Mayo3, Mayo5};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_basic_crypto_operations;
    use crate::params::Mayo1;

    #[test]
    fn test_mayo_basic_operations() {
        match test_basic_crypto_operations::<Mayo1>() {
            Ok(()) => println!("✅ Basic crypto operations test passed!"),
            Err(e) => panic!("❌ Basic crypto operations test failed: {}", e),
        }
    }
}
