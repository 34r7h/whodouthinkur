// In rust-mayo/src/lib.rs
pub mod f16;
pub mod vector;
pub mod matrix;
pub mod encoding;
pub mod params; // Add this line

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
