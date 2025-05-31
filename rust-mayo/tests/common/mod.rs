use std::fs;
use std::path::Path;
use std::error::Error;

#[derive(Debug)]
pub struct KatVector {
    pub count: usize,
    pub seed: Vec<u8>,
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
    pub msg: Vec<u8>,
    pub sm: Vec<u8>,
}

pub fn hex_decode(hex: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(hex)
}

pub fn parse_kat_file<P: AsRef<Path>>(path: P) -> Result<Vec<KatVector>, Box<dyn Error>> {
    let content = fs::read_to_string(path)?;
    let mut vectors = Vec::new();
    let mut current_vector: Option<KatVector> = None;

    for line in content.lines() {
        if line.starts_with("count = ") {
            if let Some(vector) = current_vector.take() {
                vectors.push(vector);
            }
            let count = line.trim_start_matches("count = ").parse()?;
            current_vector = Some(KatVector {
                count,
                seed: Vec::new(),
                pk: Vec::new(),
                sk: Vec::new(),
                msg: Vec::new(),
                sm: Vec::new(),
            });
        } else if line.starts_with("seed = ") {
            if let Some(ref mut vector) = current_vector {
                vector.seed = hex_decode(line.trim_start_matches("seed = "))?;
            }
        } else if line.starts_with("pk = ") {
            if let Some(ref mut vector) = current_vector {
                vector.pk = hex_decode(line.trim_start_matches("pk = "))?;
            }
        } else if line.starts_with("sk = ") {
            if let Some(ref mut vector) = current_vector {
                vector.sk = hex_decode(line.trim_start_matches("sk = "))?;
            }
        } else if line.starts_with("msg = ") {
            if let Some(ref mut vector) = current_vector {
                vector.msg = hex_decode(line.trim_start_matches("msg = "))?;
            }
        } else if line.starts_with("sm = ") {
            if let Some(ref mut vector) = current_vector {
                vector.sm = hex_decode(line.trim_start_matches("sm = "))?;
            }
        }
    }

    if let Some(vector) = current_vector.take() {
        vectors.push(vector);
    }

    Ok(vectors)
}
