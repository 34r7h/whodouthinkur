// Unpack P2 matrices
let mut p2_matrices = Vec::with_capacity(N);
let mut offset = 0;
for i in 0..N {
    // Calculate offset for P2 matrix
    // Each P1 matrix is 6x6 = 36 elements
    // Each P2 matrix is 6x4 = 24 elements
    // Total bytes per P1 matrix = 36 * 2 = 72 bytes
    // Total bytes per P2 matrix = 24 * 2 = 48 bytes
    // P2 matrices start after all P1 matrices
    offset = (N * 72) + (i * 48);
    println!("[LOG] P2 unpacking iteration {}: offset = {}, remaining bytes = {}", 
        i, offset, p1p2_bytes.len() - offset);
    
    if offset + 48 > p1p2_bytes.len() {
        println!("[ERROR] Not enough bytes left for P2 matrix");
        break;
    }
    
    let mut p2_elements = Vec::with_capacity(24);
    for j in 0..24 {
        let byte_offset = offset + (j * 2);
        if byte_offset + 1 >= p1p2_bytes.len() {
            println!("[ERROR] Not enough bytes for P2 element {} at offset {}", j, byte_offset);
            break;
        }
        let value = ((p1p2_bytes[byte_offset] as u16) << 8) | (p1p2_bytes[byte_offset + 1] as u16);
        p2_elements.push(F16(value));
    }
    
    if p2_elements.len() == 24 {
        p2_matrices.push(Some(Matrix {
            elements: p2_elements,
            rows: 6,
            cols: 4,
        }));
    } else {
        p2_matrices.push(None);
    }
}

// Print first P2 matrix for debugging
println!("[LOG] First P2 matrix: {:?}", p2_matrices.get(0).and_then(|m| m.as_ref()));

// Print all P2 matrices for debugging
println!("[LOG] All P2 matrices:");
for (i, matrix) in p2_matrices.iter().enumerate() {
    println!("[LOG] P2 matrix {}: {:?}", i, matrix);
}

// Print all P1 matrices for debugging
println!("[LOG] All P1 matrices:");
for (i, matrix) in p1_matrices.iter().enumerate() {
    println!("[LOG] P1 matrix {}: {:?}", i, matrix);
} 