# rust-mayo - Rust Implementation of MAYO

This crate provides a Rust implementation of the MAYO digital signature scheme, as specified in the official MAYO documentation. This work aims to offer a memory-safe and efficient alternative for post-quantum digital signatures.

## Purpose

The primary goal of this project is to implement the MAYO digital signature scheme in Rust, adhering to the specifications and algorithms outlined. This includes:

*   Finite field arithmetic (F16).
*   Vector and matrix operations over F16.
*   Encoding and decoding routines, including bitsliced methods.
*   Cryptographic helper functions (SHAKE256, AES-128-CTR).
*   The core MAYO algorithms: `CompactKeyGen`, `ExpandSK`, `ExpandPK`, `Sign`, and `Verify`.
*   NIST API compatible functions: `keypair`, `sign`, and `sign_open`.

## Current Status

Project initialized. The foundational structure of the Rust crate is set up. Core cryptographic functionalities are under development.

## Next Steps

The immediate next steps involve implementing the foundational layers of the MAYO scheme:

1.  **F16 Finite Field Arithmetic**: Implement operations (addition, multiplication, inverse) and encoding/decoding for elements in F16.
2.  **Vector Operations**: Develop structures and operations for vectors over F16, including encoding/decoding.
3.  **Matrix Operations**: Implement matrix structures, basic operations (addition, multiplication, transpose), the `Upper(M)` function, and encoding/decoding for the O matrix.
4.  **Bitsliced Encodings**: Implement the bitsliced encoding schemes for P1, P2, P3, and L matrices.
5.  **Helper Functions**: Integrate SHAKE256 and AES-128-CTR.
6.  **Linear Algebra**: Implement the Echelon Form (`EF`) and `SampleSolution` functions.

Following these, the main MAYO algorithms and NIST API will be implemented.

## Contributing

Contributions are welcome. Please refer to the main project README for overall contribution guidelines. Ensure that any contributions align with the cryptographic specifications of MAYO and maintain Rust best practices for safety and performance.
