# whodouthinkur

This repo includes exact MAYO signature protocols implemented in Rust and Zig, as well as, an experimental implementation building on XMBL's Cubix Markonium geometric cryptography structure.

A copy of https://github.com/PQCMayo/MAYO-C is included in the repo as a reference implimentation.

## Rust Implementation (rust-mayo)

This directory contains a new from-scratch implementation of the MAYO digital signature scheme in Rust.

*   **Purpose**: To provide a modern, memory-safe, and performant implementation of MAYO.
*   **Current Status**: Initial project scaffold created. The basic structure for the library is in place.
*   **Next Steps**:
    *   Implement F16 finite field arithmetic.
    *   Implement vector operations over F16.
    *   Implement matrix operations over F16.
    *   Develop core cryptographic routines including hashing and AES.
    *   Implement the MAYO key generation, signing, and verification algorithms.
    *   Add comprehensive tests, including Known Answer Tests (KATs).

The C implementation in the `c-mayo` directory is used as a reference.
