# whodouthinkur

This repo includes exact MAYO signature protocols implemented in Rust, as well as, an experimental implementation building on XMBL's Cubix Markonium geometric cryptography structure.

A copy of https://github.com/PQCMayo/MAYO-C is included in the repo as a reference implementation.

## Rust Implementation (rust-mayo)

This directory contains a complete from-scratch implementation of the MAYO digital signature scheme in Rust.

*   **Purpose**: To provide a modern, memory-safe, and performant implementation of MAYO with support for all standardized parameter sets.

### Current Status ✅

**Complete multi-parameter MAYO digital signature implementation supporting:**

- **MAYO-1** (n=66, m=64, o=8): SK=24B, PK=1,168B, SIG=329B
- **MAYO-2** (n=78, m=64, o=18): SK=24B, PK=2,152B, SIG=180B  
- **MAYO-3** (n=99, m=96, o=10): SK=32B, PK=2,656B, SIG=266B
- **MAYO-5** (n=133, m=128, o=12): SK=40B, PK=5,488B, SIG=838B

**Implemented Components:**
- ✅ F16 finite field arithmetic with full GF(2^4) operations
- ✅ Vector operations over F16 with encoding/decoding
- ✅ Matrix operations over F16 with transpose, multiplication, and upper triangular forms
- ✅ Cryptographic primitives (SHAKE-256, AES-128-CTR)
- ✅ Generic parameter system supporting all MAYO variants
- ✅ Complete key generation, signing, and verification algorithms
- ✅ Comprehensive test suite (59 unit tests + 5 integration tests)
- ✅ Known Answer Test (KAT) validation against official NIST test vectors
- ✅ Security property validation and message tampering detection

**Test Results:**
- All 64 tests passing (100% pass rate)
- KAT validation: 5/5 vectors passed for all parameter sets
- Zero test failures across all MAYO variants

### How to Use This Library

#### Basic Usage

```rust
use rust_mayo::crypto::{generate_keypair_generic, sign_generic, verify_generic};
use rust_mayo::params::{Mayo1, Mayo2, Mayo3, Mayo5};

// Generate keypair for MAYO-1
let (secret_key, public_key) = generate_keypair_generic::<Mayo1>()?;

// Sign a message
let message = b"Hello MAYO world!";
let signature = sign_generic::<Mayo1>(&secret_key, message)?;

// Verify signature
let is_valid = verify_generic::<Mayo1>(&public_key, message, &signature)?;
assert!(is_valid);
```

#### Using Different Parameter Sets

```rust
// MAYO-2 (smallest signatures)
let (sk2, pk2) = generate_keypair_generic::<Mayo2>()?;
let sig2 = sign_generic::<Mayo2>(&sk2, message)?;

// MAYO-3 (balanced performance)
let (sk3, pk3) = generate_keypair_generic::<Mayo3>()?;
let sig3 = sign_generic::<Mayo3>(&sk3, message)?;

// MAYO-5 (highest security)
let (sk5, pk5) = generate_keypair_generic::<Mayo5>()?;
let sig5 = sign_generic::<Mayo5>(&sk5, message)?;
```

#### Backward Compatibility (MAYO-1 only)

```rust
use rust_mayo::crypto::{generate_keypair, sign, verify};

let (secret_key, public_key) = generate_keypair()?;
let signature = sign(&secret_key, b"message")?;
let is_valid = verify(&public_key, b"message", &signature)?;
```

#### Running the Demo

```bash
cd rust-mayo
cargo run  # Demonstrates all parameter sets with KAT testing
cargo test # Runs comprehensive test suite
```

### Next Steps

**Potential Enhancements:**
- [ ] Performance optimizations (SIMD, assembly optimizations)
- [ ] Hardware acceleration support (AES-NI, AVX2)
- [ ] Constant-time implementation guarantees
- [ ] WASM compilation support
- [ ] FFI bindings for C/Python interoperability
- [ ] Benchmarking against reference implementation
- [ ] Memory usage optimization
- [ ] Documentation improvements with cryptographic background

**Research Directions:**
- [ ] Side-channel resistance analysis
- [ ] Formal verification of critical components
- [ ] Post-quantum security analysis updates
- [ ] Integration with standard cryptographic libraries

The C implementation in the `c-mayo` directory is used as a reference.
