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

**✅ Core Implementation Complete**: The MAYO digital signature scheme is fully implemented with:
- All 4 parameter sets (MAYO-1, MAYO-2, MAYO-3, MAYO-5)
- Complete key generation, signing, and verification
- WebAssembly bindings for browser usage
- Known Answer Test (KAT) validation

## Usage

### WebAssembly Frontend

A complete web-based demo is available in the `frontend/` directory:

1. **Start the development server:**
   ```bash
   cd rust-mayo
   python3 -m http.server 8080
   ```

2. **Open in browser:** Navigate to `http://localhost:8080/frontend/`

3. **Generate keys:** Click "Generate New Keypair" to create MAYO keys

4. **Sign messages:** Enter text and click "Sign Message" 

5. **Verify signatures:** Click "Verify Signature" to validate

**Available parameter sets:**
- MAYO-1 (Level 1 security)
- MAYO-2 (Level 2 security) 
- MAYO-3 (Level 3 security)
- MAYO-5 (Level 5 security)

### Rust Library

```rust
use rust_mayo::crypto::{generate_keypair_generic, sign_generic, verify_generic};
use rust_mayo::params::Mayo1;

// Generate keypair
let (secret_key, public_key) = generate_keypair_generic::<Mayo1>()?;

// Sign message
let message = b"Hello MAYO!";
let signature = sign_generic::<Mayo1>(&secret_key, message)?;

// Verify signature
let is_valid = verify_generic::<Mayo1>(&public_key, message, &signature)?;
assert!(is_valid);
```

### Building

**For native use:**
```bash
cargo build --release
```

**For WebAssembly:**
```bash
wasm-pack build --target web --out-dir pkg
```

### Testing

Run the test suite including KAT validation:
```bash
cargo test
```

## Contributing

Contributions are welcome. Please refer to the main project README for overall contribution guidelines. Ensure that any contributions align with the cryptographic specifications of MAYO and maintain Rust best practices for safety and performance.

## Build Prompt

Here are detailed instructions for implementing the MAYO digital signature scheme in pseudocode, based on the provided source material. These steps translate the algorithms and descriptions into actionable instructions suitable for building implementations in languages like Rust or Zig.

MAYO is a multivariate quadratic signature scheme, a variant of the Oil and Vinegar scheme, designed for post-quantum cryptography. Its public key is based on a set of multivariate quadratic equations over a small finite field K (specifically, F16 in this specification). Solving such systems is generally NP-hard. MAYO aims for smaller public keys compared to standard Oil and Vinegar by using a smaller "oil space" O than the number of equations, and then "whipping up" the core map into a larger one P*.

The core functionalities of MAYO include key generation, signing, and verification. The specification provides basic functionalities and also describes how to implement the NIST API using these.

Before detailing the algorithms, let's cover the necessary preliminaries, helper functions, and data conversions described in the sources.

Preliminaries and Notation
Finite Field F16: The scheme operates over the finite field F16 with 16 elements. This field is represented concretely as Z2[x]/(x⁴+x+1). Implementations need to support addition, multiplication, and multiplicative inverse over this field. Vectors: Vectors are lists of field elements over F16. Support component-wise sum and scalar multiplication. Vectors can be indexed, and sub-vectors can be extracted. Matrices: Matrices are 0-indexed arrays over F16 with specified dimensions. Support addition, multiplication, and transpose. Specific matrix types include identity matrices and upper triangular matrices. Upper(M): A function that takes a square matrix M ∈ Fn×n and outputs an upper triangular matrix where Upper(M)[i, i] = M[i, i] and Upper(M)[i, j] = M[i, j] + M[j, i] for 0 ≤ i < j < n. Notation: [k] denotes the set {0, ..., k-1}. x $←− X means selecting a value uniformly at random from set X. a || b denotes byte string concatenation. a[x : y] denotes a substring. 2. Helper Functions

Hashing and Randomness Expansion: SHAKE256(X, l): An extendable output function that takes a byte string X and an integer l, outputting l bytes. Used for hashing messages and sampling secret material. AES-128-CTR(seed, l): A seed expansion function taking a 16-byte seed and outputting l bytes. Uses AES-128 in CTR mode. The implementation does not need side-channel protection as inputs/outputs are public. Used to generate public key coefficients. Solving Linear Systems: SampleSolution(A, y, r): Takes an m x ko matrix A of rank m, a target vector y ∈ Fm, and a random vector r ∈ Fko. It outputs a solution x ∈ Fko such that Ax = y. If rank(A) != m, it outputs ⊥. It works by randomizing the system (x ← r, y ← y - Ar), putting (A|y) into echelon form using EF (Algorithm 1), and then using back-substitution to find x' such that Ax' = y', and returning x = x' + r. EF(B): Takes an m x (ko+1) matrix B and outputs its echelon form with leading ones using elementary row operations (swapping rows, scaling rows, eliminating entries below pivots). 3. Data Types and Conversions

Field Element to Nibble: EncodeF16(a): Encodes a field element a (a0 + a1x + a2x² + a3x³) into a 4-bit nibble (a0, a1, a2, a3). Nibble to Field Element: DecodeF16(nibble): The inverse of EncodeF16, taking a nibble and returning the corresponding field element. Vector to Byte String: Encodevec(x): Encodes a vector x ∈ Fn_16 into ⌈n/2⌉ bytes by concatenating the nibble encodings of field elements, padding with a zero nibble if n is odd. Byte String to Vector: Decodevec(n, bytestring): Takes a vector length n and a byte string ∈ B⌈n/2⌉, outputs a vector in Fn_16. It is the inverse of Encodevec. Matrix to Byte String (O): EncodeO(O): Encodes an (n-o) x o matrix O in row-major order into a byte string by encoding its concatenated rows as a vector. Byte String to Matrix (O): DecodeO(bytestring): Inverse of EncodeO, decoding a byte string into an (n-o) x o matrix. Bitsliced Matrix Encoding: EncodeBitslicedMatrices(r, c, {A_i}, is_triangular) (Algorithm 3): Encodes a sequence of m r x c matrices {A_i} into a byte string, using a bitsliced format. If is_triangular is true, it skips elements A_k[i, j] where j < i. Relies on EncodeBitslicedVector (Algorithm 4). EncodeBitslicedVector(v) (Algorithm 4): Encodes a vector v ∈ Fm_16 into m/2 bytes in a bitsliced format. It packs the first bit of v...v into the first byte, the second bit into the (m/8)-th byte, etc.. Specific Matrix Sequence Encodings/Decodings: EncodeP(1): Uses EncodeBitslicedMatrices for (n-o) x (n-o) upper triangular matrices {P(1)_i}. DecodeP(1) is its inverse. EncodeP(2): Uses EncodeBitslicedMatrices for (n-o) x o matrices {P(2)_i} (not triangular). DecodeP(2) is its inverse. EncodeP(3): Uses EncodeBitslicedMatrices for o x o upper triangular matrices {P(3)_i}. DecodeP(3) is its inverse. EncodeL: Uses EncodeP(2) for (n-o) x o matrices {L_i}. DecodeL is its inverse. 4. MAYO.CompactKeyGen() (Algorithm 5)

This function generates a compact secret key (csk) and a compact public key (cpk).

Pick Secret Seed: Choose a byte string seedsk uniformly at random of length sk_seed_bytes. Derive Public Seed and Oil Matrix: Call SHAKE256 with seedsk and output length pk_seed_bytes + O_bytes to get a byte string S. Parse S: The first pk_seed_bytes of S is seedpk. The next O_bytes of S is the encoded oil matrix. Decode this using DecodeO to get the matrix O ∈ F(n-o)×o. Derive P(1) and P(2) Matrices: Call AES-128-CTR with seedpk and output length P1_bytes + P2_bytes to get a byte string P. Parse P: The first P1_bytes of P encodes the sequence of m upper triangular (n-o) x (n-o) matrices {P(1)_i}. Decode this using DecodeP(1). The next P2_bytes of P encodes the sequence of m (n-o) x o matrices {P(2)_i}. Decode this using DecodeP(2). Compute P(3) Matrices: For each index i from 0 to m-1: Compute the matrix -O^T P(1)_i O - O^T P(2)_i. Apply the Upper function to this matrix to get the upper triangular matrix P(3)_i ∈ Fo×o. Encode P(3) Matrices: Encode the sequence of {P(3)_i} matrices using EncodeP(3). Construct Compact Public Key: cpk is the concatenation of seedpk and the encoded {P(3)_i}. cpk ∈ Bcpk_bytes. Construct Compact Secret Key: csk is seedsk. csk ∈ Bcsk_bytes. Output: Return the pair (cpk, csk). 5. MAYO.ExpandSK(csk) (Algorithm 6)

This function expands a compact secret key into an expanded secret key (esk).

Parse Compact Secret Key: Extract seedsk from csk by taking the first sk_seed_bytes. Derive Public Seed and Oil Matrix: Call SHAKE256 with seedsk and output length pk_seed_bytes + O_bytes to get a byte string S. Parse S: The first pk_seed_bytes of S is seedpk. The next O_bytes of S is O_bytestring. Decode O_bytestring using DecodeO to get the matrix O ∈ F(n-o)×o. Derive P(1) and P(2) Matrices: Call AES-128-CTR with seedpk and output length P1_bytes + P2_bytes to get a byte string P. Parse P: The first P1_bytes of P encodes {P(1)_i}. Decode this using DecodeP(1). The next P2_bytes of P encodes {P(2)_i}. Decode this using DecodeP(2). Compute L Matrices: For each index i from 0 to m-1: Compute the matrix Li = (P(1)_i + P(1)_i^T) O + P(2)_i. Li ∈ F(n-o)×o. Encode L Matrices: Encode the sequence of {L_i} matrices using EncodeL. Construct Expanded Secret Key: esk is the concatenation of seedsk, O_bytestring, the first P1_bytes of P, and the encoded {L_i}. esk ∈ Besk_bytes. Output: Return esk. 6. MAYO.ExpandPK(cpk) (Algorithm 7)

This function expands a compact public key into an expanded public key (epk).

Parse Compact Public Key: Extract seedpk from cpk by taking the first pk_seed_bytes. Expand Seed and Construct Expanded Public Key: Call AES-128-CTR with seedpk and output length P1_bytes + P2_bytes. Concatenate the result with the portion of cpk starting from pk_seed_bytes and ending at pk_seed_bytes + P3_bytes. This concatenated byte string is epk ∈ Bepk_bytes. Output: Return epk. Note that epk contains the encoded P(1), P(2), and P(3) matrices derived from the seed and stored in the compact key. 7. MAYO.Sign(esk, M) (Algorithm 8)

This function generates a signature for a message M using an expanded secret key (esk).

Decode Expanded Secret Key: Parse esk to retrieve seedsk, matrix O, sequence of matrices {P(1)_i}, and sequence of matrices {L_i}. seedsk is the first sk_seed_bytes. O is obtained by DecodeO on bytes sk_seed_bytes to sk_seed_bytes + O_bytes of esk. {P(1)_i} are obtained by DecodeP(1) on bytes sk_seed_bytes + O_bytes to sk_seed_bytes + O_bytes + P1_bytes of esk. {L_i} are obtained by DecodeL on bytes sk_seed_bytes + O_bytes + P1_bytes to the end of esk. Hash Message: Call SHAKE256 with message M and output length digest_bytes to get M_digest. Derive Salt and Target: Choose a randomizer R (optional, can be 0) of length R_bytes. Compute salt by calling SHAKE256 with M_digest || R || seedsk and output length salt_bytes. Compute target vector t ∈ Fm_q by calling SHAKE256 with M_digest || salt and output length ⌈m log(q)/8⌉, then decoding using Decodevec with dimension m. Attempt to Find Preimage (Loop): Start a loop iterating ctr from 0 to 255. Derive vi and r: Inside the loop, call SHAKE256 with M_digest || salt || seedsk || ctr and output length k * v_bytes + ⌈ko log(q)/8⌉ to get byte string V. Parse V: For each index i from 0 to k-1, extract the i-th (n-o) vector vi by Decodevec from bytes i * v_bytes to (i+1) * v_bytes of V. Extract vector r ∈ Fko_q by Decodevec from bytes k * v_bytes to the end of V. Build Linear System Ax = y: Initialize an m x ko matrix A with all zeros. Initialize an m x 1 vector y as t. Initialize an index ℓ to 0. Compute Mi Matrices: For each index i from 0 to m-1, compute an m x o matrix Mi. For each index j from 0 to m-1, set the j-th row of Mi (Mi[j, :]) to the result of the vector-matrix product vTi Lj (where vTi is the transpose of v from step 6). Accumulate System Coefficients: Iterate through pairs of indices (i, j) where i goes from 0 to k-1 and j goes from k-1 down to i. Compute u: If i == j, compute u as the vector { vTi P(1)a vi } for a from 0 to m-1. If i != j, compute u as the vector { vTi P(1)a vj + vTjP(1)a vi } for a from 0 to m-1. u is an m-dimensional vector. Note: This calculation of u corresponds to evaluating the constant part (relative to linearization variables x_i, x_j) of the underlying quadratic forms, as described in the thought process. Update y: Subtract E^ℓ u from y. The matrix E is a constant representing multiplication by z in F16[z]/f(z). Update A: Add E^ℓ Mi to the submatrix of A covering columns i * o to (i + 1) * o (A[:, i*o : (i+1)o]). If i != j: Add E^ℓ Mj to the submatrix of A covering columns j * o to (j + 1) * o (A[:, jo : (j+1)*o]). Increment ℓ: ℓ ← ℓ + 1. Solve the System: Call SampleSolution with matrix A, vector y, and random vector r. Store the output in x. x is either a vector in Fko_q or ⊥. Check for Solution: If x is not ⊥ (i.e., a solution was found), break out of the ctr loop. Format Signature: Initialize a vector s ∈ Fkn_q with zeros. For each index i from 0 to k-1: Extract the o-dimensional vector x_i from x (bytes i * o to (i + 1) * o of x). Compute the n-dimensional vector s_i as the concatenation of (vi + O x_i) and x_i. (vi is the vector derived in step 6, size n-o; O is the matrix from step 1, size (n-o)xo; Ox_i is matrix-vector product, size n-o; vi + Ox_i is vector sum, size n-o; x_i is vector size o). Set the i-th block of s (bytes i * n to (i + 1) * n) to s_i. Output Signature: Concatenate the byte string encoding of s (using Encodevec) and the salt. This is the signature sig ∈ Bsig_bytes. Return sig. 8. MAYO.Verify(epk, M, sig) (Algorithm 9)

This function verifies a signature (sig) for a message (M) using an expanded public key (epk).

Decode Expanded Public Key: Parse epk to retrieve the encoded P(1), P(2), and P(3) matrices. P1_bytestring is the first P1_bytes of epk. Decode using DecodeP(1) to get {P(1)_i}. P2_bytestring is bytes P1_bytes to P1_bytes + P2_bytes of epk. Decode using DecodeP(2) to get {P(2)_i}. P3_bytestring is bytes P1_bytes + P2_bytes to P1_bytes + P2_bytes + P3_bytes of epk. Decode using DecodeP(3) to get {P(3)_i}. Decode Signature: Parse sig to retrieve the encoded signature value (s) and the salt. salt is the last salt_bytes of sig. The preceding bytes (⌈nk/2⌉ bytes) encode the vector s. Decode using Decodevec with dimension kn to get s ∈ Fkn_q. Split s into blocks: For each index i from 0 to k-1, extract the n-dimensional vector si from s (bytes i * n to (i + 1) * n of s). Hash Message: Call SHAKE256 with message M and output length digest_bytes to get M_digest. Derive Target: Compute target vector t ∈ Fm_q by calling SHAKE256 with M_digest || salt and output length ⌈m log(q)/8⌉, then decoding using Decodevec with dimension m. This is the expected value of P*(s). Compute P*(s): Initialize an m-dimensional vector y with zeros. Initialize an index ℓ to 0. Iterate through pairs of indices (i, j) where i goes from 0 to k-1 and j goes from k-1 down to i. Split s_i and s_j: For each vector s_i (size n) and s_j (size n), split them into a first part of size n-o (let's call them v'_i and v'_j respectively) and a second part of size o (let's call them o'_i and o'_j respectively) [implicitly used in 45]. s_i = [v'_i; o'_i], s_j = [v'_j; o'_j]. Compute u: For each index a from 0 to m-1, compute the a-th component of u as follows: If i == j: u_a = sTi M_a si, where M_a is the n x n matrix [ P(1)_a P(2)_a; 0 P(3)_a ]. (This expands to v'_i^T P(1)_a v'_i + v'_i^T P(2)_a o'_i + o'_i^T P(3)_a o'_i). If i != j: u_a = sTi M_a sj + sTj M_a si, where M_a is the same matrix as above. (This expands to (v'_i^T P(1)_a v'_j + v'_i^T P(2)_a o'_j + o'_i^T P(3)_a o'_j) + (v'_j^T P(1)_a v'_i + v'_j^T P(2)_a o'_i + o'_j^T P(3)_a o'_i)). Update y: Add E^ℓ u to y. The matrix E is the same constant matrix as in the Sign algorithm. Increment ℓ: ℓ ← ℓ + 1. Check for Validity: Compare the computed vector y with the target vector t. Output Result: If y is equal to t, return 0 (signature is valid). Otherwise, return -1 (signature is invalid). 9. NIST API Implementations

The source also defines how the standard NIST API functions are implemented using the basic MAYO functionalities:

MAYO.API.keypair() (Algorithm 5): This is identical to MAYO.CompactKeyGen() and outputs the compact (sk, pk) pair. MAYO.API.sign(M, sk) (Algorithm 10): Takes a message M and a compact secret key sk. It first calls MAYO.ExpandSK(sk) to get the expanded secret key esk. Then it calls MAYO.Sign(esk, M) to produce the signature sig. Finally, it returns the signed message sm which is the concatenation of sig and M (sig || M). MAYO.API.sign_open(pk, sm) (Algorithm 11): Takes a compact public key pk and a signed message sm. It first calls MAYO.ExpandPK(pk) to get the expanded public key epk. It then parses sm into the signature sig (first sig_bytes) and the original message M (remaining bytes). It calls MAYO.Verify(epk, M, sig) to check the signature validity, storing the result. If the result is less than 0 (invalid), it returns the result and ⊥ for the message. If the result is 0 (valid), it returns the result and the message M. Parameters:

The specific sizes and dimensions (n, m, o, k, q, salt_bytes, etc.) are defined for different security levels (MAYO1, MAYO2, MAYO3, MAYO5) in Section 2.1.7 and summarized in Table 2.1 and 2.2. The sizes of keys and signatures (csk_bytes, cpk_bytes, esk_bytes, epk_bytes, sig_bytes) are derived from these parameters. The irreducible polynomial f(z) for F16[z]/f(z) is also specified per parameter set. The matrix E corresponding to multiplication by z mod f(z) in Fm_q must be constructed based on the chosen f(z).

These pseudocode steps provide a comprehensive guide drawn directly from the source document, detailing the operations, data structures, and helper functions necessary to implement the MAYO digital signature scheme. Implementing this will require careful attention to the finite field arithmetic, matrix operations, vector manipulations, and the specific byte-level encoding/decoding functions, including the bitsliced format.