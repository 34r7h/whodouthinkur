// Import the Wasm module
// Note: Adjust the path to your wasm module,
// it's usually in a 'pkg' directory relative to your HTML file or project root.
// For this test, we assume the html file is in 'rust-mayo/tests/'
// and the pkg dir is 'rust-mayo/pkg/'
import init, { generate_mayo_keypair, sign_with_mayo, verify_with_mayo } from '../pkg/rust_mayo.js';

async function runTests() {
    // Initialize the Wasm module
    await init();
    console.log("Wasm module initialized.");

    const paramSet = "MAYO1";
    console.log(`Testing with parameter set: ${paramSet}`);

    try {
        // Test Key Generation
        console.log("Attempting to generate keypair...");
        const keys = generate_mayo_keypair(paramSet);
        const secretKey = keys[0]; // Assuming Uint8Array
        const publicKey = keys[1]; // Assuming Uint8Array
        console.log(`Keypair generated for ${paramSet}:`);
        console.log("  Secret Key length:", secretKey.length);
        console.log("  Public Key length:", publicKey.length);
        if (secretKey.length === 0 || publicKey.length === 0) {
            console.error("Error: Key generation returned empty keys.");
            return;
        }

        // Test Signing
        const message = new TextEncoder().encode("Hello Wasm from rust-mayo!");
        console.log("Attempting to sign message...");
        const signature = sign_with_mayo(paramSet, secretKey, message);
        console.log(`Message signed with ${paramSet}:`);
        console.log("  Signature length:", signature.length);
        if (signature.length === 0) {
            console.error("Error: Signing returned an empty signature.");
            return;
        }

        // Test Verification
        console.log("Attempting to verify signature...");
        const isValid = verify_with_mayo(paramSet, publicKey, message, signature);
        console.log(`Signature verification result for ${paramSet}: ${isValid}`);

        if (isValid) {
            console.log("SUCCESS: All tests passed for " + paramSet);
        } else {
            console.error("FAILURE: Signature verification failed for " + paramSet);
        }

        // Test with a different parameter set (e.g., MAYO2) to ensure selection works
        const paramSet2 = "MAYO2";
        console.log(`
Testing with parameter set: ${paramSet2}`);
        const keys2 = generate_mayo_keypair(paramSet2);
        const secretKey2 = keys2[0];
        const publicKey2 = keys2[1];
        console.log(`Keypair generated for ${paramSet2}:`);
        console.log("  Secret Key length:", secretKey2.length);
        console.log("  Public Key length:", publicKey2.length);

        const signature2 = sign_with_mayo(paramSet2, secretKey2, message);
        console.log(`Message signed with ${paramSet2}:`);
        console.log("  Signature length:", signature2.length);

        const isValid2 = verify_with_mayo(paramSet2, publicKey2, message, signature2);
        console.log(`Signature verification result for ${paramSet2}: ${isValid2}`);

        if (isValid2) {
            console.log("SUCCESS: All tests passed for " + paramSet2);
        } else {
            console.error("FAILURE: Signature verification failed for " + paramSet2);
        }


    } catch (error) {
        console.error("Error during Wasm function execution:", error);
    }
}

runTests();
