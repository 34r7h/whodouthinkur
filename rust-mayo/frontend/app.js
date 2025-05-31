import init, { generate_mayo_keypair, sign_with_mayo, verify_with_mayo } from '../pkg/rust_mayo.js';

// Utility functions for hex conversion
function bytesToHex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
    if (hex.length === 0) return new Uint8Array(0);
    if (hex.length % 2 !== 0) throw new Error("Hex string must have an even number of characters.");
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}

// Store current keys globally for simplicity in this demo
let currentSkBytes = null;
let currentPkBytes = null;

// Wait for DOM to be ready
function waitForDOM() {
    return new Promise((resolve) => {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', resolve);
        } else {
            resolve();
        }
    });
}

async function main() {
    // Wait for DOM to be ready
    await waitForDOM();
    
    // Get DOM elements
    const paramSetSelect = document.getElementById('paramSet');
    const generateKeysBtn = document.getElementById('generateKeysBtn');
    const publicKeyText = document.getElementById('publicKey');
    const secretKeyText = document.getElementById('secretKey');
    const messageToSignText = document.getElementById('messageToSign');
    const signMessageBtn = document.getElementById('signMessageBtn');
    const signatureText = document.getElementById('signature');
    const verifySignatureBtn = document.getElementById('verifySignatureBtn');
    const statusMessage = document.getElementById('statusMessage');

    const savePkBtn = document.getElementById('savePkBtn');
    const uploadPkFile = document.getElementById('uploadPkFile');
    const saveSkBtn = document.getElementById('saveSkBtn');
    const uploadSkFile = document.getElementById('uploadSkFile');
    const saveSigBtn = document.getElementById('saveSigBtn');
    const uploadSigFile = document.getElementById('uploadSigFile');

    // Check if all elements exist
    if (!generateKeysBtn) {
        console.error('Generate keys button not found');
        return;
    }

    try {
        await init(); // Initialize Wasm module
        console.log("Rust-Mayo Wasm module initialized.");
        statusMessage.textContent = "Wasm module loaded. Ready.";
        statusMessage.className = "success";
    } catch (e) {
        console.error("Error initializing Wasm module:", e);
        statusMessage.textContent = "Error initializing Wasm: " + e;
        statusMessage.className = "error";
        return; // Stop if Wasm fails to load
    }

    generateKeysBtn.addEventListener('click', async (event) => {
        event.preventDefault();
        const paramSet = paramSetSelect.value;
        statusMessage.textContent = `Generating ${paramSet} keys...`;
        statusMessage.className = "";
        
        try {
            const keys = generate_mayo_keypair(paramSet);
            currentSkBytes = keys[0];
            currentPkBytes = keys[1];

            secretKeyText.value = bytesToHex(currentSkBytes);
            publicKeyText.value = bytesToHex(currentPkBytes);

            // LOG: Check for trailing zeros 
            const pkHex = bytesToHex(currentPkBytes);
            const trailingZeros = pkHex.match(/0*$/)?.[0]?.length || 0;
            console.log(`[DEBUG] ${paramSet} public key length: ${currentPkBytes.length} bytes`);
            console.log(`[DEBUG] ${paramSet} trailing zeros in hex: ${trailingZeros / 2} bytes`);
            if (trailingZeros > 10) {
                console.warn(`[DEBUG] ${paramSet} still has ${trailingZeros / 2} trailing zero bytes - implementation may still be incorrect`);
            } else {
                console.log(`[DEBUG] ✓ ${paramSet} trailing zeros fixed - proper compact key format`);
            }

            signatureText.value = ""; // Clear previous signature
            statusMessage.textContent = `${paramSet} Keypair generated successfully.`;
            statusMessage.className = "success";
        } catch (e) {
            console.error(`Error generating ${paramSet} keys:`, e);
            statusMessage.textContent = `Error generating keys: ${e}`;
            statusMessage.className = "error";
            secretKeyText.value = "";
            publicKeyText.value = "";
        }
    });

    signMessageBtn.addEventListener('click', async (event) => {
        event.preventDefault();
        const paramSet = paramSetSelect.value;
        const messageStr = messageToSignText.value;
        const messageBytes = new TextEncoder().encode(messageStr);

        if (!currentSkBytes) {
            statusMessage.textContent = "Please generate or load a secret key first.";
            statusMessage.className = "error";
            return;
        }

        statusMessage.textContent = `Signing message with ${paramSet}...`;
        statusMessage.className = "";
        try {
            const signatureBytes = sign_with_mayo(paramSet, currentSkBytes, messageBytes);
            signatureText.value = bytesToHex(signatureBytes);
            statusMessage.textContent = "Message signed successfully.";
            statusMessage.className = "success";
        } catch (e) {
            console.error(`Error signing message with ${paramSet}:`, e);
            statusMessage.textContent = `Error signing message: ${e}`;
            statusMessage.className = "error";
            signatureText.value = "";
        }
    });

    verifySignatureBtn.addEventListener('click', async (event) => {
        event.preventDefault();
        const paramSet = paramSetSelect.value;
        const messageStr = messageToSignText.value;
        const messageBytes = new TextEncoder().encode(messageStr);

        let pkToUse = currentPkBytes;
        if (publicKeyText.value && !currentPkBytes) {
             try {
                pkToUse = hexToBytes(publicKeyText.value);
            } catch (e) {
                statusMessage.textContent = `Invalid Public Key hex: ${e.message}`;
                statusMessage.className = "error";
                return;
            }
        }

        if (!pkToUse) {
            statusMessage.textContent = "Please generate or load a public key first.";
            statusMessage.className = "error";
            return;
        }

        let signatureBytes;
        try {
            signatureBytes = hexToBytes(signatureText.value);
            if (signatureBytes.length === 0) throw new Error("Signature is empty.");
        } catch (e) {
            statusMessage.textContent = `Invalid Signature hex: ${e.message}`;
            statusMessage.className = "error";
            return;
        }

        statusMessage.textContent = `Verifying signature with ${paramSet}...`;
        statusMessage.className = "";
        try {
            const isValid = verify_with_mayo(paramSet, pkToUse, messageBytes, signatureBytes);
            if (isValid) {
                statusMessage.textContent = "Signature is VALID.";
                statusMessage.className = "success";
            } else {
                statusMessage.textContent = "Signature is INVALID.";
                statusMessage.className = "error";
            }
        } catch (e) {
            console.error(`Error verifying signature with ${paramSet}:`, e);
            statusMessage.textContent = `Error verifying signature: ${e}`;
            statusMessage.className = "error";
        }
    });

    // File saving utility
    function saveFile(filename, data, type = 'application/octet-stream') {
        const blob = new Blob([data], { type });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    if (savePkBtn) {
        savePkBtn.addEventListener('click', () => {
            if (currentPkBytes) {
                saveFile(`${paramSetSelect.value.toLowerCase()}_public_key.key`, currentPkBytes);
            } else {
                statusMessage.textContent = "No public key to save.";
                statusMessage.className = "error";
            }
        });
    }

    if (saveSkBtn) {
        saveSkBtn.addEventListener('click', () => {
            if (currentSkBytes) {
                saveFile(`${paramSetSelect.value.toLowerCase()}_secret_key.key`, currentSkBytes);
            } else {
                statusMessage.textContent = "No secret key to save.";
                statusMessage.className = "error";
            }
        });
    }

    if (saveSigBtn) {
        saveSigBtn.addEventListener('click', () => {
            const signatureHex = signatureText.value;
            if (signatureHex) {
                try {
                    const signatureBytes = hexToBytes(signatureHex);
                    saveFile(`${paramSetSelect.value.toLowerCase()}_signature.sig`, signatureBytes);
                } catch (e) {
                     statusMessage.textContent = `Invalid signature hex for saving: ${e.message}`;
                     statusMessage.className = "error";
                }
            } else {
                statusMessage.textContent = "No signature to save.";
                statusMessage.className = "error";
            }
        });
    }

    // File loading utility
    function loadFile(fileElement, callback) {
        if (!fileElement) return;
        
        fileElement.addEventListener('change', (event) => {
            const file = event.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = (e) => {
                    const bytes = new Uint8Array(e.target.result);
                    callback(bytes, file.name);
                };
                reader.onerror = (e) => {
                    statusMessage.textContent = `Error reading file: ${e}`;
                    statusMessage.className = "error";
                };
                reader.readAsArrayBuffer(file);
            }
        });
        
        const label = document.querySelector(`label[for='${fileElement.id}']`);
        if (label) {
            label.classList.remove("hidden");
            label.addEventListener('click', () => fileElement.click() );
        } else {
             fileElement.classList.remove("hidden");
        }
    }

    loadFile(uploadPkFile, (bytes, filename) => {
        currentPkBytes = bytes;
        publicKeyText.value = bytesToHex(bytes);
        statusMessage.textContent = `Public key loaded from ${filename}.`;
        statusMessage.className = "success";
    });

    loadFile(uploadSkFile, (bytes, filename) => {
        currentSkBytes = bytes;
        secretKeyText.value = bytesToHex(bytes);
        signatureText.value = ""; // Clear previous signature as SK changed
        statusMessage.textContent = `Secret key loaded from ${filename}.`;
        statusMessage.className = "success";
    });

    loadFile(uploadSigFile, (bytes, filename) => {
        signatureText.value = bytesToHex(bytes);
        statusMessage.textContent = `Signature loaded from ${filename}.`;
        statusMessage.className = "success";
    });
}

main().catch(console.error);
