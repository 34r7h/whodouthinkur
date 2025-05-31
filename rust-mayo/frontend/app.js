// app.js - Frontend for MAYO signature demo with Web Worker

class MayoWorkerClient {
    constructor() {
        this.worker = null;
        this.pendingOperations = new Map();
        this.nextId = 1;
        this.init();
    }
    
    init() {
        this.worker = new Worker('./worker.js', { type: 'module' });
        
        this.worker.onmessage = (e) => {
            const { id, result, error } = e.data;
            const pending = this.pendingOperations.get(id);
            
            if (pending) {
                this.pendingOperations.delete(id);
                if (error) {
                    pending.reject(new Error(error));
                } else {
                    pending.resolve(result);
                }
            }
        };
        
        this.worker.onerror = (error) => {
            console.error('[CLIENT] Worker error:', error);
        };
    }
    
    async callWorker(operation, data) {
        return new Promise((resolve, reject) => {
            const id = this.nextId++;
            this.pendingOperations.set(id, { resolve, reject });
            
            this.worker.postMessage({
                operation,
                data,
                id
            });
            
            // Timeout after 30 seconds
            setTimeout(() => {
                if (this.pendingOperations.has(id)) {
                    this.pendingOperations.delete(id);
                    reject(new Error('Operation timed out'));
                }
            }, 30000);
        });
    }
    
    async generateKeys(param = 'MAYO1') {
        return this.callWorker('generateKeys', { param });
    }
    
    async sign(param, secretKey, message) {
        return this.callWorker('sign', { param, secretKey, message });
    }
    
    async verify(param, publicKey, message, signature) {
        return this.callWorker('verify', { param, publicKey, message, signature });
    }
}

// Global variables
let mayoClient = null;
let currentKeys = null;

// UI Elements
const statusElement = document.getElementById('status');
const generateBtn = document.getElementById('generateBtn');
const messageInput = document.getElementById('messageInput');
const signBtn = document.getElementById('signBtn');
const verifyBtn = document.getElementById('verifyBtn');
const signatureDisplay = document.getElementById('signatureDisplay');
const verificationResult = document.getElementById('verificationResult');

// Utility functions
function updateStatus(message, isError = false) {
    statusElement.textContent = message;
    statusElement.className = isError ? 'error' : 'success';
    console.log(`[STATUS] ${message}`);
}

function setButtonLoading(button, loading) {
    button.disabled = loading;
    button.textContent = loading ? 'Working...' : button.dataset.originalText || button.textContent;
    if (!button.dataset.originalText) {
        button.dataset.originalText = button.textContent;
    }
}

function arrayToHex(array) {
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

function hexToArray(hex) {
    const result = [];
    for (let i = 0; i < hex.length; i += 2) {
        result.push(parseInt(hex.substr(i, 2), 16));
    }
    return new Uint8Array(result);
}

// Initialize application
async function initApp() {
    try {
        updateStatus('Initializing MAYO Web Worker...');
        mayoClient = new MayoWorkerClient();
        
        // Wait a moment for worker to initialize
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        updateStatus('Ready! Generate keys to begin.');
        generateBtn.disabled = false;
        window.wasmReady = true;
        
    } catch (error) {
        updateStatus(`Failed to initialize: ${error.message}`, true);
        console.error('[INIT] Initialization failed:', error);
    }
}

// Generate keypair
async function generateKeypair() {
    try {
        setButtonLoading(generateBtn, true);
        updateStatus('Generating MAYO-1 keypair...');
        
        const keys = await mayoClient.generateKeys('MAYO1');
        currentKeys = keys;
        
        updateStatus(`Keys generated! SK: ${keys.secret_key.length} bytes, PK: ${keys.public_key.length} bytes`);
        
        // Enable other buttons
        signBtn.disabled = false;
        verifyBtn.disabled = false;
        
        console.log('[KEYS] Generated:', {
            secretKeyLength: keys.secret_key.length,
            publicKeyLength: keys.public_key.length
        });
        
    } catch (error) {
        updateStatus(`Key generation failed: ${error.message}`, true);
        console.error('[KEYS] Generation failed:', error);
    } finally {
        setButtonLoading(generateBtn, false);
    }
}

// Sign message
async function signMessage() {
    if (!currentKeys) {
        updateStatus('Please generate keys first!', true);
        return;
    }

    const message = messageInput.value.trim();
    if (!message) {
        updateStatus('Please enter a message to sign!', true);
        return;
    }

    try {
        setButtonLoading(signBtn, true);
        updateStatus('Signing message...');
        signatureDisplay.textContent = '';
        verificationResult.textContent = '';
        
        // Convert message to bytes
        const messageBytes = new TextEncoder().encode(message);
        
        const signature = await mayoClient.sign('MAYO1', currentKeys.secret_key, messageBytes);
        
        const hexSignature = arrayToHex(signature);
        signatureDisplay.textContent = hexSignature;
        
        updateStatus(`Message signed successfully! Signature: ${signature.length} bytes`);
        
        console.log('[SIGN] Success:', {
            messageLength: messageBytes.length,
            signatureLength: signature.length,
            signature: hexSignature.substring(0, 32) + '...'
        });
    } catch (error) {
        updateStatus(`Signing failed: ${error.message}`, true);
        console.error('[SIGN] Failed:', error);
        signatureDisplay.textContent = 'SIGNING FAILED';
    } finally {
        setButtonLoading(signBtn, false);
        // Log the current status text for debugging
        console.log('[DEBUG] Status after sign:', statusElement.textContent);
    }
}

// Verify signature
async function verifySignature() {
    if (!currentKeys) {
        updateStatus('Please generate keys first!', true);
        return;
    }
    
    const message = messageInput.value.trim();
    const signatureHex = signatureDisplay.textContent.trim();
    
    if (!message || !signatureHex || signatureHex === 'SIGNING FAILED') {
        updateStatus('Please sign a message first!', true);
        return;
    }
    
    try {
        setButtonLoading(verifyBtn, true);
        updateStatus('Verifying signature...');
        verificationResult.textContent = '';
        
        // Convert inputs to bytes
        const messageBytes = new TextEncoder().encode(message);
        const signatureBytes = hexToArray(signatureHex);
        
        const isValid = await mayoClient.verify('MAYO1', currentKeys.public_key, messageBytes, signatureBytes);
        
        verificationResult.textContent = isValid ? 'VALID ✓' : 'INVALID ✗';
        verificationResult.className = isValid ? 'success' : 'error';
        
        updateStatus(`Verification complete: ${isValid ? 'VALID' : 'INVALID'}`);
        
        console.log('[VERIFY] Result:', {
            messageLength: messageBytes.length,
            signatureLength: signatureBytes.length,
            isValid
        });
        
    } catch (error) {
        updateStatus(`Verification failed: ${error.message}`, true);
        console.error('[VERIFY] Failed:', error);
        verificationResult.textContent = 'VERIFICATION ERROR';
        verificationResult.className = 'error';
    } finally {
        setButtonLoading(verifyBtn, false);
    }
}

// Event listeners
generateBtn.addEventListener('click', generateKeypair);
signBtn.addEventListener('click', signMessage);
verifyBtn.addEventListener('click', verifySignature);

// Allow Enter key to trigger signing
messageInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && !signBtn.disabled) {
        signMessage();
    }
});

// Initialize when page loads
document.addEventListener('DOMContentLoaded', initApp);

console.log('[APP] MAYO Frontend with Web Worker initialized');
