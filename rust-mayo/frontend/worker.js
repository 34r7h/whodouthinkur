// worker.js - Web Worker for MAYO cryptographic operations

let wasmModule = null;

// Load WASM module in worker
async function initWasm() {
    try {
        const wasmImport = await import('./pkg/rust_mayo.js');
        await wasmImport.default();
        wasmModule = wasmImport;
        console.log('[WORKER] WASM module loaded successfully');
        return true;
    } catch (error) {
        console.error('[WORKER] Failed to load WASM:', error);
        return false;
    }
}

// Handle messages from main thread
self.onmessage = async function(e) {
    const { operation, data, id } = e.data;
    
    try {
        // Initialize WASM if not already done
        if (!wasmModule) {
            const initialized = await initWasm();
            if (!initialized) {
                self.postMessage({
                    id,
                    error: 'Failed to initialize WASM module'
                });
                return;
            }
        }
        
        let result;
        
        switch (operation) {
            case 'generateKeys':
                console.log('[WORKER] Generating MAYO keys...');
                result = wasmModule.generate_keypair_wasm(data.param);
                console.log('[WORKER] Keys generated successfully');
                break;
                
            case 'sign':
                console.log('[WORKER] Signing message with MAYO...');
                const { param, secretKey, message } = data;
                result = wasmModule.sign_with_mayo(param, secretKey, message);
                console.log('[WORKER] Message signed successfully');
                break;
                
            case 'verify':
                console.log('[WORKER] Verifying MAYO signature...');
                const { param: verifyParam, publicKey, message: verifyMessage, signature } = data;
                result = wasmModule.verify_with_mayo(verifyParam, publicKey, verifyMessage, signature);
                console.log('[WORKER] Signature verified successfully');
                break;
                
            default:
                throw new Error(`Unknown operation: ${operation}`);
        }
        
        // Send result back to main thread
        self.postMessage({
            id,
            result
        });
        
    } catch (error) {
        console.error('[WORKER] Operation failed:', error);
        self.postMessage({
            id,
            error: error.message || 'Unknown error occurred'
        });
    }
};

// Handle worker errors
self.onerror = function(error) {
    console.error('[WORKER] Worker error:', error);
};

console.log('[WORKER] Web Worker initialized and ready'); 