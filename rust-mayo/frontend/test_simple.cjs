const puppeteer = require('puppeteer');

async function quickTest() {
    console.log('Starting quick MAYO test...');
    
    const browser = await puppeteer.launch({ 
        headless: false,
        args: ['--no-sandbox']
    });
    
    const page = await browser.newPage();
    
    // Listen to console logs
    page.on('console', msg => {
        const type = msg.type();
        if (type === 'log') {
            console.log(`[BROWSER] log: ${msg.text()}`);
        } else if (type === 'error') {
            console.log(`[BROWSER] error: ${msg.text()}`);
        }
    });
    
    await page.goto('http://127.0.0.1:8080');
    
    // Wait for WASM to load
    await page.waitForFunction(() => window.wasmReady === true, { timeout: 10000 });
    console.log('WASM loaded successfully');
    
    // Generate keys
    console.log('Generating keys...');
    await page.click('#generateBtn');
    
    // Wait for keys to be generated
    await page.waitForFunction(() => window.currentKeys !== null, { timeout: 5000 });
    console.log('Keys generated');
    
    // Try signing
    console.log('Attempting to sign...');
    await page.click('#signBtn');
    
    // Wait a bit for signing to complete
    await page.waitForTimeout(5000);
    
    // Check if signature was created
    const hasSignature = await page.evaluate(() => {
        const sigDiv = document.getElementById('signatureDisplay');
        return sigDiv && sigDiv.textContent !== 'No signature yet...';
    });
    
    if (hasSignature) {
        console.log('✓ Signature created successfully');
        
        // Try verification
        console.log('Attempting verification...');
        await page.click('#verifyBtn');
        
        // Wait for verification
        await page.waitForTimeout(2000);
        
        const verificationResult = await page.evaluate(() => {
            const verifyDiv = document.getElementById('verificationResult');
            return verifyDiv ? verifyDiv.textContent : 'Unknown';
        });
        
        console.log(`Verification result: ${verificationResult}`);
        
        if (verificationResult.includes('✓')) {
            console.log('✅ MAYO implementation is working correctly!');
        } else {
            console.log('❌ Verification failed');
        }
    } else {
        console.log('❌ Signing failed - no signature created');
    }
    
    // Keep browser open for manual inspection
    console.log('Test complete - browser remains open for inspection');
    
    // Don't close the browser automatically
    // await browser.close();
}

quickTest().catch(err => {
    console.error('Test error:', err);
}); 