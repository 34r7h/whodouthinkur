import puppeteer from 'puppeteer';

async function testMayoCrypto() {
    console.log('[PUPPETEER] Starting MAYO crypto test...');
    
    let browser;
    try {
        // Launch browser with console output
        browser = await puppeteer.launch({ 
            headless: false,
            devtools: true,
            args: ['--disable-web-security', '--disable-features=VizDisplayCompositor']
        });
        
        const page = await browser.newPage();
        
        // Enable console logging from the page
        page.on('console', msg => {
            const type = msg.type();
            const text = msg.text();
            console.log(`[BROWSER ${type.toUpperCase()}] ${text}`);
        });
        
        page.on('pageerror', error => {
            console.log(`[BROWSER ERROR] ${error.message}`);
        });
        
        // Navigate to the MAYO demo page
        console.log('[PUPPETEER] Navigating to http://localhost:8082/index.html');
        await page.goto('http://localhost:8082/index.html', { 
            waitUntil: 'networkidle2', 
            timeout: 30000 
        });
        
        // Wait for the app to initialize
        console.log('[PUPPETEER] Waiting for WASM to load...');
        await page.waitForSelector('#generateBtn:not([disabled])', { timeout: 15000 });
        
        // Take screenshot after initialization
        await page.screenshot({ path: 'mayo_test_init.png' });
        console.log('[PUPPETEER] ✅ Screenshot saved: mayo_test_init.png');
        
        // Test 1: Generate keys
        console.log('[PUPPETEER] Testing key generation...');
        await page.click('#generateBtn');
        
        // Wait for key generation to complete
        await page.waitForFunction(() => {
            const status = document.getElementById('status').textContent;
            return status.includes('Keys generated!') || status.includes('failed');
        }, { timeout: 15000 });
        
        const keyStatus = await page.$eval('#status', el => el.textContent);
        console.log(`[PUPPETEER] Key generation result: ${keyStatus}`);
        
        if (keyStatus.includes('failed')) {
            throw new Error('Key generation failed');
        }
        
        // Test 2: Sign message
        console.log('[PUPPETEER] Testing message signing...');
        
        // Set a test message
        await page.$eval('#messageInput', el => el.value = 'Test MAYO signature');
        
        // Click sign button
        await page.click('#signBtn');
        
        // Wait for signing to complete (longer timeout for NIST compliance)
        await page.waitForFunction(() => {
            const status = document.getElementById('status').textContent;
            return status.includes('signed successfully') || status.includes('failed');
        }, { timeout: 60000 });
        
        const signStatus = await page.$eval('#status', el => el.textContent);
        console.log(`[PUPPETEER] Signing result: ${signStatus}`);
        
        // Get the signature
        const signature = await page.$eval('#signatureDisplay', el => el.textContent);
        console.log(`[PUPPETEER] Signature (first 64 chars): ${signature.substring(0, 64)}...`);
        
        if (signStatus.includes('failed') || signature === 'SIGNING FAILED') {
            console.log('[PUPPETEER] ❌ Signing failed - this indicates an implementation issue');
            await page.screenshot({ path: 'mayo_test_sign_fail.png' });
            
            // Log detailed error information
            const consoleMessages = await page.evaluate(() => {
                return window.lastErrorMessages || 'No error messages captured';
            });
            console.log(`[PUPPETEER] Error details: ${consoleMessages}`);
            
            return { success: false, error: 'Signing failed', stage: 'signing' };
        }
        
        // Test 3: Verify signature
        console.log('[PUPPETEER] Testing signature verification...');
        await page.click('#verifyBtn');
        
        // Wait for verification to complete
        await page.waitForFunction(() => {
            const status = document.getElementById('status').textContent;
            return status.includes('Verification complete') || status.includes('failed');
        }, { timeout: 30000 });
        
        const verifyStatus = await page.$eval('#status', el => el.textContent);
        const verifyResult = await page.$eval('#verificationResult', el => el.textContent);
        
        console.log(`[PUPPETEER] Verification result: ${verifyStatus}`);
        console.log(`[PUPPETEER] Verification status: ${verifyResult}`);
        
        // Take final screenshot
        await page.screenshot({ path: 'mayo_test_complete.png' });
        console.log('[PUPPETEER] ✅ Screenshot saved: mayo_test_complete.png');
        
        // Analyze results
        const success = verifyResult.includes('VALID ✓');
        
        console.log('\n[PUPPETEER] ============ TEST RESULTS ============');
        console.log(`[PUPPETEER] Key Generation: ✅ SUCCESS`);
        console.log(`[PUPPETEER] Message Signing: ${signStatus.includes('signed successfully') ? '✅ SUCCESS' : '❌ FAILED'}`);
        console.log(`[PUPPETEER] Signature Verification: ${success ? '✅ SUCCESS' : '❌ FAILED'}`);
        console.log(`[PUPPETEER] Overall Result: ${success ? '✅ ALL TESTS PASSED' : '❌ SOME TESTS FAILED'}`);
        
        return { 
            success, 
            keyGeneration: true,
            signing: signStatus.includes('signed successfully'),
            verification: success,
            signature: signature.substring(0, 64) + '...'
        };
        
    } catch (error) {
        console.log(`[PUPPETEER] ❌ Test failed: ${error.message}`);
        
        if (browser) {
            try {
                const page = await browser.pages()[0];
                await page.screenshot({ path: 'mayo_test_error.png' });
                console.log('[PUPPETEER] Error screenshot saved: mayo_test_error.png');
            } catch (screenshotError) {
                console.log('[PUPPETEER] Could not take error screenshot');
            }
        }
        
        return { success: false, error: error.message };
        
    } finally {
        if (browser) {
            await browser.close();
        }
    }
}

// Run the test
testMayoCrypto().then(result => {
    console.log('\n[PUPPETEER] Final Result:', JSON.stringify(result, null, 2));
    process.exit(result.success ? 0 : 1);
}).catch(error => {
    console.error('[PUPPETEER] Test crashed:', error);
    process.exit(1);
}); 