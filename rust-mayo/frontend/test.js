import puppeteer from 'puppeteer';

async function testMayoSignatures() {
    console.log('Starting MAYO signature test...');
    
    const browser = await puppeteer.launch({
        headless: false,
        defaultViewport: null,
        args: ['--window-size=1200,800']
    });
    
    try {
        const page = await browser.newPage();
        
        // Enable console logging
        page.on('console', msg => console.log('Browser console:', msg.text()));
        
        // Navigate to the local server
        await page.goto('http://localhost:8080');
        console.log('Page loaded');
        
        // Wait for WASM to initialize
        await page.waitForFunction(() => window.wasmReady === true, { timeout: 10000 });
        console.log('WASM initialized');
        
        // Generate keys
        await page.click('#generateBtn');
        await page.waitForFunction(() => {
            const status = document.getElementById('status').textContent;
            return status.includes('Keys generated');
        }, { timeout: 10000 });
        console.log('Keys generated');
        
        // Enter test message
        await page.type('#messageInput', 'Test message for MAYO signature');
        
        // Sign message
        await page.click('#signBtn');
        await page.waitForFunction(() => {
            const status = document.getElementById('status').textContent;
            return status.includes('Message signed successfully');
        }, { timeout: 10000 });
        console.log('Message signed');
        
        // Get signature
        const signature = await page.evaluate(() => {
            return document.getElementById('signatureDisplay').textContent;
        });
        console.log('Signature:', signature);
        
        // Verify signature
        await page.click('#verifyBtn');
        await page.waitForFunction(() => {
            const result = document.getElementById('verificationResult').textContent;
            return result.includes('Signature is valid');
        }, { timeout: 10000 });
        console.log('Signature verified');
        
        // Take screenshot
        await page.screenshot({ path: 'mayo-test-result.png' });
        console.log('Screenshot saved');
        
    } catch (error) {
        console.error('Test failed:', error);
    } finally {
        await browser.close();
    }
}

testMayoSignatures().catch(console.error); 